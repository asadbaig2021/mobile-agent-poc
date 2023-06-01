package tunnel

import (
	"fmt"
	"github.com/bronze1man/goStrongswanVici"
	log "github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"strconv"
)

type IpsecEngine struct {
	config *TunnelConfig
	client *goStrongswanVici.Client
	Peers  map[string]*Peer
}

func NewIpsecInterface(
	config *TunnelConfig,
) *IpsecEngine {
	return &IpsecEngine{
		config: config,
		Peers:  map[string]*Peer{},
	}
}

func (e *IpsecEngine) GetType() string {
	return "ipsec"
}

func (e *IpsecEngine) Stop() error {
	cmd := exec.Command("ipsec", "stop")
	if err := cmd.Run(); err != nil {
		return err
	}

	// remove garbage routes
	if e.config.LocalAddr != "" {
		addIPAddress := exec.Command("ip", "address", "del", e.config.LocalAddr, "dev", e.config.LocalIface)
		if err := addIPAddress.Run(); err != nil {
			log.Errorf("error removing ip address %s, %v", e.config.LocalAddr, err.Error())
		}

		for _, peer := range e.Peers {
			ip, _, err := net.ParseCIDR(peer.AllowedIPs[0])
			localIp, _, err := net.ParseCIDR(e.config.LocalAddr)

			if err == nil {
				addRoute := exec.Command("ip", "route", "del", ip.String(), "dev", e.config.LocalIface, "proto", "static", "src", localIp.String())
				if err := addRoute.Run(); err != nil {
					log.Errorf("failed to remove route %s, %v", ip.String(), err.Error())
				}
			}

		}
	}

	return nil
}

func (e *IpsecEngine) Start() error {
	var err error
	cmd := exec.Command("ipsec", "restart")
	if err = cmd.Run(); err != nil {
		return err
	}

	e.client = goStrongswanVici.NewClientFromDefaultSocket()
	if err != nil {
		fmt.Println("Error in connecting StrongSwan daemon")
	}

	if e.config.LocalAddr != "" {
		addIPAddress := exec.Command("ip", "address", "add", e.config.LocalAddr, "dev", e.config.LocalIface)
		if err := addIPAddress.Run(); err != nil {
			log.Errorf("error creating ip address %s", e.config.LocalAddr)
		}
	}

	return nil
}

func (e *IpsecEngine) AddUpdateClient(p []byte) error {

	peer, err := FromByteArray(p)

	if err != nil {
		return err
	}

	e.Peers[peer.Id] = peer

	if peer.Endpoint == "" {
		log.Debugf("skip adding conn with endpoint %s", peer.Id)
		return nil
	}

	// Create the configuration for the IPsec connection
	client, err := goStrongswanVici.NewClientConnFromDefaultSocket()
	if err != nil {
		return err
	}

	// get strongswan version
	v, err := client.Version()
	if err != nil {
		return err
	}
	log.Debugf("strongswan version %s", v)

	childConfMap := make(map[string]goStrongswanVici.ChildSAConf)

	var localTs = []string{}
	var remotePort = ""
	var remoteAddr = ""
	var connName = peer.Id
	var connChild = connName + "-child"

	if e.config.LocalAddr != "" {
		localTs = []string{e.config.LocalAddr}
	}

	if peer.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return err
		}

		remoteAddr = addr.IP.String()
		remotePort = strconv.Itoa(addr.Port)

	}
	childSAConf := goStrongswanVici.ChildSAConf{
		Local_ts:      localTs,
		Remote_ts:     peer.AllowedIPs,
		ESPProposals:  []string{"aes256-sha256-modp2048"},
		StartAction:   "trap",
		CloseAction:   "restart",
		Mode:          "tunnel",
		ReqID:         "10",
		RekeyTime:     "10m",
		InstallPolicy: "yes",
	}
	childConfMap[connChild] = childSAConf

	ip, _, err := net.ParseCIDR(peer.AllowedIPs[0])

	if err != nil {
		log.Errorf("failed to parse ip address %s", peer.AllowedIPs[0])
		return err
	}

	localIp, _, err := net.ParseCIDR(e.config.LocalAddr)

	if err != nil {
		log.Errorf("failed to parse local ip address %s", e.config.LocalAddr)
		return err
	}

	localAuthConf := goStrongswanVici.AuthConf{
		ID:         localIp.String(),
		AuthMethod: "psk",
	}
	remoteAuthConf := goStrongswanVici.AuthConf{
		ID:         ip.String(),
		AuthMethod: "psk",
	}

	ikeConfMap := make(map[string]goStrongswanVici.IKEConf)

	ikeConf := goStrongswanVici.IKEConf{
		LocalPort:   strconv.Itoa(e.config.LocalPort),
		RemotePort:  remotePort,
		LocalAddrs:  []string{"%any"},
		RemoteAddrs: []string{remoteAddr},
		Proposals:   []string{"aes256-sha256-modp2048"},
		Version:     "2",
		LocalAuth:   localAuthConf,
		RemoteAuth:  remoteAuthConf,
		Children:    childConfMap,
		Encap:       "no",
	}

	ikeConfMap[connName] = ikeConf

	//load connenction information into strongswan
	err = client.LoadConn(&ikeConfMap)
	if err != nil {
		log.Errorf("error loading connection %v", ikeConfMap)
		return err
	}

	sharedKey := &goStrongswanVici.Key{
		Typ:    "IKE",
		Data:   e.config.PreSharedKey,
		Owners: []string{ip.String()}, //IP of the remote host
	}

	//load shared key into strongswan
	err = client.LoadShared(sharedKey)
	if err != nil {
		log.Errorf("error returned from loadsharedkey \n %v", err)

		return err
	}

	err = client.Initiate(connChild, connName)
	if err != nil {
		log.Errorf("failed to initiate connection \n %v", err)
		return err
	}

	err = e.SetupConRoutes(peer.AllowedIPs[0])
	if err != nil {
		log.Errorf("failed to create route %s, %v", peer.AllowedIPs[0], err.Error())
	}

	return nil

}

func (e *IpsecEngine) UpdateAddress(addr string) {

	addIPAddress := exec.Command("ip", "address", "add", addr, "dev", e.config.LocalIface)
	if err := addIPAddress.Run(); err != nil {
		log.Errorf("error creating ip address %s", addr)
	}
	e.config.LocalAddr = addr
}

func (e *IpsecEngine) GetPeer(id string) *Peer {

	if peer, ok := e.Peers[id]; ok {
		return peer
	}
	return nil

}

func (e *IpsecEngine) UpdateEndpoint(id string, endpoint string) error {
	peer := e.GetPeer(id)
	if peer == nil {
		return nil
	}

	peer.Endpoint = endpoint
	return e.AddUpdateClient(peer.ToByteArray())
}

func (e *IpsecEngine) GetInterfaceName() string {
	return e.config.LocalIface
}

func (e *IpsecEngine) GetInterfacePort() int {
	return e.config.LocalPort
}

func (e *IpsecEngine) GetInterfaceAddress() string {
	return e.config.LocalAddr
}

func (e *IpsecEngine) SetupConRoutes(ipAddr string) error {
	ip, _, err := net.ParseCIDR(ipAddr)

	if err != nil {
		log.Errorf("failed to parse ip address %s", ipAddr)
		return err
	}

	localIp, _, err := net.ParseCIDR(e.config.LocalAddr)

	if err != nil {
		log.Errorf("failed to parse local ip address %s", e.config.LocalAddr)
		return err
	}

	delRoute := exec.Command("ip", "route", "del", "table", "220", ip.String())
	if err := delRoute.Run(); err != nil {
		log.Errorf("failed to delete route %s", ip.String())
	}

	addRoute := exec.Command("ip", "route", "add", ip.String(), "dev", e.config.LocalIface, "proto", "static", "src", localIp.String())
	if err := addRoute.Run(); err != nil {
		log.Errorf("failed to add route %s", ip.String())
		return err
	}

	return nil

}

func (e *IpsecEngine) GetPublicKey() string {
	return e.config.PreSharedKey
}
