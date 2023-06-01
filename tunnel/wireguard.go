package tunnel

import (
	"github.com/salmanmalik-emb/zta-v2/iface"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"os/exec"
	"time"
)

const DefaultWgKeepAlive = 25 * time.Second

type WireguardEngine struct {
	config      *TunnelConfig
	wgInterface *iface.WGIface
	Peers       map[string]*Peer
}

func NewWireguardInterface(
	config *TunnelConfig,
) *WireguardEngine {
	return &WireguardEngine{
		config: config,
		Peers:  map[string]*Peer{},
	}
}

func (e *WireguardEngine) GetType() string {
	return "wireguard"
}

func (e *WireguardEngine) Stop() error {
	if e.wgInterface != nil && e.wgInterface.Interface != nil {
		err := e.wgInterface.Close()
		if err != nil {
			log.Errorf("failed closing Wireguard interface %s %v", e.config.LocalIface, err)
			return err
		}
	}

	log.Infof("Wireguard Interface Stopped")
	return nil
}

func (e *WireguardEngine) Start() error {
	wgIfaceName := e.config.LocalIface
	myPrivateKey, err := wgtypes.ParseKey(e.config.PrivateKey)

	e.wgInterface, err = iface.NewWGIFace(wgIfaceName, e.config.LocalAddr, e.config.Mtu)

	if err != nil {
		log.Errorf("failed creating wireguard interface instance %s: [%s]", wgIfaceName, err.Error())
		return err
	}

	err = e.wgInterface.Create()
	if err != nil {
		log.Errorf("failed creating tunnel interface %s: [%s]", wgIfaceName, err.Error())
		return err
	}

	err = e.wgInterface.Configure(myPrivateKey.String(), e.config.LocalPort)
	if err != nil {
		log.Errorf("failed configuring Wireguard interface [%s]: %s", wgIfaceName, err.Error())
		return err
	}

	for _, peer := range e.Peers {
		err = e.addUpdateClient(peer)
		if err != nil {
			log.Errorf("failed to add peer %v, %v", peer, err.Error())
			return err
		}

	}
	return nil
}

func (e *WireguardEngine) UpdateAddress(addr string) {
	e.config.LocalAddr = addr
}

func (e *WireguardEngine) GetPeer(id string) *Peer {

	if peer, ok := e.Peers[id]; ok {
		return peer
	}
	return nil

}

func (e *WireguardEngine) AddUpdateClient(p []byte) error {

	peer, err := FromByteArray(p)

	if err != nil {
		return err
	}

	e.Peers[peer.Id] = peer

	return e.addUpdateClient(peer)

}

func (e *WireguardEngine) addUpdateClient(peer *Peer) error {
	if e.wgInterface != nil {

		var presharedParsedKey wgtypes.Key
		var err error
		if peer.PresharedKey != "" {
			presharedParsedKey, err = wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return err
			}
		}

		if err != nil {
			return err
		}

		var addr *net.UDPAddr

		if peer.Endpoint != "" {
			addr, err = net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return err
			}

		}

		err = e.wgInterface.UpdatePeer(peer.PublicKey, peer.AllowedIPs[0], DefaultWgKeepAlive,
			addr, &presharedParsedKey)

		if err != nil {
			return err
		}

		err = e.SetupConRoutes(peer.AllowedIPs[0])
		if err != nil {
			log.Errorf("failed to create route %s", peer.AllowedIPs[0])
		}

	}

	// only add peer to list if interface is not up
	e.Peers[peer.Id] = peer

	return nil

}

func (e *WireguardEngine) UpdateEndpoint(id string, endpoint string) error {
	peer := e.GetPeer(id)
	if peer == nil {
		return nil
	}

	peer.Endpoint = endpoint
	return e.AddUpdateClient(peer.ToByteArray())
}

func (e *WireguardEngine) GetInterfaceName() string {
	return e.config.LocalIface
}

func (e *WireguardEngine) GetInterfacePort() int {
	return e.config.LocalPort
}

func (e *WireguardEngine) GetInterfaceAddress() string {
	return e.config.LocalAddr
}

func (e *WireguardEngine) SetupConRoutes(ipAddr string) error {
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

	addRoute := exec.Command("ip", "route", "add", ip.String(), "dev", e.config.LocalIface, "proto", "static", "src", localIp.String())
	if err := addRoute.Run(); err != nil {
		log.Errorf("failed to add route %s", ip.String())
		return err
	}
	return nil
}

func (e *WireguardEngine) GetPublicKey() string {
	myPrivateKey, _ := wgtypes.ParseKey(e.config.PrivateKey)

	return myPrivateKey.PublicKey().String()
}
