package tunnel

type TunnelConfig struct {
	LocalIface   string `json:"local_iface"`
	LocalPort    int    `json:"local_port"`
	LocalAddr    string `json:"local_addr"`
	PreSharedKey string `json:"pre_shared_key"`
	PrivateKey   string `json:"private_key"`
	Mtu          int    `json:"mtu"`
	Peers        []Peer `json:"peers"`
}

type Tunnel interface {
	GetPublicKey() string
	GetType() string
	Start() error
	Stop() error
	GetInterfaceName() string
	GetInterfacePort() int
	UpdateEndpoint(string, string) error
	UpdateAddress(string)
	AddUpdateClient([]byte) error
	GetInterfaceAddress() string
	SetupConRoutes(string) error
}
