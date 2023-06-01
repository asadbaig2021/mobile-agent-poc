package tunnel

import (
	"encoding/json"
)

type Peer struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Id           string   `json:"id"`
}

func (p *Peer) ToByteArray() []byte {
	// Marshal the Peer struct into a byte array
	byteArray, err := json.Marshal(p)
	if err != nil {
		return nil
	}

	return byteArray
}

func FromByteArray(byteArray []byte) (*Peer, error) {
	p := &Peer{}
	err := json.Unmarshal(byteArray, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}
