package grandine

import (
	"github.com/ethereum/go-ethereum/eth"
	"github.com/grandinetech/grandine"
)

type Client struct {
}

func NewClient(eth *eth.Ethereum) *Client {
	return &Client{}
}

func (c *Client) startGrandine() {
	grandine.RunGrandine()
}

func (c *Client) Start() error {
	go c.startGrandine()

	return nil
}

func (c *Client) Stop() error {
	// close(c.shutdownCh)
	return nil
}
