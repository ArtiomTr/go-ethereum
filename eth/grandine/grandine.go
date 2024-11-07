package grandine

import (
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/node"
	"github.com/grandinetech/grandine"
	"github.com/urfave/cli/v2"
)

var (
	Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "grandine.network",
			Usage:    "Name of the Eth2 network to connect to",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.configuration-file",
			Usage:    "Load configuration from YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.configuration-directory",
			Usage:    "Load configuration from directory",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.verify-phase0-preset-file",
			Usage:    "Verify that Phase 0 variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.altair-preset-file",
			Usage:    "Verify that Altair variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.bellatrix-preset-file",
			Usage:    "Verify that Bellatrix variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.capella-preset-file",
			Usage:    "Verify that Capella variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.verify-deneb-preset-file",
			Usage:    "Verify that Deneb variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.verify-electra-preset-file",
			Usage:    "Verify that Electra variables in preset match YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.verify-configuration-file",
			Usage:    "Verify that configuration matches YAML_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.terminal-total-difficulty-override",
			Usage:    "Override TERMINAL_TOTAL_DIFFICULTY",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.terminal-block-hash-override",
			Usage:    "Override TERMINAL_BLOCK_HASH",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.terminal-block-hash-activation-epoch-override",
			Usage:    "Override TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.deposit-contract-starting-block",
			Usage:    "Start tracking deposit contract from BLOCK_NUMBER",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.genesis-state-file",
			Usage:    "Load genesis state from SSZ_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.genesis-state-download-url",
			Usage:    "Download genesis state from specified URL",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.max-empty-slots",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.checkpoint-sync-url",
			Usage:    "Beacon node API URL to load recent finalized checkpoint and sync from it",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.force-checkpoint-sync",
			Usage:    "Force checkpoint sync. Requires checkpoint-sync-url",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.eth1-rpc-urls",
			Usage:    "List of Eth1 RPC URLs",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.data-dir",
			Usage:    "Parent directory for application data files",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.store-directory",
			Usage:    "Directory to store application data files",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.network-dir",
			Usage:    "Directory to store application network files",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.archival-epoch-interval",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.prune-storage",
			Usage:    "Enable prune mode where only single checkpoint state & block are stored in the DB",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.unfinalized-states-in-memory",
			Usage:    "Number of unfinalized states to keep in memory",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.database-size",
			Usage:    "Max size of the Eth2 database",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.eth1-database-size",
			Usage:    "Max size of the Eth1 database",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.request-timeout",
			Usage:    "Default global request timeout for various services in milliseconds",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.state-cache-lock-timeout",
			Usage:    "Default state cache lock timeout in milliseconds",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.state-slot",
			Usage:    "State slot",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.subscribe-all-subnets",
			Usage:    "Subscribe to all subnets",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.suggested-fee-recipient",
			Usage:    "Suggested value for the feeRecipient field of the new payload",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.jwt-id",
			Usage:    "Optional CL unique identifier to send to EL in the JWT token claim",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.jwt-secret",
			Usage:    "Path to a file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.jwt-version",
			Usage:    "Optional CL node type/version to send to EL in the JWT token claim",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.back-sync",
			Usage:    "Enable syncing historical data",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.metrics",
			Usage:    "Collect Prometheus metrics",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.metrics-address",
			Usage:    "Metrics address for metrics endpoint",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.metrics-port",
			Usage:    "Listen port for metrics endpoint",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.remote-metrics-url",
			Usage:    "Optional remote metrics URL that Grandine will periodically send metrics to",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.track-liveness",
			Usage:    "Enable validator liveness tracking",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.detect-doppelgangers",
			Usage:    "Enable doppelganger protection (liveness tracking must be enabled for this feature)",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.in-memory",
			Usage:    "Enable in-memory mode. No data will be stored in data-dir.",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.http-address",
			Usage:    "HTTP API address",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.http-port",
			Usage:    "HTTP API port",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.http-allowed-origins",
			Usage:    "List of Access-Control-Allow-Origin header values for the HTTP API server. Defaults to the listening URL of the HTTP API server",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.max-events",
			Usage:    "Max number of events stored in a single channel for HTTP API /events api call",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.timeout",
			Usage:    "HTTP API timeout in milliseconds",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.listen-address",
			Usage:    "Listen IPv4 address",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.listen-address-ipv6",
			Usage:    "Listen IPv6 address",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.libp2p-port",
			Usage:    "libp2p IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.libp2p-port-ipv6",
			Usage:    "libp2p IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.disable-quic",
			Usage:    "Disable QUIC support as a fallback transport to TCP",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.disable-peer-scoring",
			Usage:    "Disable peer scoring",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.disable-upnp",
			Usage:    "Disable NAT traversal via UPnP",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.disable-enr-auto-update",
			Usage:    "Disable enr auto update",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.discovery-port",
			Usage:    "discv5 IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.discovery-port-ipv6",
			Usage:    "discv5 IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.quic-port",
			Usage:    "QUIC IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.quic-port-ipv6",
			Usage:    "QUIC IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.enable-private-discovery",
			Usage:    "Enable discovery of peers with private IP addresses.",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.enr-address",
			Usage:    "ENR IPv4 address",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.enr-address-ipv6",
			Usage:    "ENR IPv6 address",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-tcp-port",
			Usage:    "ENR TCP IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-tcp-port-ipv6",
			Usage:    "ENR TCP IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-udp-port",
			Usage:    "ENR UDP IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-udp-port-ipv6",
			Usage:    "ENR UDP IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-quic-port",
			Usage:    "ENR QUIC IPv4 port",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.enr-quic-port-ipv6",
			Usage:    "ENR QUIC IPv6 port",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.boot-nodes",
			Usage:    "List of ENR boot node addresses",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.libp2p-nodes",
			Usage:    "List of Multiaddr node addresses",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.libp2p-private-key-file",
			Usage:    "Load p2p private key from KEY_FILE",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.target-peers",
			Usage:    "Target number of network peers",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.target-subnet-peers",
			Usage:    "Target number of subnet peers",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.trusted-peers",
			Usage:    "List of trusted peers",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.keystore-dir",
			Usage:    "Path to a directory containing EIP-2335 keystore files",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.keystore-password-dir",
			Usage:    "Path to a directory containing passwords for keystore files",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.keystore-password-file",
			Usage:    "Path to a file containing password for keystore files",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.keystore-storage-password-file",
			Usage:    "Path to a file containing password for decrypting imported keystores from API",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.builder-api-url",
			Usage:    "[DEPRECATED] External block builder API URL",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.builder-url",
			Usage:    "External block builder URL",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.builder-disable-checks",
			Usage:    "Always use specified external block builder without checking for circuit breaker conditions",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.builder-max-skipped-slots",
			Usage:    "Max allowed consecutive missing blocks to trigger circuit breaker condition and switch to local execution engine for payload construction",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.builder-max-skipped-slots-per-epoch",
			Usage:    "Max allowed missing blocks in the last rolling epoch to trigger circuit breaker condition and switch to local execution engine for payload construction",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.web3signer-public-keys",
			Usage:    "List of public keys to use from Web3Signer",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.web3signer-refresh-keys-every-epoch",
			Usage:    "Refetches keys from Web3Signer once every epoch. This overwrites changes done via Keymanager API",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.web3signer-api-urls",
			Usage:    "[DEPRECATED] List of Web3Signer API URLs",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.web3signer-urls",
			Usage:    "List of Web3Signer URLs",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.use-validator-key-cache",
			Usage:    "Use validator key cache for faster startup",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.slashing-protection-history-limit",
			Usage:    "Number of epochs to keep slashing protection data for",
			Category: flags.GrandineCategory,
		},
		&cli.BoolFlag{
			Name:     "grandine.enable-validator-api",
			Usage:    "Enable validator API",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.validator-api-address",
			Usage:    "Validator API address",
			Category: flags.GrandineCategory,
		},
		&cli.UintFlag{
			Name:     "grandine.validator-api-port",
			Usage:    "Listen port for validator API",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.validator-api-allowed-origins",
			Usage:    "List of Access-Control-Allow-Origin header values for the validator API server. Defaults to the listening URL of the validator API server",
			Category: flags.GrandineCategory,
		},
		&cli.Uint64Flag{
			Name:     "grandine.validator-api-timeout",
			Usage:    "Validator API timeout in milliseconds",
			Category: flags.GrandineCategory,
		},
		&cli.StringFlag{
			Name:     "grandine.validator-api-token-file",
			Usage:    "Path to a file containing validator API auth token",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.graffiti",
			Usage:    "",
			Category: flags.GrandineCategory,
		},
		&cli.StringSliceFlag{
			Name:     "grandine.features",
			Usage:    "List of optional runtime features to enable",
			Category: flags.GrandineCategory,
		},
	}
)

type Client struct {
	args []string
}

func convertFlagName(name string) string {
	return "--" + name[len("grandine."):]
}

func NewClient(ctx *cli.Context, nodeConfig *node.Config) *Client {
	args := []string{}

	for _, flag := range Flags {
		strFlag, isStrFlag := flag.(*cli.StringFlag)
		if isStrFlag {
			if ctx.IsSet(strFlag.Name) {
				args = append(args, convertFlagName(strFlag.Name), ctx.String(strFlag.Name))
			}

			continue
		}

		boolFlag, isBoolFlag := flag.(*cli.BoolFlag)
		if isBoolFlag {
			if ctx.IsSet(boolFlag.Name) && ctx.Bool(boolFlag.Name) {
				args = append(args, convertFlagName(boolFlag.Name))
			}

			continue
		}

		uintFlag, isUintFlag := flag.(*cli.UintFlag)
		if isUintFlag {
			if ctx.IsSet(uintFlag.Name) {
				args = append(args, convertFlagName(uintFlag.Name), strconv.FormatUint(uint64(ctx.Uint(uintFlag.Name)), 10))
			}

			continue
		}

		uint64Flag, isUint64Flag := flag.(*cli.Uint64Flag)
		if isUint64Flag {
			if ctx.IsSet(uint64Flag.Name) {
				args = append(args, convertFlagName(uint64Flag.Name), strconv.FormatUint(ctx.Uint64(uint64Flag.Name), 10))
			}

			continue
		}

		strSliceFlag, isStrSliceFlag := flag.(*cli.StringSliceFlag)
		if isStrSliceFlag {
			if ctx.IsSet(strSliceFlag.Name) {
				for _, item := range ctx.StringSlice(strSliceFlag.Name) {
					args = append(args, convertFlagName(strSliceFlag.Name), item)
				}
			}

			continue
		}
	}

	args = append(args, "--eth1-rpc-urls", fmt.Sprintf("http://%s:%d", nodeConfig.AuthAddr, nodeConfig.AuthPort))
	args = append(args, "--jwt-secret", nodeConfig.JWTSecret)

	switch {
	case ctx.Bool(utils.MainnetFlag.Name):
		args = append(args, "--network", "mainnet")
	case ctx.Bool(utils.HoleskyFlag.Name):
		args = append(args, "--network", "holesky")
	}

	return &Client{
		args,
	}
}

func (c *Client) startGrandine(args []string) {
	grandine.RunGrandine(args)
}

func (c *Client) Start() error {
	go c.startGrandine(c.args)

	return nil
}

func (c *Client) Stop() error {
	// close(c.shutdownCh)
	return nil
}
