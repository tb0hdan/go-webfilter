package nft

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/rs/zerolog"
)

type NFTFirewall struct {
	logger zerolog.Logger
}

func (n *NFTFirewall) InstallRules(redirectPort int) error {
	commands := [][]string{
		{"nft", "add", "table", "ip", "go_webfilter"},
		{"nft", "add", "chain", "ip", "go_webfilter", "go_webfilter_nat",
			// meta skuid root return; - Do not process packets coming from user uid == 0 (root)
			// tcp dport 80 redirect to :<redirectPort>; - Redirect HTTP traffic to the specified port
			fmt.Sprintf("{meta skuid root return; tcp dport 80 redirect to :%d;}", redirectPort)},
		// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
		// priority dstnat equals to -100
		{"nft", "add", "chain", "ip", "go_webfilter", "OUTPUT", "{type nat hook output priority dstnat; policy accept; jump go_webfilter_nat; }"},
	}

	for _, cmd := range commands {
		command := exec.Command(cmd[0], cmd[1:]...)
		var out bytes.Buffer
		command.Stdout = &out
		command.Stderr = &out
		if err := command.Run(); err != nil {
			return fmt.Errorf("error running command %s: %v, output: %s", cmd, err, out.String())
		}
		n.logger.Debug().Msgf("Command %s executed successfully\n", cmd)
	}
	return nil
}

func (n *NFTFirewall) UninstallRules() error {
	n.logger.Debug().Msg("Cleaning up nftables table...")
	return exec.Command("nft", "delete", "table", "go_webfilter").Run()
}

func New(logger zerolog.Logger) *NFTFirewall {
	return &NFTFirewall{
		logger: logger,
	}
}
