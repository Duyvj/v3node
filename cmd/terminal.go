package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/terminal"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var terminalConfig string

var terminalCommand = cobra.Command{
	Use:   "terminal",
	Short: "Run the outbound ZBoard terminal relay",
	Args:  cobra.NoArgs,
	RunE:  terminalHandle,
}

func init() {
	terminalCommand.Flags().StringVarP(&terminalConfig, "config", "c", "/etc/znode/config.json", "config file path")
	command.AddCommand(&terminalCommand)
}

func terminalHandle(_ *cobra.Command, _ []string) error {
	if terminalExecutionDisabled() {
		log.Info("Terminal relay is disabled by DISABLE_EXECUTE")
		return nil
	}
	configuration := conf.New()
	if err := configuration.LoadFromPath(terminalConfig); err != nil {
		return fmt.Errorf("load terminal config: %w", err)
	}
	if !configuration.AgentConfig.Enable {
		return fmt.Errorf("terminal relay requires Agent.Enable=true")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := terminal.Run(ctx, configuration.AgentConfig); err != nil {
		return fmt.Errorf("terminal relay stopped: %w", err)
	}
	return nil
}

func terminalExecutionDisabled() bool {
	return os.Getenv("DISABLE_EXECUTE") == "1"
}
