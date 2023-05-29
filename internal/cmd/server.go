package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/xiaoxiang10086/mutationwebhook/internal/httpd"
)

var (
	httpdConf httpd.SimpleServer
	debug     bool
)

// getServerCommand returns the server cobra command to be executed.
func getServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"serve"},
		Short:   "Serve Webhook Server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
			log.Infof("SimpleServer starting to listen in port %v", httpdConf.Port)
			return httpdConf.Start()
		},
	}

	cmd.PersistentFlags().BoolVar(&httpdConf.Local, "local", false, "Local run mode")
	cmd.PersistentFlags().IntVar(&httpdConf.Port, "port", 8443, "server port.")
	cmd.PersistentFlags().StringVar(&httpdConf.CertFile, "certFile", "/etc/webhook/certs/tls.crt", "File containing tls certificate")
	cmd.PersistentFlags().StringVar(&httpdConf.KeyFile, "keyFile", "/etc/webhook/certs/tls.key", "File containing tls private key")
	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logs")

	return cmd
}
