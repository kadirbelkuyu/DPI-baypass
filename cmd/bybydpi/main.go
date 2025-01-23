package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kadirbelkuyu/DPI-bypass/internal/domain/bypass"
	"github.com/kadirbelkuyu/DPI-bypass/internal/proxy"
	"github.com/kadirbelkuyu/DPI-bypass/util"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func main() {
	// Declare and initialize config outside RunE
	config := *util.GetConfig()

	var debug bool
	var proxyAddr string
	var proxyPort int

	rootCmd := &cobra.Command{
		Use:   "bybydpi",
		Short: "DPI bypass tool",
		RunE: func(cmd *cobra.Command, args []string) error {

			var logger *zap.Logger
			var err error
			if debug {
				logger, err = zap.NewDevelopment()
			} else {
				logger, err = zap.NewProduction()
			}
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

			go func() {
				sig := <-sigChan
				logger.Info("Received signal, shutting down...", zap.String("signal", sig.String()))

				if err := proxy.ConfigureSystemProxy(false, proxyAddr, proxyPort); err != nil {
					logger.Error("Failed to cleanup proxy settings", zap.Error(err))
				}

				os.Exit(0)
			}()

			if err := proxy.ConfigureSystemProxy(true, proxyAddr, proxyPort); err != nil {
				logger.Error("Failed to configure system proxy", zap.Error(err))
				return err
			}

			service := bypass.NewService(config)

			go func() {
				if err := service.Start(); err != nil {
					logger.Error("Bypass service encountered an error", zap.Error(err))
				}
			}()

			server := proxy.NewServer(proxyAddr, proxyPort, logger)

			logger.Info("Verify TUN or iptables setup is correct")

			return server.Start(ctx)
		},
	}

	flags := rootCmd.Flags()
	flags.StringVar(&config.Interface, "interface", config.Interface, "Network interface to use")
	flags.IntVar(&config.MTU, "mtu", config.MTU, "Maximum Transmission Unit")
	flags.IntVar(&config.FragmentSize, "fragment-size", config.FragmentSize, "Fragment size for payload splitting")
	flags.IntVar(&config.Workers, "workers", config.Workers, "Number of packet processing workers")
	flags.BoolVar(&config.EnableLogging, "logging", config.EnableLogging, "Enable logging")
	flags.BoolVar(&debug, "debug", debug, "Enable debug mode (includes detailed logging)")
	flags.IntVar(&config.RateLimit, "rate-limit", config.RateLimit, "Maximum packets per second")
	flags.IntVar(&config.QueueSize, "queue-size", config.QueueSize, "Packet queue size")
	flags.IntVar(&config.CleanupFreq, "cleanup-freq", config.CleanupFreq, "Connection cleanup frequency in seconds")
	flags.StringVar(&proxyAddr, "proxy-addr", proxyAddr, "Proxy listen address")
	flags.IntVar(&proxyPort, "proxy-port", proxyPort, "Proxy listen port")

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
