package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"os/exec"

	"github.com/kadirbelkuyu/DPI-bypass/internal/domain/bypass"
	"github.com/kadirbelkuyu/DPI-bypass/internal/proxy"
	"github.com/kadirbelkuyu/DPI-bypass/util"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func main() {
	config := util.GetConfig()
	var debug bool
	var proxyAddr string
	var proxyPort int

	rootCmd := &cobra.Command{
		Use:   "bybydpi",
		Short: "DPI bypass tool",
		RunE: func(cmd *cobra.Command, args []string) error {
			config.Debug = debug

			var logger *zap.Logger
			var err error
			if config.Debug {
				logger, err = zap.NewDevelopment()
			} else {
				logger, err = zap.NewProduction()
			}
			if err != nil {
				return err
			}
			defer logger.Sync()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				sig := <-sigChan
				logger.Info("Shutting down...", zap.String("signal", sig.String()))

				if runtime.GOOS == "darwin" {
					proxy.ConfigureMacProxy(false, "", 0)
				} else if runtime.GOOS == "linux" {
					proxy.ConfigureLinuxProxy(false, "", 0)
				}
				os.Exit(0)
			}()

			if runtime.GOOS == "darwin" {
				if err := proxy.ConfigureMacProxy(true, proxyAddr, proxyPort); err != nil {
					logger.Error("Mac proxy error", zap.Error(err))
					return err
				}
				// Configure DNS servers for local resolver
				exec.Command("networksetup", "-setdnsservers", "Wi-Fi", 
					"1.1.1.1", "8.8.8.8", "9.9.9.9").Run()
			} else if runtime.GOOS == "linux" {
				if err := proxy.ConfigureLinuxProxy(true, proxyAddr, proxyPort); err != nil {
					logger.Error("Linux proxy error", zap.Error(err))
					return err
				}
			}

			service := bypass.NewService(*config)
			go func() {
				if err := service.Start(); err != nil {
					logger.Error("Service error", zap.Error(err))
				}
			}()

			server := proxy.NewServer(proxyAddr, proxyPort, logger)
			logger.Info("Proxy server started", zap.String("addr", proxyAddr), zap.Int("port", proxyPort))
			return server.Start(ctx)
		},
	}

	rootCmd.Flags().StringVar(&config.Interface, "interface", "en0", "Network interface")
	rootCmd.Flags().IntVar(&config.MTU, "mtu", 1500, "MTU size")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug mode")
	rootCmd.Flags().StringVar(&proxyAddr, "proxy-addr", "127.0.0.1", "Proxy address")
	rootCmd.Flags().IntVar(&proxyPort, "proxy-port", 8080, "Proxy port")

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
