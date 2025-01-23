package cli

import (
	"github.com/kadirbelkuyu/DPI-bypass/internal/domain/bypass"
	"github.com/kadirbelkuyu/DPI-bypass/internal/infrastructure/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "bybydpi",
	Short: "ByByDPI - A DPI bypass tool",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger
		logger := logging.InitLogger(viper.GetBool("logging"))
		defer logger.Sync()

		config := bypass.Config{
			MTU:           viper.GetInt("mtu"),
			FragmentSize:  viper.GetInt("fragment-size"),
			Interface:     viper.GetString("interface"),
			EnableLogging: viper.GetBool("logging"),
			Workers:       viper.GetInt("workers"),
		}

		service := bypass.NewService(config)
		return service.Start()
	},
}

func init() {
	rootCmd.PersistentFlags().Int("mtu", 1500, "Maximum Transmission Unit")
	rootCmd.PersistentFlags().Int("fragment-size", 1, "Fragment size for payload splitting")
	rootCmd.PersistentFlags().String("interface", "en0", "Network interface to use")
	rootCmd.PersistentFlags().Bool("logging", false, "Enable debug logging")
	rootCmd.PersistentFlags().Int("workers", 4, "Number of packet processing workers")

	viper.BindPFlags(rootCmd.PersistentFlags())
}

func Execute() error {
	return rootCmd.Execute()
}
