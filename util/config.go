package util

import (
	"github.com/kadirbelkuyu/DPI-bypass/internal/domain/bypass"
)

func GetConfig() *bypass.Config {
	return &bypass.Config{
		Interface:     "en0",
		MTU:           1500,
		FragmentSize:  1,
		Workers:       4,
		EnableLogging: false,
		RateLimit:     100000,
		QueueSize:     50000,
		CleanupFreq:   60,
	}
}
