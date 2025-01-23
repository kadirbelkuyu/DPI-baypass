package logging

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.Logger
	once   sync.Once
)

func InitLogger(debug bool) *zap.Logger {
	once.Do(func() {
		config := zap.NewProductionConfig()
		
		config.OutputPaths = []string{"bybydpi.log"}
		if debug {
			config.OutputPaths = append(config.OutputPaths, "stdout")
		}

		if debug {
			config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		} else {
			config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
		}

		config.EncoderConfig.TimeKey = "ts"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.MessageKey = "msg"
		config.EncoderConfig.LevelKey = "level"
		config.EncoderConfig.CallerKey = "caller"
		config.EncoderConfig.StacktraceKey = "stacktrace"
		
		var err error
		logger, err = config.Build(zap.AddCaller())
		if err != nil {
			os.Exit(1)
		}
	})
	return logger
}

func GetLogger() *zap.Logger {
	if logger == nil {
		return InitLogger(false)
	}
	return logger
}
