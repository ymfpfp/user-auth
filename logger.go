package main

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Utils for logging.
// The point of logging is to allow us to receive timely details about errors, anomalies, etc.

func newLogger() (*zap.Logger, error) {
	if os.Getenv("ENV") == "production" {
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		return cfg.Build()
	}
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return cfg.Build()
}

func loggerFromContext(ctx context.Context) *zap.Logger {
	if logger, ok := ctx.Value(loggerKey).(*zap.Logger); ok {
		return logger
	}
	// Return a global logger as backup.
	return zap.L()
}
