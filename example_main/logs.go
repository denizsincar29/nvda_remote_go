package main

import (
	"io"
	"log/slog"
)

func replAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == "time" {
		a.Value = slog.StringValue("now")
	}
	return a
}

// NewLogger creates a new logger with the given options.
func NewLogger(writer io.Writer) *slog.Logger {
	opts := slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelDebug,
		ReplaceAttr: replAttr,
	}
	return slog.New(slog.NewTextHandler(writer, &opts))
}
