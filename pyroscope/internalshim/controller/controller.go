package controller // import "go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/controller"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/log"
)

type Controller struct {
	*controller.Controller
}

func (c *Controller) Start(ctx context.Context) error {
	return c.Controller.Start(ctx)
}

type Config struct {
	*controller.Config
}

func (cfg *Config) Validate() error {
	return cfg.Config.Validate()
}

func New(cfg *Config) *Controller {
	// set debugging logging if requested; this is otherwise done in main.go
	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
		// Dump the arguments in debug mode.
		cfg.Dump()
	}

	return &Controller{
		controller.New(cfg.Config),
	}
}
