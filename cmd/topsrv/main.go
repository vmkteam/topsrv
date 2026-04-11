package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vmkteam/topsrv/internal/app"

	"github.com/BurntSushi/toml"
	"github.com/namsral/flag"
	"github.com/vmkteam/embedlog"
)

const appName = "topsrv"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	fs           = flag.NewFlagSetWithEnvPrefix(os.Args[0], strings.ToUpper(appName), 0)
	flConfigPath = fs.String("config", "cfg/local.toml", "path to config file")
	flVerbose    = fs.Bool("verbose", false, "verbose logging")
	flJSONLogs   = fs.Bool("json", false, "output logs in JSON format")
	flVersion    = fs.Bool("version", false, "print version and exit")
	cfg          app.Config
)

func main() {
	flag.DefaultConfigFlagname = "config.flag"
	exitOnError(fs.Parse(os.Args[1:]))

	if *flVersion {
		_, _ = fmt.Fprintf(os.Stdout, "topsrv %s (%s, %s)\n", version, commit, date)
		os.Exit(0)
	}

	// logger
	sl := embedlog.NewLogger(*flVerbose, *flJSONLogs)
	slog.SetDefault(sl.Log())

	// config
	if _, err := toml.DecodeFile(*flConfigPath, &cfg); err != nil {
		slog.Error("failed to load config", "error", err) //nolint:sloglint
		os.Exit(1)
	}

	// app
	a := app.New(appName, version, sl, cfg)

	// run
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := a.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("app run error", "error", err)
			os.Exit(1)
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down") //nolint:sloglint
	cancel()
	a.Shutdown()
}

func exitOnError(err error) {
	if err != nil {
		slog.Error("fatal", "error", err) //nolint:sloglint
		os.Exit(1)
	}
}
