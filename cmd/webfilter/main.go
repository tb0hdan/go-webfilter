package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/tb0hdan/go-webfilter/pkg/server"
	"github.com/ziflex/lecho/v3"
)

func main() {
	var (
		dump  = flag.Bool("dump", false, "Dump all HTTP requests/responses to stdout")
		debug = flag.Bool("debug", false, "Enable debug mode")
	)
	flag.Parse()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger.Debug().Msg("Debug mode enabled")
	}
	srv := server.New(logger, *dump)
	// Get a free port for the server to listen on
	srv.Setup()
	//
	e := echo.New()
	e.HideBanner = true
	e.Logger = lecho.From(logger)
	e.Use(middleware.Recover())
	//
	srv.RegisterRoutes(e)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := e.Start(fmt.Sprintf(":%d", srv.Port)); err != nil {
			e.Logger.Fatal("Error starting server: ", err)
		}
	}()
	<-ctx.Done()
	logger.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv.Cleanup()

	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal("Error shutting down server: ", err)
	}
}
