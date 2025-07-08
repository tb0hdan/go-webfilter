package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/tb0hdan/go-webfilter/pkg/hooks"
	"github.com/tb0hdan/go-webfilter/pkg/server"
	"github.com/tb0hdan/go-webfilter/pkg/utils"
	"github.com/ziflex/lecho/v3"
)

func main() {
	var (
		dump     = flag.Bool("dump", false, "Dump all HTTP requests/responses to stdout")
		debug    = flag.Bool("debug", false, "Enable debug mode")
		snakeOil = flag.Bool("snakeoil", true, "Use snakeoil self-signed certificate")
	)
	flag.Parse()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger.Debug().Msg("Debug mode enabled")
	}
	serverHooks := hooks.New(logger)
	srv := server.New(logger, *dump)
	// Get a free port for the server to listen on
	srv.Setup()
	srv.SetHooks(serverHooks)

	// HTTP server
	e := echo.New()
	e.HideBanner = true
	e.Logger = lecho.From(logger)
	e.Use(middleware.Recover())
	srv.RegisterRoutes(e)

	// HTTPS server
	eHTTPS := echo.New()
	eHTTPS.HideBanner = true
	eHTTPS.Logger = lecho.From(logger)
	eHTTPS.Use(middleware.Recover())
	srv.RegisterRoutes(eHTTPS)

	// Load or generate self-signed certificate
	cert, key, err := utils.LoadOrGenerateCert(*snakeOil)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error loading or generating self-signed certificate")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start HTTP server
	go func() {
		logger.Info().Msgf("Starting HTTP server on :%d", srv.Port)
		if err := e.Start(fmt.Sprintf(":%d", srv.Port)); err != nil && err != http.ErrServerClosed {
			e.Logger.Errorf("Error starting HTTP server: ", err)
			stop()
		}
	}()

	// Start HTTPS server
	go func() {
		logger.Info().Msgf("Starting HTTPS server on :%d", srv.HTTPSPort)
		logger.Info().Msgf("Using self-signed certificate: %s", cert)
		logger.Info().Msgf("Using self-signed key: %s", key)
		// Use the self-signed certificate for HTTPS
		if err := eHTTPS.StartTLS(fmt.Sprintf(":%d", srv.HTTPSPort), cert, key); err != nil && err != http.ErrServerClosed {
			eHTTPS.Logger.Errorf("Error starting HTTPS server: ", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Println("Shutting down servers...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv.Cleanup()

	// Shutdown both servers
	if err := e.Shutdown(shutdownCtx); err != nil {
		e.Logger.Fatal("Error shutting down HTTP server: ", err)
	}
	if err := eHTTPS.Shutdown(shutdownCtx); err != nil {
		eHTTPS.Logger.Fatal("Error shutting down HTTPS server: ", err)
	}
}
