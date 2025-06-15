package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	uuid "github.com/jackc/pgx-gofrs-uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/papers/internal/web"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	envPostgresURL, ok := os.LookupEnv("PAPERS_PG_URL")
	if !ok {
		logger.Error(
			"required environment variable was not set",
			"variable", "PAPERS_PG_URL",
		)

		os.Exit(1)
	}

	poolConfig, err := pgxpool.ParseConfig(envPostgresURL)
	if err != nil {
		logger.Error(
			"failed to parse postgres connection string",
			"error", err.Error(),
		)

		os.Exit(1)
	}

	poolConfig.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		uuid.Register(c.TypeMap())
		return nil
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		logger.Error(
			"failed to connect to postgres database",
			"error", err.Error(),
		)

		os.Exit(1)
	}

	serverConfig := web.DefaultServerConfiguration()

	if envSessionLifetime, ok := os.LookupEnv("PAPERS_SESSION_LIFETIME"); ok {
		lifetime, err := time.ParseDuration(envSessionLifetime)
		if err != nil {
			logger.Error(
				"failed to parse provided session lifetime",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		serverConfig.SessionLifetime = lifetime
	}

	if envResetLifetime, ok := os.LookupEnv("PAPERS_RESET_LIFETIME"); ok {
		lifetime, err := time.ParseDuration(envResetLifetime)
		if err != nil {
			logger.Error(
				"failed to parse provided reset lifetime",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		serverConfig.ResetLifetime = lifetime
	}

	server := web.NewServer(logger, pool, serverConfig)

	mux := http.NewServeMux()
	server.Bind(mux)

	http.ListenAndServe(":51876", mux)
}
