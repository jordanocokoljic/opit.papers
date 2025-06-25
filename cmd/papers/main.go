package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"time"

	uuid "github.com/jackc/pgx-gofrs-uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/opit.papers/internal/jrpc"
	"github.com/jordanocokoljic/opit.papers/internal/services"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	envHMACKey, ok := os.LookupEnv("PAPERS_HMAC_KEY")
	if !ok {
		logger.Error(
			"required environment variable was not set",
			"variable", "PAPERS_HMAC_KEY",
		)

		os.Exit(1)
	}

	hmacKey, err := hex.DecodeString(envHMACKey)
	if err != nil {
		logger.Error(
			"failed to decode provided hmac key",
			"error", err.Error(),
		)

		os.Exit(1)
	}

	resetLifetime := time.Minute * 15
	if envResetLifetime, ok := os.LookupEnv("PAPERS_RESET_LIFETIME"); ok {
		lifetime, err := time.ParseDuration(envResetLifetime)
		if err != nil {
			logger.Error(
				"failed to parse provided reset lifetime",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		resetLifetime = lifetime
	}

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

	server := jrpc.NewServer(logger)

	identities := services.NewIdentities(pool, hmacKey, resetLifetime)

	jrpc.RegisterMethod(
		&server, "v1:createIdentity",
		jrpc.Transform[services.CreateIdentityRequest],
		identities.CreateIdentity,
	)

	jrpc.RegisterMethod(
		&server, "v1:verifyCredentials",
		jrpc.Transform[services.VerifyCredentialsRequest],
		identities.VerifyCredentials,
	)

	jrpc.RegisterMethod(
		&server, "v1:createResetToken",
		jrpc.Transform[services.CreateResetTokenRequest],
		identities.CreateResetToken,
	)

	http.ListenAndServe(":51876", &server)
}
