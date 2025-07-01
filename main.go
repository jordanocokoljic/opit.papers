package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	uuid "github.com/jackc/pgx-gofrs-uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	usernameRegex := regexp.MustCompile(`^.{1,}$`)
	if envRegex, ok := os.LookupEnv("PAPERS_USERNAME_REGEX"); ok {
		compiled, err := regexp.Compile(envRegex)
		if err != nil {
			logger.Error(
				"failed to compile provided username regex",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		usernameRegex = compiled
	}

	passwordRegex := regexp.MustCompile(`^.{8,}$`)
	if envRegex, ok := os.LookupEnv("PAPERS_PASSWORD_REGEX"); ok {
		compiled, err := regexp.Compile(envRegex)
		if err != nil {
			logger.Error(
				"failed to compile provided password regex",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		passwordRegex = compiled
	}

	resetLifetime := time.Minute * 15
	if envLifetime, ok := os.LookupEnv("PAPERS_RESET_LIFETIME"); ok {
		lifetime, err := time.ParseDuration(envLifetime)
		if err != nil {
			logger.Error(
				"failed to parse provided reset lifetime",
				"error", err.Error(),
			)

			os.Exit(1)
		}

		resetLifetime = lifetime
	}

	envServerKey, ok := os.LookupEnv("PAPERS_SERVER_KEY")
	if !ok {
		logger.Error(
			"required environment variable was not set",
			"variable", "PAPERS_SERVER_KEY",
		)

		os.Exit(1)
	}

	serverKey, err := hex.DecodeString(envServerKey)
	if err != nil {
		logger.Error(
			"failed to decode provided server key as hex",
			"error", err.Error(),
		)

		os.Exit(1)
	}

	if l := len(serverKey); l != 32 {
		logger.Error(
			"provided server key was invalid, must be 32 bytes long",
			"length", l,
		)

		os.Exit(1)
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

	httpPort := "51987"
	if envPort, ok := os.LookupEnv("PAPERS_HTTP_PORT"); ok {
		httpPort = envPort
	}

	api := server{
		log:           logger,
		db:            pool,
		serverKey:     serverKey,
		usernameRegex: usernameRegex,
		passwordRegex: passwordRegex,
		resetLifetime: resetLifetime,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /identities", api.postIdentities)
	mux.HandleFunc("POST /resets", api.postResets)
	mux.HandleFunc("PUT  /resets/{reset}", api.putResets)
	mux.HandleFunc("POST /login", api.postLogin)

	http.ListenAndServe(net.JoinHostPort("127.0.0.1", httpPort), mux)
}
