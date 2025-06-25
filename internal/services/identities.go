package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/argon2id"
	"github.com/jordanocokoljic/opit.papers/internal/jrpc"
)

type Identities struct {
	db            *pgxpool.Pool
	hmacKey       []byte
	resetLifetime time.Duration
}

func NewIdentities(
	db *pgxpool.Pool,
	hmacKey []byte,
	resetLiftime time.Duration,
) Identities {
	return Identities{
		db:            db,
		hmacKey:       hmacKey,
		resetLifetime: resetLiftime,
	}
}

type CreateIdentityRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (i *Identities) CreateIdentity(
	ctx context.Context, log *slog.Logger,
	request *CreateIdentityRequest,
) jrpc.Response {
	if strings.TrimSpace(request.Username) == "" {
		return jrpc.Error(http.StatusUnprocessableEntity, "INVALID_USERNAME")
	}

	if strings.TrimSpace(request.Password) == "" {
		return jrpc.Error(http.StatusUnprocessableEntity, "INVALID_PASSWORD")
	}

	hash, err := argon2id.GenerateFromPassword(
		[]byte(request.Password),
		argon2id.OWASPMinimumParameters(),
	)

	if err != nil {
		log.Error(
			"failed to derive hash from provided password",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Error(
			"failed to generate UUID for new identity",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	_, err = i.db.Exec(
		ctx,
		`
		insert into identity (id, username, password)
		values ($1, $2, $3)
		`,
		id,
		request.Username,
		hash,
	)

	if err != nil {
		if isUsernameTaken(err) {
			return jrpc.Error(http.StatusConflict, "USERNAME_TAKEN")
		}

		log.Error(
			"failed to store new identity in database",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	return jrpc.JSON(map[string]string{"id": id.String()})
}

type VerifyCredentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (i *Identities) VerifyCredentials(
	ctx context.Context, log *slog.Logger,
	request *VerifyCredentialsRequest,
) jrpc.Response {
	row := i.db.QueryRow(
		ctx,
		`
		select id, password
		from identity
		where username = $1
		`,
		request.Username,
	)

	var (
		id   uuid.UUID
		hash []byte
	)

	err := row.Scan(&id, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return jrpc.Error(http.StatusUnprocessableEntity, "USER_NOT_FOUND")
		}

		log.Error(
			"failed to query database for id and password hash",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	err = argon2id.CompareHashAndPassword(hash, []byte(request.Password))
	if err != nil {
		return jrpc.Error(http.StatusBadRequest, "PASSWORD_INCORRECT")
	}

	return jrpc.JSON(map[string]string{"id": id.String()})
}

type CreateResetTokenRequest struct {
	Username string `json:"username"`
}

func (i *Identities) CreateResetToken(
	ctx context.Context, log *slog.Logger,
	request *CreateResetTokenRequest,
) jrpc.Response {
	token := randomURLSafe(32)
	expiresIn := i.resetLifetime

	mac := hmac.New(sha256.New, i.hmacKey)
	_, err := mac.Write([]byte(token))
	if err != nil {
		log.Error(
			"failed to write reset token to hmac",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	_, err = i.db.Exec(
		ctx,
		`
		insert into reset (token, identity, expires)
		values ($1, (select id from identity where username = $2), $3)
		`,
		base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
		request.Username,
		time.Now().Add(expiresIn).UTC(),
	)

	if err != nil {
		if isUserNotRegistered(err) {
			return jrpc.Error(http.StatusUnprocessableEntity, "USER_NOT_FOUND")
		}

		log.Error(
			"failed to store new reset in database",
			"error", err.Error(),
		)

		return jrpc.Error(http.StatusInternalServerError, "SERVER_ERROR")
	}

	return jrpc.JSON(map[string]any{
		"reset":   token,
		"expires": expiresIn.Seconds(),
	})
}

func isUsernameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "identity_username_key"
}

func isUserNotRegistered(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23502" &&
		pgErr.ColumnName == "identity" &&
		pgErr.TableName == "reset"
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
