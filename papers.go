package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/argon2id"
)

type server struct {
	log *slog.Logger
	db  *pgxpool.Pool

	serverKey []byte

	usernameRegex *regexp.Regexp
	passwordRegex *regexp.Regexp

	resetLifetime time.Duration
}

func (s *server) postIdentities(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := unmarshalBody(r.Body, &body)
	if err != nil {
		log.Warn(
			"unable to decode request body",
			"error", err.Error(),
		)

		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]string{
				"error":  "BAD_REQUEST",
				"detail": "request was unparsable",
			},
		)

		return
	}

	if !s.usernameRegex.MatchString(body.Username) {
		log.Warn(
			"username did not match username regex",
			"username", body.Username,
		)

		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":  "INVALID_USERNAME",
				"detail": "provided username was invalid",
			},
		)

		return
	}

	if !s.passwordRegex.MatchString(body.Password) {
		log.Warn("password did not match password regex")

		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":  "INVALID_PASSWORD",
				"detail": "provided password was invalid",
			},
		)

		return
	}

	hash, err := argon2id.GenerateFromPassword(
		[]byte(body.Password),
		argon2id.OWASPMinimumParameters(),
	)

	if err != nil {
		log.Error(
			"failed to generate hash from password",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Error(
			"failed to generate id for identity",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		INSERT INTO identity (id, username, password_hash)
		VALUES ($1, $2, $3)
		`,
		id,
		body.Username,
		hash,
	)

	if err != nil {
		if isUsernameTaken(err) {
			log.Warn(
				"username was already in use",
				"username", body.Username,
			)

			respondJSON(
				log, w,
				http.StatusConflict,
				map[string]string{
					"error":  "USERNAME_TAKEN",
					"detail": "provided username is already in use",
				},
			)

			return
		}

		log.Error(
			"failed to store new identity in database",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	respondJSON(
		log, w,
		http.StatusCreated,
		map[string]string{"id": id.String()},
	)
}

func (s *server) postLogin(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := unmarshalBody(r.Body, &body)
	if err != nil {
		log.Warn(
			"unable to decode request body",
			"error", err.Error(),
		)

		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]string{
				"error":  "BAD_REQUEST",
				"detail": "request was unparsable",
			},
		)

		return
	}

	row := s.db.QueryRow(
		r.Context(),
		`
		SELECT id, password_hash
		FROM identity
		WHERE username = $1
		`,
		body.Username,
	)

	var (
		id           uuid.UUID
		passwordHash []byte
	)

	err = row.Scan(&id, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondJSON(
				log, w,
				http.StatusUnauthorized,
				map[string]string{
					"error":  "USER_NOT_FOUND",
					"detail": "no user registered with provided username",
				},
			)

			return
		}

		log.Error(
			"failed to query database for identity details",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	err = argon2id.CompareHashAndPassword(passwordHash, []byte(body.Password))
	if err != nil {
		if errors.Is(err, argon2id.ErrMismatchedHashAndPassword) {
			respondJSON(
				log, w,
				http.StatusUnauthorized,
				map[string]string{
					"error":  "PASSWORD_INCORRECT",
					"detail": "provided credentials were incorrect",
				},
			)

			return
		}

		log.Error(
			"password comparison failed unexpectedly",
			"id", id.String(),
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	respondJSON(
		log, w,
		http.StatusOK,
		map[string]string{
			"id": id.String(),
		},
	)
}

func (s *server) postResets(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	var body struct {
		Username string `json:"username"`
	}

	err := unmarshalBody(r.Body, &body)
	if err != nil {
		log.Warn(
			"unable to decode request body",
			"error", err.Error(),
		)

		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]string{
				"error":  "BAD_REQUEST",
				"detail": "request was unparsable",
			},
		)

		return
	}

	tokenBytes := make([]byte, 24)
	rand.Read(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	mac := hmac.New(sha256.New, s.serverKey)
	_, err = mac.Write([]byte(token))
	if err != nil {
		log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		INSERT INTO reset (token_hash, identity, expires)
		VALUES ($1, (SELECT id FROM identity WHERE username = $2), $3)
		`,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
		body.Username,
		time.Now().Add(time.Minute*5).UTC(),
	)

	if err != nil {
		if isUserNotFound(err) {
			respondJSON(
				log, w,
				http.StatusUnprocessableEntity,
				map[string]string{
					"error":  "USER_NOT_FOUND",
					"detail": "no user registered with provided username",
				},
			)

			return
		}

		log.Error(
			"failed to store new reset in database",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	respondJSON(
		log, w,
		http.StatusAccepted,
		map[string]any{"reset": token},
	)
}

func (s *server) putResets(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	var body struct {
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Warn(
			"failed to decode request body",
			"error", err.Error(),
		)

		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]string{
				"error":       "INVALID_BODY",
				"description": "request body could not be decoded",
			},
		)

		return
	}

	if !s.passwordRegex.MatchString(body.Password) {
		log.Warn("password did not match password regex")

		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":  "INVALID_PASSWORD",
				"detail": "provided password was invalid",
			},
		)

		return
	}

	passwordHash, err := argon2id.GenerateFromPassword(
		[]byte(body.Password),
		argon2id.OWASPMinimumParameters(),
	)

	if err != nil {
		log.Error(
			"failed to generate hash from password",
			"err", err.Error(),
		)

		internalServerError(w)
		return
	}

	mac := hmac.New(sha256.New, s.serverKey)
	_, err = mac.Write([]byte(r.PathValue("reset")))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	tokenHash := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		log.Error(
			"failed to begin database transaction",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	defer tx.Rollback(r.Context())

	tag, err := tx.Exec(
		r.Context(),
		`
		UPDATE identity
		SET password_hash = $2
		FROM reset
		WHERE reset.identity = identity.id
		  AND reset.token_hash = $1
		  AND reset.expires >= NOW()
		`,
		tokenHash,
		passwordHash,
	)

	if err != nil {
		log.Error(
			"failed to update password in database",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	if tag.RowsAffected() == 0 {
		respondJSON(
			log, w,
			http.StatusNotFound,
			map[string]string{
				"error":  "RESET_NOT_FOUND",
				"detail": "provided reset token was invalid",
			},
		)

		return
	}

	_, err = tx.Exec(
		r.Context(),
		`
		DELETE FROM reset
		WHERE token_hash = $1
		`,
		tokenHash,
	)

	if err != nil {
		log.Error(
			"failed to delete reset from database",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	tx.Commit(r.Context())

	w.WriteHeader(http.StatusNoContent)
}

func isUsernameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "identity_username_key"
}

func isUserNotFound(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23502" &&
		pgErr.ColumnName == "identity" &&
		pgErr.TableName == "reset"
}

func unmarshalBody[T any](body io.ReadCloser, into *T) error {
	all, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(all, into)
	if err != nil {
		return err
	}

	return nil
}

func respondJSON(log *slog.Logger, w http.ResponseWriter, status int, v any) {
	marshalled, err := json.Marshal(v)
	if err != nil {
		log.Error(
			"failed to encode response data as JSON",
			"error", err.Error(),
		)

		internalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(marshalled)
}

func internalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Sorry, an internal server error occurred."))
}
