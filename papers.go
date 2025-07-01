package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/argon2id"
)

type server struct {
	log *slog.Logger
	db  *pgxpool.Pool

	usernameRegex *regexp.Regexp
	passwordRegex *regexp.Regexp
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
		insert into identity (id, username, password_hash)
		values ($1, $2, $3)
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
		select id, password_hash
		from identity
		where username = $1
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

func isUsernameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "identity_username_key"
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
