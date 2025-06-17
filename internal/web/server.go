package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
)

type Server struct {
	log     *slog.Logger
	db      *pgxpool.Pool
	hmacKey []byte
	config  ServerConfiguration
}

func NewServer(log *slog.Logger, db *pgxpool.Pool, hmacKey []byte, config ServerConfiguration) *Server {
	return &Server{
		log:     log,
		db:      db,
		hmacKey: hmacKey,
		config:  config,
	}
}

func (s *Server) Bind(mux *http.ServeMux) {
	mux.HandleFunc("POST   /identities", s.postIdentities)
	mux.HandleFunc("POST   /sessions", s.postSessions)
	mux.HandleFunc("GET    /sessions/{session}", s.getSession)
	mux.HandleFunc("DELETE /sessions/{session}", s.deleteSession)
	mux.HandleFunc("POST   /resets", s.postResets)
	mux.HandleFunc("PUT    /resets/{reset}", s.putReset)
}

func (s *Server) postIdentities(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	var body struct {
		Username *string
		Password *string
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

	if body.Username == nil {
		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]any{
				"error":       "MISSING_FIELD",
				"description": "a required field was not provided",
				"details": map[string]any{
					"field": "username",
				},
			},
		)

		return
	}

	if strings.TrimSpace(*body.Username) == "" {
		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]any{
				"error":       "INVALID_USERNAME",
				"description": "the provided username was invalid",
			},
		)

		return
	}

	if body.Password == nil {
		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]any{
				"error":       "MISSING_FIELD",
				"description": "a required field was not provided",
				"details": map[string]any{
					"field": "password",
				},
			},
		)

		return
	}

	if strings.TrimSpace(*body.Password) == "" {
		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":       "INVALID_PASSWORD",
				"description": "the provided password was invalid",
			},
		)

		return
	}

	hash, err := argon2id.GenerateFromPassword([]byte(*body.Password), argon2id.OWASPMinimumParameters())
	if err != nil {
		log.Error(
			"failed to generate hash from password",
			"err", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Error(
			"failed to generate id for new identity",
			"err", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		insert into identity (id, username, password)
		values ($1, $2, $3)
		`,
		id,
		body.Username,
		hash,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "identity_username_key" {
			respondJSON(
				log, w,
				http.StatusConflict,
				map[string]string{
					"error":       "USERNAME_TAKEN",
					"description": "the provided username is already in registered",
				},
			)

			return
		}

		log.Error(
			"failed to store new identity in database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	respondJSON(
		log, w,
		http.StatusCreated,
		map[string]string{"id": id.String()},
	)
}

func (s *Server) postSessions(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	var body struct {
		Username *string
		Password *string
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

	if body.Username == nil {
		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]any{
				"error":       "MISSING_FIELD",
				"description": "a required field was not provided",
				"details": map[string]any{
					"field": "username",
				},
			},
		)

		return
	}

	if strings.TrimSpace(*body.Username) == "" {
		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]any{
				"error":       "INVALID_USERNAME",
				"description": "the provided username was invalid",
			},
		)

		return
	}

	if body.Password == nil {
		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]any{
				"error":       "MISSING_FIELD",
				"description": "a required field was not provided",
				"details": map[string]any{
					"field": "password",
				},
			},
		)

		return
	}

	if strings.TrimSpace(*body.Password) == "" {
		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":       "INVALID_PASSWORD",
				"description": "the provided password was invalid",
			},
		)

		return
	}

	row := s.db.QueryRow(
		r.Context(),
		`
		select id, password
		from identity
		where username = $1
		`,
		*body.Username,
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
					"error":       "USER_NOT_FOUND",
					"description": "no identity registered with provided username",
				},
			)

			return
		}

		log.Error(
			"failed to query database for id and password hash",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	err = argon2id.CompareHashAndPassword(passwordHash, []byte(*body.Password))
	if err != nil {
		respondJSON(
			log, w,
			http.StatusUnauthorized,
			map[string]string{
				"error":       "PASSWORD_INCORRECT",
				"description": "username password combination was incorrect",
			},
		)

		return
	}

	token := randomURLSafe(24)
	expiresIn := s.config.SessionLifetime

	mac := hmac.New(sha256.New, s.hmacKey)
	_, err = mac.Write([]byte(token))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		insert into session (token, identity, expires)
		values ($1, $2, $3)
		`,
		base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
		id,
		time.Now().Add(expiresIn).UTC(),
	)

	if err != nil {
		log.Error(
			"failed to store new session in database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	respondJSON(
		log, w,
		http.StatusOK,
		map[string]any{
			"id":      id.String(),
			"session": token,
			"expires": expiresIn.Seconds(),
		},
	)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	mac := hmac.New(sha256.New, s.hmacKey)
	_, err := mac.Write([]byte(r.PathValue("session")))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	row := s.db.QueryRow(
		r.Context(),
		`
		select identity.id, extract(epoch from (session.expires - now()))::int
		from session
				 join identity on session.identity = identity.id
		where session.expires > now()
		  and session.token = $1
		`,
		base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
	)

	var (
		id        uuid.UUID
		expiresIn int
	)

	err = row.Scan(&id, &expiresIn)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondJSON(
				log, w,
				http.StatusNotFound,
				map[string]string{
					"error":       "SESSION_NOT_FOUND",
					"description": "no valid session found for token",
				},
			)

			return
		}

		log.Error(
			"failed to query database for session details",
			"error", err.Error(),
		)

		return
	}

	respondJSON(
		log, w,
		http.StatusOK,
		map[string]any{
			"id":      id,
			"expires": expiresIn,
		},
	)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	mac := hmac.New(sha256.New, s.hmacKey)
	_, err := mac.Write([]byte(r.PathValue("session")))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		delete
		from session
		where token = $1;
		`,
		base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
	)

	if err != nil {
		log.Error(
			"failed to delete session from database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postResets(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	var body struct {
		Username *string
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

	if body.Username == nil {
		respondJSON(
			log, w,
			http.StatusBadRequest,
			map[string]any{
				"error":       "MISSING_FIELD",
				"description": "a required field was not provided",
				"details": map[string]any{
					"field": "username",
				},
			},
		)

		return
	}

	token := randomURLSafe(32)
	expiresIn := s.config.ResetLifetime

	mac := hmac.New(sha256.New, s.hmacKey)
	_, err = mac.Write([]byte(token))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = s.db.Exec(
		r.Context(),
		`
		insert into reset (token, identity, expires)
		values ($1, (select id from identity where username = $2), $3)
		`,
		base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
		*body.Username,
		time.Now().Add(expiresIn).UTC(),
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) &&
			pgErr.Code == "23502" &&
			pgErr.ColumnName == "identity" &&
			pgErr.TableName == "reset" {

			respondJSON(
				log, w,
				http.StatusUnprocessableEntity,
				map[string]string{
					"error":       "USER_NOT_FOUND",
					"description": "no identity registered with provided username",
				},
			)

			return
		}

		log.Error(
			"failed to store new reset in database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	respondJSON(
		log, w,
		http.StatusAccepted,
		map[string]any{
			"reset":   token,
			"expires": expiresIn.Seconds(),
		},
	)
}

func (s *Server) putReset(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(
		"method", r.Method,
		"endpoint", r.URL.Path,
	)

	var body struct {
		Password *string
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

	if strings.TrimSpace(*body.Password) == "" {
		respondJSON(
			log, w,
			http.StatusUnprocessableEntity,
			map[string]string{
				"error":       "INVALID_PASSWORD",
				"description": "the provided password was invalid",
			},
		)

		return
	}

	hash, err := argon2id.GenerateFromPassword([]byte(*body.Password), argon2id.OWASPMinimumParameters())
	if err != nil {
		log.Error(
			"failed to generate hash from password",
			"err", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		log.Error(
			"failed to start database transaction",
			"err", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	defer tx.Rollback(r.Context())

	mac := hmac.New(sha256.New, s.hmacKey)
	_, err = mac.Write([]byte(r.PathValue("reset")))
	if err != nil {
		s.log.Error(
			"failed to write token to hmac",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	tokenHash := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))

	_, err = tx.Exec(
		r.Context(),
		`
		update identity
		set password = $2
		from reset
		where reset.identity = identity.id
		  and reset.token = $1
		`,
		tokenHash,
		hash,
	)

	if err != nil {
		log.Error(
			"failed to update password in database",
			"errir", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = tx.Exec(
		r.Context(),
		`
		delete
		from session using reset
		where session.identity = reset.identity
		  and reset.token = $1
		`,
		tokenHash,
	)

	if err != nil {
		log.Error(
			"failed to remove sessions from database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	_, err = tx.Exec(
		r.Context(),
		`
		delete
		from reset
		where token = $1
		`,
		tokenHash,
	)

	if err != nil {
		log.Error(
			"failed to delete reset from database",
			"error", err.Error(),
		)

		respondInternalServerError(log, w)
		return
	}

	tx.Commit(r.Context())

	w.WriteHeader(http.StatusNoContent)
}

func respondJSON(log *slog.Logger, w http.ResponseWriter, code int, data any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		log.Error(
			"failed to write to encode data as json",
			"error", err.Error(),
		)

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Error(
			"failed to write response",
			"error", err.Error(),
		)
	}
}

var (
	internalServerError = []byte(`{"error":"INTERNAL_ERROR","description":"an internal server error occurred"}`)
)

func respondInternalServerError(log *slog.Logger, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)

	if _, err := w.Write(internalServerError); err != nil {
		log.Error(
			"failed to write response",
			"error", err.Error(),
		)
	}
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
