package papers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jordanocokoljic/argon2id"
	"github.com/jordanocokoljic/opit.papers/internal/xrap"
)

type Service struct {
	db *pgxpool.Pool
}

func NewService(db *pgxpool.Pool) Service {
	return Service{
		db: db,
	}
}

type CreateIdentityRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Service) CreateIdentity(
	ctx context.Context,
	request *CreateIdentityRequest,
) xrap.Result {
	if strings.TrimSpace(request.Username) == "" {
		return xrap.Then(
			xrap.Status(http.StatusBadRequest),
			xrap.JSON(map[string]string{
				"error":       "BAD_USERNAME",
				"description": "Provided username is invalid",
			}),
		)
	}

	if strings.TrimSpace(request.Password) == "" {
		return xrap.Then(
			xrap.Status(http.StatusBadRequest),
			xrap.JSON(map[string]string{
				"error":       "BAD_PASSWORD",
				"description": "Provided password is invalid",
			}),
		)
	}

	hash, err := argon2id.GenerateFromPassword(
		[]byte(request.Password),
		argon2id.OWASPMinimumParameters(),
	)

	if err != nil {
		return xrap.Error(err)
	}

	id, err := uuid.NewV4()
	if err != nil {
		return xrap.Error(err)
	}

	_, err = s.db.Exec(
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
			return xrap.Then(
				xrap.Status(http.StatusConflict),
				xrap.JSON(map[string]string{
					"error":       "USERNAME_TAKEN",
					"description": "Provided username is already in use",
				}),
			)
		}

		return xrap.Error(err)
	}

	return xrap.Then(
		xrap.Status(http.StatusCreated),
		xrap.JSON(map[string]string{"id": id.String()}),
	)
}

func isUsernameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "identity_username_key"
}
