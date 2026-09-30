// Package postgres persists accounts using parameterized queries and row transactions.
package postgres

import (
	"access-control/internal/accounts"
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

type Repository struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Repository, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("некорректный DATABASE_URL")
	}
	config.MaxConns = 4
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("не удалось создать пул PostgreSQL")
	}
	r := &Repository{pool: pool}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("не удалось подключиться к PostgreSQL; проверьте DATABASE_URL и состояние базы")
	}
	if err = r.migrate(ctx); err != nil {
		pool.Close()
		return nil, errors.New("не удалось инициализировать таблицы PostgreSQL; проверьте права пользователя базы")
	}
	return r, nil
}
func (r *Repository) Close() { r.pool.Close() }
func (r *Repository) migrate(ctx context.Context) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize concurrent startup DDL. Transaction-scoped lock is released on failure.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(741952813)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, schema); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func storageError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return accounts.ErrNotFound
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return accounts.ErrDuplicate
	}
	return accounts.ErrStorage // SQL messages may contain bound data; never expose them.
}
func readUser(row pgx.Row) (accounts.User, error) {
	var u accounts.User
	err := row.Scan(&u.Name, &u.PasswordHash, &u.Blocked, &u.Restricted)
	if err != nil {
		return u, storageError(err)
	}
	return u, nil
}
func (r *Repository) Get(ctx context.Context, name string) (accounts.User, error) {
	return readUser(r.pool.QueryRow(ctx, "SELECT name, password_hash, blocked, restricted FROM users WHERE name=$1", name))
}
func (r *Repository) List(ctx context.Context) ([]accounts.PublicUser, error) {
	rows, err := r.pool.Query(ctx, "SELECT name, blocked, restricted, password_hash = '' FROM users ORDER BY (name='ADMIN') DESC, name")
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	users := make([]accounts.PublicUser, 0)
	for rows.Next() {
		var u accounts.PublicUser
		if err = rows.Scan(&u.Name, &u.Blocked, &u.Restricted, &u.Initial); err != nil {
			return nil, storageError(err)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return nil, storageError(err)
	}
	return users, nil
}
func (r *Repository) ListCredentials(ctx context.Context) ([]accounts.User, error) {
	rows, err := r.pool.Query(ctx, "SELECT name, password_hash, blocked, restricted FROM users ORDER BY (name='ADMIN') DESC, name")
	if err != nil {
		return nil, storageError(err)
	}
	defer rows.Close()
	users := make([]accounts.User, 0)
	for rows.Next() {
		var u accounts.User
		if err = rows.Scan(&u.Name, &u.PasswordHash, &u.Blocked, &u.Restricted); err != nil {
			return nil, storageError(err)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return nil, storageError(err)
	}
	return users, nil
}
func (r *Repository) Create(ctx context.Context, u accounts.User) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO users (name, password_hash, blocked, restricted) VALUES ($1,$2,$3,$4)", u.Name, u.PasswordHash, u.Blocked, u.Restricted)
	if err != nil {
		return storageError(err)
	}
	return nil
}
func (r *Repository) Update(ctx context.Context, name string, change func(*accounts.User) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return storageError(err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	u, err := readUser(tx.QueryRow(ctx, "SELECT name, password_hash, blocked, restricted FROM users WHERE name=$1 FOR UPDATE", name))
	if err != nil {
		return err
	}
	if err = change(&u); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE users SET password_hash=$2, blocked=$3, restricted=$4 WHERE name=$1", name, u.PasswordHash, u.Blocked, u.Restricted); err != nil {
		return storageError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return storageError(err)
	}
	return nil
}
