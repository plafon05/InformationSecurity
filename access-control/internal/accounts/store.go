// Package accounts implements account rules independently of storage and HTTP.
package accounts

import (
	"access-control/internal/password"
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrPassword  = errors.New("Неверный пароль.")
	ErrNotFound  = errors.New("Пользователь с таким именем не зарегистрирован.")
	ErrDuplicate = errors.New("Это имя уже зарегистрировано.")
	ErrStorage   = errors.New("Хранилище недоступно. Повторите попытку позже.")
	ErrBlocked   = errors.New("Учётная запись заблокирована администратором.")
)

// User is internal only: credentials cannot accidentally appear in JSON responses.
type User struct {
	Name         string
	PasswordHash string `json:"-"`
	Blocked      bool
	Restricted   bool
}
type PublicUser struct {
	Name       string `json:"name"`
	Blocked    bool   `json:"blocked"`
	Restricted bool   `json:"restricted"`
	Initial    bool   `json:"initial"`
}

func (u User) Public() PublicUser {
	return PublicUser{u.Name, u.Blocked, u.Restricted, u.PasswordHash == ""}
}

// Repository.Update must lock the row and commit the callback's changes atomically.
// This keeps password verification and policy checks consistent with concurrent updates.
type Repository interface {
	Get(context.Context, string) (User, error)
	List(context.Context) ([]PublicUser, error)
	ListCredentials(context.Context) ([]User, error)
	Create(context.Context, User) error
	Update(context.Context, string, func(*User) error) error
}
type Store struct{ repo Repository }

func New(repo Repository) *Store                                { return &Store{repo: repo} }
func (s *Store) List(ctx context.Context) ([]PublicUser, error) { return s.repo.List(ctx) }

// Credentials is for the administrator export path only; normal API responses use PublicUser.
func (s *Store) Credentials(ctx context.Context) ([]User, error) { return s.repo.ListCredentials(ctx) }
func (s *Store) Get(ctx context.Context, name string) (PublicUser, error) {
	u, err := s.repo.Get(ctx, name)
	return u.Public(), err
}
func verify(u User, plain string) error {
	if u.Blocked {
		return ErrBlocked
	}
	ok, err := password.Verify(u.PasswordHash, plain)
	if err != nil {
		return ErrStorage
	} // Do not expose stored credentials or parsing details.
	if !ok {
		return ErrPassword
	}
	return nil
}
func (s *Store) Authenticate(ctx context.Context, name, plain string) (PublicUser, error) {
	u, err := s.repo.Get(ctx, name)
	if err != nil {
		return PublicUser{}, err
	}
	if err = verify(u, plain); err != nil {
		return PublicUser{}, err
	}
	return u.Public(), nil
}
func ValidPassword(plain string, restricted bool) error {
	if plain == "" {
		return errors.New("Пароль не может быть пустым.")
	}
	if len(plain) > password.MaxLength {
		return errors.New("Пароль слишком длинный (максимум 1024 байта).")
	}
	if restricted {
		latin, cyrillic := false, false
		for _, r := range plain {
			latin = latin || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
			cyrillic = cyrillic || (unicode.Is(unicode.Cyrillic, r) && unicode.IsLetter(r))
		}
		if !latin || !cyrillic {
			return errors.New("Добавьте хотя бы одну латинскую букву (A–Z, a–z) и одну кириллическую букву.")
		}
	}
	return nil
}
func (s *Store) ChangePassword(ctx context.Context, name, old, plain, confirmation string) error {
	return s.repo.Update(ctx, name, func(u *User) error {
		if err := verify(*u, old); err != nil {
			return err
		}
		if plain != confirmation {
			return errors.New("Пароли не совпадают.")
		}
		if err := ValidPassword(plain, u.Restricted); err != nil {
			return err
		}
		hash, err := password.Hash(plain)
		if err != nil {
			return ErrStorage
		}
		u.PasswordHash = hash
		return nil
	})
}
func (s *Store) Add(ctx context.Context, name string) error {
	if !utf8.ValidString(name) || name == "" || strings.TrimSpace(name) != name || len([]rune(name)) > 64 {
		return errors.New("Имя: от 1 до 64 символов, без пробелов по краям.")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("Недопустимый символ в имени.")
		}
	}
	return s.repo.Create(ctx, User{Name: name})
}
func (s *Store) Update(ctx context.Context, name string, blocked, restricted bool) error {
	if name == "ADMIN" && blocked {
		return errors.New("Блокировка ADMIN запрещена.")
	}
	return s.repo.Update(ctx, name, func(u *User) error { u.Blocked = blocked; u.Restricted = restricted; return nil })
}
