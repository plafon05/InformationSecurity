package filestore

import (
	"access-control/internal/accounts"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Repository struct {
	mu    sync.Mutex
	path  string
	users map[string]accounts.User
}

type record struct {
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
	Blocked      bool   `json:"blocked"`
	Restricted   bool   `json:"restricted"`
}

type document struct {
	Users []record `json:"users"`
}

func Open(path string) (*Repository, error) {
	r := &Repository{path: path, users: make(map[string]accounts.User)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		r.users["ADMIN"] = accounts.User{Name: "ADMIN"}
		if err = r.save(); err != nil {
			return nil, err
		}
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var doc document
	if err = json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Users) == 0 {
		return nil, errors.New("файл пользователей пуст")
	}
	for _, v := range doc.Users {
		if v.Name == "" {
			return nil, errors.New("в файле пользователей есть пустое имя")
		}
		if _, exists := r.users[v.Name]; exists {
			return nil, errors.New("в файле пользователей есть повторяющиеся имена")
		}
		r.users[v.Name] = accounts.User{Name: v.Name, PasswordHash: v.PasswordHash, Blocked: v.Blocked, Restricted: v.Restricted}
	}
	if admin, ok := r.users["ADMIN"]; !ok || admin.Blocked {
		return nil, errors.New("в файле пользователей отсутствует активный ADMIN")
	}
	return r, nil
}

func (r *Repository) save() error {
	names := make([]string, 0, len(r.users))
	for name := range r.users {
		names = append(names, name)
	}
	sort.Strings(names)
	doc := document{Users: make([]record, 0, len(names))}
	for _, name := range names {
		u := r.users[name]
		doc.Users = append(doc.Users, record{u.Name, u.PasswordHash, u.Blocked, u.Restricted})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(r.path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".users-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), r.path)
}

func (r *Repository) Get(_ context.Context, name string) (accounts.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[name]
	if !ok {
		return u, accounts.ErrNotFound
	}
	return u, nil
}
func (r *Repository) List(_ context.Context) ([]accounts.PublicUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]accounts.PublicUser, 0, len(r.users))
	for _, u := range r.users {
		out = append(out, u.Public())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == "ADMIN" {
			return true
		}
		if out[j].Name == "ADMIN" {
			return false
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
func (r *Repository) ListCredentials(_ context.Context) ([]accounts.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]accounts.User, 0, len(r.users))
	for _, u := range r.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == "ADMIN" {
			return true
		}
		if out[j].Name == "ADMIN" {
			return false
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
func (r *Repository) Create(_ context.Context, u accounts.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[u.Name]; ok {
		return accounts.ErrDuplicate
	}
	r.users[u.Name] = u
	if err := r.save(); err != nil {
		delete(r.users, u.Name)
		return accounts.ErrStorage
	}
	return nil
}
func (r *Repository) Update(_ context.Context, name string, change func(*accounts.User) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.users[name]
	if !ok {
		return accounts.ErrNotFound
	}
	u := old
	if err := change(&u); err != nil {
		return err
	}
	r.users[name] = u
	if err := r.save(); err != nil {
		r.users[name] = old
		return accounts.ErrStorage
	}
	return nil
}
