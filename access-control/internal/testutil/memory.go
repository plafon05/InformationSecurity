// Package testutil supplies in-memory repositories for unit tests only.
package testutil

import (
	"access-control/internal/accounts"
	"context"
	"sort"
	"sync"
)

type Memory struct {
	mu    sync.Mutex
	users map[string]accounts.User
}

func NewMemory() *Memory { return &Memory{users: map[string]accounts.User{"ADMIN": {Name: "ADMIN"}}} }
func (m *Memory) Get(_ context.Context, name string) (accounts.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return u, accounts.ErrNotFound
	}
	return u, nil
}
func (m *Memory) List(_ context.Context) ([]accounts.PublicUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]accounts.PublicUser, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (m *Memory) ListCredentials(_ context.Context) ([]accounts.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]accounts.User, 0, len(m.users))
	for _, u := range m.users {
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
func (m *Memory) Create(_ context.Context, u accounts.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Name]; ok {
		return accounts.ErrDuplicate
	}
	m.users[u.Name] = u
	return nil
}
func (m *Memory) Update(_ context.Context, name string, change func(*accounts.User) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return accounts.ErrNotFound
	}
	if err := change(&u); err != nil {
		return err
	}
	m.users[name] = u
	return nil
}
