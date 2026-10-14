package web

import (
	"access-control/internal/accounts"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"sync"
	"time"
)

//go:embed ui/*
var assets embed.FS

type Server struct {
	mu                sync.Mutex
	store             *accounts.Store
	token, user, host string
	failures          int
	ended             bool
	stop              func()
}

func New(store *accounts.Store, host string, stop func()) http.Handler {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s := &Server{store: store, host: host, token: hex.EncodeToString(b), stop: stop}
	static, _ := fs.Sub(assets, "ui")
	files := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Host != s.host {
			http.Error(w, "Invalid host", 403)
			return
		}
		if r.URL.Path == "/api" {
			s.api(w, r)
			return
		}
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		if r.URL.Path == "/" {
			s.mu.Lock()
			token := s.token
			s.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "access", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		files.ServeHTTP(w, r)
	})
}

type request struct {
	Action       string `json:"action"`
	Format       string `json:"format"`
	Name         string `json:"name"`
	Password     string `json:"password"`
	Old          string `json:"old"`
	Confirmation string `json:"confirmation"`
	Blocked      bool   `json:"blocked"`
	Restricted   bool   `json:"restricted"`
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	reply := func(status int, v any) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(v) }
	fail := func(err error) {
		status := http.StatusBadRequest
		if errors.Is(err, accounts.ErrStorage) {
			status = http.StatusServiceUnavailable
		}
		reply(status, map[string]any{"error": err.Error(), "ended": s.ended, "remaining": 3 - s.failures})
	}
	if r.Method != "POST" {
		reply(405, map[string]string{"error": "Требуется POST."})
		return
	}
	c, err := r.Cookie("access")
	if err != nil || c.Value != s.token || r.Header.Get("Origin") != "http://"+s.host {
		reply(403, map[string]string{"error": "Доступ запрещён."})
		return
	}
	if s.ended {
		reply(410, map[string]any{"error": "Работа завершена.", "ended": true})
		return
	}
	var q request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&q); err != nil {
		fail(errors.New("Некорректный запрос."))
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		fail(errors.New("Некорректный запрос."))
		return
	}
	end := func() { s.ended = true; go s.stop() }
		if q.Action == "exit" {
			end()
			reply(200, map[string]any{"ended": true})
			return
		}
	passwordFailure := func(err error) {
		if errors.Is(err, accounts.ErrPassword) {
			s.failures++
			if s.failures >= 3 {
				end()
				err = errors.New("Три неверных пароля. Работа программы завершена.")
			}
		}
		fail(err)
	}
	if q.Action == "logout" {
		if s.user == "" {
			reply(401, map[string]string{"error": "Сначала войдите в систему."})
			return
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fail(accounts.ErrStorage)
			return
		}
		s.user = ""
		s.token = hex.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{Name: "access", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		reply(200, map[string]bool{"ok": true})
		return
	}
	if q.Action == "login" {
		if s.user != "" {
			fail(errors.New("Вход уже выполнен."))
			return
		}
		u, e := s.store.Authenticate(ctx, q.Name, q.Password)
		if e != nil {
			passwordFailure(e)
			return
		}
		s.user = u.Name
		reply(200, map[string]any{"user": u})
		return
	}
	if q.Action == "state" && s.user == "" {
		reply(200, map[string]any{"user": nil})
		return
	}
	if s.user == "" {
		reply(401, map[string]string{"error": "Сначала войдите в систему."})
		return
	}
	u, e := s.store.Get(ctx, s.user)
	if e != nil {
		fail(e)
		return
	}
	if u.Blocked {
		reply(403, map[string]string{"error": "Доступ запрещён."})
		return
	}
	if q.Action == "state" {
		reply(200, map[string]any{"user": u})
		return
	}
	if q.Action == "password" {
		if e = s.store.ChangePassword(ctx, s.user, q.Old, q.Password, q.Confirmation); e != nil {
			passwordFailure(e)
			return
		}
		u, e = s.store.Get(ctx, s.user)
		if e != nil {
			fail(e)
			return
		}
		reply(200, map[string]any{"user": u})
		return
	}
	if u.Initial {
		reply(403, map[string]string{"error": "Сначала установите пароль."})
		return
	}
	if s.user != "ADMIN" {
		reply(403, map[string]string{"error": "Действие доступно только администратору."})
		return
	}
	switch q.Action {
	case "export":
		if q.Format != "json" && q.Format != "csv" && q.Format != "xml" {
			fail(errors.New("Выберите формат JSON, CSV или XML."))
			return
		}
		users, err := s.store.Credentials(ctx)
		if err != nil {
			fail(err)
			return
		}
		data, contentType, err := encodeExport(q.Format, users)
		if err != nil {
			fail(accounts.ErrStorage)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "attachment; filename=kontur-users."+q.Format)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	case "list":
		users, err := s.store.List(ctx)
		if err != nil {
			fail(err)
			return
		}
		reply(200, map[string]any{"users": users})
		return
	case "add":
		e = s.store.Add(ctx, q.Name)
	case "update":
		e = s.store.Update(ctx, q.Name, q.Blocked, q.Restricted)
	default:
		e = errors.New("Неизвестная команда.")
	}
	if e != nil {
		fail(e)
		return
	}
	reply(200, map[string]bool{"ok": true})
}
