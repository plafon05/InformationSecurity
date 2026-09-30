package web

import (
	"access-control/internal/accounts"
	"access-control/internal/testutil"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type client struct {
	handler http.Handler
	cookie  *http.Cookie
}

func newClient(t *testing.T) (*client, *accounts.Store, chan struct{}) {
	t.Helper()
	s := accounts.New(testutil.NewMemory())
	stopped := make(chan struct{})
	h := New(s, "localhost", func() { close(stopped) })
	r := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return &client{h, w.Result().Cookies()[0]}, s, stopped
}
func (c *client) call(q request) *httptest.ResponseRecorder {
	body, _ := json.Marshal(q)
	r := httptest.NewRequest("POST", "http://localhost/api", bytes.NewReader(body))
	r.AddCookie(c.cookie)
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, r)
	return w
}
func TestInitialAndRoleGates(t *testing.T) {
	c, s, _ := newClient(t)
	if w := c.call(request{Action: "list"}); w.Code != 401 {
		t.Fatal(w.Code)
	}
	c.call(request{Action: "login", Name: "ADMIN"})
	if w := c.call(request{Action: "add", Name: "alice"}); w.Code != 403 {
		t.Fatal("initial bypass", w.Code)
	}
	if w := c.call(request{Action: "password", Password: "admin", Confirmation: "admin"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := c.call(request{Action: "add", Name: "alice"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := c.call(request{Action: "list"}); bytes.Contains(w.Body.Bytes(), []byte("salt")) || bytes.Contains(w.Body.Bytes(), []byte("\"password\"")) {
		t.Fatal("credentials leaked")
	}
	c.handler = New(s, "localhost", func() {})
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/", nil))
	c.cookie = w.Result().Cookies()[0]
	c.call(request{Action: "login", Name: "alice"})
	c.call(request{Action: "password", Password: "user", Confirmation: "user"})
	for _, action := range []string{"list", "add", "update"} {
		if w = c.call(request{Action: action, Name: "bob"}); w.Code != 403 {
			t.Fatal("role bypass", action, w.Code)
		}
	}
}
func TestThreeIncorrectPasswords(t *testing.T) {
	c, _, stopped := newClient(t)
	c.call(request{Action: "login", Name: "missing"})
	for i := 0; i < 3; i++ {
		w := c.call(request{Action: "login", Name: "ADMIN", Password: "wrong"})
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		if i < 2 {
			select {
			case <-stopped:
				t.Fatal("early termination")
			default:
			}
		}
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("did not stop")
	}
	if w := c.call(request{Action: "login", Name: "ADMIN"}); w.Code != 410 {
		t.Fatal("continued after termination")
	}
}
func TestLogoutKeepsProgramRunning(t *testing.T) {
	c, _, stopped := newClient(t)
	if w := c.call(request{Action: "logout"}); w.Code != 401 {
		t.Fatal("anonymous logout", w.Code)
	}
	if w := c.call(request{Action: "login", Name: "ADMIN"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	oldCookie := c.cookie
	w := c.call(request{Action: "logout"})
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("logout failed", w.Code, w.Body.String())
	}
	select {
	case <-stopped:
		t.Fatal("logout stopped the program")
	default:
	}
	if w := c.call(request{Action: "state"}); w.Code != 403 {
		t.Fatal("old session remained valid", w.Code)
	}
	c.cookie = w.Result().Cookies()[0]
	if c.cookie.Value == oldCookie.Value {
		t.Fatal("session token not rotated")
	}
	if w := c.call(request{Action: "state"}); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"user":null`)) {
		t.Fatal("new session is not anonymous", w.Code, w.Body.String())
	}
	if w := c.call(request{Action: "login", Name: "ADMIN"}); w.Code != 200 {
		t.Fatal("cannot log in again", w.Code, w.Body.String())
	}
	if w := c.call(request{Action: "password", Password: "new-secret", Confirmation: "new-secret"}); w.Code != 200 {
		t.Fatal("cannot set first password after logout", w.Code, w.Body.String())
	}
	w = c.call(request{Action: "logout"})
	c.cookie = w.Result().Cookies()[0]
	if w := c.call(request{Action: "login", Name: "ADMIN", Password: "new-secret"}); w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(`"initial":true`)) {
		t.Fatal("password lost after logout", w.Code, w.Body.String())
	}
}
func TestRequestProtection(t *testing.T) {
	c, _, _ := newClient(t)
	for _, origin := range []string{"", "http://evil.example"} {
		r := httptest.NewRequest("POST", "http://localhost/api", bytes.NewBufferString(`{"action":"logout"}`))
		r.AddCookie(c.cookie)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		c.handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://evil.example/", nil)
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host bypass")
	}
}
