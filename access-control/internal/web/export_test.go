package web

import (
	"access-control/internal/accounts"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

func TestEncodeExport(t *testing.T) {
	users := []accounts.User{{Name: "ADMIN", PasswordHash: "$argon2id$example"}, {Name: "=SUM(1,1)", PasswordHash: "$argon2id$other", Blocked: true, Restricted: true}, {Name: "Иван<&>", PasswordHash: ""}}
	data, mime, err := encodeExport("json", users)
	if err != nil || mime != "application/json; charset=utf-8" {
		t.Fatal(err, mime)
	}
	var document exportDocument
	if err = json.Unmarshal(data, &document); err != nil || len(document.Users) != 3 || document.Users[1].PasswordHash != "$argon2id$other" || !document.Users[2].Initial {
		t.Fatal(err, document)
	}
	data, mime, err = encodeExport("csv", users)
	if err != nil || mime != "text/csv; charset=utf-8" {
		t.Fatal(err, mime)
	}
	records, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil || len(records) != 4 || records[2][0] != "'=SUM(1,1)" || records[3][0] != "Иван<&>" {
		t.Fatal(err, records)
	}
	data, mime, err = encodeExport("xml", users)
	if err != nil || mime != "application/xml; charset=utf-8" {
		t.Fatal(err, mime)
	}
	if err = xml.Unmarshal(data, &document); err != nil || document.Users[2].Name != "Иван<&>" {
		t.Fatal(err, document)
	}
	if _, _, err = encodeExport("yaml", users); err == nil {
		t.Fatal("unsupported format")
	}
}
func TestExportPermissionsAndContent(t *testing.T) {
	c, s, _ := newClient(t)
	if w := c.call(request{Action: "export", Format: "json"}); w.Code != 401 {
		t.Fatal("anonymous export", w.Code)
	}
	if w := c.call(request{Action: "login", Name: "ADMIN"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := c.call(request{Action: "export", Format: "json"}); w.Code != 403 {
		t.Fatal("initial password export", w.Code)
	}
	if w := c.call(request{Action: "password", Password: "admin-secret", Confirmation: "admin-secret"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := s.Add(context.Background(), "=SUM(1,1)"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(context.Background(), "=SUM(1,1)", "", "LatinЯ", "LatinЯ"); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "csv", "xml"} {
		w := c.call(request{Action: "export", Format: format})
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "kontur-users."+format) || bytes.Contains(w.Body.Bytes(), []byte("LatinЯ")) {
			t.Fatal("bad export", format, w.Code, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte("$argon2id$")) {
			t.Fatal("missing hash", format)
		}
	}
	if w := c.call(request{Action: "export", Format: "yaml"}); w.Code != 400 {
		t.Fatal("invalid format", w.Code)
	}
	w := c.call(request{Action: "logout"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	c.cookie = w.Result().Cookies()[0]
	if w := c.call(request{Action: "login", Name: "=SUM(1,1)", Password: "LatinЯ"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := c.call(request{Action: "export", Format: "csv"}); w.Code != 403 {
		t.Fatal("ordinary user export", w.Code)
	}
}
