package web

import (
	"access-control/internal/accounts"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"strconv"
	"strings"
)

type exportUser struct {
	Name         string `json:"name" xml:"name"`
	PasswordHash string `json:"password_hash" xml:"password_hash"`
	Blocked      bool   `json:"blocked" xml:"blocked"`
	Restricted   bool   `json:"restricted" xml:"restricted"`
	Initial      bool   `json:"initial" xml:"initial"`
}
type exportDocument struct {
	XMLName xml.Name     `json:"-" xml:"users"`
	Users   []exportUser `json:"users" xml:"user"`
}

// encodeExport is called only after the administrator check in api.
// The hash is a verifier, never a recoverable password.
func encodeExport(format string, users []accounts.User) ([]byte, string, error) {
	document := exportDocument{Users: make([]exportUser, 0, len(users))}
	for _, u := range users {
		document.Users = append(document.Users, exportUser{u.Name, u.PasswordHash, u.Blocked, u.Restricted, u.PasswordHash == ""})
	}
	switch format {
	case "json":
		data, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return nil, "", err
		}
		return append(data, '\n'), "application/json; charset=utf-8", nil
	case "xml":
		data, err := xml.MarshalIndent(document, "", "  ")
		if err != nil {
			return nil, "", err
		}
		return append([]byte(xml.Header), append(data, '\n')...), "application/xml; charset=utf-8", nil
	case "csv":
		var output bytes.Buffer
		output.WriteString("\xef\xbb\xbf") // UTF-8 BOM for spreadsheet programs.
		writer := csv.NewWriter(&output)
		if err := writer.Write([]string{"name", "password_hash", "blocked", "restricted", "initial"}); err != nil {
			return nil, "", err
		}
		for _, u := range document.Users {
			// A leading formula character in a name must not execute in spreadsheets.
			name := u.Name
			if name != "" && strings.ContainsRune("=+-@", rune(name[0])) {
				name = "'" + name
			}
			if err := writer.Write([]string{name, u.PasswordHash, strconv.FormatBool(u.Blocked), strconv.FormatBool(u.Restricted), strconv.FormatBool(u.Initial)}); err != nil {
				return nil, "", err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, "", err
		}
		return output.Bytes(), "text/csv; charset=utf-8", nil
	default:
		return nil, "", errors.New("Выберите формат JSON, CSV или XML.")
	}
}
