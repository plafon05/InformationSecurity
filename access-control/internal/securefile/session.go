// Package securefile keeps the durable account file encrypted and exposes a
// restricted-permission plaintext working file for the duration of a run.
package securefile

import (
	"crypto/rc4"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var magic = []byte("KONTUR1\n")

type Session struct {
	encryptedPath, workingPath, stagedPath string
	key                                    [16]byte
}
type accountFile struct {
	Users []struct {
		Name         string `json:"name"`
		PasswordHash string `json:"password_hash"`
		Blocked      bool   `json:"blocked"`
		Restricted   bool   `json:"restricted"`
	} `json:"users"`
}

func HasState(path string) bool {
	for _, candidate := range []string{path, path + ".next", path + ".plain"} {
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".users-") {
				return true
			}
		}
	}
	return false
}

func Open(path, phrase string, legacyPaths ...string) (*Session, error) {
	if phrase == "" {
		return nil, errors.New("Парольная фраза не может быть пустой.")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Session{encryptedPath: path, workingPath: path + ".plain", stagedPath: path + ".next", key: md2([]byte(phrase))}
	mainBytes, mainErr := os.ReadFile(path)
	stageBytes, stageErr := os.ReadFile(s.stagedPath)
	plainBytes, plainErr := os.ReadFile(s.workingPath)
	if mainErr != nil && !errors.Is(mainErr, os.ErrNotExist) {
		return nil, mainErr
	}
	if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
		return nil, stageErr
	}
	if plainErr != nil && !errors.Is(plainErr, os.ErrNotExist) {
		return nil, plainErr
	}

	var recovered []byte
	var validEncrypted bool
	if len(stageBytes) != 0 {
		if clear, err := decrypt(stageBytes, s.key[:]); err == nil && validAccounts(clear) {
			recovered, validEncrypted = clear, true
		}
	}
	if len(mainBytes) != 0 && !validEncrypted {
		if clear, err := decrypt(mainBytes, s.key[:]); err == nil && validAccounts(clear) {
			recovered, validEncrypted = clear, true
		}
	}
	if validEncrypted {
		workingFileValid := len(plainBytes) != 0 && validAccounts(plainBytes)
		writeWorkingFile := !workingFileValid
		if workingFileValid {
			recovered = plainBytes
		}
		orphanPath, orphanData := newestValidWorkingTemp(dir)
		if orphanPath != "" {
			workingInfo, _ := os.Stat(s.workingPath)
			orphanInfo, _ := os.Stat(orphanPath)
			if workingInfo == nil || (orphanInfo != nil && orphanInfo.ModTime().After(workingInfo.ModTime())) {
				recovered = orphanData
				writeWorkingFile = true
			}
		}
		if writeWorkingFile {
			if err := writeRestricted(s.workingPath, recovered); err != nil {
				return nil, err
			}
		}
		if err := removeWorkingTemps(dir); err != nil {
			return nil, fmt.Errorf("не удалось очистить незавершённый временный файл: %w", err)
		}
		for _, legacy := range legacyPaths {
			if legacy != "" {
				if err := wipeAndRemove(legacy); err != nil {
					return nil, fmt.Errorf("не удалось удалить старый незашифрованный файл: %w", err)
				}
			}
		}
		return s, nil
	}
	if len(mainBytes) != 0 || len(stageBytes) != 0 {
		return nil, errors.New("Неверная парольная фраза или файл учётных записей повреждён.")
	}
	if len(plainBytes) != 0 {
		return nil, errors.New("Не удалось проверить парольную фразу: зашифрованная копия отсутствует, временный файл сохранён для восстановления.")
	}
	initial := []byte("{\n  \"users\": [\n    {\n      \"name\": \"ADMIN\",\n      \"password_hash\": \"\",\n      \"blocked\": false,\n      \"restricted\": false\n    }\n  ]\n}\n")
	legacyPath := ""
	if len(legacyPaths) != 0 {
		legacyPath = legacyPaths[0]
	}
	if legacyPath != "" {
		if legacy, err := os.ReadFile(legacyPath); err == nil {
			if !validAccounts(legacy) {
				return nil, errors.New("старый файл пользователей не прошёл проверку; он сохранён без изменений")
			}
			initial = legacy
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err := writeEncrypted(path, initial, s.key[:]); err != nil {
		return nil, err
	}
	if err := writeRestricted(s.workingPath, initial); err != nil {
		return nil, err
	}
	if legacyPath != "" {
		if err := wipeAndRemove(legacyPath); err != nil {
			return nil, fmt.Errorf("данные перенесены, но старый файл не удалось удалить: %w", err)
		}
	}
	return s, nil
}

func newestValidWorkingTemp(dir string) (string, []byte) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil
	}
	var bestPath string
	var bestData []byte
	var bestTime time.Time
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".users-") || entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := os.ReadFile(path)
		info, statErr := entry.Info()
		if readErr == nil && statErr == nil && validAccounts(data) && (bestPath == "" || info.ModTime().After(bestTime)) {
			bestPath, bestData, bestTime = path, data, info.ModTime()
		}
	}
	return bestPath, bestData
}

func removeWorkingTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".users-") && !entry.IsDir() {
			if err := wipeAndRemove(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func validAccounts(clear []byte) bool {
	var doc accountFile
	if json.Unmarshal(clear, &doc) != nil || len(doc.Users) == 0 {
		return false
	}
	seen := make(map[string]bool, len(doc.Users))
	admin := false
	for _, u := range doc.Users {
		if u.Name == "" || seen[u.Name] {
			return false
		}
		seen[u.Name] = true
		if u.Name == "ADMIN" {
			admin = !u.Blocked
		}
	}
	return admin
}

func crypt(data, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}
func encrypt(clear, key []byte) ([]byte, error) {
	body, err := crypt(clear, key)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), magic...), body...), nil
}
func decrypt(data, key []byte) ([]byte, error) {
	if !strings.HasPrefix(string(data), string(magic)) {
		return nil, errors.New("unknown format")
	}
	return crypt(data[len(magic):], key)
}
func writeRestricted(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func writeEncrypted(path string, clear, key []byte) error {
	data, err := encrypt(clear, key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func wipeAndRemove(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if statErr == nil {
		zeros := make([]byte, 32*1024)
		for left := info.Size(); left > 0 && err == nil; {
			n := int64(len(zeros))
			if left < n {
				n = left
			}
			var written int
			written, err = f.Write(zeros[:n])
			left -= int64(written)
		}
		if err == nil {
			err = f.Sync()
		}
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = statErr
	}
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// Commit writes a recoverable encrypted checkpoint before overwriting the old
// ciphertext. If interrupted, Open can recover from either the checkpoint or
// the restricted-permission working file after validating the phrase.
func (s *Session) Commit() error {
	clear, err := os.ReadFile(s.workingPath)
	if err != nil {
		return err
	}
	if !validAccounts(clear) {
		return errors.New("Рабочий файл учётных записей повреждён; исходный зашифрованный файл сохранён.")
	}
	encrypted, err := encrypt(clear, s.key[:])
	if err != nil {
		return err
	}
	if err = writeRestricted(s.stagedPath, encrypted); err != nil {
		return err
	}
	old, err := os.OpenFile(s.encryptedPath, os.O_WRONLY, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		info, statErr := old.Stat()
		if statErr != nil {
			old.Close()
			return statErr
		}
		if _, err = old.Seek(0, io.SeekStart); err == nil {
			zeros := make([]byte, 32*1024)
			for left := info.Size(); left > 0 && err == nil; {
				n := int64(len(zeros))
				if left < n {
					n = left
				}
				var written int
				written, err = old.Write(zeros[:n])
				left -= int64(written)
			}
		}
		if err == nil {
			err = old.Sync()
		}
		closeErr := old.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	if err = writeRestricted(s.encryptedPath, encrypted); err != nil {
		return err
	}
	if err = os.Remove(s.stagedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = wipeAndRemove(s.workingPath); err != nil {
		return fmt.Errorf("файл зашифрован, но временный файл не удалось удалить: %w", err)
	}
	return nil
}

func (s *Session) WorkingPath() string { return s.workingPath }

// Rekey verifies the current phrase, then writes a recoverable encrypted copy
// under the new key while keeping the plaintext working file available.
func (s *Session) Rekey(oldPhrase, newPhrase string) error {
	if newPhrase == "" {
		return errors.New("Новая парольная фраза не может быть пустой.")
	}
	oldKey := md2([]byte(oldPhrase))
	if subtle.ConstantTimeCompare(oldKey[:], s.key[:]) != 1 {
		return errors.New("Текущая парольная фраза неверна.")
	}
	clear, err := os.ReadFile(s.workingPath)
	if err != nil {
		return err
	}
	if !validAccounts(clear) {
		return errors.New("Рабочий файл учётных записей повреждён.")
	}
	newKey := md2([]byte(newPhrase))
	encrypted, err := encrypt(clear, newKey[:])
	if err != nil {
		return err
	}
	if err = writeRestricted(s.stagedPath, encrypted); err != nil {
		return err
	}
	s.key = newKey
	old, err := os.OpenFile(s.encryptedPath, os.O_WRONLY, 0)
	if err == nil {
		info, statErr := old.Stat()
		if statErr != nil {
			old.Close()
			return statErr
		}
		if _, err = old.Seek(0, io.SeekStart); err == nil {
			zeros := make([]byte, 32*1024)
			for left := info.Size(); left > 0 && err == nil; {
				n := int64(len(zeros))
				if left < n {
					n = left
				}
				var written int
				written, err = old.Write(zeros[:n])
				left -= int64(written)
			}
		}
		if err == nil {
			err = old.Sync()
		}
		closeErr := old.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = writeRestricted(s.encryptedPath, encrypted); err != nil {
		return err
	}
	if err = os.Remove(s.stagedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
