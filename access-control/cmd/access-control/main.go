package main

import (
	"access-control/internal/accounts"
	"access-control/internal/filestore"
	"access-control/internal/securefile"
	"access-control/internal/web"
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	noBrowser := flag.Bool("no-browser", false, "Не открывать браузер автоматически")
	port := flag.Int("port", 8080, "Порт локального веб-интерфейса")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("Порт должен быть числом от 1 до 65535.")
	}
	dataFile := os.Getenv("ACCESS_CONTROL_DATA_FILE")
	if dataFile == "" {
		dataFile = "data/users.enc"
	}
	phrase, err := readPhrase(dataFile)
	if err != nil {
		log.Fatal(err)
	}
	legacyFile := ""
	if dataFile == "data/users.enc" {
		legacyFile = "data/users.json"
	}
	session, err := securefile.Open(dataFile, phrase, legacyFile)
	if err != nil {
		log.Fatalf("Не удалось открыть хранилище: %v", err)
	}
	repository, err := filestore.Open(session.WorkingPath())
	if err != nil {
		log.Fatalf("Не удалось прочитать временный файл учётных записей: %v", err)
	}
	store := accounts.New(repository)
	address := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		if commitErr := session.Commit(); commitErr != nil {
			log.Printf("Не удалось зашифровать файл при завершении: %v", commitErr)
		}
		log.Fatalf("Не удалось открыть %s: %v. Освободите порт или задайте другой через -port.", address, err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan struct{})
	var once sync.Once
	var commitErr error
	stop := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			commitErr = session.Commit()
			close(done)
		})
	}
	server.Handler = web.New(store, listener.Addr().String(), stop, session.Rekey)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			stop()
		case <-done:
		}
	}()
	url := "http://" + listener.Addr().String()
	fmt.Printf("Разграничение доступа: %s\nХранилище: %s\n", url, dataFile)
	if !*noBrowser {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		default:
			cmd = exec.Command("xdg-open", url)
		}
		if err := cmd.Start(); err != nil {
			fmt.Println("Откройте адрес в браузере вручную.")
		} else {
			go cmd.Wait()
		}
	}
	if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("Веб-сервер завершился с ошибкой: %v", err)
		stop()
	}
	<-done
	if commitErr != nil {
		log.Fatalf("Не удалось зашифровать файл при завершении: %v", commitErr)
	}
}

func readPhrase(path string) (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", fmt.Errorf("Введите парольную фразу из интерактивного терминала")
	}
	newStore := !securefile.HasState(path)
	first, err := readSecret("Введите парольную фразу для файла учётных записей: ")
	if err != nil || first == "" {
		return "", fmt.Errorf("Парольная фраза не введена. Работа завершена")
	}
	if newStore {
		second, readErr := readSecret("Повторите парольную фразу: ")
		if readErr != nil || first != second {
			return "", fmt.Errorf("Парольные фразы не совпали. Работа завершена")
		}
	}
	return first, nil
}

func readSecret(prompt string) (string, error) {
	fmt.Print(prompt)
	if runtime.GOOS != "windows" {
		getState := exec.Command("stty", "-g")
		getState.Stdin = os.Stdin
		state, err := getState.Output()
		if err != nil {
			return "", err
		}
		setNoEcho := exec.Command("stty", "-echo", "-isig")
		setNoEcho.Stdin = os.Stdin
		if err = setNoEcho.Run(); err != nil {
			return "", err
		}
		defer func() {
			restore := exec.Command("stty", string(bytes.TrimSpace(state)))
			restore.Stdin = os.Stdin
			_ = restore.Run()
			fmt.Println()
		}()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.ContainsRune(line, '\x03') {
		return "", fmt.Errorf("Ввод парольной фразы отменён")
	}
	return strings.TrimRight(line, "\r\n"), err
}
