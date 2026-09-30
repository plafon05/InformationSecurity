package main

import (
	"access-control/internal/accounts"
	"access-control/internal/postgres"
	"access-control/internal/web"
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
	"sync"
	"time"
)

func main() {
	noBrowser := flag.Bool("no-browser", false, "Не открывать браузер автоматически")
	port := flag.Int("port", 8080, "Порт локального веб-интерфейса")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("Порт должен быть числом от 1 до 65535.")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("Задайте DATABASE_URL. Для локального запуска используйте scripts/start.sh.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	repository, err := postgres.Open(ctx, databaseURL)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	defer repository.Close()
	store := accounts.New(repository)
	address := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Не удалось открыть %s: %v. Освободите порт или задайте другой через -port.", address, err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			close(done)
		})
	}
	server.Handler = web.New(store, listener.Addr().String(), stop)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			stop()
		case <-done:
		}
	}()
	url := "http://" + listener.Addr().String()
	fmt.Printf("Разграничение доступа: %s\nХранилище: PostgreSQL\n", url)
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
		log.Fatal(err)
	}
	<-done
}
