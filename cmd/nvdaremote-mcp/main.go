// Command nvdaremote-mcp — MCP-сервер для NVDA Remote.
//
// Говорит по stdio (построчный JSON-RPC 2.0), поэтому его можно
// подключить к любому MCP-клиенту как обычный локальный сервер:
//
//	{"mcpServers":{"nvda":{"command":"nvdaremote-mcp"}}}
//
// Переменные окружения NVDA_HOST / NVDA_PORT / NVDA_CHANNEL позволяют
// подключиться сразу при старте, чтобы инструменты работали без
// отдельного вызова connect.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/denizsincar29/nvda_remote_go/mcp"
)

func main() {
	host := flag.String("host", os.Getenv("NVDA_HOST"), "адрес релея (например 127.0.0.1)")
	port := flag.String("port", envDefault("NVDA_PORT", "6837"), "порт релея")
	channel := flag.String("channel", os.Getenv("NVDA_CHANNEL"), "ключ канала")
	autoConnect := flag.Bool("connect", os.Getenv("NVDA_AUTOCONNECT") == "1", "подключиться сразу при старте")
	flag.Parse()

	sess := mcp.NewSession()
	srv := mcp.NewServer(os.Stdout)
	mcp.RegisterTools(srv, sess)

	if *autoConnect && *host != "" && *channel != "" {
		go func() {
			time.Sleep(200 * time.Millisecond)
			if _, err := sess.Connect(*host, *port, *channel); err != nil {
				fmt.Fprintf(os.Stderr, "автоподключение не удалось: %v\n", err)
			}
		}()
	}

	if err := srv.Serve(os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка чтения stdin: %v\n", err)
		os.Exit(1)
	}
	sess.Disconnect()
}

func envDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
