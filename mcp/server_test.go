package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runOne прогоняет один JSON-RPC запрос через Serve и возвращает ответ.
func runOne(t *testing.T, srv *Server, request string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	srv.out = &out
	if err := srv.Serve(strings.NewReader(request + "\n")); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("ответ не JSON (%q): %v", out.String(), err)
	}
	return resp
}

func TestInitializeHandshake(t *testing.T) {
	srv := NewServer(nil)
	resp := runOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("нет result: %v", resp)
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Fatalf("protocolVersion = %v", result["protocolVersion"])
	}
	info := result["serverInfo"].(map[string]any)
	if info["name"] != ServerName {
		t.Fatalf("serverInfo.name = %v", info["name"])
	}
}

func TestToolsListIncludesRegistered(t *testing.T) {
	srv := NewServer(nil)
	sess := NewSession()
	RegisterTools(srv, sess)

	var out bytes.Buffer
	srv.out = &out
	if err := srv.Serve(strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resp struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	names := make(map[string]bool)
	for _, tool := range resp.Result.Tools {
		names[tool.Name] = true
		if tool.Description == "" {
			t.Fatalf("у инструмента %s пустое описание", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Fatalf("у инструмента %s нет inputSchema", tool.Name)
		}
	}
	for _, want := range []string{"connect", "disconnect", "status", "type_text", "send_keys", "window_list", "wait_speech", "speech_drain", "key_down", "key_up", "speak"} {
		if !names[want] {
			t.Fatalf("инструмент %s не зарегистрирован", want)
		}
	}
}

func TestToolsCallReportsError(t *testing.T) {
	srv := NewServer(nil)
	sess := NewSession()
	RegisterTools(srv, sess)

	var out bytes.Buffer
	srv.out = &out
	req := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_keys","arguments":{"keys":["enter"]}}}`
	if err := srv.Serve(strings.NewReader(req + "\n")); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if !resp.Result.IsError {
		t.Fatal("без подключения send_keys должен возвращать isError")
	}
	if len(resp.Result.Content) == 0 || !strings.Contains(resp.Result.Content[0].Text, "нет подключения") {
		t.Fatalf("неожиданный текст ошибки: %+v", resp.Result.Content)
	}
}

func TestUnknownMethodReturnsError(t *testing.T) {
	srv := NewServer(nil)
	resp := runOne(t, srv, `{"jsonrpc":"2.0","id":4,"method":"nope"}`)
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("ждали error, получили %v", resp)
	}
	if errObj["code"].(float64) != -32601 {
		t.Fatalf("код ошибки = %v", errObj["code"])
	}
}

func TestNotificationsDoNotProduceOutput(t *testing.T) {
	srv := NewServer(nil)
	var out bytes.Buffer
	srv.out = &out
	if err := srv.Serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("на уведомление не должно быть ответа, получили %q", out.String())
	}
}

func TestFormatSpeech(t *testing.T) {
	speech := []Utterance{{Text: "первое"}, {Text: "второе"}}
	got := formatSpeech(speech)
	if !strings.Contains(got, "первое") || !strings.Contains(got, "второе") {
		t.Fatalf("речь потерялась: %q", got)
	}
	if got := withSpeech("готово", nil); got != "готово" {
		t.Fatalf("withSpeech без речи = %q", got)
	}
	if got := withSpeech("", nil); got != "NVDA молчал" {
		t.Fatalf("withSpeech пустой = %q", got)
	}
}
