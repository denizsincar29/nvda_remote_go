package mcp

import (
	"fmt"
	"strings"
	"time"
)

// RegisterTools наполняет сервер инструментами NVDA Remote.
//
// Все инструменты возвращают текст, в который всегда подмешана речь
// NVDA: без неё управление слепой машиной вслепую бессмысленно —
// единственный источник правды о том, что произошло, это то, что
// произносит скринридер.
func RegisterTools(srv *Server, sess *Session) {
	srv.AddTool(Tool{
		Name:        "connect",
		Description: "Подключиться к релею NVDA Remote как master. Возвращает клиентов канала и первую речь NVDA.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":    map[string]any{"type": "string", "description": "Адрес релея, например 127.0.0.1"},
				"port":    map[string]any{"type": "string", "description": "Порт, по умолчанию 6837"},
				"channel": map[string]any{"type": "string", "description": "Ключ канала (пароль подключения)"},
			},
			"required": []string{"host", "channel"},
		},
		Handler: func(args map[string]any) (string, error) {
			host, err := argString(args, "host")
			if err != nil {
				return "", err
			}
			channel, err := argString(args, "channel")
			if err != nil {
				return "", err
			}
			port := argStringDefault(args, "port", "6837")
			msg, err := sess.Connect(host, port, channel)
			if err != nil {
				return "", err
			}
			return withSpeech(msg, sess.DrainSpeech()), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "disconnect",
		Description: "Закрыть соединение с релеем.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(map[string]any) (string, error) {
			sess.Disconnect()
			return "соединение закрыто", nil
		},
	})

	srv.AddTool(Tool{
		Name:        "status",
		Description: "Состояние подключения: адрес, канал, клиенты канала.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(map[string]any) (string, error) {
			if !sess.Connected() {
				return "не подключено", nil
			}
			return fmt.Sprintf("подключено к %s:%s, канал %q, клиенты: %v",
				sess.host, sess.port, sess.channel, sess.Clients()), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "type_text",
		Description: "Напечатать текст на удалённой машине с человеческим ритмом (по умолчанию 5 клавиш/с и разброс ±30%). Только ASCII: кириллицу набрать нельзя.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text":         map[string]any{"type": "string", "description": "Что напечатать"},
				"keys_per_sec": map[string]any{"type": "number", "description": "Скорость, по умолчанию 5"},
				"jitter":       map[string]any{"type": "number", "description": "Разброс пауз 0..1, по умолчанию 0.3"},
			},
			"required": []string{"text"},
		},
		Handler: func(args map[string]any) (string, error) {
			text, err := argString(args, "text")
			if err != nil {
				return "", err
			}
			speed := argFloatDefault(args, "keys_per_sec", 5)
			jitter := argFloatDefault(args, "jitter", 0.3)
			sess.DrainSpeech()
			if err := sess.TypeText(text, speed, jitter); err != nil {
				return "", err
			}
			return withSpeech(fmt.Sprintf("набрано %d символов со скоростью %.1f клавиш/с", len([]rune(text)), speed),
				sess.WaitForSpeech(1200*time.Millisecond)), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "send_keys",
		Description: "Отправить последовательность аккордов, например [\"control+c\", \"alt+tab\", \"enter\"].",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"keys":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Аккорды по одному"},
				"pause_ms": map[string]any{"type": "number", "description": "Пауза между аккордами, по умолчанию 150"},
				"jitter":   map[string]any{"type": "number", "description": "Разброс пауз 0..1, по умолчанию 0.25"},
			},
			"required": []string{"keys"},
		},
		Handler: func(args map[string]any) (string, error) {
			keys, err := argStringSlice(args, "keys")
			if err != nil {
				return "", err
			}
			pause := time.Duration(argFloatDefault(args, "pause_ms", 150)) * time.Millisecond
			jitter := argFloatDefault(args, "jitter", 0.25)
			sess.DrainSpeech()
			if err := sess.SendKeys(keys, pause, jitter); err != nil {
				return "", err
			}
			return withSpeech(fmt.Sprintf("отправлено %d аккордов: %s", len(keys), strings.Join(keys, ", ")),
				sess.WaitForSpeech(1500*time.Millisecond)), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "key_down",
		Description: "Зажать клавишу (для удержаний). Отпускать через key_up.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"key": map[string]any{"type": "string", "description": "Имя клавиши, например alt"}},
			"required":   []string{"key"},
		},
		Handler: func(args map[string]any) (string, error) {
			key, err := argString(args, "key")
			if err != nil {
				return "", err
			}
			if err := sess.KeyDown(key); err != nil {
				return "", err
			}
			return "зажато: " + key, nil
		},
	})

	srv.AddTool(Tool{
		Name:        "key_up",
		Description: "Отпустить клавишу.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"key": map[string]any{"type": "string", "description": "Имя клавиши, например alt"}},
			"required":   []string{"key"},
		},
		Handler: func(args map[string]any) (string, error) {
			key, err := argString(args, "key")
			if err != nil {
				return "", err
			}
			if err := sess.KeyUp(key); err != nil {
				return "", err
			}
			return "отпущено: " + key, nil
		},
	})

	srv.AddTool(Tool{
		Name: "window_list",
		Description: "Перечислить активные окна так же, как это делает человек: зажать Alt, жать Tab и слушать NVDA, " +
			"пока имя окна не начнёт повторяться. Возвращает список окон с речью NVDA.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"max_windows":  map[string]any{"type": "number", "description": "Максимум шагов, по умолчанию 25"},
				"key_pause_ms": map[string]any{"type": "number", "description": "Сколько ждать речь после Tab, по умолчанию 450"},
			},
		},
		Handler: func(args map[string]any) (string, error) {
			maxWindows := int(argFloatDefault(args, "max_windows", 25))
			pause := time.Duration(argFloatDefault(args, "key_pause_ms", 450)) * time.Millisecond
			sess.DrainSpeech()
			windows, err := sess.WindowList(maxWindows, pause)
			if err != nil {
				return withSpeech("ошибка обхода окон: "+err.Error(), sess.DrainSpeech()), err
			}
			if len(windows) == 0 {
				return withSpeech("окна не определились: NVDA молчал", sess.DrainSpeech()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "окон найдено: %d\n", len(windows))
			for i, w := range windows {
				fmt.Fprintf(&b, "%d. %s\n", i+1, w)
			}
			b.WriteString(withSpeech("", sess.DrainSpeech()))
			return b.String(), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "wait_speech",
		Description: "Подождать, пока NVDA что-нибудь скажет, и вернуть речь. Полезно после действия, у которого нет мгновенного отклика.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"timeout_ms": map[string]any{"type": "number", "description": "Сколько ждать, по умолчанию 5000"},
			},
		},
		Handler: func(args map[string]any) (string, error) {
			timeout := time.Duration(argFloatDefault(args, "timeout_ms", 5000)) * time.Millisecond
			speech := sess.WaitForSpeech(timeout)
			if len(speech) == 0 {
				return fmt.Sprintf("NVDA молчал %s", timeout), nil
			}
			return formatSpeech(speech), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "speech_drain",
		Description: "Забрать всю накопленную речь NVDA и очистить буфер.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(map[string]any) (string, error) {
			speech := sess.DrainSpeech()
			if len(speech) == 0 {
				return "буфер речи пуст", nil
			}
			return formatSpeech(speech), nil
		},
	})

	srv.AddTool(Tool{
		Name:        "speak",
		Description: "Озвучить текст на удалённой машине через NVDA.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string", "description": "Что произнести"}},
			"required":   []string{"text"},
		},
		Handler: func(args map[string]any) (string, error) {
			text, err := argString(args, "text")
			if err != nil {
				return "", err
			}
			if err := sess.Speak(text); err != nil {
				return "", err
			}
			return "озвучено: " + text, nil
		},
	})
}

// formatSpeech склеивает фразы в читаемый блок.
func formatSpeech(speech []Utterance) string {
	var b strings.Builder
	for _, u := range speech {
		fmt.Fprintf(&b, "[%s] %s\n", u.At.Format("15:04:05.000"), u.Text)
	}
	return strings.TrimRight(b.String(), "\n")
}

// withSpeech добавляет к ответу речь NVDA, если она была.
func withSpeech(prefix string, speech []Utterance) string {
	text := strings.TrimSpace(prefix)
	if len(speech) == 0 {
		if text == "" {
			return "NVDA молчал"
		}
		return text
	}
	spoken := formatSpeech(speech)
	if text == "" {
		return "речь NVDA:\n" + spoken
	}
	return text + "\n\nречь NVDA:\n" + spoken
}

func argString(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok {
		return "", errMissing(name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("аргумент %s должен быть строкой", name)
	}
	return s, nil
}

func argStringDefault(args map[string]any, name, def string) string {
	if s, ok := args[name].(string); ok && s != "" {
		return s
	}
	return def
}

func argFloatDefault(args map[string]any, name string, def float64) float64 {
	if v, ok := args[name].(float64); ok {
		return v
	}
	return def
}

func argStringSlice(args map[string]any, name string) ([]string, error) {
	raw, ok := args[name]
	if !ok {
		return nil, errMissing(name)
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("аргумент %s должен быть массивом строк", name)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("аргумент %s должен содержать только строки", name)
		}
		out = append(out, s)
	}
	return out, nil
}
