package mcp

import (
	"reflect"
	"strings"
	"testing"
)

func TestKeystrokesForTextPlain(t *testing.T) {
	got, err := KeystrokesForText("abc 123")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := []string{"a", "b", "c", "space", "1", "2", "3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("получили %v, ждали %v", got, want)
	}
}

func TestKeystrokesForTextShifted(t *testing.T) {
	got, err := KeystrokesForText("A!~|{}")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := []string{"shift+a", "shift+1", "shift+`", "shift+\\", "shift+[", "shift+]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("получили %v, ждали %v", got, want)
	}
}

func TestKeystrokesForTextControl(t *testing.T) {
	got, err := KeystrokesForText("a\nb\tc")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := []string{"a", "enter", "b", "tab", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("получили %v, ждали %v", got, want)
	}
}

func TestKeystrokesForTextRejectsNonASCII(t *testing.T) {
	_, err := KeystrokesForText("привет")
	if err == nil {
		t.Fatal("ждали ошибку для кириллицы, получили nil")
	}
	if !strings.Contains(err.Error(), "не поддерживается") {
		t.Fatalf("неожиданный текст ошибки: %v", err)
	}
}

func TestKeystrokesForTextRejectsPartiallyBadInput(t *testing.T) {
	// смешанный ввод не должен давать частичный результат
	got, err := KeystrokesForText("ok✓")
	if err == nil {
		t.Fatal("ждали ошибку")
	}
	if got != nil {
		t.Fatalf("при ошибке ждали nil, получили %v", got)
	}
}
