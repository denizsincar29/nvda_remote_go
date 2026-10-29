package mcp

import (
	"fmt"
	"strings"
)

// KeyForRune переводит один символ в имя клавиши (или аккорд с shift),
// понятное пакету key из протокола NVDA Remote.
//
// Раскладка — американская: только ASCII. Кириллица и прочие
// нелатинские символы не поддерживаются, потому что удалённая машина
// может быть в любой раскладке, и тогда символ всё равно наберётся
// неверно. О таких символах сообщаем ошибкой, чтобы вызывающая сторона
// не думала, что текст ушёл.
func KeyForRune(r rune) (string, error) {
	switch r {
	case '\n':
		return "enter", nil
	case '\t':
		return "tab", nil
	case ' ':
		return "space", nil
	}

	if r >= 'a' && r <= 'z' {
		return string(r), nil
	}
	if r >= '0' && r <= '9' {
		return string(r), nil
	}
	if r >= 'A' && r <= 'Z' {
		return "shift+" + strings.ToLower(string(r)), nil
	}

	if plain, ok := plainPunctuation[r]; ok {
		return plain, nil
	}
	if shifted, ok := shiftedPunctuation[r]; ok {
		return "shift+" + shifted, nil
	}

	return "", fmt.Errorf("символ %q (%U) не поддерживается: только ASCII", r, r)
}

// plainPunctuation — символы, которые набираются без shift.
var plainPunctuation = map[rune]string{
	'-':  "-",
	'=':  "=",
	'[':  "[",
	']':  "]",
	'\\': "\\",
	';':  ";",
	'\'': "'",
	',':  ",",
	'.':  ".",
	'/':  "/",
	'`':  "`",
}

// shiftedPunctuation — символ → базовая клавиша, которую нажимают с shift.
var shiftedPunctuation = map[rune]string{
	'!': "1",
	'@': "2",
	'#': "3",
	'$': "4",
	'%': "5",
	'^': "6",
	'&': "7",
	'*': "8",
	'(': "9",
	')': "0",
	'_': "-",
	'+': "=",
	'{': "[",
	'}': "]",
	'|': "\\",
	':': ";",
	'"': "'",
	'<': ",",
	'>': ".",
	'?': "/",
	'~': "`",
}

// KeystrokesForText разбирает строку в последовательность клавиш.
// Возвращает ошибку, если встретился неподдерживаемый символ — целиком,
// без частичной отправки: лучше не отправить ничего, чем половину.
func KeystrokesForText(s string) ([]string, error) {
	keys := make([]string, 0, len(s))
	for _, r := range s {
		k, err := KeyForRune(r)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}
