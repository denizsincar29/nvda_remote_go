package vgui

import (
	"fmt"
	"sync"
)

// Locale represents a language/locale code
type Locale string

const (
	LocaleEnglish Locale = "en"
	LocaleRussian Locale = "ru"
	LocaleGerman  Locale = "de"
)

// Localizer handles localized strings for the GUI
type Localizer struct {
	locale       Locale
	translations map[Locale]map[string]string
	mu           sync.RWMutex
}

// NewLocalizer creates a new localizer with the given locale
func NewLocalizer(locale Locale) *Localizer {
	l := &Localizer{
		locale:       locale,
		translations: make(map[Locale]map[string]string),
	}
	l.loadTranslations()
	return l
}

// loadTranslations loads all available translations
func (l *Localizer) loadTranslations() {
	// English translations
	l.translations[LocaleEnglish] = map[string]string{
		// Roles
		"button":   "button",
		"listbox":  "listbox",
		"checkbox": "checkbox",
		"label":    "label",
		"textbox":  "textbox",
		"textarea": "textarea",
		
		// States
		"checked":     "checked",
		"not checked": "not checked",
		"selected":    "selected",
		
		// Navigation messages
		"top of list":          "Top of list",
		"bottom of list":       "Bottom of list",
		"no elements":          "No elements",
		"no focusable elements": "No focusable elements",
		"no element focused":   "No element focused",
		
		// Position indicators
		"of": "of",
		
		// TextBox/TextArea
		"blank":           "blank",
		"end of text":     "end of text",
		"beginning of text": "beginning of text",
		"empty":           "empty",
		
		// Dialog
		"ok":     "OK",
		"cancel": "Cancel",
		"yes":    "Yes",
		"no":     "No",
	}
	
	// Russian translations
	l.translations[LocaleRussian] = map[string]string{
		// Roles
		"button":   "кнопка",
		"listbox":  "список",
		"checkbox": "флажок",
		"label":    "метка",
		"textbox":  "поле ввода",
		"textarea": "текстовая область",
		
		// States
		"checked":     "установлен",
		"not checked": "не установлен",
		"selected":    "выбрано",
		
		// Navigation messages
		"top of list":          "Начало списка",
		"bottom of list":       "Конец списка",
		"no elements":          "Нет элементов",
		"no focusable elements": "Нет фокусируемых элементов",
		"no element focused":   "Нет сфокусированного элемента",
		
		// Position indicators
		"of": "из",
		
		// TextBox/TextArea
		"blank":           "пробел",
		"end of text":     "конец текста",
		"beginning of text": "начало текста",
		"empty":           "пусто",
		
		// Dialog
		"ok":     "ОК",
		"cancel": "Отмена",
		"yes":    "Да",
		"no":     "Нет",
	}
	
	// German translations
	l.translations[LocaleGerman] = map[string]string{
		// Roles
		"button":   "Schaltfläche",
		"listbox":  "Listenfeld",
		"checkbox": "Kontrollkästchen",
		"label":    "Beschriftung",
		"textbox":  "Textfeld",
		"textarea": "Textbereich",
		
		// States
		"checked":     "aktiviert",
		"not checked": "nicht aktiviert",
		"selected":    "ausgewählt",
		
		// Navigation messages
		"top of list":          "Listenanfang",
		"bottom of list":       "Listenende",
		"no elements":          "Keine Elemente",
		"no focusable elements": "Keine fokussierbaren Elemente",
		"no element focused":   "Kein Element fokussiert",
		
		// Position indicators
		"of": "von",
		
		// TextBox/TextArea
		"blank":           "Leerzeichen",
		"end of text":     "Textende",
		"beginning of text": "Textanfang",
		"empty":           "leer",
		
		// Dialog
		"ok":     "OK",
		"cancel": "Abbrechen",
		"yes":    "Ja",
		"no":     "Nein",
	}
}

// T translates a key to the current locale
func (l *Localizer) T(key string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	if translations, ok := l.translations[l.locale]; ok {
		if translated, ok := translations[key]; ok {
			return translated
		}
	}
	
	// Fallback to English
	if translations, ok := l.translations[LocaleEnglish]; ok {
		if translated, ok := translations[key]; ok {
			return translated
		}
	}
	
	// Return key itself if no translation found
	return key
}

// TWithArgs translates a key and formats it with arguments
func (l *Localizer) TWithArgs(key string, args ...interface{}) string {
	translated := l.T(key)
	return fmt.Sprintf(translated, args...)
}

// SetLocale changes the current locale
func (l *Localizer) SetLocale(locale Locale) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locale = locale
}

// GetLocale returns the current locale
func (l *Localizer) GetLocale() Locale {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.locale
}
