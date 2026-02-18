package vgui

import (
	"strings"
	"unicode"
)

// TextBox represents a single-line text input element
type TextBox struct {
	BaseElement
	Text         string
	CursorPos    int
	OnChange     func(text string) string
	Placeholder  string
}

// NewTextBox creates a new textbox with the given name and initial text
func NewTextBox(name string, initialText string) *TextBox {
	return &TextBox{
		BaseElement: BaseElement{
			Name:      name,
			role:      RoleTextBox,
			focusable: true,
		},
		Text:      initialText,
		CursorPos: len(initialText),
	}
}

// GetDescription returns the description including current text
func (t *TextBox) GetDescription() string {
	roleStr := string(t.role)
	if t.localizer != nil {
		roleStr = t.localizer.T(string(t.role))
	}
	
	if t.Text == "" {
		emptyMsg := "empty"
		if t.localizer != nil {
			emptyMsg = t.localizer.T("empty")
		}
		return t.Name + ", " + roleStr + ", " + emptyMsg
	}
	
	return t.Name + ", " + roleStr + ", " + t.Text
}

// GetCurrentChar returns the character at the cursor position
func (t *TextBox) GetCurrentChar() rune {
	if t.CursorPos >= len(t.Text) {
		return 0
	}
	return rune(t.Text[t.CursorPos])
}

// InsertChar inserts a character at the cursor position
func (t *TextBox) InsertChar(ch rune) string {
	text := []rune(t.Text)
	text = append(text[:t.CursorPos], append([]rune{ch}, text[t.CursorPos:]...)...)
	t.Text = string(text)
	t.CursorPos++
	
	if t.OnChange != nil {
		return t.OnChange(t.Text)
	}
	
	return string(ch)
}

// MoveLeft moves the cursor left and announces the previous character
func (t *TextBox) MoveLeft() string {
	if t.CursorPos > 0 {
		t.CursorPos--
		ch := t.GetCurrentChar()
		return t.announceChar(ch)
	}
	
	if t.localizer != nil {
		return t.localizer.T("beginning of text")
	}
	return "beginning of text"
}

// MoveRight moves the cursor right and announces the next character
func (t *TextBox) MoveRight() string {
	if t.CursorPos < len(t.Text) {
		t.CursorPos++
		if t.CursorPos < len(t.Text) {
			ch := t.GetCurrentChar()
			return t.announceChar(ch)
		}
	}
	
	if t.localizer != nil {
		return t.localizer.T("end of text")
	}
	return "end of text"
}

// MoveToStart moves the cursor to the start of the text
func (t *TextBox) MoveToStart() string {
	t.CursorPos = 0
	if t.Text == "" {
		if t.localizer != nil {
			return t.localizer.T("empty")
		}
		return "empty"
	}
	ch := t.GetCurrentChar()
	return t.announceChar(ch)
}

// MoveToEnd moves the cursor to the end of the text
func (t *TextBox) MoveToEnd() string {
	t.CursorPos = len(t.Text)
	if t.localizer != nil {
		return t.localizer.T("end of text")
	}
	return "end of text"
}

// MoveToPreviousWord moves the cursor to the start of the previous word
func (t *TextBox) MoveToPreviousWord() string {
	if t.CursorPos == 0 {
		if t.localizer != nil {
			return t.localizer.T("beginning of text")
		}
		return "beginning of text"
	}
	
	// Skip whitespace backwards
	for t.CursorPos > 0 && unicode.IsSpace(rune(t.Text[t.CursorPos-1])) {
		t.CursorPos--
	}
	
	// Skip word characters backwards
	for t.CursorPos > 0 && !unicode.IsSpace(rune(t.Text[t.CursorPos-1])) {
		t.CursorPos--
	}
	
	// Get the word at the cursor
	word := t.getCurrentWord()
	return word
}

// MoveToNextWord moves the cursor to the start of the next word
func (t *TextBox) MoveToNextWord() string {
	textLen := len(t.Text)
	
	if t.CursorPos >= textLen {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	// Skip current word
	for t.CursorPos < textLen && !unicode.IsSpace(rune(t.Text[t.CursorPos])) {
		t.CursorPos++
	}
	
	// Skip whitespace
	for t.CursorPos < textLen && unicode.IsSpace(rune(t.Text[t.CursorPos])) {
		t.CursorPos++
	}
	
	if t.CursorPos >= textLen {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	// Get the word at the cursor
	word := t.getCurrentWord()
	return word
}

// getCurrentWord returns the word at the current cursor position
func (t *TextBox) getCurrentWord() string {
	if t.CursorPos >= len(t.Text) {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	start := t.CursorPos
	end := t.CursorPos
	
	// Find word start
	for start > 0 && !unicode.IsSpace(rune(t.Text[start-1])) {
		start--
	}
	
	// Find word end
	for end < len(t.Text) && !unicode.IsSpace(rune(t.Text[end])) {
		end++
	}
	
	word := t.Text[start:end]
	if word == "" {
		if t.localizer != nil {
			return t.localizer.T("blank")
		}
		return "blank"
	}
	
	return word
}

// DeleteCharBefore deletes the character before the cursor (Backspace)
func (t *TextBox) DeleteCharBefore() string {
	if t.CursorPos == 0 {
		if t.localizer != nil {
			return t.localizer.T("beginning of text")
		}
		return "beginning of text"
	}
	
	deletedChar := rune(t.Text[t.CursorPos-1])
	text := []rune(t.Text)
	text = append(text[:t.CursorPos-1], text[t.CursorPos:]...)
	t.Text = string(text)
	t.CursorPos--
	
	if t.OnChange != nil {
		return t.OnChange(t.Text)
	}
	
	return t.announceChar(deletedChar)
}

// DeleteCharAfter deletes the character after the cursor (Delete)
func (t *TextBox) DeleteCharAfter() string {
	if t.CursorPos >= len(t.Text) {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	deletedChar := rune(t.Text[t.CursorPos])
	text := []rune(t.Text)
	text = append(text[:t.CursorPos], text[t.CursorPos+1:]...)
	t.Text = string(text)
	
	if t.OnChange != nil {
		return t.OnChange(t.Text)
	}
	
	return t.announceChar(deletedChar)
}

// announceChar announces a character with special handling for spaces
func (t *TextBox) announceChar(ch rune) string {
	if ch == 0 {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	if ch == ' ' || ch == '\t' {
		if t.localizer != nil {
			return t.localizer.T("blank")
		}
		return "blank"
	}
	
	return string(ch)
}

// SetCursorPosition sets the cursor position (for testing)
func (t *TextBox) SetCursorPosition(pos int) {
	if pos < 0 {
		pos = 0
	}
	if pos > len(t.Text) {
		pos = len(t.Text)
	}
	t.CursorPos = pos
}

// OnActivate activates the textbox (does nothing for textboxes)
func (t *TextBox) OnActivate() string {
	return ""
}

// TextArea represents a multi-line text input element
type TextArea struct {
	TextBox
	lines    []string
	Row      int // Current row (line) position
	Col      int // Current column position
	MaxLines int
}

// NewTextArea creates a new textarea with the given name and initial text
func NewTextArea(name string, initialText string) *TextArea {
	lines := strings.Split(initialText, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}
	
	return &TextArea{
		TextBox: TextBox{
			BaseElement: BaseElement{
				Name:      name,
				role:      RoleTextArea,
				focusable: true,
			},
			Text: initialText,
		},
		lines: lines,
		Row:   0,
		Col:   0,
	}
}

// GetDescription returns the description including current text
func (t *TextArea) GetDescription() string {
	roleStr := string(t.role)
	if t.localizer != nil {
		roleStr = t.localizer.T(string(t.role))
	}
	
	if t.Text == "" {
		emptyMsg := "empty"
		if t.localizer != nil {
			emptyMsg = t.localizer.T("empty")
		}
		return t.Name + ", " + roleStr + ", " + emptyMsg
	}
	
	return t.Name + ", " + roleStr
}

// syncFromLines syncs the Text field from the lines array
func (t *TextArea) syncFromLines() {
	t.Text = strings.Join(t.lines, "\n")
}

// getCurrentLine returns the current line text
func (t *TextArea) getCurrentLine() string {
	if t.Row >= len(t.lines) {
		return ""
	}
	return t.lines[t.Row]
}

// InsertChar inserts a character at the cursor position
func (t *TextArea) InsertChar(ch rune) string {
	if ch == '\n' {
		// Insert newline
		line := t.lines[t.Row]
		t.lines[t.Row] = line[:t.Col]
		t.lines = append(t.lines[:t.Row+1], append([]string{line[t.Col:]}, t.lines[t.Row+1:]...)...)
		t.Row++
		t.Col = 0
		t.syncFromLines()
		return "new line"
	}
	
	line := []rune(t.lines[t.Row])
	line = append(line[:t.Col], append([]rune{ch}, line[t.Col:]...)...)
	t.lines[t.Row] = string(line)
	t.Col++
	t.syncFromLines()
	
	if t.OnChange != nil {
		return t.OnChange(t.Text)
	}
	
	return string(ch)
}

// MoveLeft moves the cursor left
func (t *TextArea) MoveLeft() string {
	if t.Col > 0 {
		t.Col--
		ch := rune(t.lines[t.Row][t.Col])
		return t.announceChar(ch)
	} else if t.Row > 0 {
		t.Row--
		t.Col = len(t.lines[t.Row])
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of line"
	}
	
	if t.localizer != nil {
		return t.localizer.T("beginning of text")
	}
	return "beginning of text"
}

// MoveRight moves the cursor right
func (t *TextArea) MoveRight() string {
	line := t.getCurrentLine()
	if t.Col < len(line) {
		t.Col++
		if t.Col < len(line) {
			ch := rune(line[t.Col])
			return t.announceChar(ch)
		}
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of line"
	} else if t.Row < len(t.lines)-1 {
		t.Row++
		t.Col = 0
		line = t.getCurrentLine()
		if line == "" {
			if t.localizer != nil {
				return t.localizer.T("blank")
			}
			return "blank"
		}
		ch := rune(line[0])
		return t.announceChar(ch)
	}
	
	if t.localizer != nil {
		return t.localizer.T("end of text")
	}
	return "end of text"
}

// MoveUp moves the cursor up one line
func (t *TextArea) MoveUp() string {
	if t.Row > 0 {
		t.Row--
		// Adjust column if new line is shorter
		if t.Col > len(t.lines[t.Row]) {
			t.Col = len(t.lines[t.Row])
		}
		return t.getCurrentLine()
	}
	
	if t.localizer != nil {
		return t.localizer.T("top of list")
	}
	return "Top of text"
}

// MoveDown moves the cursor down one line
func (t *TextArea) MoveDown() string {
	if t.Row < len(t.lines)-1 {
		t.Row++
		// Adjust column if new line is shorter
		if t.Col > len(t.lines[t.Row]) {
			t.Col = len(t.lines[t.Row])
		}
		return t.getCurrentLine()
	}
	
	if t.localizer != nil {
		return t.localizer.T("bottom of list")
	}
	return "Bottom of text"
}

// MoveToLineStart moves the cursor to the start of the current line
func (t *TextArea) MoveToLineStart() string {
	t.Col = 0
	line := t.getCurrentLine()
	if line == "" {
		if t.localizer != nil {
			return t.localizer.T("blank")
		}
		return "blank"
	}
	ch := rune(line[0])
	return t.announceChar(ch)
}

// MoveToLineEnd moves the cursor to the end of the current line
func (t *TextArea) MoveToLineEnd() string {
	t.Col = len(t.lines[t.Row])
	if t.localizer != nil {
		return t.localizer.T("end of text")
	}
	return "end of line"
}

// DeleteCharBefore deletes the character before the cursor
func (t *TextArea) DeleteCharBefore() string {
	if t.Col > 0 {
		line := []rune(t.lines[t.Row])
		deletedChar := line[t.Col-1]
		line = append(line[:t.Col-1], line[t.Col:]...)
		t.lines[t.Row] = string(line)
		t.Col--
		t.syncFromLines()
		
		if t.OnChange != nil {
			return t.OnChange(t.Text)
		}
		
		return t.announceChar(deletedChar)
	} else if t.Row > 0 {
		// Join with previous line
		prevLine := t.lines[t.Row-1]
		currentLine := t.lines[t.Row]
		t.lines[t.Row-1] = prevLine + currentLine
		t.lines = append(t.lines[:t.Row], t.lines[t.Row+1:]...)
		t.Col = len(prevLine)
		t.Row--
		t.syncFromLines()
		
		if t.OnChange != nil {
			return t.OnChange(t.Text)
		}
		
		return "line joined"
	}
	
	if t.localizer != nil {
		return t.localizer.T("beginning of text")
	}
	return "beginning of text"
}

// DeleteCharAfter deletes the character after the cursor
func (t *TextArea) DeleteCharAfter() string {
	line := t.getCurrentLine()
	if t.Col < len(line) {
		lineRunes := []rune(line)
		deletedChar := lineRunes[t.Col]
		lineRunes = append(lineRunes[:t.Col], lineRunes[t.Col+1:]...)
		t.lines[t.Row] = string(lineRunes)
		t.syncFromLines()
		
		if t.OnChange != nil {
			return t.OnChange(t.Text)
		}
		
		return t.announceChar(deletedChar)
	} else if t.Row < len(t.lines)-1 {
		// Join with next line
		currentLine := t.lines[t.Row]
		nextLine := t.lines[t.Row+1]
		t.lines[t.Row] = currentLine + nextLine
		t.lines = append(t.lines[:t.Row+1], t.lines[t.Row+2:]...)
		t.syncFromLines()
		
		if t.OnChange != nil {
			return t.OnChange(t.Text)
		}
		
		return "line joined"
	}
	
	if t.localizer != nil {
		return t.localizer.T("end of text")
	}
	return "end of text"
}

// MoveToPreviousWord moves the cursor to the start of the previous word
func (t *TextArea) MoveToPreviousWord() string {
	line := t.getCurrentLine()
	
	// If at beginning of line, move to previous line
	if t.Col == 0 && t.Row > 0 {
		t.Row--
		t.Col = len(t.lines[t.Row])
		line = t.getCurrentLine()
	}
	
	// Skip whitespace backwards
	for t.Col > 0 && unicode.IsSpace(rune(line[t.Col-1])) {
		t.Col--
	}
	
	// Skip word characters backwards
	for t.Col > 0 && !unicode.IsSpace(rune(line[t.Col-1])) {
		t.Col--
	}
	
	// Get the word at the cursor
	return t.getCurrentWord()
}

// MoveToNextWord moves the cursor to the start of the next word
func (t *TextArea) MoveToNextWord() string {
	line := t.getCurrentLine()
	
	// Skip current word
	for t.Col < len(line) && !unicode.IsSpace(rune(line[t.Col])) {
		t.Col++
	}
	
	// Skip whitespace
	for t.Col < len(line) && unicode.IsSpace(rune(line[t.Col])) {
		t.Col++
	}
	
	// If at end of line, move to next line
	if t.Col >= len(line) && t.Row < len(t.lines)-1 {
		t.Row++
		t.Col = 0
		line = t.getCurrentLine()
	}
	
	if t.Col >= len(line) {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of text"
	}
	
	// Get the word at the cursor
	return t.getCurrentWord()
}

// getCurrentWord returns the word at the current cursor position
func (t *TextArea) getCurrentWord() string {
	line := t.getCurrentLine()
	if t.Col >= len(line) {
		if t.localizer != nil {
			return t.localizer.T("end of text")
		}
		return "end of line"
	}
	
	start := t.Col
	end := t.Col
	
	// Find word start
	for start > 0 && !unicode.IsSpace(rune(line[start-1])) {
		start--
	}
	
	// Find word end
	for end < len(line) && !unicode.IsSpace(rune(line[end])) {
		end++
	}
	
	word := line[start:end]
	if word == "" {
		if t.localizer != nil {
			return t.localizer.T("blank")
		}
		return "blank"
	}
	
	return word
}
