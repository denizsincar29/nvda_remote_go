package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

const todosFile = "todos.json"

type Todo struct {
	Text      string `json:"text"`
	Completed bool   `json:"completed"`
}

type TodoList struct {
	Todos []Todo `json:"todos"`
}

func main() {
	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	e := goerror.NewError(logger)

	// Load configuration
	config := exampleconfig.Load()

	// Connect to NVDA remote server
	logger.Info("Connecting to NVDA remote server", "host", config.Host, "port", config.Port)
	remote, err := nvda_remote_go.NewClient(config.Host, config.Port, config.Key, "slave", logger)
	e.Must(err, "Failed to create NVDA remote client")
	defer remote.Close()

	logger.Info("Connected to NVDA remote server")

	// Load todos from file
	todoList := loadTodos(logger)

	// Create GUI
	gui := vgui.NewGUI()

	// Add title
	gui.AddElement(vgui.NewLabel("Todo List Manager"))

	// Create listbox with todos
	todoItems := getTodoStrings(todoList)
	listbox := vgui.NewListBox("Todos", todoItems)
	gui.AddElement(listbox)

	// Helper function to refresh listbox
	refreshList := func() {
		todoItems = getTodoStrings(todoList)
		listbox.Items = todoItems
		if listbox.SelectedIndex >= len(todoItems) {
			listbox.SelectedIndex = len(todoItems) - 1
		}
		if listbox.SelectedIndex < 0 && len(todoItems) > 0 {
			listbox.SelectedIndex = 0
		}
	}

	// Add New button
	addBtn := vgui.NewButton("Add New Todo")
	addBtn.OnClick = func() string {
		// In a real app, this would show a dialog with a textbox
		// For now, we'll add a placeholder
		newTodo := Todo{
			Text:      "New Todo (edit in todos.json)",
			Completed: false,
		}
		todoList.Todos = append(todoList.Todos, newTodo)
		refreshList()
		saveTodos(todoList, logger)
		return fmt.Sprintf("Added new todo. Total: %d", len(todoList.Todos))
	}
	gui.AddElement(addBtn)

	// Toggle Complete button
	toggleBtn := vgui.NewButton("Toggle Complete")
	toggleBtn.OnClick = func() string {
		if len(todoList.Todos) == 0 {
			return "No todos to toggle"
		}
		idx := listbox.SelectedIndex
		if idx >= 0 && idx < len(todoList.Todos) {
			todoList.Todos[idx].Completed = !todoList.Todos[idx].Completed
			refreshList()
			saveTodos(todoList, logger)
			status := "incomplete"
			if todoList.Todos[idx].Completed {
				status = "completed"
			}
			return fmt.Sprintf("Todo marked as %s", status)
		}
		return "No todo selected"
	}
	gui.AddElement(toggleBtn)

	// Delete button
	deleteBtn := vgui.NewButton("Delete Todo")
	deleteBtn.OnClick = func() string {
		if len(todoList.Todos) == 0 {
			return "No todos to delete"
		}
		idx := listbox.SelectedIndex
		if idx >= 0 && idx < len(todoList.Todos) {
			deletedText := todoList.Todos[idx].Text
			todoList.Todos = append(todoList.Todos[:idx], todoList.Todos[idx+1:]...)
			refreshList()
			saveTodos(todoList, logger)
			return fmt.Sprintf("Deleted: %s", deletedText)
		}
		return "No todo selected"
	}
	gui.AddElement(deleteBtn)

	// Register hotkeys
	gui.RegisterHotkey("ctrl+n", func() string {
		return addBtn.OnActivate()
	})

	gui.RegisterHotkey("delete", func() string {
		// Show confirmation dialog
		return "Press the Delete button or confirm deletion"
	})

	// Space key toggles completion
	gui.RegisterHotkey("space", func() string {
		return toggleBtn.OnActivate()
	})

	// Create and start handler
	handler := vgui.NewHandler(remote, gui, logger)
	handler.Start()

	logger.Info("Todo List Manager is ready")
	logger.Info("Controls:")
	logger.Info("  - Tab: Navigate between elements")
	logger.Info("  - Up/Down: Navigate todos in list")
	logger.Info("  - Space: Toggle todo completion")
	logger.Info("  - Ctrl+N: Add new todo")
	logger.Info("  - Delete button: Delete selected todo")
	logger.Info("Press Ctrl+C to exit")

	// Keep running
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-remote.Errors():
			logger.Error("Error from NVDA remote client", "error", err)
			e.Must(err, "Fatal error from NVDA remote client")
		case <-ticker.C:
			// Keep alive
		}
	}
}

// loadTodos loads todos from JSON file
func loadTodos(logger *slog.Logger) *TodoList {
	data, err := os.ReadFile(todosFile)
	if err != nil {
		logger.Info("No existing todos file, creating new one")
		return &TodoList{Todos: []Todo{}}
	}

	var todoList TodoList
	err = json.Unmarshal(data, &todoList)
	if err != nil {
		logger.Error("Failed to parse todos file", "error", err)
		return &TodoList{Todos: []Todo{}}
	}

	logger.Info("Loaded todos", "count", len(todoList.Todos))
	return &todoList
}

// saveTodos saves todos to JSON file
func saveTodos(todoList *TodoList, logger *slog.Logger) {
	data, err := json.MarshalIndent(todoList, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal todos", "error", err)
		return
	}

	err = os.WriteFile(todosFile, data, 0644)
	if err != nil {
		logger.Error("Failed to save todos", "error", err)
		return
	}

	logger.Debug("Saved todos", "count", len(todoList.Todos))
}

// getTodoStrings converts todos to strings for the listbox
func getTodoStrings(todoList *TodoList) []string {
	if len(todoList.Todos) == 0 {
		return []string{"No todos yet"}
	}

	items := make([]string, len(todoList.Todos))
	for i, todo := range todoList.Todos {
		status := "[ ]"
		if todo.Completed {
			status = "[X]"
		}
		items[i] = fmt.Sprintf("%s %s", status, todo.Text)
	}
	return items
}
