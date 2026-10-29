package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion — версия MCP, которую поддерживает сервер.
const ProtocolVersion = "2024-11-05"

// ServerName и ServerVersion попадают в ответ на initialize.
const (
	ServerName    = "nvda-remote-mcp"
	ServerVersion = "0.1.0"
)

// ToolHandler выполняет инструмент и возвращает текст для модели.
type ToolHandler func(args map[string]any) (string, error)

// Tool — описание инструмента MCP.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Handler     ToolHandler    `json:"-"`
}

// Server — минимальная реализация MCP поверх stdio (построчный JSON-RPC 2.0).
type Server struct {
	tools   map[string]Tool
	order   []string
	mu      sync.Mutex
	writeMu sync.Mutex
	out     io.Writer
}

// NewServer создаёт сервер с пустым набором инструментов.
func NewServer(out io.Writer) *Server {
	return &Server{tools: make(map[string]Tool), out: out}
}

// AddTool регистрирует инструмент.
func (s *Server) AddTool(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name]; !exists {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve читает запросы из in и пишет ответы в s.out до конца потока.
func (s *Server) Serve(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error: " + err.Error()}})
			continue
		}
		s.handle(req)
	}
	return scanner.Err()
}

func (s *Server) handle(req rpcRequest) {
	switch req.Method {
	case "initialize":
		s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": ServerName, "version": ServerVersion},
		}})

	case "notifications/initialized", "initialized":
		// уведомление — ответа не требуется

	case "ping":
		s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})

	case "tools/list":
		s.mu.Lock()
		tools := make([]map[string]any, 0, len(s.order))
		for _, name := range s.order {
			t := s.tools[name]
			schema := t.InputSchema
			if schema == nil {
				schema = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			tools = append(tools, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": schema,
			})
		}
		s.mu.Unlock()
		s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": tools}})

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "bad params: " + err.Error()}})
			return
		}
		s.mu.Lock()
		tool, ok := s.tools[params.Name]
		s.mu.Unlock()
		if !ok {
			s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "unknown tool: " + params.Name}})
			return
		}
		text, err := tool.Handler(params.Arguments)
		result := map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		}
		if err != nil {
			result["isError"] = true
			if text == "" {
				result["content"] = []map[string]any{{"type": "text", "text": err.Error()}}
			}
		}
		s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})

	default:
		if len(req.ID) > 0 {
			s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}})
		}
	}
}

func (s *Server) write(resp rpcResponse) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if _, err := s.out.Write(data); err != nil {
		fmt.Fprintf(io.Discard, "%v", err)
	}
}

// errMissing сообщает о пропущенном обязательном аргументе.
func errMissing(name string) error {
	return errors.New("не передан обязательный аргумент " + name)
}
