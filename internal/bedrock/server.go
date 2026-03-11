package bedrock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const serverShutdownTimeout = 5 * time.Second

var localhostListen = func(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// Server exposes a local OpenAI-compatible HTTP adapter for AWS Bedrock.
type Server struct {
	Provider   *Provider
	listener   net.Listener
	httpServer *http.Server
	port       int
}

// Start launches the local adapter on a random localhost port.
func (s *Server) Start(ctx context.Context) error {
	if s.Provider == nil {
		return fmt.Errorf("bedrock server requires a provider")
	}
	if s.listener != nil {
		return nil
	}

	listener, err := localhostListen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for bedrock adapter: %w", err)
	}

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("bedrock adapter listener is not TCP")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)

	s.listener = listener
	s.port = addr.Port
	s.httpServer = &http.Server{
		BaseContext: func(net.Listener) context.Context {
			if ctx == nil {
				return context.Background()
			}
			return ctx
		},
		Handler: mux,
	}

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = listener.Close()
		}
	}()

	return nil
}

// Stop gracefully shuts down the local adapter.
func (s *Server) Stop() {
	if s.httpServer == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancel()

	_ = s.httpServer.Shutdown(shutdownCtx)
	_ = s.listener.Close()

	s.httpServer = nil
	s.listener = nil
	s.port = 0
}

// Endpoint returns the local API base URL.
func (s *Server) Endpoint() string {
	if s.port == 0 {
		return ""
	}

	return fmt.Sprintf("http://127.0.0.1:%d/v1", s.port)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req chatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode request: %v", err), http.StatusBadRequest)
		return
	}

	if req.Model == "" {
		req.Model = s.Provider.ModelID
	}

	resp, err := s.Provider.completeChat(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("complete chat: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
	}
}
