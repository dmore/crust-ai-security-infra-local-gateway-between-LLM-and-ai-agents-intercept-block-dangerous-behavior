package mcpgateway

import (
	"sync"
	"time"
)

// maxSessionIDLen is the maximum allowed length for an MCP session ID.
const maxSessionIDLen = 256

// SessionStore tracks active MCP sessions by their session IDs.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]time.Time
}

// NewSessionStore creates a new empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]time.Time),
	}
}

// Track records a session ID. If the ID exceeds maxSessionIDLen, it is ignored.
func (s *SessionStore) Track(id string) {
	if id == "" || len(id) > maxSessionIDLen {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = time.Now()
}

// Remove deletes a session ID from the store.
func (s *SessionStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// Exists reports whether a session ID is tracked.
func (s *SessionStore) Exists(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sessions[id]
	return ok
}
