package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// publicEnginesCallbackURL builds the ingest URL the engine will POST to.
// Uses BASE_URL (same origin as tracking links).
func (s *Server) publicEnginesCallbackURL(engineID uuid.UUID) string {
	return strings.TrimRight(s.baseURL, "/") + "/api/v1/engines/" + engineID.String() + "/events"
}