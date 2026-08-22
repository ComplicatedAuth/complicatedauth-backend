package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
)

func (s *Server) beginIdempotentRequest(w http.ResponseWriter, r *http.Request, request store.IdempotencyRequest) (store.IdempotencyClaim, bool) {
	claim, err := s.idempotency.Begin(r.Context(), request)
	if errors.Is(err, store.ErrIdempotencyConflict) {
		fail(w, r, http.StatusConflict, "idempotency_key_reused", "the idempotency key was already used with different inputs")
		return store.IdempotencyClaim{}, false
	}
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "dependency_unavailable", "idempotency coordination is unavailable")
		return store.IdempotencyClaim{}, false
	}
	if claim.Replay != nil {
		writeStoredResponse(w, *claim.Replay)
		return store.IdempotencyClaim{}, false
	}
	if claim.LeaseUID == uuid.Nil {
		seconds := int64(claim.RetryAfter / time.Second)
		if claim.RetryAfter%time.Second != 0 {
			seconds++
		}
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		fail(w, r, http.StatusConflict, "idempotency_in_progress", "an identical request is still being processed")
		return store.IdempotencyClaim{}, false
	}
	return claim, true
}
