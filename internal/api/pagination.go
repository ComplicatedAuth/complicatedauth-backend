package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

type pageCursor struct {
	CreatedAt time.Time `json:"created_at"`
	UID       string    `json:"uid"`
}

func pagination(r *http.Request) (int, *pageCursor, error) {
	limit := 25
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, nil, errors.New("limit must be between 1 and 100")
		}
		limit = parsed
	}
	value := r.URL.Query().Get("cursor")
	if value == "" {
		return limit, nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, nil, errors.New("cursor is invalid")
	}
	var cursor pageCursor
	if json.Unmarshal(raw, &cursor) != nil || cursor.UID == "" || cursor.CreatedAt.IsZero() {
		return 0, nil, errors.New("cursor is invalid")
	}
	return limit, &cursor, nil
}

func nextCursor(createdAt time.Time, uid string) string {
	raw, _ := json.Marshal(pageCursor{CreatedAt: createdAt, UID: uid})
	return base64.RawURLEncoding.EncodeToString(raw)
}
