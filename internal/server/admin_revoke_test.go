package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func revokeRequest(t *testing.T, secret, name, remoteAddr string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodDelete, "/_admin/tokens/"+name, nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	r.RemoteAddr = remoteAddr
	return r
}

func TestAdminRevoke_DeletesTokenAndFiresCallbacks(t *testing.T) {
	const secret = "topsecret"
	store := newMemTokenStore()
	if err := store.Add(context.Background(), "alice", "tok-1", 0); err != nil {
		t.Fatal(err)
	}
	revokes := NewRevokeRegistry()
	var fired atomic.Int32
	revokes.Register("alice", func() { fired.Add(1) })

	iss := NewAdminSecretIssuer(secret, store, time.Hour, zap.NewNop())
	iss.SetRevokes(revokes)

	w := httptest.NewRecorder()
	iss.ServeHTTP(w, revokeRequest(t, secret, "alice", "127.0.0.1:1234"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Name    string
		Deleted bool
		Killed  int
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Name != "alice" || !body.Deleted || body.Killed != 1 {
		t.Errorf("body = %+v", body)
	}
	if fired.Load() != 1 {
		t.Errorf("callback fired %d times, want 1", fired.Load())
	}
	if ok, _ := store.Validate(context.Background(), "tok-1"); ok {
		t.Error("token survived revoke")
	}
}

func TestAdminRevoke_UnknownNameReturns404(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())
	iss.SetRevokes(NewRevokeRegistry())

	w := httptest.NewRecorder()
	iss.ServeHTTP(w, revokeRequest(t, secret, "ghost", "127.0.0.1:1234"))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAdminRevoke_BadAuthRejected(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())
	iss.SetRevokes(NewRevokeRegistry())

	w := httptest.NewRecorder()
	iss.ServeHTTP(w, revokeRequest(t, "wrong-secret", "alice", "127.0.0.1:1234"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminRevoke_NonLoopbackForbidden(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())
	iss.SetRevokes(NewRevokeRegistry())

	w := httptest.NewRecorder()
	iss.ServeHTTP(w, revokeRequest(t, secret, "alice", "8.8.8.8:1234"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAdminRevoke_RejectsSlashInName(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())
	iss.SetRevokes(NewRevokeRegistry())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/_admin/tokens/alice/extra", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	r.RemoteAddr = "127.0.0.1:1234"
	iss.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for nested path; body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

func TestAdminRevoke_OnlyDeletedNoCallbacksReturns200(t *testing.T) {
	const secret = "topsecret"
	store := newMemTokenStore()
	if err := store.Add(context.Background(), "alice", "tok-1", 0); err != nil {
		t.Fatal(err)
	}
	iss := NewAdminSecretIssuer(secret, store, time.Hour, zap.NewNop())
	iss.SetRevokes(NewRevokeRegistry())

	w := httptest.NewRecorder()
	iss.ServeHTTP(w, revokeRequest(t, secret, "alice", "127.0.0.1:1234"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Deleted bool
		Killed  int
	}
	_ = json.NewDecoder(w.Body).Decode(&body)
	if !body.Deleted || body.Killed != 0 {
		t.Errorf("body = %+v", body)
	}
}
