package store

import (
	"context"
	"testing"
)

func openTestStore(t *testing.T) *BadgerStore {
	t.Helper()
	bs, err := OpenBadger(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("open badger: %v", err)
	}
	t.Cleanup(func() { _ = bs.Close() })
	return bs
}

func TestOwnerOf_Hit(t *testing.T) {
	bs := openTestStore(t)
	ctx := context.Background()
	if err := bs.Add(ctx, "alice", "tok-1", 0); err != nil {
		t.Fatal(err)
	}
	name, ok, err := bs.OwnerOf(ctx, "tok-1")
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if !ok || name != "alice" {
		t.Errorf("got name=%q ok=%v, want alice/true", name, ok)
	}
}

func TestOwnerOf_Miss(t *testing.T) {
	bs := openTestStore(t)
	name, ok, err := bs.OwnerOf(context.Background(), "no-such-token")
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if ok || name != "" {
		t.Errorf("got name=%q ok=%v, want empty/false", name, ok)
	}
}

func TestDelete_RemovesAllTokensForName(t *testing.T) {
	bs := openTestStore(t)
	ctx := context.Background()
	for _, tok := range []string{"tok-a", "tok-b", "tok-c"} {
		if err := bs.Add(ctx, "alice", tok, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.Add(ctx, "bob", "tok-bob", 0); err != nil {
		t.Fatal(err)
	}

	deleted, err := bs.Delete(ctx, "alice")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	for _, tok := range []string{"tok-a", "tok-b", "tok-c"} {
		ok, _ := bs.Validate(ctx, tok)
		if ok {
			t.Errorf("alice token %q should be gone", tok)
		}
	}

	ok, _ := bs.Validate(ctx, "tok-bob")
	if !ok {
		t.Error("bob's token should survive")
	}
}

func TestDelete_UnknownNameReturnsFalse(t *testing.T) {
	bs := openTestStore(t)
	deleted, err := bs.Delete(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if deleted {
		t.Error("expected deleted=false for unknown name")
	}
}

func TestDelete_OwnerOfReturnsFalseAfterDelete(t *testing.T) {
	bs := openTestStore(t)
	ctx := context.Background()
	if err := bs.Add(ctx, "alice", "tok-x", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.Delete(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	_, ok, err := bs.OwnerOf(ctx, "tok-x")
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if ok {
		t.Error("OwnerOf should return ok=false after Delete")
	}
}
