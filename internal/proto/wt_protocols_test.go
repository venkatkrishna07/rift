package proto

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestControlMsgAllowedWTProtocolsRoundTrip pins the invariant that nil and
// empty AllowedWTProtocols are JSON-indistinguishable on the wire and both
// mean "accept any protocol" downstream. If a future change tries to add
// distinct semantics for the two, this test fires.
func TestControlMsgAllowedWTProtocolsRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := ControlMsg{Type: TypeRegister, AllowedWTProtocols: tc.in}
			b, err := json.Marshal(&m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			// omitempty must drop the field for both nil and empty.
			if got := string(b); got != `{"type":"register"}` {
				t.Errorf("wire payload mismatch: %s", got)
			}
			var out ControlMsg
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if out.AllowedWTProtocols != nil {
				t.Errorf("expected nil after round-trip, got %v", out.AllowedWTProtocols)
			}
		})
	}

	// Non-empty round-trip preserves order.
	in := []string{"rift.demo.v1", "rift.echo.v1"}
	m := ControlMsg{Type: TypeRegister, AllowedWTProtocols: in}
	b, _ := json.Marshal(&m)
	var out ControlMsg
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out.AllowedWTProtocols) {
		t.Errorf("non-empty round-trip mismatch: in=%v out=%v", in, out.AllowedWTProtocols)
	}
}
