package vpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// Independent Python cryptography fixtures maintained by the parent integration
// tests. The test fails if those fixtures are missing, not silently skipped.
func TestIndependentPythonVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PSK     string `json:"psk_hex"`
		Vectors []struct {
			Direction Direction `json:"direction"`
			Kind      Kind      `json:"kind"`
			Session   string    `json:"session_id_hex"`
			Sequence  uint64    `json:"sequence"`
			Plaintext string    `json:"plaintext_hex"`
			Key       string    `json:"key_hex"`
			Frame     string    `json:"frame_hex"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("empty vectors")
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	psk := unhex(fixture.PSK)
	for i, v := range fixture.Vectors {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			sid, err := strconv.ParseUint(v.Session, 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			m := Message{sid, v.Sequence, v.Kind, unhex(v.Plaintext)}
			got, err := Seal(psk, v.Direction, m)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, unhex(v.Frame)) {
				t.Fatalf("wire mismatch got=%x want=%s", got, v.Frame)
			}
			opened, err := Open(psk, v.Direction, unhex(v.Frame))
			if err != nil || opened.SessionID != sid || opened.Sequence != v.Sequence || opened.Kind != v.Kind || !bytes.Equal(opened.Payload, m.Payload) {
				t.Fatalf("open %+v %v", opened, err)
			}
			mac := hmac.New(sha256.New, psk)
			mac.Write([]byte("icmp-vpn-v1/"))
			mac.Write([]byte{byte(v.Direction)})
			var id [8]byte
			binary.BigEndian.PutUint64(id[:], sid)
			mac.Write(id[:])
			if !bytes.Equal(mac.Sum(nil), unhex(v.Key)) {
				t.Fatal("derived key mismatch")
			}
		})
	}
}
