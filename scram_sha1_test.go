package sasl_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SCRAM-SHA-1 test driver.
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"golang.org/x/crypto/pbkdf2"
)

// scramSha1Client mirrors scramClient (SHA-256) but pinned to
// SHA-1 — kept short because the SCRAM state machine itself is
// already exhaustively covered by the SHA-256 tests; this file
// only validates that the digest plumbing wires through to SHA-1
// without breaking the AuthMessage/ClientProof construction.
type scramSha1Client struct {
	username, password string
	clientNonce        string
	gs2Header          string
	cbData             []byte
}

func (c *scramSha1Client) clientFirst() string {
	return fmt.Sprintf("%sn=%s,r=%s", c.gs2Header, c.username, c.clientNonce)
}

func (c *scramSha1Client) clientFinal(t *testing.T, serverFirst string) string {
	t.Helper()
	var combinedNonce, saltB64 string
	var iter int
	for _, attr := range strings.Split(serverFirst, ",") {
		switch attr[0] {
		case 'r':
			combinedNonce = attr[2:]
		case 's':
			saltB64 = attr[2:]
		case 'i':
			fmt.Sscanf(attr[2:], "%d", &iter) //nolint:errcheck
		}
	}
	salt, _ := base64.StdEncoding.DecodeString(saltB64)

	cb := append([]byte(c.gs2Header), c.cbData...)
	cbB64 := base64.StdEncoding.EncodeToString(cb)
	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", cbB64, combinedNonce)
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", c.username, c.clientNonce)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	salted := pbkdf2.Key([]byte(c.password), salt, iter, sha1.Size, sha1.New)
	clientKey := hmacSumSha1Test(sha1.New, salted, []byte("Client Key"))
	storedKey := sha1SumTest(clientKey)
	clientSig := hmacSumSha1Test(sha1.New, storedKey, []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	return fmt.Sprintf("%s,p=%s", clientFinalWithoutProof,
		base64.StdEncoding.EncodeToString(proof))
}

func hmacSumSha1Test(newHash func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha1SumTest(data []byte) []byte {
	h := sha1.Sum(data) //nolint:gosec // SCRAM-SHA-1.
	return h[:]
}

func TestScramSha1_HappyPath(t *testing.T) {
	creds, err := sasl.GenerateScramSha1Credentials("hunter2", sasl.MinScramIterations)
	if err != nil {
		t.Fatal(err)
	}
	srv := sasl.NewScramSha1Server(func(user string) (*sasl.ScramCredentials, error) {
		if user == "alice" {
			return creds, nil
		}
		return nil, nil
	})
	client := &scramSha1Client{
		username: "alice", password: "hunter2",
		clientNonce: "rOprNGfwEbeRWgbNEkqO", gs2Header: "n,,",
	}
	chal, done, err := srv.Next([]byte(client.clientFirst()))
	if err != nil || done {
		t.Fatalf("client-first: done=%v err=%v", done, err)
	}
	clientFinal := client.clientFinal(t, string(chal))
	chal2, done, err := srv.Next([]byte(clientFinal))
	if err != nil || !done {
		t.Fatalf("client-final: done=%v err=%v", done, err)
	}
	if !strings.HasPrefix(string(chal2), "v=") {
		t.Errorf("server-final missing v=: %q", chal2)
	}
}

func TestScramSha1_WrongPasswordRejected(t *testing.T) {
	creds, _ := sasl.GenerateScramSha1Credentials("hunter2", sasl.MinScramIterations)
	srv := sasl.NewScramSha1Server(func(_ string) (*sasl.ScramCredentials, error) {
		return creds, nil
	})
	client := &scramSha1Client{
		username: "alice", password: "WRONG",
		clientNonce: "x", gs2Header: "n,,",
	}
	chal, _, _ := srv.Next([]byte(client.clientFirst()))
	clientFinal := client.clientFinal(t, string(chal))
	_, done, err := srv.Next([]byte(clientFinal))
	if !done || err == nil {
		t.Errorf("expected auth-failed: done=%v err=%v", done, err)
	}
}

// Verifier byte sizes differ between SHA-1 (20 B) and SHA-256
// (32 B); make sure the keygen path actually produces 20-byte
// StoredKey/ServerKey so a future refactor that hard-codes 32
// gets caught.
func TestScramSha1_VerifierByteSize(t *testing.T) {
	c, _ := sasl.GenerateScramSha1Credentials("hunter2", sasl.MinScramIterations)
	if len(c.StoredKey) != sha1.Size {
		t.Errorf("StoredKey size: got %d want %d", len(c.StoredKey), sha1.Size)
	}
	if len(c.ServerKey) != sha1.Size {
		t.Errorf("ServerKey size: got %d want %d", len(c.ServerKey), sha1.Size)
	}
}

func TestScramSha1_DeriveDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, 16)
	a := sasl.DeriveScramSha1Credentials("hunter2", salt, sasl.MinScramIterations)
	b := sasl.DeriveScramSha1Credentials("hunter2", salt, sasl.MinScramIterations)
	if !bytes.Equal(a.StoredKey, b.StoredKey) || !bytes.Equal(a.ServerKey, b.ServerKey) {
		t.Errorf("DeriveScramSha1Credentials not deterministic")
	}
}

func TestScramSha1Plus_HappyPath(t *testing.T) {
	creds, _ := sasl.GenerateScramSha1Credentials("hunter2", sasl.MinScramIterations)
	cbData := []byte("fake-tls-exporter-32-bytes-data!")
	srv := sasl.NewScramSha1PlusServer(
		func(_ string) (*sasl.ScramCredentials, error) { return creds, nil },
		sasl.ScramServerOptions{ChannelBindingData: cbData},
	)
	client := &scramSha1Client{
		username: "alice", password: "hunter2",
		clientNonce: "rOprNGfwEbeRWgbN",
		gs2Header:   "p=tls-exporter,,",
		cbData:      cbData,
	}
	chal, _, err := srv.Next([]byte(client.clientFirst()))
	if err != nil {
		t.Fatal(err)
	}
	clientFinal := client.clientFinal(t, string(chal))
	_, done, err := srv.Next([]byte(clientFinal))
	if err != nil || !done {
		t.Fatalf("PLUS happy: done=%v err=%v", done, err)
	}
}
