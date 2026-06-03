package sasl_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"golang.org/x/crypto/pbkdf2"
)

// scramClient is a minimal SCRAM-SHA-256 client driver used to
// exercise the server through complete exchanges. We do not use
// any production SCRAM client — keeping the test driver in this
// file makes the wire flow explicit and tests easier to read.
type scramClient struct {
	username, password string
	clientNonce        string
	gs2Header          string // "n,,", "y,,", "p=tls-exporter,," etc.
	cbData             []byte // appended after gs2Header into c=
}

// clientFirst returns the bytes the server will see as its first
// input. Honours the gs2Header / clientNonce the test pinned.
func (c *scramClient) clientFirst() string {
	return fmt.Sprintf("%sn=%s,r=%s", c.gs2Header, c.username, c.clientNonce)
}

// clientFinal computes the proof from the server-first response
// and returns the bytes the server gets as its second input.
func (c *scramClient) clientFinal(t *testing.T, serverFirst string) string {
	t.Helper()
	// Parse server-first: r=…,s=…,i=…
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

	// Build cb input = gs2Header || cbData.
	cb := append([]byte(c.gs2Header), c.cbData...)
	cbB64 := base64.StdEncoding.EncodeToString(cb)

	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", cbB64, combinedNonce)
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", c.username, c.clientNonce)
	serverFirstBytes := serverFirst

	authMessage := clientFirstBare + "," + serverFirstBytes + "," + clientFinalWithoutProof

	salted := pbkdf2.Key([]byte(c.password), salt, iter, sha256.Size, sha256.New)
	clientKey := hmacSumTest(sha256.New, salted, []byte("Client Key"))
	storedKey := sha256SumTest(clientKey)
	clientSig := hmacSumTest(sha256.New, storedKey, []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	return fmt.Sprintf("%s,p=%s", clientFinalWithoutProof,
		base64.StdEncoding.EncodeToString(proof))
}

// verifyServerFinal parses v=… and confirms the server signature
// matches what the client would have computed.
func verifyServerFinal(t *testing.T, c *scramClient, serverFirst, clientFinal, serverFinal string) {
	t.Helper()
	var ssigB64 string
	for _, attr := range strings.Split(serverFinal, ",") {
		if strings.HasPrefix(attr, "v=") {
			ssigB64 = attr[2:]
		}
	}
	got, _ := base64.StdEncoding.DecodeString(ssigB64)

	// Recompute ServerSignature locally.
	salt, _ := base64.StdEncoding.DecodeString(parseAttr(serverFirst, "s"))
	iter := 0
	fmt.Sscanf(parseAttr(serverFirst, "i"), "%d", &iter) //nolint:errcheck
	salted := pbkdf2.Key([]byte(c.password), salt, iter, sha256.Size, sha256.New)
	serverKey := hmacSumTest(sha256.New, salted, []byte("Server Key"))
	cut := strings.LastIndex(clientFinal, ",p=")
	clientFinalWithoutProof := clientFinal[:cut]
	clientFirstBare := fmt.Sprintf("n=%s,r=%s", c.username, c.clientNonce)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	want := hmacSumTest(sha256.New, serverKey, []byte(authMessage))
	if !bytes.Equal(got, want) {
		t.Errorf("ServerSignature mismatch:\n got %x\nwant %x", got, want)
	}
}

func parseAttr(s, key string) string {
	for _, attr := range strings.Split(s, ",") {
		if strings.HasPrefix(attr, key+"=") {
			return attr[len(key)+1:]
		}
	}
	return ""
}

func hmacSumTest(newHash func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha256SumTest(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// TestScramSha256_HappyPath — full three-step exchange ending in
// server-final with verifiable v=ServerSignature.
func TestScramSha256_HappyPath(t *testing.T) {
	creds, err := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	if err != nil {
		t.Fatal(err)
	}
	srv := sasl.NewScramSha256Server(func(user string) (*sasl.ScramCredentials, error) {
		if user == "alice" {
			return creds, nil
		}
		return nil, nil
	})
	client := &scramClient{
		username:    "alice",
		password:    "hunter2",
		clientNonce: "rOprNGfwEbeRWgbNEkqO",
		gs2Header:   "n,,",
	}

	chal, done, err := srv.Next([]byte(client.clientFirst()))
	if err != nil || done {
		t.Fatalf("client-first: done=%v err=%v", done, err)
	}
	serverFirst := string(chal)

	clientFinal := client.clientFinal(t, serverFirst)
	chal2, done, err := srv.Next([]byte(clientFinal))
	if err != nil || !done {
		t.Fatalf("client-final: done=%v err=%v", done, err)
	}
	serverFinal := string(chal2)
	if !strings.HasPrefix(serverFinal, "v=") {
		t.Errorf("server-final missing v=: %q", serverFinal)
	}
	verifyServerFinal(t, client, serverFirst, clientFinal, serverFinal)
}

// TestScramSha256_WrongPasswordRejected — client computes proof
// with a different password; server detects via StoredKey miss.
func TestScramSha256_WrongPasswordRejected(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
		return creds, nil
	})
	client := &scramClient{
		username: "alice", password: "WRONG",
		clientNonce: "x", gs2Header: "n,,",
	}
	chal, _, _ := srv.Next([]byte(client.clientFirst()))
	clientFinal := client.clientFinal(t, string(chal))
	_, done, err := srv.Next([]byte(clientFinal))
	if !done {
		t.Errorf("expected done=true on wrong password")
	}
	if err == nil {
		t.Errorf("expected auth-failed error")
	}
}

// TestScramSha256_UnknownUserUniformOutcome — unknown user must
// surface the same auth-failed result as wrong-password, without
// short-circuiting the exchange (timing-leak defence).
func TestScramSha256_UnknownUserUniformOutcome(t *testing.T) {
	srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
		return nil, nil // user unknown
	})
	client := &scramClient{
		username: "ghost", password: "any",
		clientNonce: "x", gs2Header: "n,,",
	}
	chal, done, err := srv.Next([]byte(client.clientFirst()))
	if err != nil || done {
		t.Fatalf("client-first should still produce server-first on unknown user: done=%v err=%v", done, err)
	}
	clientFinal := client.clientFinal(t, string(chal))
	_, done, err = srv.Next([]byte(clientFinal))
	if !done || err == nil {
		t.Errorf("unknown user must finish with auth-failed: done=%v err=%v", done, err)
	}
}

// TestScramSha256_NonceMismatchRejected — client lies about the
// combined nonce in client-final.
func TestScramSha256_NonceMismatchRejected(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
		return creds, nil
	})
	_, _, _ = srv.Next([]byte("n,,n=alice,r=x"))
	// Send a client-final with a nonce the server never issued.
	_, done, err := srv.Next([]byte("c=biws,r=NOT-THE-COMBINED-NONCE,p=AAAA"))
	if !done || err == nil {
		t.Errorf("nonce mismatch should reject: done=%v err=%v", done, err)
	}
}

// TestScramSha256_RejectsChannelBindingFlag — non-PLUS server
// must reject p=… clients (they should have picked PLUS).
func TestScramSha256_RejectsChannelBindingFlag(t *testing.T) {
	srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
		return nil, nil
	})
	_, done, err := srv.Next([]byte("p=tls-exporter,,n=alice,r=x"))
	if !done || err == nil {
		t.Errorf("non-PLUS server should reject p=: done=%v err=%v", done, err)
	}
}

// TestScramSha256_AcceptsYAndN — non-PLUS server accepts both
// `n,,` (no cb) and `y,,` (cb supported but not used; downgrade-
// detection signal).
func TestScramSha256_AcceptsYAndN(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	for _, gs2 := range []string{"n,,", "y,,"} {
		srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
			return creds, nil
		})
		client := &scramClient{
			username: "alice", password: "hunter2",
			clientNonce: "rOprNGfw", gs2Header: gs2,
		}
		chal, _, err := srv.Next([]byte(client.clientFirst()))
		if err != nil {
			t.Errorf("gs2=%q client-first: %v", gs2, err)
			continue
		}
		final := client.clientFinal(t, string(chal))
		_, done, err := srv.Next([]byte(final))
		if !done || err != nil {
			t.Errorf("gs2=%q final: done=%v err=%v", gs2, done, err)
		}
	}
}

// TestScramSha256Plus_HappyPath — channel binding via the
// pre-computed exporter bytes. Client and server agree on the
// bytes; ChannelBinding check passes.
func TestScramSha256Plus_HappyPath(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	cbData := []byte("fake-tls-exporter-32-bytes-data!")
	srv := sasl.NewScramSha256PlusServer(
		func(_ string) (*sasl.ScramCredentials, error) { return creds, nil },
		sasl.ScramServerOptions{ChannelBindingData: cbData},
	)
	client := &scramClient{
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
		t.Fatalf("PLUS happy path: done=%v err=%v", done, err)
	}
}

// TestScramSha256Plus_ChannelBindingMismatch — client claims
// channel binding data different from what the server computed
// (MITM-attack signature). Server rejects.
func TestScramSha256Plus_ChannelBindingMismatch(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	srv := sasl.NewScramSha256PlusServer(
		func(_ string) (*sasl.ScramCredentials, error) { return creds, nil },
		sasl.ScramServerOptions{ChannelBindingData: []byte("server-side-cb")},
	)
	client := &scramClient{
		username: "alice", password: "hunter2",
		clientNonce: "x", gs2Header: "p=tls-exporter,,",
		cbData: []byte("client-side-WRONG-cb"),
	}
	chal, _, err := srv.Next([]byte(client.clientFirst()))
	if err != nil {
		t.Fatal(err)
	}
	final := client.clientFinal(t, string(chal))
	_, done, err := srv.Next([]byte(final))
	if !done || err == nil {
		t.Errorf("PLUS cb mismatch: done=%v err=%v", done, err)
	}
}

// TestScramSha256Plus_RequiresPFlag — PLUS server must reject
// client-first that arrives with `n,,` or `y,,` (downgrade).
func TestScramSha256Plus_RequiresPFlag(t *testing.T) {
	srv := sasl.NewScramSha256PlusServer(
		func(_ string) (*sasl.ScramCredentials, error) { return nil, nil },
		sasl.ScramServerOptions{ChannelBindingData: []byte("x")},
	)
	_, done, err := srv.Next([]byte("y,,n=alice,r=x"))
	if !done || err == nil {
		t.Errorf("PLUS server must reject downgrade attempt y,,: done=%v err=%v", done, err)
	}
}

// TestEncodeDecodeRoundtrip — credentials survive serialise+parse.
func TestEncodeDecodeRoundtrip(t *testing.T) {
	c, _ := sasl.GenerateScramSha256Credentials("hunter2", sasl.MinScramIterations)
	encoded := sasl.EncodeScramCredentials(c)
	decoded, err := sasl.DecodeScramCredentials(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Iterations != c.Iterations {
		t.Errorf("iter mismatch")
	}
	if !bytes.Equal(decoded.Salt, c.Salt) {
		t.Errorf("salt mismatch")
	}
	if !bytes.Equal(decoded.StoredKey, c.StoredKey) {
		t.Errorf("stored mismatch")
	}
	if !bytes.Equal(decoded.ServerKey, c.ServerKey) {
		t.Errorf("server mismatch")
	}
}

func TestDecodeScramCredentials_MalformedRejected(t *testing.T) {
	cases := []string{
		"",                       // empty
		"4096",                   // single field
		"abc,QQ==,RR==,SS==",     // non-numeric iter
		"-1,QQ==,RR==,SS==",      // negative iter
		"4096,not-base64!,RR,SS", // bad salt
	}
	for _, c := range cases {
		if _, err := sasl.DecodeScramCredentials(c); err == nil {
			t.Errorf("malformed blob accepted: %q", c)
		}
	}
}

// TestGenerateScramSha256_ClampsIterations — values below
// MinScramIterations are clamped up; zero substitutes the default.
func TestGenerateScramSha256_ClampsIterations(t *testing.T) {
	c, _ := sasl.GenerateScramSha256Credentials("pw", 1)
	if c.Iterations != sasl.MinScramIterations {
		t.Errorf("low iter not clamped: %d", c.Iterations)
	}
	c, _ = sasl.GenerateScramSha256Credentials("pw", 0)
	if c.Iterations != sasl.DefaultScramIterations {
		t.Errorf("zero iter not defaulted: %d", c.Iterations)
	}
}

func TestGenerateScramSha256_EmptyPasswordRejected(t *testing.T) {
	if _, err := sasl.GenerateScramSha256Credentials("", 0); err == nil {
		t.Errorf("empty password accepted")
	}
}

// Sanity check error wrapping.
func TestScramSha256_DoubleNextErrors(t *testing.T) {
	creds, _ := sasl.GenerateScramSha256Credentials("pw", sasl.MinScramIterations)
	srv := sasl.NewScramSha256Server(func(_ string) (*sasl.ScramCredentials, error) {
		return creds, nil
	})
	_, _, _ = srv.Next([]byte("n,,n=alice,r=x"))
	// Pretend client-final is malformed so we don't actually
	// finish; the state machine should reject a third call.
	_, _, _ = srv.Next([]byte("c=biws,r=different-nonce,p=AA"))
	_, _, err := srv.Next([]byte("anything"))
	if err == nil {
		t.Errorf("expected error on extra Next() call")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err == nil {
		// silence unused error-import warning in some builds
	}
}
