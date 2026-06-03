package sasl

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SCRAM-SHA-1 is a SASL wire mechanism, not a password hash; the HMAC construction is not broken by SHA-1 collision attacks.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// SCRAM mechanism names per RFC 5802 + RFC 7677.
const (
	ScramSha1       = "SCRAM-SHA-1"        // RFC 5802
	ScramSha1Plus   = "SCRAM-SHA-1-PLUS"   // RFC 5802 §6 (channel binding)
	ScramSha256     = "SCRAM-SHA-256"      // RFC 7677
	ScramSha256Plus = "SCRAM-SHA-256-PLUS" // RFC 5802 §6 + RFC 7677 (channel binding)
)

// ScramCredentials are the per-user verifier the server stores
// (Dovecot-compatible {SCRAM-SHA-256} blob). The plain password is
// NEVER part of this struct — the entire point of SCRAM is that
// the server validates challenge-response without ever seeing it.
//
// Fields:
//   - Iterations:  PBKDF2 iteration count.
//   - Salt:        per-user random salt.
//   - StoredKey:   H(ClientKey) where ClientKey = HMAC(SaltedPassword, "Client Key").
//   - ServerKey:   HMAC(SaltedPassword, "Server Key").
//
// SaltedPassword = PBKDF2-HMAC(SHA-256, password, salt, iterations).
type ScramCredentials struct {
	Iterations int
	Salt       []byte
	StoredKey  []byte
	ServerKey  []byte
}

// ScramCredentialsLookup is the per-username verifier lookup. It
// is invoked once per SCRAM exchange — the username is extracted
// from the client-first message. Returning (nil, nil) signals
// "user unknown"; the server completes the exchange with fake
// credentials so a probe cannot distinguish "unknown user" from
// "wrong password" by timing (defence against user enumeration).
type ScramCredentialsLookup func(username string) (*ScramCredentials, error)

// ScramServerOptions tunes a SCRAM server. ChannelBindingData is
// required for SCRAM-SHA-256-PLUS — supply the TLS exporter
// output (RFC 9266) computed from the underlying TLS conn. For
// SCRAM-SHA-256 (without channel binding) leave it nil.
type ScramServerOptions struct {
	// ChannelBindingData is the cb-data the client is expected to
	// include in the c= field of its client-final message,
	// concatenated with the GS2 header. For SCRAM-SHA-256-PLUS
	// the value is the TLS exporter output. Leave nil for the
	// non-PLUS mechanism.
	ChannelBindingData []byte
}

// NewScramSha256Server builds a SCRAM-SHA-256 server (no channel
// binding). The auth callback is invoked once per exchange with
// the username extracted from client-first; it must return the
// stored credentials or (nil, nil) for unknown user.
func NewScramSha256Server(auth ScramCredentialsLookup) Server {
	return newScramServer(scramConfig{
		mech:    ScramSha256,
		newHash: sha256.New,
		auth:    auth,
		plus:    false,
	})
}

// NewScramSha256PlusServer builds the channel-bound variant. The
// caller MUST supply the TLS exporter bytes; on a non-TLS conn
// (or TLS 1.2) the caller should not advertise SCRAM-SHA-256-PLUS
// in the first place — the mechanism only makes sense over TLS
// 1.3+ with the RFC 9266 exporter available.
func NewScramSha256PlusServer(auth ScramCredentialsLookup, opts ScramServerOptions) Server {
	return newScramServer(scramConfig{
		mech:       ScramSha256Plus,
		newHash:    sha256.New,
		auth:       auth,
		plus:       true,
		cbExpected: opts.ChannelBindingData,
	})
}

// NewScramSha1Server builds a SCRAM-SHA-1 server (no channel
// binding). Kept for compatibility with older clients (legacy
// Thunderbird, Apple Mail fallback); new deployments should
// prefer SCRAM-SHA-256.
func NewScramSha1Server(auth ScramCredentialsLookup) Server {
	return newScramServer(scramConfig{
		mech:    ScramSha1,
		newHash: sha1.New,
		auth:    auth,
		plus:    false,
	})
}

// NewScramSha1PlusServer is the channel-bound SHA-1 variant. The
// same TLS-1.3+ exporter requirement applies as for the SHA-256
// PLUS mechanism.
func NewScramSha1PlusServer(auth ScramCredentialsLookup, opts ScramServerOptions) Server {
	return newScramServer(scramConfig{
		mech:       ScramSha1Plus,
		newHash:    sha1.New,
		auth:       auth,
		plus:       true,
		cbExpected: opts.ChannelBindingData,
	})
}

// scramConfig is the internal construction shape shared between
// the two public factories. Kept small so the state machine
// (scramServer) does not balloon with constructor noise.
type scramConfig struct {
	mech       string
	newHash    func() hash.Hash
	auth       ScramCredentialsLookup
	plus       bool   // true → SCRAM-SHA-256-PLUS (channel binding required)
	cbExpected []byte // tls-exporter bytes for the PLUS variant; nil otherwise
}

func newScramServer(cfg scramConfig) *scramServer {
	return &scramServer{cfg: cfg}
}

// scramServer is the SASL server-side state machine.
//
// Three Next() calls drive the exchange:
//
//  1. response = client-first
//     → server emits server-first challenge
//  2. response = client-final
//     → server emits server-final (success) or returns error
//  3. (should not happen) — protocol library exits the loop on
//     done=true returned in step 2.
type scramServer struct {
	cfg   scramConfig
	state int

	username       string
	clientNonce    string
	combinedNonce  string
	clientFirstBare []byte
	serverFirst    []byte

	creds *ScramCredentials
	// fakeCreds carries fabricated salt+iter for the "unknown
	// user" code path so the server can drive the protocol
	// through to a uniform "auth failed" outcome without leaking
	// existence-of-user via timing.
	fakeCreds *ScramCredentials
}

// Next implements sasl.Server.
func (s *scramServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.state {
	case 0:
		s.state = 1
		return s.handleClientFirst(response)
	case 1:
		s.state = 2
		return s.handleClientFinal(response)
	default:
		return nil, true, errors.New("sasl/scram: unexpected client response after server-final")
	}
}

// handleClientFirst parses `[gs2-cbind-flag,authzid,]n=<user>,r=<nonce>[,extensions]`.
// Channel-binding flag policy:
//
//   - PLUS mechanism: client MUST send `p=tls-exporter`. `y` or
//     `n` is a downgrade attempt and rejected.
//   - Non-PLUS mechanism: client MAY send `y` (channel binding
//     supported but absent — typical for clients that recognise
//     both variants) or `n` (no channel binding). `p=…` is
//     forbidden — the client should have picked the PLUS
//     mechanism if it has channel binding data.
func (s *scramServer) handleClientFirst(response []byte) ([]byte, bool, error) {
	// Split off the gs2 header (everything before the second
	// comma) — what remains is the client-first-bare message
	// that goes into AuthMessage.
	idx1 := bytes.IndexByte(response, ',')
	if idx1 < 0 {
		return nil, true, fmt.Errorf("sasl/scram: client-first missing gs2 header: %q", response)
	}
	idx2 := bytes.IndexByte(response[idx1+1:], ',')
	if idx2 < 0 {
		return nil, true, fmt.Errorf("sasl/scram: client-first missing authzid field: %q", response)
	}
	gs2HeaderEnd := idx1 + 1 + idx2 + 1
	gs2Header := string(response[:gs2HeaderEnd])
	clientFirstBare := response[gs2HeaderEnd:]
	s.clientFirstBare = append([]byte(nil), clientFirstBare...)

	cbFlag := string(response[:idx1])
	if err := s.validateChannelBindingFlag(cbFlag); err != nil {
		return nil, true, err
	}
	_ = gs2Header // retained for AuthMessage via clientFirstBare/cb-data path

	// Parse n=user,r=nonce[,…] from client-first-bare.
	for _, attr := range strings.Split(string(clientFirstBare), ",") {
		if len(attr) < 2 || attr[1] != '=' {
			return nil, true, fmt.Errorf("sasl/scram: malformed client-first attribute %q", attr)
		}
		switch attr[0] {
		case 'n':
			s.username = decodeSaslName(attr[2:])
		case 'r':
			s.clientNonce = attr[2:]
		}
	}
	if s.username == "" || s.clientNonce == "" {
		return nil, true, errors.New("sasl/scram: client-first missing n= or r=")
	}

	// Look up the user. On miss, fabricate plausible
	// (salt, iter) so the exchange completes without timing-
	// leaking the user's existence — the final ClientProof check
	// will fail because we never wrote a StoredKey to compare
	// against.
	creds, lookupErr := s.cfg.auth(s.username)
	if lookupErr != nil {
		return nil, true, fmt.Errorf("sasl/scram: lookup: %w", lookupErr)
	}
	if creds == nil {
		s.fakeCreds = fabricateScramCredentials(s.cfg.newHash())
		creds = s.fakeCreds
	}
	s.creds = creds

	// Build server-first: r=combinedNonce,s=base64Salt,i=iter.
	serverNonce, err := randomBase64(18)
	if err != nil {
		return nil, true, fmt.Errorf("sasl/scram: nonce: %w", err)
	}
	s.combinedNonce = s.clientNonce + serverNonce
	saltB64 := base64.StdEncoding.EncodeToString(creds.Salt)
	s.serverFirst = []byte(fmt.Sprintf("r=%s,s=%s,i=%d",
		s.combinedNonce, saltB64, creds.Iterations))
	out := append([]byte(nil), s.serverFirst...)
	return out, false, nil
}

// validateChannelBindingFlag enforces the per-mechanism rules
// laid out at the head of handleClientFirst.
func (s *scramServer) validateChannelBindingFlag(flag string) error {
	if s.cfg.plus {
		if flag != "p=tls-exporter" {
			return fmt.Errorf("sasl/scram: PLUS mechanism requires p=tls-exporter, got %q", flag)
		}
		return nil
	}
	switch flag {
	case "n", "y":
		return nil
	}
	if strings.HasPrefix(flag, "p=") {
		// Non-PLUS server seeing a channel-binding request — the
		// client should have picked the PLUS mechanism.
		return fmt.Errorf("sasl/scram: non-PLUS server rejects channel binding %q", flag)
	}
	return fmt.Errorf("sasl/scram: invalid gs2-cbind-flag %q", flag)
}

// handleClientFinal parses `c=<base64-cb-data>,r=<combined-nonce>,p=<base64-proof>[,extensions]`
// and verifies the client's proof of knowledge of the password.
func (s *scramServer) handleClientFinal(response []byte) ([]byte, bool, error) {
	var cbInputB64, nonce, proofB64 string
	attrs := strings.Split(string(response), ",")
	clientFinalWithoutProof := response
	for _, attr := range attrs {
		if len(attr) < 2 || attr[1] != '=' {
			return nil, true, fmt.Errorf("sasl/scram: malformed client-final attribute %q", attr)
		}
		switch attr[0] {
		case 'c':
			cbInputB64 = attr[2:]
		case 'r':
			nonce = attr[2:]
		case 'p':
			proofB64 = attr[2:]
			// AuthMessage uses client-final-without-proof —
			// truncate at the `,p=…` segment.
			if cut := bytes.Index(response, []byte(",p=")); cut >= 0 {
				clientFinalWithoutProof = response[:cut]
			}
		}
	}
	if nonce != s.combinedNonce {
		return nil, true, errors.New("sasl/scram: combined nonce mismatch")
	}
	if proofB64 == "" || cbInputB64 == "" {
		return nil, true, errors.New("sasl/scram: client-final missing c= or p=")
	}

	// Verify channel binding. The c= field is base64 of
	// gs2-header concatenated with cb-data. For PLUS the
	// cb-data is the TLS exporter bytes the caller supplied;
	// for non-PLUS it is empty.
	cbInput, err := base64.StdEncoding.DecodeString(cbInputB64)
	if err != nil {
		return nil, true, fmt.Errorf("sasl/scram: c= not base64: %w", err)
	}
	if err := s.verifyChannelBinding(cbInput); err != nil {
		return nil, true, err
	}

	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return nil, true, fmt.Errorf("sasl/scram: p= not base64: %w", err)
	}

	// AuthMessage := client-first-bare + "," + server-first + "," + client-final-without-proof.
	authMessage := concat(s.clientFirstBare, []byte{','}, s.serverFirst, []byte{','}, clientFinalWithoutProof)

	// ClientSignature = HMAC(StoredKey, AuthMessage)
	// ClientKey       = ClientProof XOR ClientSignature
	// StoredKey'      = H(ClientKey)
	// On unknown-user (s.fakeCreds == s.creds) the StoredKey is
	// zero-filled fake; comparison will fail uniformly with the
	// known-user wrong-password path.
	csig := hmacSum(s.cfg.newHash, s.creds.StoredKey, authMessage)
	if len(proof) != len(csig) {
		return nil, true, errors.New("sasl/scram: proof length mismatch")
	}
	clientKey := xorBytes(proof, csig)
	h := s.cfg.newHash()
	h.Write(clientKey)
	derivedStored := h.Sum(nil)
	if subtle.ConstantTimeCompare(derivedStored, s.creds.StoredKey) != 1 {
		return nil, true, errors.New("sasl/scram: authentication failed")
	}

	// Build server-final = v=<base64 ServerSignature>
	ssig := hmacSum(s.cfg.newHash, s.creds.ServerKey, authMessage)
	serverFinal := []byte("v=" + base64.StdEncoding.EncodeToString(ssig))
	return serverFinal, true, nil
}

// verifyChannelBinding compares the client-provided c= payload
// against what the server expects. For the PLUS mechanism the
// payload must equal `gs2-header || cb-data`. For non-PLUS the
// payload must equal `gs2-header || ""`.
func (s *scramServer) verifyChannelBinding(cbInput []byte) error {
	var expected []byte
	if s.cfg.plus {
		// gs2-header on the PLUS path is `p=tls-exporter,,` — flag + empty authzid + trailing comma.
		expected = concat([]byte("p=tls-exporter,,"), s.cfg.cbExpected)
	} else {
		// Non-PLUS: gs2-header is `n,,` or `y,,` (we don't keep
		// the original flag separately, but the spec mandates
		// the client uses the same flag here it sent in client-
		// first). We accept either canonical encoding because
		// real clients do both.
		if bytes.Equal(cbInput, []byte("n,,")) || bytes.Equal(cbInput, []byte("y,,")) {
			return nil
		}
		return fmt.Errorf("sasl/scram: unexpected gs2-header in c=: %q", cbInput)
	}
	if subtle.ConstantTimeCompare(cbInput, expected) != 1 {
		return errors.New("sasl/scram: channel binding mismatch")
	}
	return nil
}

// fabricateScramCredentials returns a verifier with a random salt
// and a zero-filled StoredKey + ServerKey. Used on the
// unknown-user path so the protocol still completes through
// client-final with a uniform timing profile; ClientProof
// verification will fail because no client can derive zeroes.
func fabricateScramCredentials(h hash.Hash) *ScramCredentials {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	digest := h.Size()
	return &ScramCredentials{
		Iterations: 4096,
		Salt:       salt,
		StoredKey:  make([]byte, digest),
		ServerKey:  make([]byte, digest),
	}
}

// --- helpers --------------------------------------------------

// hmacSum returns HMAC(key, data) under the supplied digest.
func hmacSum(newHash func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}

// xorBytes returns a xor b (both must be the same length).
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// concat avoids the gymnastics of repeated append for clarity.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// randomBase64 returns n bytes of randomness, base64-encoded (no
// padding so the result is safe to embed in comma-separated SCRAM
// attributes).
func randomBase64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

// decodeSaslName unescapes the saslname-encoding used in n= and a=
// attributes: `=2C` → `,` and `=3D` → `=`. Per RFC 5802 §5.1.
func decodeSaslName(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	s = strings.ReplaceAll(s, "=2C", ",")
	s = strings.ReplaceAll(s, "=3D", "=")
	return s
}

// EncodeScramCredentials emits the Dovecot-compatible blob
// format: `<iterations>,<base64-salt>,<base64-stored-key>,<base64-server-key>`.
// Operators run this once (via CLI) when registering a user; the
// blob lands in the SQL password column under the
// `{SCRAM-SHA-256}` scheme prefix.
func EncodeScramCredentials(c *ScramCredentials) string {
	return fmt.Sprintf("%d,%s,%s,%s",
		c.Iterations,
		base64.StdEncoding.EncodeToString(c.Salt),
		base64.StdEncoding.EncodeToString(c.StoredKey),
		base64.StdEncoding.EncodeToString(c.ServerKey),
	)
}

// DecodeScramCredentials parses the blob produced by
// EncodeScramCredentials. Used by the SQL passdb to recover the
// verifier on lookup.
func DecodeScramCredentials(blob string) (*ScramCredentials, error) {
	parts := strings.Split(blob, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("sasl/scram: expected 4 comma-separated fields, got %d", len(parts))
	}
	iter, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("sasl/scram: parse iterations: %w", err)
	}
	if iter <= 0 {
		return nil, errors.New("sasl/scram: non-positive iterations")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("sasl/scram: parse salt: %w", err)
	}
	stored, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("sasl/scram: parse stored_key: %w", err)
	}
	server, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("sasl/scram: parse server_key: %w", err)
	}
	return &ScramCredentials{
		Iterations: iter,
		Salt:       salt,
		StoredKey:  stored,
		ServerKey:  server,
	}, nil
}
