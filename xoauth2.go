package sasl

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// XOAuth2 is the SASL mechanism name for the Google/Microsoft
// XOAUTH2 extension. The wire format is simpler than the IETF
// OAUTHBEARER (RFC 7628): no GS2 header, no key=value port/host
// fields — just user= and auth=.
//
// Clients that only speak XOAUTH2 include legacy Outlook
// configurations, older Android mail apps, and some older
// Thunderbird OAuth setups. New clients should use OAUTHBEARER.
const XOAuth2 = "XOAUTH2"

// XOAuth2Options carries the credential pair extracted from the
// client's initial XOAUTH2 response. The shape matches
// OAuthBearerOptions so callers can reuse the same authenticator
// callback for both mechanisms.
type XOAuth2Options struct {
	// Username is the mail account identifier from the user= field.
	Username string
	// Token is the bare OAuth2 bearer token (the "Bearer " prefix
	// is stripped by the parser before calling the authenticator).
	Token string
}

// XOAuth2Authenticator is the callback invoked by the XOAUTH2
// server once it has parsed the client message. Return nil on
// success; return a non-nil *OAuthBearerError on rejection so the
// wire error JSON is consistent with the OAUTHBEARER error format.
type XOAuth2Authenticator func(opts XOAuth2Options) *OAuthBearerError

type xoauth2Server struct {
	done         bool
	authenticate XOAuth2Authenticator
}

// Next implements sasl.Server.
//
// Round 0 (response == nil): returns an empty challenge so
// protocol frameworks that issue an initial server challenge
// before reading the client response work correctly.
// Round 1 (response = client message): parse + validate.
func (s *xoauth2Server) Next(response []byte) ([]byte, bool, error) {
	if s.done {
		return nil, true, errors.New("sasl/xoauth2: Next called after done")
	}

	if response == nil {
		return []byte{}, false, nil
	}

	s.done = true

	opts, err := ParseXOAuth2Initial(response)
	if err != nil {
		blob, _ := json.Marshal(OAuthBearerError{
			Status:  "invalid_request",
			Schemes: "bearer",
		})
		return blob, true, err
	}

	if authzErr := s.authenticate(opts); authzErr != nil {
		blob, jerr := json.Marshal(authzErr)
		if jerr != nil {
			return nil, true, jerr
		}
		return blob, true, authzErr
	}
	return nil, true, nil
}

// NewXOAuth2Server returns an XOAUTH2 SASL server. The auth
// callback is invoked once per exchange with the (Username, Token)
// pair extracted from the client's initial response. Fast-fail:
// on rejection done=true is returned immediately (no RFC 7628
// §3.2.3 dummy 0x01 round needed — the error JSON is terminal).
func NewXOAuth2Server(auth XOAuth2Authenticator) Server {
	return &xoauth2Server{authenticate: auth}
}

// ParseXOAuth2Initial parses the XOAUTH2 client initial response:
//
//	"user=<username>\x01auth=Bearer <token>\x01\x01"
//
// Fields are separated by 0x01 (SOH). The trailing double 0x01
// marks end-of-message. Order is fixed by the protocol but we
// accept any order for robustness. The "Bearer " prefix on auth=
// is case-insensitive and stripped before returning.
func ParseXOAuth2Initial(resp []byte) (XOAuth2Options, error) {
	var opts XOAuth2Options
	for _, kv := range bytes.Split(resp, []byte{0x01}) {
		if len(kv) == 0 {
			continue
		}
		eq := bytes.IndexByte(kv, '=')
		if eq < 0 {
			return opts, errors.New("sasl/xoauth2: malformed field (no '=')")
		}
		key := string(kv[:eq])
		value := string(kv[eq+1:])
		switch key {
		case "user":
			opts.Username = value
		case "auth":
			const prefix = "bearer "
			if !strings.HasPrefix(strings.ToLower(value), prefix) {
				return opts, errors.New("sasl/xoauth2: unsupported token type (only Bearer)")
			}
			opts.Token = value[len(prefix):]
		}
	}
	if opts.Token == "" {
		return opts, errors.New("sasl/xoauth2: missing auth=Bearer field")
	}
	return opts, nil
}
