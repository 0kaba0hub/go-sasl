package sasl_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
)

func TestXOAuth2_HappyPath(t *testing.T) {
	var gotUser, gotToken string
	srv := sasl.NewXOAuth2Server(func(opts sasl.XOAuth2Options) *sasl.OAuthBearerError {
		gotUser = opts.Username
		gotToken = opts.Token
		return nil
	})

	// Round 0: server emits empty challenge.
	chal, done, err := srv.Next(nil)
	if err != nil || done {
		t.Fatalf("round 0: done=%v err=%v", done, err)
	}
	if len(chal) != 0 {
		t.Errorf("round 0: expected empty challenge, got %q", chal)
	}

	// Round 1: client sends initial response.
	msg := "user=alice@example.com\x01auth=Bearer ya29.faketoken\x01\x01"
	_, done, err = srv.Next([]byte(msg))
	if err != nil || !done {
		t.Fatalf("round 1: done=%v err=%v", done, err)
	}
	if gotUser != "alice@example.com" {
		t.Errorf("username: got %q", gotUser)
	}
	if gotToken != "ya29.faketoken" {
		t.Errorf("token: got %q", gotToken)
	}
}

func TestXOAuth2_AuthFailure(t *testing.T) {
	srv := sasl.NewXOAuth2Server(func(_ sasl.XOAuth2Options) *sasl.OAuthBearerError {
		return &sasl.OAuthBearerError{Status: "invalid_token", Schemes: "bearer"}
	})
	srv.Next(nil) //nolint:errcheck
	blob, done, err := srv.Next([]byte("user=alice@example.com\x01auth=Bearer bad\x01\x01"))
	if !done {
		t.Errorf("expected done=true on auth failure")
	}
	if err == nil {
		t.Errorf("expected error on auth failure")
	}
	if !strings.Contains(string(blob), "invalid_token") {
		t.Errorf("expected JSON error blob, got %q", blob)
	}
}

func TestXOAuth2_MissingAuthField(t *testing.T) {
	srv := sasl.NewXOAuth2Server(func(_ sasl.XOAuth2Options) *sasl.OAuthBearerError { return nil })
	srv.Next(nil) //nolint:errcheck
	_, done, err := srv.Next([]byte("user=alice@example.com\x01\x01"))
	if !done || err == nil {
		t.Errorf("expected error on missing auth= field: done=%v err=%v", done, err)
	}
}

func TestXOAuth2_BearerCaseInsensitive(t *testing.T) {
	var gotToken string
	srv := sasl.NewXOAuth2Server(func(opts sasl.XOAuth2Options) *sasl.OAuthBearerError {
		gotToken = opts.Token
		return nil
	})
	srv.Next(nil) //nolint:errcheck
	_, done, err := srv.Next([]byte("user=alice@example.com\x01auth=BEARER mytoken\x01\x01"))
	if err != nil || !done {
		t.Fatalf("uppercase BEARER: done=%v err=%v", done, err)
	}
	if gotToken != "mytoken" {
		t.Errorf("token: got %q", gotToken)
	}
}

func TestXOAuth2_ParseXOAuth2Initial_FieldOrder(t *testing.T) {
	// auth= before user= — non-standard order, we still accept it.
	opts, err := sasl.ParseXOAuth2Initial([]byte("auth=Bearer tok\x01user=bob\x01\x01"))
	if err != nil {
		t.Fatal(err)
	}
	if opts.Token != "tok" {
		t.Errorf("token: %q", opts.Token)
	}
	if opts.Username != "bob" {
		t.Errorf("user: %q", opts.Username)
	}
}
