package aesite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"math/big"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
)

// Session is the type of a user login session.
// It is stored as an entity of kind "Session" in Google Cloud Datastore.
type Session struct {
	// ID is a unique random identifier for the session.
	ID int64

	// UserKey is the Google Cloud Datastore key for the User entity associated with this session.
	UserKey *datastore.Key

	// CSRFKey is a unique random bytestring that can be used for CSRF protection.
	// See Session.CSRFToken and Session.CSRFCheck.
	CSRFKey []byte

	// Active is true until Session.Cancel is called.
	Active bool

	// Exp is the expiration time for this session.
	// This defaults to 30 days after the session was created.
	Exp time.Time
}

var maxint64 = big.NewInt(math.MaxInt64)

// Key returns this session's datastore key.
func (s *Session) Key() *datastore.Key {
	return datastore.IDKey("Session", s.ID, nil)
}

const sessionDur = 30 * 24 * time.Hour

// NewSession creates a new session for the given user and stores it in the datastore.
func NewSession(ctx context.Context, client *datastore.Client, userKey *datastore.Key) (*Session, error) {
	id, err := rand.Int(rand.Reader, maxint64)
	if err != nil {
		return nil, errors.Wrap(err, "choosing random session ID")
	}
	s := &Session{
		ID:      id.Int64(),
		UserKey: userKey,
		CSRFKey: make([]byte, 32),
		Active:  true,
		Exp:     time.Now().Add(sessionDur),
	}

	_, err = rand.Read(s.CSRFKey[:])
	if err != nil {
		return nil, errors.Wrap(err, "choosing random CSRF key")
	}

	_, err = client.Put(ctx, s.Key(), s)
	return s, err
}

const cookieName = "s"

// GetSession checks for a session cookie in a given HTTP request
// and gets the session from the datastore.
// The cookie must have been handed out in an earlier HTTP response via Session.SetCookie.
// If the cookie is not present,
// or if the session does not exist, is inactive, or is expired, this returns nil, nil.
func GetSession(ctx context.Context, client *datastore.Client, req *http.Request) (*Session, error) {
	cookie, err := req.Cookie(cookieName)
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "getting session cookie from HTTP request")
	}
	key, err := datastore.DecodeKey(cookie.Value)
	if err != nil {
		return nil, errors.Wrap(err, "decoding session cookie")
	}
	var s Session
	err = client.Get(ctx, key, &s)
	if err == datastore.ErrNoSuchEntity {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "reading session from datastore")
	}
	if !s.Active || s.Exp.Before(time.Now()) {
		return nil, nil
	}
	return &s, nil
}

// GetUser looks up the user associated with this session and places it in uw.
func (s *Session) GetUser(ctx context.Context, client *datastore.Client, uw UserWrapper) error {
	return client.Get(ctx, s.UserKey, uw)
}

// SetCookie adds a cookie for this session to an HTTP response.
func (s *Session) SetCookie(w http.ResponseWriter) {
	if !s.Active || s.Exp.Before(time.Now()) {
		return
	}
	cookie := &http.Cookie{
		Name:    cookieName,
		Value:   s.Key().Encode(),
		Expires: s.Exp,
	}
	http.SetCookie(w, cookie)
}

// Cancel cancels this session, setting its Active field to false.
// This is the way to effect a logout.
func (s *Session) Cancel(ctx context.Context, client *datastore.Client) error {
	s.Active = false
	_, err := client.Put(ctx, s.Key(), s)
	return err
}

const csrfNonceLen = 16

// CSRFToken generates a new token containing a random nonce hashed with this session's CSRF key.
// It can be used to protect against CSRF attacks.
// Resources served by the application (e.g. HTML pages) should include a CSRF token.
// State-changing requests to the application that rely on a Session for authentication
// should require the caller to supply a valid CSRF token.
// Validity can be checked with Session.CSRFCheck.
// For more on this topic see https://en.wikipedia.org/wiki/Cross-site_request_forgery.
func (s *Session) CSRFToken() (string, error) {
	var buf [csrfNonceLen + sha256.Size]byte
	_, err := rand.Read(buf[:csrfNonceLen])
	if err != nil {
		return "", errors.Wrap(err, "generating random nonce")
	}
	h := hmac.New(sha256.New, s.CSRFKey)
	_, err = h.Write(buf[:csrfNonceLen])
	if err != nil {
		return "", errors.Wrap(err, "computing HMAC")
	}
	copy(buf[csrfNonceLen:], h.Sum(nil))
	return base64.StdEncoding.EncodeToString(buf[:]), nil
}

// ErrCSRF is the error produced when an invalid CSRF token is presented to CSRFCheck.
var ErrCSRF = errors.New("CSRF check failed")

// CSRFCheck checks a CSRF token for validity against this session.
// The token should have been produced with Session.CSRFToken.
// If the token is invalid, the result is CSRFErr.
// Other errors are possible too.
// A return value of nil means the token is valid.
func (s *Session) CSRFCheck(inp string) error {
	got, err := base64.StdEncoding.DecodeString(inp)
	if err != nil {
		return errors.Wrap(err, "decoding base64")
	}
	if len(got) != csrfNonceLen+sha256.Size {
		return errors.Wrap(err, "CSRF token has wrong length")
	}
	h := hmac.New(sha256.New, s.CSRFKey)
	_, err = h.Write(got[:csrfNonceLen])
	if err != nil {
		return errors.Wrap(err, "computing HMAC")
	}
	want := h.Sum(nil)
	if !hmac.Equal(got[csrfNonceLen:], want) {
		return ErrCSRF
	}
	return nil
}
