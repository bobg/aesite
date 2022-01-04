package aesite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	ID int64 `json:"id"`

	// UserKey is the Google Cloud Datastore key for the User entity associated with this session.
	UserKey *datastore.Key `json:"user_key"`

	// CSRFKey is a unique random bytestring that can be used for CSRF protection.
	// See Session.CSRFToken and Session.CSRFCheck.
	CSRFKey []byte `json:"-"`

	// Active is true until Session.Cancel is called.
	Active bool `json:"active"`

	// Exp is the expiration time for this session.
	// This defaults to 30 days after the session was created.
	Exp time.Time `json:"exp"`
}

var maxint64 = big.NewInt(math.MaxInt64)

// Key returns this session's datastore key.
func (s *Session) Key() *datastore.Key {
	return datastore.IDKey("Session", s.ID, nil)
}

const defaultSessionDur = 30 * 24 * time.Hour

// NewSession creates a new session for the given user and stores it in the datastore.
func NewSession(ctx context.Context, client *datastore.Client, userKey *datastore.Key) (*Session, error) {
	return NewSessionWithDuration(ctx, client, userKey, defaultSessionDur)
}

// NewSessionWithDuration creates a new session for the given user that expires after the given duration,
// and stores it in the datastore.
func NewSessionWithDuration(ctx context.Context, client *datastore.Client, userKey *datastore.Key, dur time.Duration) (*Session, error) {
	id, err := rand.Int(rand.Reader, maxint64)
	if err != nil {
		return nil, errors.Wrap(err, "choosing random session ID")
	}
	s := &Session{
		ID:      id.Int64(),
		UserKey: userKey,
		CSRFKey: make([]byte, 32),
		Active:  true,
		Exp:     time.Now().Add(dur),
	}

	_, err = rand.Read(s.CSRFKey[:])
	if err != nil {
		return nil, errors.Wrap(err, "choosing random CSRF key")
	}

	_, err = client.Put(ctx, s.Key(), s)
	return s, err
}

// CookieName is the name of the aesite session cookie.
var CookieName = "s"

// ErrInactive means a session is inactive or expired.
var ErrInactive = errors.New("inactive session")

// GetSession checks for a session cookie in a given HTTP request
// and gets the session from the datastore.
// The cookie must have been handed out in an earlier HTTP response via Session.SetCookie.
// If there is no cookie in the HTTP request,
// the resulting error is http.ErrNoCookie.
// If the session is not present in the datastore,
// the resulting error is datastore.ErrNoSuchEntity.
// If the session is present but expired or inactive,
// the resulting error is ErrInactive.
// You can use IsNoSession to test whether the error is any one of those.
func GetSession(ctx context.Context, client *datastore.Client, req *http.Request) (*Session, error) {
	cookie, err := req.Cookie(CookieName)
	if err == http.ErrNoCookie {
		return nil, err
	}
	if err != nil {
		return nil, errors.Wrap(err, "getting session cookie from HTTP request")
	}
	key, err := datastore.DecodeKey(cookie.Value)
	if err != nil {
		return nil, errors.Wrap(err, "decoding session cookie")
	}
	return GetSessionByKey(ctx, client, key)
}

// IsNoSession tells whether err is one of the unexceptional no-session errors
// (http.ErrNoCookie, datastore.ErrNoSuchEntity, and ErrInactive).
func IsNoSession(err error) bool {
	return errors.Is(err, http.ErrNoCookie) || errors.Is(err, datastore.ErrNoSuchEntity) || errors.Is(err, ErrInactive)
}

// GetSessionByKey gets the session with the given key.
// If the session is not present in the datastore,
// the resulting error is datastore.ErrNoSuchEntity.
// If the session is present but expired or inactive,
// the resulting error is ErrInactive.
func GetSessionByKey(ctx context.Context, client *datastore.Client, key *datastore.Key) (*Session, error) {
	var s Session
	err := client.Get(ctx, key, &s)
	if err == datastore.ErrNoSuchEntity {
		return nil, err
	}
	if err != nil {
		return nil, errors.Wrap(err, "reading session from datastore")
	}
	if !s.Active || s.Exp.Before(time.Now()) {
		return nil, ErrInactive
	}
	return &s, nil
}

// ErrAnonymous is the result of calling Session.GetUser on an anonymous session
// (i.e., one with no UserKey set).
var ErrAnonymous = errors.New("anonymous session")

// GetUser looks up the user associated with this session and places it in uw.
func (s *Session) GetUser(ctx context.Context, client *datastore.Client, uw UserWrapper) error {
	if s.UserKey == nil {
		return ErrAnonymous
	}
	return client.Get(ctx, s.UserKey, uw)
}

// SetCookie adds a cookie for this session to an HTTP response.
func (s *Session) SetCookie(w http.ResponseWriter) {
	if !s.Active || s.Exp.Before(time.Now()) {
		return
	}
	cookie := &http.Cookie{
		Name:    CookieName,
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
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ErrCSRF is the error produced when an invalid CSRF token is presented to CSRFCheck.
var ErrCSRF = errors.New("CSRF check failed")

// CSRFCheck checks a CSRF token for validity against this session.
// The token should have been produced with Session.CSRFToken.
// If the token is invalid, the result is CSRFErr.
// Other errors are possible too.
// A return value of nil means the token is valid.
func (s *Session) CSRFCheck(inp string) error {
	got, err := base64.RawURLEncoding.DecodeString(inp)
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

// SessionHandler is HTTP middleware.
// It calls GetSession on an HTTP request.
// If one is found,
// the request's context is decorated with the session object before calling the next handler in the chain.
// That next handler can access the session by calling ContextSession.
func SessionHandler(client *datastore.Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		sess, err := GetSession(ctx, client, req)
		if err != nil && !IsNoSession(err) {
			http.Error(w, fmt.Sprintf("looking up session: %s", err), http.StatusInternalServerError)
			return
		}
		ctx = context.WithValue(ctx, sessKey{}, sess)
		req = req.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}

type sessKey struct{}

// ContextSession returns the session attached to the context by SessionHandler, if any.
func ContextSession(ctx context.Context) *Session {
	val := ctx.Value(sessKey{})
	if val != nil {
		return val.(*Session)
	}
	return nil
}
