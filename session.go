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

type Session struct {
	ID      int64
	UserKey *datastore.Key
	CSRFKey []byte
	Active  bool
	Exp     time.Time
}

var maxint64 = big.NewInt(math.MaxInt64)

func (s *Session) Key() *datastore.Key {
	return datastore.IDKey("Session", s.ID, nil)
}

const sessionDur = 30 * 24 * time.Hour

// NewSession creates a new session for the given user and stores it in the datastore.
// The caller should seed the RNG (with rand.Seed) before calling this function.
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

// GetSession checks for a session cookie in a given HTTP request and gets the session from the datastore.
// If the session does not exist, is inactive, or is expired, this returns nil, nil.
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

func (s *Session) GetUser(ctx context.Context, client *datastore.Client, uw UserWrapper) error {
	return client.Get(ctx, s.UserKey, uw)
}

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

func (s *Session) Cancel(ctx context.Context, client *datastore.Client) error {
	s.Active = false
	_, err := client.Put(ctx, s.Key(), s)
	return err
}

const csrfNonceLen = 16

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

var CSRFErr = errors.New("CSRF check failed")

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
		return CSRFErr
	}
	return nil
}
