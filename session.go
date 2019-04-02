package aesite

import (
	"context"
	"math/rand"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
)

type Session struct {
	ID      int64
	UserKey *datastore.Key
	Active  bool
	Exp     time.Time
}

func (s *Session) Key() *datastore.Key {
	return datastore.IDKey("Session", s.ID, nil)
}

const sessionDur = 30 * 24 * time.Hour

// NewSession creates a new session for the given user and stores it in the datastore.
// The caller should seed the RNG (with rand.Seed) before calling this function.
func NewSession(ctx context.Context, client *datastore.Client, userKey *datastore.Key) (*Session, error) {
	id := rand.Int63()
	s := &Session{
		ID:      id,
		UserKey: userKey,
		Active:  true,
		Exp:     time.Now().Add(sessionDur),
	}
	_, err := client.Put(ctx, s.Key(), s)
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
