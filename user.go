package aesite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"
)

// User is the type of a user identified by an e-mail address.
type User struct {
	// Email is the user's e-mail address. It is used as a unique key for the User record.
	Email string

	// PWHash is the scrypt hash (salted with Salt) of the user's password.
	PWHash []byte // scrypt

	// Salt is a random byte string used as scrypt salt for PWHash.
	Salt []byte

	// Verified is false until User.Verify is called, setting it to true.
	// When signing up new users,
	// Verify should be the result of navigating to an e-mail-confirmation link.
	Verified bool

	// VToken is a random URL-safe string.
	// The caller of VerifyUser passes in a string that is compared to VToken; they must match.
	// When a new user signs up and is not yet verified,
	// the application should send a URL to the user's e-mail address,
	// containing this token as a parameter.
	// Visiting the URL should result in a VerifyUser call that passes in the URL parameter.
	VToken string

	// The time at which VToken expires
	// (i.e., when VerifyUser will produce an error rather than set Verified to true).
	// By default this is 1 day after the new User record is created.
	VTokenExp time.Time
}

// UserWrapper is the type of an object with kind "User" that gets written to and read from the datastore.
// It can be used by callers to wrap application-specific user data around the User type defined here.
// The caller's implementation of UserWrapper must be able to convert to and from aesite.User.
type UserWrapper interface {
	// GetUser unwraps the UserWrapper object to produce a *User.
	GetUser() *User

	// SetUser sets the *User of a UserWrapper.
	SetUser(*User)
}

// NewUser creates a new User object,
// places it in the given UserWrapper,
// and writes the whole thing to the datastore.
func NewUser(ctx context.Context, client *datastore.Client, email, pw string, uw UserWrapper) error {
	email, err := CanonicalizeEmail(email)
	if err != nil {
		return errors.Wrap(err, "canonicalizing e-mail address")
	}
	var salt [16]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return errors.Wrap(err, "getting random salt")
	}
	pwhash, err := scrypt.Key([]byte(pw), salt[:], 32768, 8, 1, 32)
	if err != nil {
		return errors.Wrap(err, "hashing password")
	}
	var vbytes [16]byte
	_, err = rand.Read(vbytes[:])
	if err != nil {
		return errors.Wrap(err, "getting random verification token")
	}
	vtoken := hex.EncodeToString(vbytes[:])
	u := &User{
		Email:     email,
		PWHash:    pwhash,
		Salt:      salt[:],
		VToken:    vtoken,
		VTokenExp: time.Now().Add(24 * time.Hour),
	}
	uw.SetUser(u)

	// To get errors on inserting keys that already exist,
	// you have to use Mutate instead of Put.
	ins := datastore.NewInsert(u.Key(), uw)
	_, err = client.Mutate(ctx, ins)
	if me, ok := err.(datastore.MultiError); ok && len(me) == 1 {
		err = me[0]
	}
	return errors.Wrap(err, "storing user")
}

// Key returns the datastore key for this user.
func (u *User) Key() *datastore.Key {
	return datastore.NameKey("User", u.Email, nil)
}

// CheckPW tests a password input for validity against this user's Salt and PWHash.
func (u *User) CheckPW(pw string) (bool, error) {
	pwhash, err := scrypt.Key([]byte(pw), u.Salt, 32768, 8, 1, 32)
	return bytes.Equal(pwhash, u.PWHash), err
}

// VerifyUser sets Verified to true for the User in uw.
// The supplied token presumably comes from a URL parameter and must match the user's VToken string,
// which must also be unexpired. (See User.VToken for more.)
// If the user is already verified, this is a no-op.
func VerifyUser(ctx context.Context, client *datastore.Client, uw UserWrapper, token string) error {
	u := uw.GetUser()
	if u.Verified {
		return nil
	}
	if u.VTokenExp.Before(time.Now()) {
		return fmt.Errorf("verification token expired")
	}
	if token != u.VToken {
		return fmt.Errorf("token mismatch")
	}
	u.Verified = true
	_, err := client.Put(ctx, u.Key(), uw)
	return err
}

// LookupUser looks up a user by e-mail address and places the result in uw.
// The email argument is canonicalized with CanonicalizeEmail before the lookup.
func LookupUser(ctx context.Context, client *datastore.Client, email string, uw UserWrapper) error {
	var err error
	email, err = CanonicalizeEmail(email)
	if err != nil {
		return errors.Wrapf(err, "canonicalizing e-mail address %s", email)
	}
	key := datastore.NameKey("User", email, nil)
	return client.Get(ctx, key, uw)
}

// CanonicalizeEmail parses an e-mail address and returns it in a canonical form
// suitable for use as a lookup key.
func CanonicalizeEmail(inp string) (string, error) {
	addr, err := mail.ParseAddress(inp)
	if err != nil {
		return "", err
	}
	return strings.ToLower(addr.Address), nil
}
