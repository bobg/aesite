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
	Email            string
	PWHash           []byte // scrypt
	Salt             []byte
	Verified, Active bool
	VToken           string
	VTokenExp        time.Time
}

// UserWrapper is the type of an object with kind "User" that gets written to and read from the datastore.
type UserWrapper interface {
	GetUser() *User
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
		Active:    true,
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

func (u *User) Key() *datastore.Key {
	return datastore.NameKey("User", u.Email, nil)
}

func (u *User) CheckPW(pw string) (bool, error) {
	pwhash, err := scrypt.Key([]byte(pw), u.Salt, 32768, 8, 1, 32)
	return bytes.Equal(pwhash, u.PWHash), err
}

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

func CanonicalizeEmail(inp string) (string, error) {
	addr, err := mail.ParseAddress(inp)
	if err != nil {
		return "", err
	}
	return strings.ToLower(addr.Address), nil
}
