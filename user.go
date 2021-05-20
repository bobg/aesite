package aesite

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/mail"
	"reflect"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"
)

// User is the type of a user identified by an e-mail address.
type User struct {
	// Email is the user's e-mail address. It is used as a unique key for the User record.
	Email string `json:"email"`

	// PWHash is the scrypt hash (salted with Salt) of the user's password.
	PWHash []byte `json:"-"` // scrypt

	// Salt is a random byte string used as scrypt salt for PWHash.
	Salt []byte `json:"-"`

	// Verified is false until User.Verify is called, setting it to true.
	// When signing up new users,
	// Verify should be the result of navigating to an e-mail-confirmation link.
	Verified bool `json:"verified"`

	// Secret is a random bytestring used for calculating verification tokens.
	// Applications must take care not to let this value leak.
	Secret []byte `json:"-"`

	// UpdateCounter is incremented at the end of a successful call to UpdateUser.
	// It should not be used for any other purpose.
	UpdateCounter int64 `json:"-"`
}

// UserWrapper is the type of an object with kind "User" that gets written to and read from the datastore.
// It can be used by callers to wrap application-specific user data around the User type defined here.
// The caller's implementation of UserWrapper must be able to convert to and from aesite.User.
// Note: aesite.User can act as its own (trivial) UserWrapper.
type UserWrapper interface {
	// GetUser unwraps the UserWrapper object to produce a *User.
	GetUser() *User

	// SetUser sets the *User of a UserWrapper.
	SetUser(*User)
}

// NewUser creates a new User object,
// places it in the given UserWrapper (which must be a pointer),
// and writes the whole thing to the datastore.
func NewUser(ctx context.Context, client *datastore.Client, email, pw string, uw UserWrapper) error {
	email, err := CanonicalizeEmail(email)
	if err != nil {
		return errors.Wrap(err, "canonicalizing e-mail address")
	}

	salt, pwhash, err := saltedPWHash(pw)
	if err != nil {
		return errors.Wrap(err, "generating salted pwhash")
	}

	var secret [32]byte
	_, err = rand.Read(secret[:])
	if err != nil {
		return errors.Wrap(err, "generating random user secret")
	}

	u := &User{
		Email:  email,
		PWHash: pwhash,
		Salt:   salt,
		Secret: secret[:],
	}
	uw.SetUser(u)

	// To get errors on inserting keys that already exist,
	// you have to use Mutate instead of Put.
	ins := datastore.NewInsert(u.Key(), uw)
	_, err = client.Mutate(ctx, ins)
	var me datastore.MultiError
	if errors.As(err, &me) && len(me) == 1 {
		err = me[0]
	}
	return errors.Wrap(err, "storing user")
}

// GetUser implements UserWrapper.GetUser.
func (u *User) GetUser() *User { return u }

// SetUser implements UserWrapper.SetUser.
func (u *User) SetUser(u2 *User) { *u = *u2 }

// Key returns the datastore key for this user.
func (u *User) Key() *datastore.Key {
	return datastore.NameKey("User", u.Email, nil)
}

// CheckPW tests a password input for validity against this user's Salt and PWHash.
func (u *User) CheckPW(pw string) bool {
	pwhash, _ := scrypt.Key([]byte(pw), u.Salt, 32768, 8, 1, 32)
	return bytes.Equal(pwhash, u.PWHash)
}

func (u *User) SecureToken(wt io.WriterTo) (string, error) {
	t, err := u.secureToken(wt)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

func (u *User) CheckToken(wt io.WriterTo, token string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return errors.Wrap(err, "decoding token")
	}

	computed, err := u.secureToken(wt)
	if err != nil {
		return errors.Wrap(err, "computing token")
	}

	if !hmac.Equal(computed, decoded) {
		return ErrVerification
	}

	return nil
}

func (u *User) secureToken(wt io.WriterTo) ([]byte, error) {
	h := hmac.New(sha256.New, u.Secret)
	_, err := wt.WriteTo(h)
	return h.Sum(nil), err
}

const (
	verifyTokenDur = time.Hour
	verifyNonceLen = 15 // to make base64 encoding come out nicely
)

// VerificationToken generates a new verification token
// from a random nonce and an expiration time
// hashed with the user secret in uw.
// It returns the expTime, the nonce, and the token
// (all of which are needed by CheckVerificationToken).
func VerificationToken(uw UserWrapper) (expSecs int64, nonce, token string, err error) {
	expSecs = time.Now().Add(verifyTokenDur).Unix()

	var nonceBuf [verifyNonceLen]byte
	_, err = rand.Read(nonceBuf[:])
	if err != nil {
		err = errors.Wrap(err, "generating random nonce")
		return
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBuf[:])

	u := uw.GetUser()
	h := hmac.New(sha256.New, u.Secret)

	err = binary.Write(h, binary.LittleEndian, expSecs)
	if err != nil {
		err = errors.Wrap(err, "hashing exp time")
		return
	}

	_, err = h.Write(nonceBuf[:])
	if err != nil {
		err = errors.Wrap(err, "hashing nonce")
		return
	}

	token = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return expSecs, nonce, token, nil
}

var (
	// ErrExpired is the result of checking an expired token.
	ErrExpired = errors.New("token expired")

	// ErrVerification is the result of checking an invalid token.
	ErrVerification = errors.New("token check failed")
)

// CheckVerificationToken checks a verification token for validity
// (including whether it has expired).
func CheckVerificationToken(uw UserWrapper, expSecs int64, nonce, token string) error {
	nowSecs := time.Now().Unix()
	if nowSecs > expSecs {
		return ErrExpired
	}

	u := uw.GetUser()
	h := hmac.New(sha256.New, u.Secret)

	err := binary.Write(h, binary.LittleEndian, expSecs)
	if err != nil {
		return errors.Wrap(err, "hashing exp time")
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return errors.Wrap(err, "decoding nonce")
	}

	_, err = h.Write(nonceBytes)
	if err != nil {
		return errors.Wrap(err, "hashing nonce")
	}

	got := h.Sum(nil)

	want, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return errors.Wrap(err, "decoding token")
	}

	if !hmac.Equal(got, want) {
		return ErrVerification
	}
	return nil
}

// VerifyUser checks a verification token for validity and sets the user's Verified flag to true.
// If the user is already verified, this is a no-op.
// The UserWrapper argument must be a pointer.
func VerifyUser(ctx context.Context, client *datastore.Client, uw UserWrapper, expSecs int64, nonce, token string) error {
	u := uw.GetUser()
	if u.Verified {
		return nil
	}

	err := CheckVerificationToken(uw, expSecs, nonce, token)
	if err != nil {
		return errors.Wrap(err, "checking verification token")
	}

	u.Verified = true
	uw.SetUser(u)
	_, err = client.Put(ctx, u.Key(), uw)
	return errors.Wrap(err, "storing updated user record")
}

// LookupUser looks up a user by e-mail address and places the result in uw
// (which must be a pointer).
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

// ErrUpdateConflict is the result of calling UpdateUser and losing a race with another concurrent caller.
var ErrUpdateConflict = errors.New("update conflict")

// UpdateUser atomically updates a user.
//
// To achieve this, UpdateUser uses optimistic locking.
// It starts a datastore transaction, then looks up the user and places it in uw
// (which must be a pointer).
// It next calls f to update the value in uw.
// After f runs (without error),
// UpdateUser fetches a new copy of the same user record
// to ensure that its UpdateCounter field hasn't changed.
// If it has, the transaction is rolled back and the error ErrUpdateConflict is returned.
// Otherwise, UpdateCounter is incremented and the transaction committed.
//
// Note that this means f runs even if the user cannot ultimately be atomically updated.
// So f should not have side effects beyond what can be rolled back with tx.
func UpdateUser(ctx context.Context, client *datastore.Client, email string, uw UserWrapper, f func(tx *datastore.Transaction) error) error {
	t := reflect.TypeOf(uw)
	if t.Kind() != reflect.Ptr {
		return errors.New("user argument is not a pointer")
	}

	err := LookupUser(ctx, client, email, uw)
	if err != nil {
		return errors.Wrapf(err, "looking up user %s", email)
	}

	tx, err := client.NewTransaction(ctx)
	if err != nil {
		return errors.Wrap(err, "beginning datastore transaction")
	}
	defer tx.Rollback()

	err = f(tx)
	if err != nil {
		return err
	}

	uw2 := reflect.New(t.Elem()).Interface().(UserWrapper)
	err = LookupUser(ctx, client, email, uw2)
	if err != nil {
		return errors.Wrapf(err, "re-looking up user %s", email)
	}

	var (
		u  = uw.GetUser()
		u2 = uw2.GetUser()
	)
	if u.UpdateCounter != u2.UpdateCounter {
		return ErrUpdateConflict
	}

	u.UpdateCounter++
	uw.SetUser(u)

	_, err = client.Put(ctx, u.Key(), uw)
	if err != nil {
		return errors.Wrap(err, "storing user")
	}

	_, err = tx.Commit()
	return errors.Wrapf(err, "committing transaction")
}

// UpdatePW sets a new password for the given user.
func UpdatePW(ctx context.Context, client *datastore.Client, uw UserWrapper, pw string) error {
	salt, pwhash, err := saltedPWHash(pw)
	if err != nil {
		return errors.Wrap(err, "generating salted pwhash")
	}

	u := uw.GetUser()
	u.Salt = salt[:]
	u.PWHash = pwhash
	uw.SetUser(u)
	_, err = client.Put(ctx, u.Key(), uw)
	return errors.Wrap(err, "storing updated user record")
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

func saltedPWHash(pw string) (salt, pwhash []byte, err error) {
	salt = make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting random salt")
	}
	pwhash, err = scrypt.Key([]byte(pw), salt, 32768, 8, 1, 32)
	return salt, pwhash, errors.Wrap(err, "hashing password")
}
