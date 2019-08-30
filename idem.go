package aesite

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IdemKey struct {
	Key string
	Exp time.Time
}

// An idempotency key lasts at least this long.
var idemDur = time.Hour

// ErrIdempotency is the error returned by Idempotent
// when the given key has been seen recently.
var ErrIdempotency = errors.New("idempotency check failed")

// Idempotent stores a key (a string) in the datastore.
// A second attempt to store the same key will fail (with ErrIdempotent) for about an hour.
// This can be used to dedupe multiple identical task requests:
// every attempt calls Idempotent with the same string,
// and only the one that doesn't result in an error proceeds.
//
// Calling Idempotent opportunistically deletes expired IdemKey records.
func Idempotent(ctx context.Context, client *datastore.Client, key string) error {
	err := idemExpire(ctx, client)
	if err != nil {
		return errors.Wrap(err, "expiring idempotency keys")
	}

	k := &IdemKey{
		Key: key,
		Exp: time.Now().Add(idemDur),
	}
	ins := datastore.NewInsert(datastore.NameKey("IdemKey", key, nil), k)
	_, err = client.Mutate(ctx, ins)
	if status.Code(err) == codes.AlreadyExists {
		return ErrIdempotency
	}
	if merr, ok := err.(datastore.MultiError); ok && status.Code(merr[0]) == codes.AlreadyExists {
		return ErrIdempotency
	}
	return errors.Wrapf(err, "storing idempotency key %s", key)
}

const multiLimit = 500

func idemExpire(ctx context.Context, client *datastore.Client) error {
	q := datastore.NewQuery("IdemKey").Filter("Exp <", time.Now()).KeysOnly()
	it := client.Run(ctx, q)
	var keys []*datastore.Key
	del := func() error {
		if len(keys) == 0 {
			return nil
		}
		defer func() { keys = nil }()
		return client.DeleteMulti(ctx, keys)
	}
	for {
		k, err := it.Next(nil)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		keys = append(keys, k)
		if len(keys) == multiLimit {
			err = del()
			if err != nil {
				return err
			}
		}
	}
	return del()
}
