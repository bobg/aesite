package aesite

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
)

type IdemKey struct {
	Key string
	Exp time.Time
}

// An idempotency key lasts at least this long.
var idemDur = time.Hour

// Idempotent stores a key (a string) in the datastore.
// A second attempt to store the same key will fail for about an hour.
// This can be used to dedupe multiple identical task requests:
// every attempt calls Idempotent with the same string,
// and only the one that doesn't result in an error proceeds.
//
// Calling Idempotent opportunistically deletes expired IdemKey records.
func Idempotent(ctx context.Context, client *datastore.Client, key string) error {
	// Opportunistically delete expired idempotency keys.
	q := datastore.NewQuery("IdemKey").Filter("Exp <", time.Now()).KeysOnly()
	keys, err := client.GetAll(ctx, q, nil)
	if err != nil {
		return errors.Wrap(err, "getting expired idempotency keys")
	}
	if len(keys) > 0 {
		err = client.DeleteMulti(ctx, keys)
		if err != nil {
			return errors.Wrap(err, "deleting expired idempotency keys")
		}
	}

	k := &IdemKey{
		Key: key,
		Exp: time.Now().Add(idemDur),
	}
	ins := datastore.NewInsert(datastore.NameKey("IdemKey", key, nil), k)
	_, err = client.Mutate(ctx, ins)
	return errors.Wrapf(err, "storing idempotency key %s", key)
}
