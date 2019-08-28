package aesite

import (
	"context"

	"cloud.google.com/go/datastore"
)

type Setting struct {
	Name  string
	Value []byte
}

func settingKey(name string) *datastore.Key {
	return datastore.NameKey("Setting", name, nil)
}

func SetSetting(ctx context.Context, client *datastore.Client, name string, value []byte) error {
	s := &Setting{Name: name, Value: value}
	_, err := client.Put(ctx, settingKey(name), s)
	return err
}

// NewSetting sets the value for a setting key only if it doesn't already exist.
func NewSetting(ctx context.Context, client *datastore.Client, name string, value []byte) error {
	s := &Setting{Name: name, Value: value}
	k := settingKey(name)
	m := datastore.NewInsert(k, s)
	_, err := client.Mutate(ctx, m)
	return err
}

func GetSetting(ctx context.Context, client *datastore.Client, name string) ([]byte, error) {
	var s Setting
	err := client.Get(ctx, settingKey(name), &s)
	if err != nil {
		return nil, err
	}
	return s.Value, nil
}
