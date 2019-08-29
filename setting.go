package aesite

import (
	"context"

	"cloud.google.com/go/datastore"
)

// Setting is a name-value pair stored as an entity of kind "Setting" in Google Cloud Datastore.
type Setting struct {
	Name  string
	Value []byte
}

func settingKey(name string) *datastore.Key {
	return datastore.NameKey("Setting", name, nil)
}

// SetSetting creates or updates the value of a given setting.
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

// GetSetting gets the value of a setting.
// If the setting does not exist, the result is datastore.ErrNoSuchEntity.
func GetSetting(ctx context.Context, client *datastore.Client, name string) ([]byte, error) {
	var s Setting
	err := client.Get(ctx, settingKey(name), &s)
	return s.Value, err
}
