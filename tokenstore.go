package oauthflows

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"os"
	"time"
)

type TokenStore interface {
	Get(key string) (*oauth2.Token, error)
	Put(key string, token *oauth2.Token) error
}

type fileTokenStore struct {
}

func (f *fileTokenStore) Get(key string) (*oauth2.Token, error) {
	filename := fmt.Sprintf("token.%s.json", key)
	t, err := tokenFromFile(filename)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, nil
	}

	if t.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("token expired at %s", t.Expiry)
	}
	return t, nil
}

func (f *fileTokenStore) Put(key string, token *oauth2.Token) error {
	filename := fmt.Sprintf("token.%s.json", key)
	return saveToken(filename, token)
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	t := new(oauth2.Token)
	err = json.NewDecoder(f).Decode(t)
	return t, err
}

func saveToken(file string, token *oauth2.Token) error {
	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("failed to cache oauth token: %w", err)
	}
	err = f.Chmod(os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("failed to limit filemode: %w", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
	return nil
}
