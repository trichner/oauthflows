package oauthflows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"strings"
)

type config struct {
	tokenStore  TokenStore
	oauthConfig *oauth2.Config
}

type ClientOption func(c *config) error

func WithConfig(conf *oauth2.Config) ClientOption {
	return func(c *config) error {
		c.oauthConfig = conf
		return nil
	}
}

func WithClientSecretsFile(filepath string, scopes []string) ClientOption {
	return func(c *config) error {
		slurp, err := ioutil.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", filepath, err)
		}

		conf, err := google.ConfigFromJSON(slurp, scopes...)
		if err != nil {
			return fmt.Errorf("cannot parse config %s: %w", filepath, err)
		}
		c.oauthConfig = conf
		return nil
	}
}

func WithTokenStore(t TokenStore) ClientOption {
	return func(c *config) error {
		c.tokenStore = t
		return nil
	}
}

func WithFileTokenStore() ClientOption {
	return func(c *config) error {
		c.tokenStore = &fileTokenStore{}
		return nil
	}
}

func NewClient(configer ...ClientOption) (*http.Client, error) {

	c := config{}

	for _, e := range configer {
		if err := e(&c); err != nil {
			return nil, err
		}
	}

	if c.oauthConfig == nil {
		return nil, fmt.Errorf("no oauth2 client configured")
	}

	ctx := context.Background()

	cacheName := deriveCacheName(c.oauthConfig)

	var ts oauth2.TokenSource
	ts, err := NewBrowserFlowTokenSource(ctx, c.oauthConfig)
	if err != nil {
		return nil, err
	}

	if c.tokenStore != nil {
		ts, err = NewCachedTokenSource(ctx, cacheName, c.tokenStore, ts)
		if err != nil {
			return nil, err
		}
	}

	return oauth2.NewClient(ctx, ts), nil
}

func deriveCacheName(config *oauth2.Config) string {
	hash := sha256.New()
	hash.Write([]byte(config.ClientID))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(strings.Join(config.Scopes, " ")))
	hashed := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashed)
}
