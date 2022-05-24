package oauthflows

import (
	"context"
	"golang.org/x/oauth2"
)

type cachedTokenStore struct {
	ctx       context.Context
	cacheName string
	source    oauth2.TokenSource
	store     TokenStore
}

func NewCachedTokenSource(ctx context.Context, cacheName string, store TokenStore, source oauth2.TokenSource) (oauth2.TokenSource, error) {
	return &cachedTokenStore{
		ctx:       ctx,
		cacheName: cacheName,
		store:     store,
		source:    source,
	}, nil
}

func (f *cachedTokenStore) Token() (*oauth2.Token, error) {
	key := f.cacheName
	token, err := f.store.Get(key)

	if err != nil {
		return nil, err
	}

	if token != nil {
		return token, nil
	}

	token, err = f.source.Token()
	if err != nil {
		return nil, err
	}
	if err := f.store.Put(key, token); err != nil {
		return nil, err
	}

	return token, nil
}
