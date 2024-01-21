package oauthflows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

type config struct {
	tokenStore          TokenStore
	oauthConfig         *oauth2.Config
	failOnMissingScopes bool
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
		slurp, err := os.ReadFile(filepath)
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

func FailOnMissingScopes(doFail bool) ClientOption {
	return func(c *config) error {
		c.failOnMissingScopes = doFail
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

	tkn, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get a token: %w", err)
	}

	err = verifyScopes(tkn.AccessToken, c.oauthConfig.Scopes)
	if errors.Is(err, ErrMissingScopes) {
		if c.failOnMissingScopes {
			return nil, err
		}
		log.Printf("actual token lacks requested scopes: %v", err)
	} else if err != nil {
		return nil, err
	}

	return oauth2.NewClient(ctx, ts), nil
}

var ErrMissingScopes = errors.New("missing scopes")

func verifyScopes(accessToken string, scopes []string) error {

	info, err := introspectAccessToken(accessToken)
	if err != nil {
		return fmt.Errorf("failed to verify scopes: %w", err)
	}

	actual := strings.Split(info.Scope, " ")
	missing := subtractList(scopes, actual)
	if len(missing) > 0 {
		return fmt.Errorf("missing scopes, expected at least %v but got %v missing %v: %w", scopes, actual, missing, ErrMissingScopes)
	}

	return nil
}

func subtractList(all []string, subtrahend []string) []string {
	var remaining []string
	for _, s := range all {
		if !slices.Contains(subtrahend, s) {
			remaining = append(remaining, s)
		}
	}
	return remaining
}

type introspectedToken struct {
	IssuedTo      string `json:"issued_to"`
	Audience      string `json:"audience"`
	UserId        string `json:"user_id"`
	Scope         string `json:"scope"`
	ExpiresIn     int    `json:"expires_in"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	AccessType    string `json:"access_type"`
}

func introspectAccessToken(accessToken string) (*introspectedToken, error) {

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	var tokenInfoEndpoint = "https://www.googleapis.com/oauth2/v1/tokeninfo"
	res, err := client.Get(tokenInfoEndpoint + "?access_token=" + accessToken)

	if err != nil {
		return nil, fmt.Errorf("failed to introspect access token at %q: %w", tokenInfoEndpoint, err)
	}
	defer res.Body.Close()

	txt, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read access token introspection: %w", err)
	}

	var body introspectedToken
	err = json.Unmarshal(txt, &body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token introspection: %w", err)
	}

	return &body, nil
}

type jwtPayload struct {
	Scope string `json:"scope"`
}

func deriveCacheName(config *oauth2.Config) string {
	hash := sha256.New()
	hash.Write([]byte(config.ClientID))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(strings.Join(config.Scopes, " ")))
	hashed := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashed)
}
