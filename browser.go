package oauthflows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/http/httptest"
	"os/exec"
)

type browserTokenSource struct {
	ctx  context.Context
	conf *oauth2.Config
}

func (b *browserTokenSource) Token() (*oauth2.Token, error) {
	return ExecuteOAuth2BrowserTokenFlow(b.ctx, b.conf)
}

func NewBrowserFlowTokenSource(ctx context.Context, conf *oauth2.Config) (oauth2.TokenSource, error) {
	ts := &browserTokenSource{conf: conf, ctx: ctx}
	return oauth2.ReuseTokenSource(nil, ts), nil
}

func ExecuteOAuth2BrowserTokenFlow(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	ch := make(chan string)

	randState := generateNonce()
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			http.Error(rw, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			log.Printf("state doesn't match: req = %#v", req)
			http.Error(rw, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			fmt.Fprintf(rw, "<h1>Success 🥳</h1>Authorized.")
			rw.(http.Flusher).Flush()
			ch <- code
			return
		}
		log.Printf("no code")
		http.Error(rw, "", 500)
	}))
	defer ts.Close()

	conf.RedirectURL = ts.URL
	authURL := conf.AuthCodeURL(randState)
	go openURL(authURL)
	log.Printf("Authorize this app at: %s", authURL)
	code := <-ch
	log.Printf("Got code: %s", code)

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange error: %w", err)
	}
	return token, nil
}

func openURL(url string) {
	try := []string{"xdg-open", "google-chrome", "open"}
	for _, bin := range try {
		err := exec.Command(bin, url).Run()
		if err == nil {
			return
		}
	}
	log.Printf("Error opening URL in browser.")
}

func generateNonce() string {

	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		panic(fmt.Errorf("cannot create random string: %w", err))
	}
	return hex.EncodeToString(buf)
}
