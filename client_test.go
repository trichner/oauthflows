package oauthflows

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

//FIXME
const clientSecretsPath = "/the/path/to/client_secret.json"

func TestNewClient(t *testing.T) {
	t.Skip("e2e test")

	scopes := []string{"openid", "profile"}
	client, err := NewClient(WithClientSecretsFile(clientSecretsPath, scopes), WithFileTokenStore())
	assert.NoError(t, err)

	res, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	defer res.Body.Close()
	assert.NoError(t, err)

	data, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	fmt.Println(string(data))
}

func TestNewClient_ClientSecretsFile(t *testing.T) {
	t.Skip("e2e test")

	scopes := []string{"https://www.googleapis.com/auth/userinfo.profile", "openid", "email", "profile"}
	client, err := NewClient(WithClientSecretsFile(clientSecretsPath, scopes))
	assert.NoError(t, err)

	res, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	defer res.Body.Close()
	assert.NoError(t, err)

	data, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	fmt.Println(string(data))
}
