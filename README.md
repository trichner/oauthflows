# OAuth2 Browser Flows for CLIs

Obtain OAuth2 tokens by sending users through the OAuth2 flow in a local webserver.

```go
scopes := []string{"openid", "profile"}
client, err := oauthflows.NewClient(oauthflows.WithClientSecretsFile(clientSecretsPath, scopes), oauthflows.WithFileTokenStore())
if err != nil {
log.Fatal(err)
}

res, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
defer res.Body.Close()
if err != nil {
log.Fatal(err)
}

data, err := io.ReadAll(res.Body)
if err != nil {
log.Fatal(err)
}

fmt.Println(string(data))
```