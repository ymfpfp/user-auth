package oauth

import (
	"context"
	"strconv"

	"github.com/ymfpfp/user-auth/github"
)

type GithubOIDCResolver struct {
	Issuer string
}

func NewGithubOIDCProvider(config Config, client Client) Provider {
	return Provider{
		Client: client,
		Config: config,
		Resolver: &GithubOIDCResolver{
			Issuer: config.Issuer,
		},
	}
}

func (resolver *GithubOIDCResolver) Resolve(tokens Tokens, ctx context.Context) (context.Context, error) {
	// We will manually inject claims by using `access_token` to grab user data.
	claims := OIDCClaims{
		Issuer: resolver.Issuer,
		Raw:    map[string]any{},
	}

	user, err := github.GetUser(tokens.AccessToken)
	if err != nil {
		return ctx, err
	}

	email, err := github.GetEmail(tokens.AccessToken)
	if err != nil {
		return ctx, err
	}

	claims.Subject = strconv.FormatInt(user.Id, 10)
	if len(user.Name) != 0 {
		claims.Raw["name"] = user.Name
	} else {
		// Use username as backup.
		claims.Raw["name"] = user.Username
	}
	claims.Raw["email"] = email

	return context.WithValue(ctx, claimsKey, claims), nil
}
