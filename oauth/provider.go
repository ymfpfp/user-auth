package oauth

import (
	"log"

	"github.com/ymfpfp/user-auth/jwt"
)

type Client struct {
	Callback string

	Id string
	Secret string

	Scopes string 
}

// A provider is made up of config info, client specific info, and a resolver which is just 
// a callback that performs either OAuth or OIDC.
type Provider struct {
	Client Client
	Config Config
	Resolver Resolver
}

func NewOIDCProvider(config Config, client Client) Provider {
	jwks, err := jwt.GetJWKS(config.JWKSUri)
	if err != nil {
		log.Fatalf("Unable to get JWKS for provider %s: %v", config.Issuer, err)
	}

	return Provider{
		Client: client,
		Config: config,
		Resolver: &OIDCResolver{
			JWKS: jwks,
			ToVerify: OIDCVerification{
				Audience: client.Id,
				Issuer: config.Issuer,
			},
		},
	}
}
