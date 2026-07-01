package oauth

import "github.com/ymfpfp/user-auth/utils"

type Client struct {
	Callback string
	Id string
	Scopes string 
	Secret string
}

// A provider is made up of config info and client specific info.
type Provider struct {
	Config Config
	Client Client
}

// todo(jc): I think a lot of OAuth libraries have specific code for specific providers
// and maybe that's something we could figure out.
func (p Provider) PreferredResponseType() string {
	if len(p.Config.ResponseTypesSupported) == 1 {
		return p.Config.ResponseTypesSupported[0]
	}
	// In the OAuth standard, `response_type` is fixed to `token` but nowadays 
	// Authorization Code Flow with `code` is preferred - you get an authorization code,
	// then exchange it server-side for tokens, rather than getting a token directly back
	// which is bad for security and also bad for refresh tokens.
	if utils.Contains(p.Config.ResponseTypesSupported, "code") {
		return "code"
	}

	return "token"
}
