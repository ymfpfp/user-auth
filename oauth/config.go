package oauth

import (
	"encoding/json"
	"net/http"
)

const (
	GithubConfigEndpoint string = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
	GoogleConfigEndpoint string = "https://accounts.google.com/.well-known/openid-configuration"
)

// This is actually part of the OIDC specification.
type Config struct {
	Issuer string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	JWKSUri string `json:"jwks_uri"`
	SubjectTypesSupported []string `json:"subject_types_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
}

func GetConfig(path string) (Config, error) {
	var config Config

	configResponse, err := http.Get(path)
	if err != nil {
		return config, err
	}
	defer configResponse.Body.Close()

	err = json.NewDecoder(configResponse.Body).Decode(&config)
	if err != nil {
		return config, err
	}

	return config, nil
}
