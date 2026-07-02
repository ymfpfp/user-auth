package oauth

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	GoogleConfigEndpoint string = "https://accounts.google.com/.well-known/openid-configuration"
)

// httpClient is shared by all outbound OAuth/OIDC requests so they get a
// bounded timeout instead of hanging on a slow or unresponsive provider.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// This is actually part of the OIDC specification.
type Config struct {
	// Unique issuer.
	Issuer string `json:"issuer"`
	// Authorization server endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	JWKSUri string `json:"jwks_uri,omitempty"`
	// Subject types are unique identification types for users.
	SubjectTypesSupported []string `json:"subject_types_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// Support scopes.
	ScopesSupported []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
}

func GetConfig(path string) (Config, error) {
	var config Config

	configResponse, err := httpClient.Get(path)
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
