package oauth

type contextKey string

const (
	tokensKey contextKey = "tokens"
	claimsKey contextKey = "claims"
)

