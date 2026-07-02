package main

import (
	"database/sql"
	"encoding/json"
	// "html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/ymfpfp/user-auth/data"
	"github.com/ymfpfp/user-auth/oauth"
)

type Config struct {
	GoogleClientId string
	GoogleClientSecret string

	GithubClientId string
	GithubClientSecret string

	Port string
}

type Handler struct {
	db *sql.DB
	config *Config
	sessions *data.Sessions
}

func main() {
	godotenv.Load()

	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "9000"
	} else {
		_, err := strconv.Atoi(port)
		if err != nil {
			port = "9000"
		}
	}

	config := Config {
		GoogleClientId: os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),

		GithubClientId: os.Getenv("GITHUB_CLIENT_ID"),
		GithubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),

		Port: port,
	}

	db := data.NewDb()
	defer db.Close()

	h := &Handler{
		db: db,
		config: &config,
		sessions: data.EmptySession(),
	}
	_ = h

	// Set up new server mux.
	serveMux := http.NewServeMux()

	serveMux.HandleFunc("/", index)

	googleConfig, err := oauth.GetConfig(oauth.GoogleConfigEndpoint)
	if err != nil {
		log.Fatal("Unable to configure Google OIDC ", err)
	}
	googleClient := oauth.Client{
		Callback: "/oauth2/google", 
		Id: config.GoogleClientId,
		Scopes: "openid email profile",
		Secret: config.GoogleClientSecret,
	}
	googleProvider := oauth.NewOIDCProvider(googleConfig, googleClient) 
	serveMux.Handle("/login/google", googleProvider.Redirect())
	serveMux.Handle("/oauth2/google", googleProvider.Callback(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			claims, ok := oauth.ClaimsFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(claims)
		},
	)))

	githubConfig := oauth.Config{
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
	}
	githubClient := oauth.Client{
		Callback: "/oauth2/github",
		Id: config.GithubClientId,
		Scopes: "profile",
		Secret: config.GithubClientSecret,
	}

	mux := drainAndClose(serveMux)

	server := &http.Server{
		Addr: "127.0.0.1:" + config.Port,
		Handler: http.TimeoutHandler(
			mux,
			2 * time.Minute,
			"",
		),
		IdleTimeout: 5 * time.Minute,
		ReadHeaderTimeout: time.Minute,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Listening on ", server.Addr)
	err = server.Serve(listener)
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func drainAndClose(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

func index(w http.ResponseWriter, r *http.Request) {
	html := `
	<!doctype html>
	<html>
		<head></head>
		<body>
			<p><a href="/login/google">Continue with Google</a><p>
			<p><a href="/login/email">Continue with email</a></p>
			<p><a href="/login/saml">Continue with SAML SSO</a></p>
			<p><a href="/login/passkey">Login with passkey</a></p>
		</body>
	</html>
	`
	w.Write([]byte(html))
}

