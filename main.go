package main

import (
	"database/sql"
	"encoding/hex"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/ymfpfp/user-auth/data"
	"github.com/ymfpfp/user-auth/github"
	"github.com/ymfpfp/user-auth/oauth"
	"github.com/ymfpfp/user-auth/utils"
)

type Config struct {
	GoogleClientId string
	GoogleClientSecret string

	GithubClientId string
	GithubClientSecret string

	Port string

	RootKey []byte
}

type Handler struct {
	db *sql.DB
	config *Config
	mailer *Mailer
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

	rootKey, err := hex.DecodeString(os.Getenv("ROOT_KEY"))
	if err != nil {
		log.Fatal("Invalid ROOT_KEY: ", err)
	}

	config := Config{
		GoogleClientId: os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),

		GithubClientId: os.Getenv("GITHUB_CLIENT_ID"),
		GithubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),

		Port: port,

		RootKey: rootKey,
	}

	db := data.NewDb()
	defer db.Close()

	h := &Handler{
		db: db,
		config: &config,
		mailer: NewSESMailerFromEnv(),
	}

	// Set up new server mux.
	serveMux := http.NewServeMux()

	serveMux.HandleFunc("/", index)
	serveMux.HandleFunc("/login/email", h.emailLogin)
	serveMux.HandleFunc("/login/email/{code}", h.emailVerify)
	serveMux.Handle("/loggedIn", h.Authenticated(http.HandlerFunc(h.loggedIn)))
	serveMux.Handle("/logout", h.Authenticated(http.HandlerFunc(h.logout)))

	googleConfig, err := oauth.GetConfig(oauth.GoogleConfigEndpoint)
	if err != nil {
		log.Fatal("Unable to configure Google OIDC ", err)
	}
	googleClient := oauth.Client{
		Callback: "/oauth2/google",
		Id:       config.GoogleClientId,
		Scopes:   "openid email profile",
		Secret:   config.GoogleClientSecret,
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

			// Upsert user and provider.
			id, _, err := h.UpsertLoginFromClaims(claims)
			if id < 0 {
				log.Print(err)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Create a new session.
			// Get device and IP addr.
			device := r.UserAgent()
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			session, err := h.CreateSession(id, ip, device, time.Hour * 24 * 7)
			if err != nil {
				log.Print(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if err := h.RecordActivity(id, "Logged in via Google from " + ip); err != nil {
				log.Print(err)
			}

			// Return session cookie.
			http.SetCookie(w, &http.Cookie{
				Name: "session",
				Value: session,
				HttpOnly: true,
				Path: "/",
			})

			http.Redirect(w, r, "/loggedIn", http.StatusFound)
		},
	)))

	// In typical OAuth libraries, these are pre-filled properly for you;
	// here we'll fill them just with what we need.
	//
	// GitHub access tokens are long-lived. Typical OAuth apps will have get a
	// refresh token to maintain longevity; in that case, we'd also store a refresh token in
	// the db.
	githubConfig := oauth.Config{
		Issuer: "GitHub",
		AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
		TokenEndpoint: "https://github.com/login/oauth/access_token",
		ResponseTypesSupported: []string{"code"},
		ScopesSupported: []string{"repo", "read:user", "user:email"},
	}
	githubClient := oauth.Client{
		Callback: "/oauth2/github",
		Id: config.GithubClientId,
		Scopes: "repo read:user user:email",
		Secret: config.GithubClientSecret,
	}
	githubProvider := oauth.NewGithubOIDCProvider(githubConfig, githubClient)
	serveMux.Handle("/connect/github", h.Authenticated(githubProvider.Redirect()))
	serveMux.Handle("/oauth2/github", h.Authenticated(githubProvider.Callback(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// todo(jc): Implement "Connect with GitHub" and remove auth gate.

			ctx := r.Context()
			session, ok := SessionFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			tokens, ok := oauth.TokensFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			claims, ok := oauth.ClaimsFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Store GitHub as a provider.
			err := h.LinkProvider(session.IdentityId, claims.Issuer, claims.Subject, tokens.AccessToken)
			if err != nil {
				log.Print(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
		},
	))))

	mux := DrainAndClose(serveMux)

	server := &http.Server{
		Addr: "localhost:" + config.Port,
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
	// To serve over TLS, need a trusted signed cert file and a private key.
	// Generate local test one with mkcert, openssl, etc.
	err = server.ServeTLS(listener, "cert.pem", "private.pem")
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

var htmlTemplates = template.Must(
	template.New("loggedIn.html").Funcs(template.FuncMap{
		"date": func(ts int64) string {
			return time.Unix(ts, 0).Format("Jan 2, 2006 3:04 PM MST")
		},
	}).ParseFiles("templates/loggedIn.html"),
)

func index(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err == nil {
		// Try redirecting to /loggedIn, where the authentication middleware will run.
		http.Redirect(w, r, "/loggedIn", http.StatusSeeOther)
		return
	}

	html := `
	<!doctype html>
	<html>
		<head></head>
		<body>
			<p><a href="/login/google">Continue with Google</a><p>
			<form action="/login/email" method="POST">
				<input type="email" name="email" required />
				<button>Continue with email</button>
			</form>
			<p><a href="/login/saml">Continue with SAML SSO</a></p>
			<p><a href="/login/passkey">Login with passkey</a></p>
		</body>
	</html>
	`
	w.Write([]byte(html))
}

func (h *Handler) loggedIn(w http.ResponseWriter, r *http.Request) {
	activeSession, ok := SessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get active sessions.
	sessions, _ := h.GetActiveSessions(activeSession.IdentityId)

	// Get recent activity.
	activities, _ := h.GetRecentActivities(activeSession.IdentityId, 10)

	// Try to get repos. Skipped silently if GitHub isn't connected (no token)
	// or the call fails — the page still renders, just without repos.
	var repos []github.Repo
	if token, err := h.GetProviderToken(activeSession.IdentityId, "GitHub"); err != nil {
		log.Print(err)
	} else if token != "" {
		if repos, err = github.GetRepos(token); err != nil {
			log.Print(err)
		}
	}

	log.Print(repos)

	err := htmlTemplates.ExecuteTemplate(w, "loggedIn.html", map[string]any{
		"Name": activeSession.Name,
		"Email": activeSession.Email,
		"Sessions": sessions,
		"Activities": activities,
		"Repos": repos,
	})
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	activeSession, ok := SessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.RevokeSession(activeSession.Id)

	if err := h.RecordActivity(activeSession.IdentityId, "Logged out"); err != nil {
		log.Print(err)
	}

	utils.ClearCookies(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}
