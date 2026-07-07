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
	"github.com/ymfpfp/user-auth/email"
	"github.com/ymfpfp/user-auth/github"
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
	mailer *email.Mailer
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

	db := newDB()
	defer db.Close()

	h := &Handler{
		db: db,
		config: &config,
		mailer: email.NewSESMailerFromEnv(),
	}

	// Set up new server mux.
	serveMux := http.NewServeMux()

	serveMux.HandleFunc("/", index)
	serveMux.Handle("/loggedIn", h.authenticated(http.HandlerFunc(h.loggedIn)))
	serveMux.Handle("/logout", h.authenticated(http.HandlerFunc(h.logout)))

	// Don't strip prefix for pendantry.
	serveMux.Handle("/oauth/", oauthMux(h))
	serveMux.Handle("/login/email/", http.StripPrefix("/login/email", emailMux(h)))

	mux := drainAndClose(serveMux)

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
			<p><a href="/oauth/login/google">Continue with Google</a><p>
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
	activeSession, ok := sessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get active sessions.
	sessions, _ := h.getActiveSessions(activeSession.IdentityId)

	// Get recent activity.
	activities, _ := h.getRecentActivities(activeSession.IdentityId, 10)

	// Try to get repos. Skipped silently if GitHub isn't connected (no token)
	// or the call fails — the page still renders, just without repos.
	var repos []github.Repo
	if token, err := h.getProviderToken(activeSession.IdentityId, "GitHub"); err != nil {
		log.Print(err)
	} else if token != "" {
		if repos, err = github.GetRepos(token); err != nil {
			log.Print(err)
		}
	}

	// Generate a challenge for passkey, if user doesn't already have one.
	challenge, err := h.passkeyChallenge(activeSession.IdentityId)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	err = htmlTemplates.ExecuteTemplate(w, "loggedIn.html", map[string]any{
		"Id": activeSession.IdentityId,
		"Challenge": challenge,
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
	activeSession, ok := sessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.revokeSession(activeSession.Id)

	if err := h.recordActivity(activeSession.IdentityId, "Logged out"); err != nil {
		log.Print(err)
	}

	clearCookies(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}
