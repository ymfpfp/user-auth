package main

import (
	"database/sql"
	"html/template"

	// "html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/ymfpfp/user-auth/data"
	"github.com/ymfpfp/user-auth/oauth"
	"github.com/ymfpfp/user-auth/utils"
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
	}
	_ = h

	// Set up new server mux.
	serveMux := http.NewServeMux()

	serveMux.HandleFunc("/", index)
	serveMux.Handle("/loggedIn", h.Authenticated(http.HandlerFunc(h.loggedIn)))
	serveMux.Handle("/logout", h.Authenticated(http.HandlerFunc(h.logout)))

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

			// Upsert user and provider.
			name, ok := utils.Get[string](claims.Raw, "name")
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			email, ok := utils.Get[string](claims.Raw, "email")
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			id, _, err := h.UpsertLogin(claims.Issuer, claims.Subject, name, email)
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

	// githubConfig := oauth.Config{
	// 	AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
	// }
	// githubClient := oauth.Client{
	// 	Callback: "/oauth2/github",
	// 	Id: config.GithubClientId,
	// 	Scopes: "profile",
	// 	Secret: config.GithubClientSecret,
	// }

	mux := DrainAndClose(serveMux)

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

var htmlTemplates = template.Must(
	template.New("loggedIn").Funcs(template.FuncMap{
		"date": func(ts int64) string {
			return time.Unix(ts, 0).Format("Jan 2, 2006 3:04 PM MST")
		},
	}).Parse(`
		<!doctype html>
		<html>
			<head></head>
			<body>
				<p>Logged in as {{.Name}} at {{.Email}}!</p>
				<h2>Active Sessions</h2>
				{{range .Sessions}}
					<hr>
					<p>{{.IpAddr}}</p>
					<p>{{.Device}}</p>
					<p>Signed in on {{.Created | date}}</p>
					<p>Expires on {{.ExpiresAt | date}}<p>
					<hr>
				{{end}}
				<h2>Recent Activity</h2>
				{{range .Activities}}
					<p>{{.Action}} on {{.Created | date}}</p>
				{{else}}
					<p>No recent activity.</p>
				{{end}}
				<p><a href="/logout">Log out</a></p>
			</body>
		</html>
	`),
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
			<p><a href="/login/email">Continue with email</a></p>
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

	err := htmlTemplates.ExecuteTemplate(w, "loggedIn", map[string]any{
		"Name": activeSession.Name,
		"Email": activeSession.Email,
		"Sessions": sessions,
		"Activities": activities,
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
