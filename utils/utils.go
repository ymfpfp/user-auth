package utils

import "net/http"

func ClearCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			HttpOnly: true,
			MaxAge:   -1,
			Path:     "/",
			// Secure: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func Get[T any](m map[string]any, key string) (T, bool) {
    v, ok := m[key]
    if !ok {
        var zero T
        return zero, false
    }

    t, ok := v.(T)
    if !ok {
        var zero T
        return zero, false
    }

    return t, true
}
