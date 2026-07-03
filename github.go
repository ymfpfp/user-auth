package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// githubAPIClient bounds calls to the GitHub REST API.
var githubAPIClient = &http.Client{Timeout: 10 * time.Second}

// Repo is a subset of the GitHub repository representation.
type Repo struct {
	Id          int64  `json:"id"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
}

func GetRepos(accessToken string) ([]Repo, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/repos", nil)
	if err != nil {
		return nil, err
	}

	// GitHub authenticates the caller from this bearer token, and requires
	// both an Accept and a User-Agent header (it rejects requests without one).
	req.Header.Set("Authorization", "Bearer " + accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "user-auth")

	response, err := githubAPIClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("github: unexpected status %d: %s", response.StatusCode, body)
	}

	var repos []Repo
	if err := json.NewDecoder(response.Body).Decode(&repos); err != nil {
		return nil, err
	}
	return repos, nil
}
