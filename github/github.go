package github

// todo(jc): Errors in this file

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var githubAPIClient = &http.Client{Timeout: 10 * time.Second}

// User is a subset of the GitHub authenticated-user representation.
type User struct {
	Id       int64  `json:"id"`
	Username string `json:"login"`
	Name     string `json:"name"`
}

func GetUser(accessToken string) (User, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return User{}, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "user-auth")

	response, err := githubAPIClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return User{}, fmt.Errorf("github: unexpected status %d: %s", response.StatusCode, body)
	}

	var user User
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		return User{}, err
	}
	return user, nil
}

func GetEmail(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "user-auth")

	response, err := githubAPIClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("github: unexpected status %d: %s", response.StatusCode, body)
	}

	type Email struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	var emails []Email
	if err := json.NewDecoder(response.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}
	return "", fmt.Errorf("github: no primary verified email found")
}

type Repo struct {
	Id          int64  `json:"id"`
	Name        string `json:"name"`
	Url         string `json:"html_url"`
	Description string `json:"description"`
}

// perPage is GitHub's maximum page size for the repos listing.
const perPage = 100

func GetRepos(accessToken string) ([]Repo, error) {
	var repos []Repo

	// type=owner limits the result to repos the authenticated user owns
	// (excludes ones they only collaborate on or access via an org).
	// We walk pages until GitHub returns a short (under a full) page,
	// which means there's nothing left to fetch.
	for page := 1; ; page++ {
		url := fmt.Sprintf(
			"https://api.github.com/user/repos?type=owner&per_page=%d&page=%d",
			perPage, page,
		)
		pageRepos, err := getRepoPage(accessToken, url)
		if err != nil {
			return nil, err
		}

		repos = append(repos, pageRepos...)
		if len(pageRepos) < perPage {
			break
		}
	}

	return repos, nil
}

func getRepoPage(accessToken, url string) ([]Repo, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// GitHub authenticates the caller from this bearer token, and requires
	// both an Accept and a User-Agent header (it rejects requests without one).
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
