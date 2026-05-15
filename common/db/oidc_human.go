// Copyright (C) MongoDB, Inc. 2014-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mongodb/mongo-tools/common/log"
	mopt "go.mongodb.org/mongo-driver/v2/mongo/options"
)

type oidcEndpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// makeHumanCallback returns an OIDCCallback that implements the authorization
// code + PKCE flow. redirectURIOverride, if non-empty, sets the redirect URI;
// otherwise a random localhost port is chosen at callback time.
func makeHumanCallback(redirectURIOverride string) mopt.OIDCCallback {
	return func(ctx context.Context, args *mopt.OIDCArgs) (*mopt.OIDCCredential, error) {
		if args.IDPInfo == nil {
			return nil, fmt.Errorf(
				"OIDC human flow: server did not provide IdP information",
			)
		}

		endpoints, err := discoverOIDCEndpoints(ctx, args.IDPInfo.Issuer)
		if err != nil {
			return nil, fmt.Errorf(
				"OIDC human flow: endpoint discovery failed: %w",
				err,
			)
		}

		// Try refresh token first to avoid a browser round-trip.
		if args.RefreshToken != nil {
			cred, refreshErr := refreshAccessToken(
				ctx,
				endpoints.TokenEndpoint,
				args.IDPInfo.ClientID,
				*args.RefreshToken,
			)
			if refreshErr == nil {
				return cred, nil
			}
			log.Logvf(
				log.DebugLow,
				"OIDC refresh token failed, falling back to browser flow: %v",
				refreshErr,
			)
		}

		return runAuthCodeFlow(
			ctx,
			endpoints,
			args.IDPInfo.ClientID,
			args.IDPInfo.RequestScopes,
			redirectURIOverride,
		)
	}
}

// runAuthCodeFlow performs the full authorization code + PKCE exchange.
func runAuthCodeFlow(
	ctx context.Context,
	endpoints *oidcEndpoints,
	clientID string,
	scopes []string,
	redirectURIOverride string,
) (*mopt.OIDCCredential, error) {
	// Default matches mongosh so the same Azure app registration works
	// without extra configuration.
	if redirectURIOverride == "" {
		redirectURIOverride = "http://localhost:27097/redirect"
	}

	u, err := url.Parse(redirectURIOverride)
	if err != nil {
		return nil, fmt.Errorf(
			"OIDC human flow: invalid oidcRedirectUri: %w",
			err,
		)
	}

	listenPort, _ := strconv.Atoi(u.Port())
	listenAddr := fmt.Sprintf("%s:%d", u.Hostname(), listenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf(
			"OIDC human flow: could not bind to %s: %w",
			listenAddr,
			err,
		)
	}

	// If the port was 0 the OS picked one; update the redirect URI to match.
	redirectURI := redirectURIOverride
	if listenPort == 0 {
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			panic("OIDC: listener address is not a TCP address")
		}
		redirectURI = fmt.Sprintf(
			"%s://%s:%d%s",
			u.Scheme,
			u.Hostname(),
			tcpAddr.Port,
			u.Path,
		)
	}

	callbackPath := u.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	verifier, challenge := generatePKCE()
	state := generateState()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("OIDC human flow: state mismatch in redirect")
			return
		}
		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			http.Error(w, "authentication error", http.StatusBadRequest)
			errCh <- fmt.Errorf(
				"OIDC human flow: IdP returned error %q: %s",
				errParam,
				desc,
			)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf(
				"OIDC human flow: redirect did not contain authorization code",
			)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(
			w,
			"<html><body><p>Authentication successful. "+
				"You may close this window.</p></body></html>",
		)
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(listener)
	}()
	defer srv.Close()
	scopeStr := "openid"
	if len(scopes) > 0 {
		scopeStr = strings.Join(scopes, " ")
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopeStr},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := endpoints.AuthorizationEndpoint + "?" + params.Encode()

	log.Logvf(log.Always, "Opening browser for OIDC authentication...")
	if openErr := openBrowser(authURL); openErr != nil {
		// Browser open failed — print URL so user can open it manually.
		log.Logvf(
			log.Always,
			"Could not open browser automatically. "+
				"Visit the following URL to authenticate:\n%s",
			authURL,
		)
	}

	select {
	case code := <-codeCh:
		return exchangeCodeForToken(
			ctx,
			endpoints.TokenEndpoint,
			clientID,
			code,
			verifier,
			redirectURI,
		)
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"OIDC human flow: timed out waiting for browser authentication",
		)
	}
}

func discoverOIDCEndpoints(
	ctx context.Context,
	issuer string,
) (*oidcEndpoints, error) {
	discoveryURL := strings.TrimSuffix(issuer, "/") +
		"/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"discovery endpoint returned HTTP %d",
			resp.StatusCode,
		)
	}
	var endpoints oidcEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return nil, err
	}
	if endpoints.AuthorizationEndpoint == "" || endpoints.TokenEndpoint == "" {
		return nil, fmt.Errorf(
			"discovery document missing authorization_endpoint or token_endpoint",
		)
	}
	return &endpoints, nil
}

// generatePKCE returns a base64url-encoded verifier and its S256 challenge.
func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("OIDC: failed to generate PKCE verifier: " + err.Error())
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func generateState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("OIDC: failed to generate state: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(rawURL string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{rawURL}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		cmd = "xdg-open"
		args = []string{rawURL}
	}
	return exec.Command(cmd, args...).Start()
}

func exchangeCodeForToken(
	ctx context.Context,
	tokenEndpoint, clientID, code, verifier, redirectURI string,
) (*mopt.OIDCCredential, error) {
	return doTokenRequest(ctx, tokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
}

func refreshAccessToken(
	ctx context.Context,
	tokenEndpoint, clientID, refreshToken string,
) (*mopt.OIDCCredential, error) {
	return doTokenRequest(ctx, tokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
}

func doTokenRequest(
	ctx context.Context,
	tokenEndpoint string,
	form url.Values,
) (*mopt.OIDCCredential, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		tokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"token endpoint returned HTTP %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response did not contain an access token")
	}

	cred := &mopt.OIDCCredential{
		AccessToken: tr.AccessToken,
	}
	if tr.ExpiresIn > 0 {
		exp := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
		cred.ExpiresAt = &exp
	}
	if tr.RefreshToken != "" {
		cred.RefreshToken = &tr.RefreshToken
	}
	return cred, nil
}
