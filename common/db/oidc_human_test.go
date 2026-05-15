// Copyright (C) MongoDB, Inc. 2014-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mongodb/mongo-tools/common/testtype"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCE(t *testing.T) {
	testtype.SkipUnlessTestType(t, testtype.UnitTestType)
	require := require.New(t)

	verifier, challenge := generatePKCE()

	require.NotEmpty(verifier, "PKCE verifier is non-empty")
	require.NotEmpty(challenge, "PKCE challenge is non-empty")

	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	require.Equal(expected, challenge, "challenge is S256(verifier)")
}

func TestGenerateState(t *testing.T) {
	testtype.SkipUnlessTestType(t, testtype.UnitTestType)
	require := require.New(t)

	s1 := generateState()
	s2 := generateState()
	require.NotEmpty(s1, "state is non-empty")
	require.NotEqual(s1, s2, "consecutive states are unique")
}

func TestDiscoverOIDCEndpoints(t *testing.T) {
	testtype.SkipUnlessTestType(t, testtype.UnitTestType)
	require := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal("/.well-known/openid-configuration", r.URL.Path, "discovery path is correct")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint":         "https://idp.example.com/token",
		})
	}))
	defer srv.Close()

	endpoints, err := discoverOIDCEndpoints(context.Background(), srv.URL)
	require.NoError(err, "discoverOIDCEndpoints does not error")
	require.Equal(
		"https://idp.example.com/authorize",
		endpoints.AuthorizationEndpoint,
		"authorization_endpoint parsed correctly",
	)
	require.Equal(
		"https://idp.example.com/token",
		endpoints.TokenEndpoint,
		"token_endpoint parsed correctly",
	)
}

func TestDiscoverOIDCEndpointsMissingFields(t *testing.T) {
	testtype.SkipUnlessTestType(t, testtype.UnitTestType)
	require := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
			// token_endpoint intentionally omitted
		})
	}))
	defer srv.Close()

	_, err := discoverOIDCEndpoints(context.Background(), srv.URL)
	require.Error(err, "discoverOIDCEndpoints errors when token_endpoint is missing")
}

func TestRunAuthCodeFlowContextCancel(t *testing.T) {
	testtype.SkipUnlessTestType(t, testtype.UnitTestType)
	require := require.New(t)

	endpoints := &oidcEndpoints{
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := runAuthCodeFlow(ctx, endpoints, "client-id", []string{"openid"}, "")
	require.Error(err, "canceled context causes runAuthCodeFlow to return an error")
}
