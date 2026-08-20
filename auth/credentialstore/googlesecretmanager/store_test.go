// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package googlesecretmanager

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockSecretManagerClient is a thread-safe mock for Secret Manager client interface.
type mockSecretManagerClient struct {
	mu       sync.RWMutex
	secrets  map[string]*secretmanagerpb.Secret
	versions map[string][][]byte // secretName -> list of payloads
}

func newMockClient() *mockSecretManagerClient {
	return &mockSecretManagerClient{
		secrets:  make(map[string]*secretmanagerpb.Secret),
		versions: make(map[string][][]byte),
	}
}

func (m *mockSecretManagerClient) GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sec, ok := m.secrets[req.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return sec, nil
}

func (m *mockSecretManagerClient) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	secretName := fmt.Sprintf("%s/secrets/%s", req.Parent, req.SecretId)
	if _, exists := m.secrets[secretName]; exists {
		return nil, status.Error(codes.AlreadyExists, "secret already exists")
	}
	sec := req.Secret
	if sec == nil {
		sec = &secretmanagerpb.Secret{}
	}
	sec.Name = secretName
	m.secrets[secretName] = sec
	return sec, nil
}

func (m *mockSecretManagerClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[req.Parent]; !ok {
		return nil, status.Error(codes.NotFound, "secret parent not found")
	}
	payload := req.GetPayload().GetData()
	m.versions[req.Parent] = append(m.versions[req.Parent], payload)
	versionNum := len(m.versions[req.Parent])
	return &secretmanagerpb.SecretVersion{
		Name: fmt.Sprintf("%s/versions/%d", req.Parent, versionNum),
	}, nil
}

func (m *mockSecretManagerClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// e.g. "projects/my-project/secrets/my-secret/versions/latest"
	parts := strings.Split(req.Name, "/versions/")
	if len(parts) != 2 {
		return nil, status.Error(codes.InvalidArgument, "invalid version name")
	}
	secretName := parts[0]
	versionStr := parts[1]

	vers, ok := m.versions[secretName]
	if !ok || len(vers) == 0 {
		return nil, status.Error(codes.NotFound, "secret or version not found")
	}

	var payload []byte
	if versionStr == "latest" {
		payload = vers[len(vers)-1]
	} else {
		return nil, status.Error(codes.Unimplemented, "specific version not implemented in mock")
	}

	return &secretmanagerpb.AccessSecretVersionResponse{
		Name: req.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: payload,
		},
	}, nil
}

func (m *mockSecretManagerClient) Close() error {
	return nil
}

func TestSecretIDScheme(t *testing.T) {
	mockClient := newMockClient()
	store, err := New(context.Background(), &Config{
		Client:    mockClient,
		ProjectID: "test-project",
		Prefix:    "a2a-cred",
	})
	if err != nil {
		t.Fatalf("Failed to initialize store: %v", err)
	}

	email := "Alice.Smith@Example.COM"
	provider := "google"

	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte("alice.smith@example.com")))
	expectedSecretID := fmt.Sprintf("a2a-cred-%s-google", expectedHash)

	actualSecretID := store.SecretID(email, provider)
	if actualSecretID != expectedSecretID {
		t.Errorf("Expected secret ID %q, got %q", expectedSecretID, actualSecretID)
	}

	// Verify prefix + user-hash + provider order
	if !strings.HasPrefix(actualSecretID, "a2a-cred-"+expectedHash) {
		t.Errorf("Secret ID must start with prefix and user-hash: %s", actualSecretID)
	}
	if !strings.HasSuffix(actualSecretID, "-google") {
		t.Errorf("Secret ID must end with provider: %s", actualSecretID)
	}
}

func TestStoreSetAndGetCredential(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockClient()
	store, err := New(ctx, &Config{
		Client:    mockClient,
		ProjectID: "test-project",
		Prefix:    "test-prefix",
		CacheTTL:  1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to initialize store: %v", err)
	}

	email := "user@example.com"
	provider := "github"
	tokenData := []byte("ghp_secret_access_token_12345")

	// 1. Get before set should return not found
	_, err = store.GetCredential(ctx, email, provider)
	if err == nil {
		t.Fatalf("Expected error getting nonexistent credential, got nil")
	}
	if !strings.Contains(err.Error(), "credential not found") {
		t.Errorf("Expected 'credential not found' error message, got: %v", err)
	}

	// 2. Set credential
	if err := store.SetCredential(ctx, email, provider, tokenData); err != nil {
		t.Fatalf("Failed to set credential: %v", err)
	}

	// 3. Get credential
	gotData, err := store.GetCredential(ctx, email, provider)
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}
	if string(gotData) != string(tokenData) {
		t.Errorf("Expected %q, got %q", string(tokenData), string(gotData))
	}

	// 4. Update credential with new version
	newTokenData := []byte("ghp_rotated_token_67890")
	if err := store.SetCredential(ctx, email, provider, newTokenData); err != nil {
		t.Fatalf("Failed to update credential: %v", err)
	}

	gotNewData, err := store.GetCredential(ctx, email, provider)
	if err != nil {
		t.Fatalf("Failed to get updated credential: %v", err)
	}
	if string(gotNewData) != string(newTokenData) {
		t.Errorf("Expected %q, got %q", string(newTokenData), string(gotNewData))
	}
}

func TestDelegatedAuthProviderLazyLoading(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockClient()
	store, err := New(ctx, &Config{
		Client:    mockClient,
		ProjectID: "test-project",
	})
	if err != nil {
		t.Fatalf("Failed to initialize store: %v", err)
	}

	email := "alice@example.com"
	googleToken := []byte("google-oauth-token")
	githubToken := []byte("github-oauth-token")

	_ = store.SetCredential(ctx, email, "google", googleToken)
	_ = store.SetCredential(ctx, email, "github", githubToken)

	// DelegatedProvider creation is instant and lazy
	delegated := store.DelegatedProvider(ctx, email)
	if delegated == nil {
		t.Fatalf("DelegatedProvider returned nil")
	}
	if delegated.Email() != email {
		t.Errorf("Expected email %s, got %s", email, delegated.Email())
	}

	// Get existing provider credential via DelegatedAuthProvider
	gotGoogle, err := delegated.GetCredential(ctx, "google")
	if err != nil {
		t.Fatalf("Failed to get google credential via delegated provider: %v", err)
	}
	if string(gotGoogle) != string(googleToken) {
		t.Errorf("Expected %s, got %s", string(googleToken), string(gotGoogle))
	}

	gotGithub, err := delegated.GetCredential(ctx, "github")
	if err != nil {
		t.Fatalf("Failed to get github credential via delegated provider: %v", err)
	}
	if string(gotGithub) != string(githubToken) {
		t.Errorf("Expected %s, got %s", string(githubToken), string(gotGithub))
	}

	// Nonexistent provider
	_, err = delegated.GetCredential(ctx, "buffer")
	if err == nil {
		t.Fatalf("Expected error for missing provider, got nil")
	}
}

func TestMultiUserIsolation(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockClient()
	store, _ := New(ctx, &Config{
		Client:    mockClient,
		ProjectID: "test-project",
	})

	user1 := "user1@example.com"
	user2 := "user2@example.com"
	provider := "google"

	token1 := []byte("token-for-user1")
	token2 := []byte("token-for-user2")

	_ = store.SetCredential(ctx, user1, provider, token1)
	_ = store.SetCredential(ctx, user2, provider, token2)

	p1 := store.DelegatedProvider(ctx, user1)
	p2 := store.DelegatedProvider(ctx, user2)

	got1, err := p1.GetCredential(ctx, provider)
	if err != nil || string(got1) != string(token1) {
		t.Errorf("User 1 got wrong token: %v, err: %v", string(got1), err)
	}

	got2, err := p2.GetCredential(ctx, provider)
	if err != nil || string(got2) != string(token2) {
		t.Errorf("User 2 got wrong token: %v, err: %v", string(got2), err)
	}
}

func TestNilConfig(t *testing.T) {
	t.Setenv("GOOGLE_CLOUD_PROJECT", "env-project-123")
	mockClient := newMockClient()

	// When cfg is nil, default config is used.
	store, err := New(context.Background(), &Config{
		Client: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to initialize store: %v", err)
	}
	if store.projectID != "env-project-123" {
		t.Errorf("Expected project ID %q, got %q", "env-project-123", store.projectID)
	}
	if store.prefix != defaultSecretPrefix {
		t.Errorf("Expected prefix %q, got %q", defaultSecretPrefix, store.prefix)
	}
	if !store.cacheEnabled {
		t.Errorf("Expected cacheEnabled to be true by default")
	}
	if store.cacheTTL != defaultCacheTTL {
		t.Errorf("Expected cacheTTL %v, got %v", defaultCacheTTL, store.cacheTTL)
	}
	if store.negCacheTTL != defaultNegCacheTTL {
		t.Errorf("Expected negCacheTTL %v, got %v", defaultNegCacheTTL, store.negCacheTTL)
	}

	// Test with explicit nil config
	// (Will try to create a real client since Client is nil, but we can verify New accepts nil before attempting client init)
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("GCP_PROJECT", "")
	t.Setenv("GCLOUD_PROJECT", "")
	_, err = New(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "gcp project ID is required") {
		t.Errorf("Expected missing project ID error when passing nil config, got: %v", err)
	}

	// Test with omitted config New(ctx)
	_, err = New(context.Background())
	if err == nil || !strings.Contains(err.Error(), "gcp project ID is required") {
		t.Errorf("Expected missing project ID error when omitting config, got: %v", err)
	}
}

func TestConfigCustom(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockClient()
	cfg := &Config{
		ProjectID:        "test-project",
		Prefix:           "custom-prefix",
		CacheTTL:         2 * time.Minute,
		NegativeCacheTTL: 30 * time.Second,
		DisableCache:     false,
		Client:           mockClient,
	}

	store, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize store from config: %v", err)
	}

	if store.SecretID("user@example.com", "google") != fmt.Sprintf("custom-prefix-%x-google", sha256.Sum256([]byte("user@example.com"))) {
		t.Errorf("Secret ID does not reflect custom config prefix")
	}
	if store.cacheTTL != 2*time.Minute {
		t.Errorf("Expected cacheTTL 2m, got %v", store.cacheTTL)
	}
	if store.negCacheTTL != 30*time.Second {
		t.Errorf("Expected negCacheTTL 30s, got %v", store.negCacheTTL)
	}
}

func TestDisableCache(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockClient()
	cfg := &Config{
		ProjectID:    "test-project",
		Client:       mockClient,
		DisableCache: true,
	}

	store, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize store: %v", err)
	}
	if store.cacheEnabled {
		t.Errorf("Expected cacheEnabled to be false when DisableCache is true")
	}
}

func TestMissingProjectID(t *testing.T) {
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("GCP_PROJECT", "")
	t.Setenv("GCLOUD_PROJECT", "")

	_, err := New(context.Background(), nil)
	if err == nil {
		t.Fatalf("Expected error when project ID cannot be resolved, got nil")
	}
	if !strings.Contains(err.Error(), "gcp project ID is required") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestInterfaceSatisfaction(t *testing.T) {
	var _ auth.CredentialStore = (*Store)(nil)
}
