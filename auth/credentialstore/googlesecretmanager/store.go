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
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultSecretPrefix = "a2a-cred"
	defaultCacheTTL     = 5 * time.Minute
	defaultNegCacheTTL  = 1 * time.Minute
	labelManagedBy      = "a2a-agenthost"
)

var labelSanitizer = regexp.MustCompile(`[^a-z0-9_-]`)

// Client defines the interface for interacting with Google Cloud Secret Manager.
type Client interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	Close() error
}

type cacheEntry struct {
	value     []byte
	err       error
	expiresAt time.Time
}

// Config holds the configuration options for Store.
type Config struct {
	ProjectID        string
	Prefix           string
	Replication      *secretmanagerpb.Replication
	CacheTTL         time.Duration
	NegativeCacheTTL time.Duration
	DisableCache     bool
	Client           Client
	ClientOptions    []option.ClientOption
}

// Store implements auth.CredentialStore using Google Cloud Secret Manager.
type Store struct {
	client           Client
	projectID        string
	prefix           string
	replication      *secretmanagerpb.Replication
	cacheTTL         time.Duration
	negCacheTTL      time.Duration
	cacheEnabled     bool
	cacheMu          sync.RWMutex
	cache            map[string]cacheEntry
	closeClientOnEnd bool
}

// New creates a new Store instance implementing auth.CredentialStore with Google Secret Manager.
// If cfg is omitted, nil, or empty, default configuration is used.
func New(ctx context.Context, cfg ...*Config) (*Store, error) {
	var c *Config
	if len(cfg) > 0 && cfg[0] != nil {
		c = cfg[0]
	} else {
		c = &Config{}
	}

	prefix := c.Prefix
	if prefix == "" {
		prefix = defaultSecretPrefix
	}

	cacheTTL := c.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}

	negCacheTTL := c.NegativeCacheTTL
	if negCacheTTL <= 0 {
		negCacheTTL = defaultNegCacheTTL
	}

	replication := c.Replication
	if replication == nil {
		replication = &secretmanagerpb.Replication{
			Replication: &secretmanagerpb.Replication_Automatic_{
				Automatic: &secretmanagerpb.Replication_Automatic{},
			},
		}
	}

	projectID := c.ProjectID
	if projectID == "" {
		projectID = resolveProjectID()
	}
	if projectID == "" && c.Client == nil {
		return nil, fmt.Errorf("gcp project ID is required for secret manager credential store")
	}

	client := c.Client
	closeClientOnEnd := false
	if client == nil {
		var smClient *secretmanager.Client
		var err error
		if len(c.ClientOptions) > 0 {
			smClient, err = secretmanager.NewClient(ctx, c.ClientOptions...)
		} else {
			smClient, err = secretmanager.NewClient(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create secret manager client: %w", err)
		}
		client = smClient
		closeClientOnEnd = true
	}

	return &Store{
		client:           client,
		projectID:        projectID,
		prefix:           prefix,
		replication:      replication,
		cacheTTL:         cacheTTL,
		negCacheTTL:      negCacheTTL,
		cacheEnabled:     !c.DisableCache,
		cache:            make(map[string]cacheEntry),
		closeClientOnEnd: closeClientOnEnd,
	}, nil
}

func resolveProjectID() string {
	if p := os.Getenv("GOOGLE_CLOUD_PROJECT"); p != "" {
		return p
	}
	if p := os.Getenv("GCP_PROJECT"); p != "" {
		return p
	}
	if p := os.Getenv("GCLOUD_PROJECT"); p != "" {
		return p
	}
	return ""
}

// SecretID derives the Secret Manager secret ID using: prefix + "-" + user-hash + "-" + provider.
func (s *Store) SecretID(email string, provider string) string {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	userHash := fmt.Sprintf("%x", sha256.Sum256([]byte(normalizedEmail)))
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedProvider = labelSanitizer.ReplaceAllString(normalizedProvider, "_")

	return fmt.Sprintf("%s-%s-%s", s.prefix, userHash, normalizedProvider)
}

func (s *Store) cacheKey(email string, provider string) string {
	return strings.ToLower(strings.TrimSpace(email)) + ":" + strings.ToLower(strings.TrimSpace(provider))
}

func (s *Store) labels(email string, provider string) map[string]string {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	userHash := fmt.Sprintf("%x", sha256.Sum256([]byte(normalizedEmail)))
	if len(userHash) > 63 {
		userHash = userHash[:63]
	}

	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedProvider = labelSanitizer.ReplaceAllString(normalizedProvider, "_")
	if len(normalizedProvider) > 63 {
		normalizedProvider = normalizedProvider[:63]
	}

	return map[string]string{
		"managed-by": labelManagedBy,
		"user-hash":  userHash,
		"provider":   normalizedProvider,
	}
}

func (s *Store) annotations(email string) map[string]string {
	return map[string]string{
		"user-email": strings.TrimSpace(email),
	}
}

// GetCredential retrieves a credential from Google Secret Manager.
func (s *Store) GetCredential(ctx context.Context, email string, provider string) ([]byte, error) {
	ck := s.cacheKey(email, provider)

	if s.cacheEnabled {
		s.cacheMu.RLock()
		if entry, ok := s.cache[ck]; ok && time.Now().Before(entry.expiresAt) {
			s.cacheMu.RUnlock()
			if entry.err != nil {
				return nil, entry.err
			}
			return entry.value, nil
		}
		s.cacheMu.RUnlock()
	}

	secretID := s.SecretID(email, provider)
	versionName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", s.projectID, secretID)

	resp, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			notFoundErr := fmt.Errorf("credential not found for provider %s and user %s", provider, email)
			if s.cacheEnabled {
				s.cacheMu.Lock()
				s.cache[ck] = cacheEntry{
					err:       notFoundErr,
					expiresAt: time.Now().Add(s.negCacheTTL),
				}
				s.cacheMu.Unlock()
			}
			return nil, notFoundErr
		}
		return nil, fmt.Errorf("failed to access secret %s: %w", secretID, err)
	}

	data := resp.GetPayload().GetData()

	if s.cacheEnabled {
		s.cacheMu.Lock()
		s.cache[ck] = cacheEntry{
			value:     data,
			expiresAt: time.Now().Add(s.cacheTTL),
		}
		s.cacheMu.Unlock()
	}

	return data, nil
}

// SetCredential stores a credential in Google Secret Manager, creating the secret if it doesn't exist.
func (s *Store) SetCredential(ctx context.Context, email string, provider string, cred []byte) error {
	secretID := s.SecretID(email, provider)
	secretName := fmt.Sprintf("projects/%s/secrets/%s", s.projectID, secretID)

	// Check if secret already exists
	_, err := s.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: secretName,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// Create secret with labels and annotations
			_, createErr := s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
				Parent:   fmt.Sprintf("projects/%s", s.projectID),
				SecretId: secretID,
				Secret: &secretmanagerpb.Secret{
					Replication: s.replication,
					Labels:      s.labels(email, provider),
					Annotations: s.annotations(email),
				},
			})
			if createErr != nil && status.Code(createErr) != codes.AlreadyExists {
				return fmt.Errorf("failed to create secret %s: %w", secretID, createErr)
			}
		} else {
			return fmt.Errorf("failed to query secret %s: %w", secretID, err)
		}
	}

	// Add secret version with credential payload
	_, err = s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: cred,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add secret version to %s: %w", secretID, err)
	}

	// Update in-memory cache
	if s.cacheEnabled {
		ck := s.cacheKey(email, provider)
		s.cacheMu.Lock()
		s.cache[ck] = cacheEntry{
			value:     cred,
			expiresAt: time.Now().Add(s.cacheTTL),
		}
		s.cacheMu.Unlock()
	}

	return nil
}

// DelegatedProvider returns a user-scoped DelegatedAuthProvider backed by this store.
func (s *Store) DelegatedProvider(ctx context.Context, email string) *auth.DelegatedAuthProvider {
	return auth.NewDelegatedAuthProvider(s, email)
}

// Close releases resources held by the store, closing the client connection if owned.
func (s *Store) Close() error {
	if s.closeClientOnEnd && s.client != nil {
		return s.client.Close()
	}
	return nil
}
