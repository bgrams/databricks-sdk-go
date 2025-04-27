package config

import (
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/databricks/databricks-sdk-go/credentials/u2m"
	"github.com/databricks/databricks-sdk-go/httpclient/fixtures"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func assertFederatedAuthHeaders(t *testing.T, cfg *Config) {
	subjectToken, err := cfg.getSubjectToken()
	require.NoError(t, err)

	expectedReqValues := url.Values{
		"code":               {""},
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"scope":              {"all-apis"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	}

	if cfg.ClientID != "" {
		expectedReqValues.Set("client_id", cfg.ClientID)
	}

	tokenResponse := oauth2.Token{
		TokenType:   "Some",
		AccessToken: "cde",
	}

	tokenEndpointFixture := fixtures.HTTPFixture{
		ExpectedHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedRequest: expectedReqValues,
		Response:        tokenResponse,
	}

	if cfg.AccountID == "" {
		cfg.HTTPTransport = fixtures.MappingTransport{
			"GET /oidc/.well-known/oauth-authorization-server": fixtures.HTTPFixture{
				Response: u2m.OAuthAuthorizationServer{
					TokenEndpoint: "https://localhost:1234/dummy/token",
				},
			},
			"POST /dummy/token": tokenEndpointFixture,
		}
	} else {
		tokenEndpoint := fmt.Sprintf("POST /oidc/accounts/%s/v1/token", cfg.AccountID)
		cfg.HTTPTransport = fixtures.MappingTransport{
			tokenEndpoint: tokenEndpointFixture,
		}
	}

	assertHeaders(t, cfg, map[string]string{
		"Authorization": fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken),
	})
}

func TestFederationHappyFlowForAccountPolicy(t *testing.T) {
	assertFederatedAuthHeaders(t, &Config{
		Host:         "a",
		SubjectToken: "c",
	})
}

func TestFederationHappyFlowForServicePrincipalPolicy(t *testing.T) {
	assertFederatedAuthHeaders(t, &Config{
		Host:         "a",
		ClientID:     "b",
		SubjectToken: "c",
	})
}

func TestFederationHappyFlowForAccountHost(t *testing.T) {
	assertFederatedAuthHeaders(t, &Config{
		Host:         "accounts.cloud.databricks.com",
		AccountID:    "a",
		SubjectToken: "c",
	})
}

func TestFederationHappyFlowWithSubjectTokenFile(t *testing.T) {
	file, err := os.CreateTemp("", "subjectTokenFile")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	err = os.WriteFile(file.Name(), []byte("c"), 0777)
	require.NoError(t, err)

	assertFederatedAuthHeaders(t, &Config{
		Host:             "a",
		SubjectTokenFile: file.Name(),
	})
}
