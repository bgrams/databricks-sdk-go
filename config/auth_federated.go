package config

import (
	"context"
	"fmt"

	"github.com/databricks/databricks-sdk-go/config/credentials"
	"github.com/databricks/databricks-sdk-go/logger"
	"golang.org/x/oauth2"
)

// FederatedCredentials is a credential strategy that supports RFC8693 token exchange for a provided
// JWT when account or service principal federation policies are configured. The token may be supplied
// directly via Config.SubjectToken, or loaded from a file configured in Config.SubjectTokenFile to
// support token refreshes from an external process for long-running applications. Account federation
// is used by default, and service principal federation is used when the Config.ClientID is non-empty.
type FederatedCredentials struct{}

func (c FederatedCredentials) Name() string {
	return "oauth-federated"
}

func (c FederatedCredentials) Configure(ctx context.Context, cfg *Config) (credentials.CredentialsProvider, error) {
	if cfg.SubjectToken == "" && cfg.SubjectTokenFile == "" {
		return nil, nil
	}

	tokenSource, err := NewFederatedTokenSource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	if cfg.ClientID != "" {
		logger.Debugf(ctx, "Generating Databricks OAuth token for Service Principal (%s)", cfg.ClientID)
	} else {
		logger.Debugf(ctx, "Generating Databricks OAuth token for federated account identity")
	}

	visitor := refreshableVisitor(tokenSource)
	return credentials.NewOAuthCredentialsProvider(visitor, tokenSource.Token), nil
}

type FederatedTokenSource struct {
	credentialConfig *oauth2.Config
	cfg              *Config
	ctx              context.Context
}

func NewFederatedTokenSource(ctx context.Context, config *Config) (*FederatedTokenSource, error) {
	endpoints, err := config.getOidcEndpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	return &FederatedTokenSource{
		credentialConfig: &oauth2.Config{
			ClientID: config.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInParams,
				TokenURL:  endpoints.TokenEndpoint,
			},
		},
		cfg: config,
		ctx: ctx,
	}, nil
}

func (s *FederatedTokenSource) Token() (*oauth2.Token, error) {
	subjectToken, err := s.cfg.getSubjectToken()
	if err != nil {
		return nil, err
	}

	// Pending official docs: https://github.com/golang/oauth2/issues/409
	authCodeOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
		oauth2.SetAuthURLParam("scope", "all-apis"),
		oauth2.SetAuthURLParam("subject_token", subjectToken),
		oauth2.SetAuthURLParam("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
	}

	return s.credentialConfig.Exchange(s.ctx, "", authCodeOpts...)
}
