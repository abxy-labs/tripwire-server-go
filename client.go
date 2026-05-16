package foil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultBaseURL  = "https://api.usefoil.com"
	defaultTimeout  = 30 * time.Second
	sdkClientHeader = "foil-server-go/0.1.0"
)

type Option func(*clientConfig)

type clientConfig struct {
	secretKey  string
	baseURL    string
	timeout    time.Duration
	userAgent  string
	httpClient *http.Client
}

func WithSecretKey(secretKey string) Option {
	return func(cfg *clientConfig) {
		cfg.secretKey = secretKey
	}
}

func WithBaseURL(baseURL string) Option {
	return func(cfg *clientConfig) {
		cfg.baseURL = baseURL
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.timeout = timeout
	}
}

func WithUserAgent(userAgent string) Option {
	return func(cfg *clientConfig) {
		cfg.userAgent = userAgent
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(cfg *clientConfig) {
		cfg.httpClient = client
	}
}

type Client struct {
	baseURL    string
	secretKey  string
	httpClient *http.Client
	userAgent  string

	Sessions      *SessionsService
	Fingerprints  *FingerprintsService
	Organizations *OrganizationsService
	Gate          *GateService
	Webhooks      *WebhooksService
}

func NewClient(options ...Option) (*Client, error) {
	cfg := &clientConfig{
		secretKey: os.Getenv("FOIL_SECRET_KEY"),
		baseURL:   defaultBaseURL,
		timeout:   defaultTimeout,
	}

	for _, option := range options {
		option(cfg)
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		copied := *httpClient
		httpClient = &copied
	}
	httpClient.Timeout = cfg.timeout

	client := &Client{
		baseURL:    cfg.baseURL,
		secretKey:  cfg.secretKey,
		httpClient: httpClient,
		userAgent:  cfg.userAgent,
	}
	client.Sessions = &SessionsService{client: client}
	client.Fingerprints = &FingerprintsService{client: client}
	client.Organizations = &OrganizationsService{client: client}
	client.Organizations.APIKeys = &APIKeysService{client: client}
	client.Gate = &GateService{client: client}
	client.Gate.Registry = &GateRegistryService{client: client}
	client.Gate.Services = &GateManagedServicesService{client: client}
	client.Gate.Sessions = &GateSessionsService{client: client}
	client.Gate.LoginSessions = &GateLoginSessionsService{client: client}
	client.Gate.AgentTokens = &GateAgentTokensService{client: client}
	client.Webhooks = &WebhooksService{client: client}
	return client, nil
}

func (c *Client) buildURL(path string, query map[string]string) (string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", err
	}
	relative, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(relative)
	values := resolved.Query()
	for key, value := range query {
		if value == "" {
			continue
		}
		values.Set(key, value)
	}
	resolved.RawQuery = values.Encode()
	return resolved.String(), nil
}

func (c *Client) doJSON(ctx context.Context, method string, path string, query map[string]string, body any, out any) error {
	return c.doJSONWithAuth(ctx, method, path, query, body, out, authConfig{Mode: authModeSecret})
}

type authMode string

const (
	authModeSecret authMode = "secret"
	authModeNone   authMode = "none"
	authModeBearer authMode = "bearer"
)

type authConfig struct {
	Mode  authMode
	Token string
}

func (c *Client) doJSONWithAuth(ctx context.Context, method string, path string, query map[string]string, body any, out any, auth authConfig) error {
	var requestBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(payload)
	}

	rawURL, err := c.buildURL(path, query)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, requestBody)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Foil-Client", sdkClientHeader)
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	switch auth.Mode {
	case authModeNone:
	case authModeBearer:
		if auth.Token == "" {
			return &ConfigurationError{Message: "Missing bearer token for this Foil request."}
		}
		request.Header.Set("Authorization", "Bearer "+auth.Token)
	default:
		if c.secretKey == "" {
			return &ConfigurationError{
				Message: "Missing Foil secret key. Pass WithSecretKey or set FOIL_SECRET_KEY.",
			}
		}
		request.Header.Set("Authorization", "Bearer "+c.secretKey)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode >= 400 {
		return parseAPIError(response.StatusCode, response.Header.Get("x-request-id"), responseBody, response.Status)
	}

	if out == nil || response.StatusCode == http.StatusNoContent || len(responseBody) == 0 {
		return nil
	}

	if err := json.Unmarshal(responseBody, out); err != nil {
		return wrapInvalidJSONError(err)
	}
	return nil
}

func parseAPIError(status int, requestID string, body []byte, fallbackMessage string) error {
	payload := map[string]any{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
	}

	var envelope apiErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error.Code != "" {
		if requestID == "" {
			requestID = envelope.Error.RequestID
		}
		return &APIError{
			Status:      status,
			Code:        envelope.Error.Code,
			Message:     envelope.Error.Message,
			RequestID:   requestID,
			FieldErrors: envelope.Error.Details.Fields,
			DocsURL:     envelope.Error.DocsURL,
			Body:        payload,
		}
	}

	return newGenericAPIError(status, fallbackMessage, requestID, payload)
}

func normalizeList[T any](envelope resourceListEnvelope[T]) ListResult[T] {
	return ListResult[T]{
		Items:      envelope.Data,
		Limit:      envelope.Pagination.Limit,
		HasMore:    envelope.Pagination.HasMore,
		NextCursor: envelope.Pagination.NextCursor,
	}
}

type SessionsService struct {
	client *Client
}

func (s *SessionsService) List(ctx context.Context, params SessionListParams) (ListResult[SessionSummary], error) {
	var envelope resourceListEnvelope[SessionSummary]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/sessions", map[string]string{
		"limit":   intToString(params.Limit),
		"cursor":  params.Cursor,
		"verdict": params.Verdict,
		"search":  params.Search,
	}, nil, &envelope)
	if err != nil {
		return ListResult[SessionSummary]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *SessionsService) Get(ctx context.Context, sessionID string) (SessionDetail, error) {
	var envelope resourceEnvelope[SessionDetail]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(sessionID), nil, nil, &envelope)
	if err != nil {
		return SessionDetail{}, err
	}
	return envelope.Data, nil
}

func (s *SessionsService) Iter(ctx context.Context, params SessionListParams, yield func(SessionSummary) error) error {
	cursor := params.Cursor
	for {
		page, err := s.List(ctx, SessionListParams{
			Limit:   params.Limit,
			Cursor:  cursor,
			Verdict: params.Verdict,
			Search:  params.Search,
		})
		if err != nil {
			return err
		}
		for _, item := range page.Items {
			if err := yield(item); err != nil {
				return err
			}
		}
		if !page.HasMore || page.NextCursor == "" {
			return nil
		}
		cursor = page.NextCursor
	}
}

type FingerprintsService struct {
	client *Client
}

func (s *FingerprintsService) List(ctx context.Context, params FingerprintListParams) (ListResult[VisitorFingerprintSummary], error) {
	var envelope resourceListEnvelope[VisitorFingerprintSummary]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/fingerprints", map[string]string{
		"limit":  intToString(params.Limit),
		"cursor": params.Cursor,
		"search": params.Search,
		"sort":   params.Sort,
	}, nil, &envelope)
	if err != nil {
		return ListResult[VisitorFingerprintSummary]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *FingerprintsService) Get(ctx context.Context, visitorID string) (VisitorFingerprintDetail, error) {
	var envelope resourceEnvelope[VisitorFingerprintDetail]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/fingerprints/"+url.PathEscape(visitorID), nil, nil, &envelope)
	if err != nil {
		return VisitorFingerprintDetail{}, err
	}
	return envelope.Data, nil
}

func (s *FingerprintsService) Iter(ctx context.Context, params FingerprintListParams, yield func(VisitorFingerprintSummary) error) error {
	cursor := params.Cursor
	for {
		page, err := s.List(ctx, FingerprintListParams{
			Limit:  params.Limit,
			Cursor: cursor,
			Search: params.Search,
			Sort:   params.Sort,
		})
		if err != nil {
			return err
		}
		for _, item := range page.Items {
			if err := yield(item); err != nil {
				return err
			}
		}
		if !page.HasMore || page.NextCursor == "" {
			return nil
		}
		cursor = page.NextCursor
	}
}

type OrganizationsService struct {
	client  *Client
	APIKeys *APIKeysService
}

func (s *OrganizationsService) Create(ctx context.Context, params CreateOrganizationParams) (Organization, error) {
	var envelope resourceEnvelope[Organization]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations", nil, params, &envelope)
	if err != nil {
		return Organization{}, err
	}
	return envelope.Data, nil
}

func (s *OrganizationsService) Get(ctx context.Context, organizationID string) (Organization, error) {
	var envelope resourceEnvelope[Organization]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/organizations/"+url.PathEscape(organizationID), nil, nil, &envelope)
	if err != nil {
		return Organization{}, err
	}
	return envelope.Data, nil
}

func (s *OrganizationsService) Update(ctx context.Context, organizationID string, params UpdateOrganizationParams) (Organization, error) {
	var envelope resourceEnvelope[Organization]
	err := s.client.doJSON(ctx, http.MethodPatch, "/v1/organizations/"+url.PathEscape(organizationID), nil, params, &envelope)
	if err != nil {
		return Organization{}, err
	}
	return envelope.Data, nil
}

type APIKeysService struct {
	client *Client
}

func (s *APIKeysService) Create(ctx context.Context, organizationID string, params CreateAPIKeyParams) (IssuedAPIKey, error) {
	var envelope resourceEnvelope[IssuedAPIKey]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations/"+url.PathEscape(organizationID)+"/api-keys", nil, params, &envelope)
	if err != nil {
		return IssuedAPIKey{}, err
	}
	return envelope.Data, nil
}

func (s *APIKeysService) List(ctx context.Context, organizationID string, params APIKeyListParams) (ListResult[APIKey], error) {
	var envelope resourceListEnvelope[APIKey]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/organizations/"+url.PathEscape(organizationID)+"/api-keys", map[string]string{
		"limit":  intToString(params.Limit),
		"cursor": params.Cursor,
	}, nil, &envelope)
	if err != nil {
		return ListResult[APIKey]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *APIKeysService) Update(ctx context.Context, organizationID string, keyID string, params UpdateAPIKeyParams) (APIKey, error) {
	var envelope resourceEnvelope[APIKey]
	err := s.client.doJSON(ctx, http.MethodPatch, "/v1/organizations/"+url.PathEscape(organizationID)+"/api-keys/"+url.PathEscape(keyID), nil, params, &envelope)
	if err != nil {
		return APIKey{}, err
	}
	return envelope.Data, nil
}

func (s *APIKeysService) Revoke(ctx context.Context, organizationID string, keyID string) (APIKey, error) {
	var envelope resourceEnvelope[APIKey]
	err := s.client.doJSON(ctx, http.MethodDelete, "/v1/organizations/"+url.PathEscape(organizationID)+"/api-keys/"+url.PathEscape(keyID), nil, nil, &envelope)
	if err != nil {
		return APIKey{}, err
	}
	return envelope.Data, nil
}

func (s *APIKeysService) Rotate(ctx context.Context, organizationID string, keyID string) (IssuedAPIKey, error) {
	var envelope resourceEnvelope[IssuedAPIKey]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations/"+url.PathEscape(organizationID)+"/api-keys/"+url.PathEscape(keyID)+"/rotations", nil, nil, &envelope)
	if err != nil {
		return IssuedAPIKey{}, err
	}
	return envelope.Data, nil
}

func intToString(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value)
}
