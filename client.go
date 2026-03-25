package tripwire

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
	defaultBaseURL  = "https://api.tripwirejs.com"
	defaultTimeout  = 30 * time.Second
	sdkClientHeader = "tripwire-server-go/0.1.0"
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

	Sessions     *SessionsService
	Fingerprints *FingerprintsService
	Teams        *TeamsService
}

func NewClient(options ...Option) (*Client, error) {
	cfg := &clientConfig{
		secretKey: os.Getenv("TRIPWIRE_SECRET_KEY"),
		baseURL:   defaultBaseURL,
		timeout:   defaultTimeout,
	}

	for _, option := range options {
		option(cfg)
	}

	if cfg.secretKey == "" {
		return nil, &ConfigurationError{
			Message: "Missing Tripwire secret key. Pass WithSecretKey or set TRIPWIRE_SECRET_KEY.",
		}
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
	client.Teams = &TeamsService{client: client}
	client.Teams.APIKeys = &APIKeysService{client: client}
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
	request.Header.Set("Authorization", "Bearer "+c.secretKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Tripwire-Client", sdkClientHeader)
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
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

	var envelope publicErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error.Code != "" {
		if requestID == "" {
			requestID = envelope.Error.RequestID
		}
		return &APIError{
			Status:      status,
			Code:        envelope.Error.Code,
			Message:     envelope.Error.Message,
			RequestID:   requestID,
			FieldErrors: envelope.Error.Details.FieldErrors,
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

func (s *FingerprintsService) List(ctx context.Context, params FingerprintListParams) (ListResult[FingerprintSummary], error) {
	var envelope resourceListEnvelope[FingerprintSummary]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/fingerprints", map[string]string{
		"limit":  intToString(params.Limit),
		"cursor": params.Cursor,
		"search": params.Search,
		"sort":   params.Sort,
	}, nil, &envelope)
	if err != nil {
		return ListResult[FingerprintSummary]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *FingerprintsService) Get(ctx context.Context, visitorID string) (FingerprintDetail, error) {
	var envelope resourceEnvelope[FingerprintDetail]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/fingerprints/"+url.PathEscape(visitorID), nil, nil, &envelope)
	if err != nil {
		return FingerprintDetail{}, err
	}
	return envelope.Data, nil
}

func (s *FingerprintsService) Iter(ctx context.Context, params FingerprintListParams, yield func(FingerprintSummary) error) error {
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

type TeamsService struct {
	client  *Client
	APIKeys *APIKeysService
}

func (s *TeamsService) Create(ctx context.Context, params CreateTeamParams) (Team, error) {
	var envelope resourceEnvelope[Team]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/teams", nil, params, &envelope)
	if err != nil {
		return Team{}, err
	}
	return envelope.Data, nil
}

func (s *TeamsService) Get(ctx context.Context, teamID string) (Team, error) {
	var envelope resourceEnvelope[Team]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/teams/"+url.PathEscape(teamID), nil, nil, &envelope)
	if err != nil {
		return Team{}, err
	}
	return envelope.Data, nil
}

func (s *TeamsService) Update(ctx context.Context, teamID string, params UpdateTeamParams) (Team, error) {
	var envelope resourceEnvelope[Team]
	err := s.client.doJSON(ctx, http.MethodPatch, "/v1/teams/"+url.PathEscape(teamID), nil, params, &envelope)
	if err != nil {
		return Team{}, err
	}
	return envelope.Data, nil
}

type APIKeysService struct {
	client *Client
}

func (s *APIKeysService) Create(ctx context.Context, teamID string, params CreateAPIKeyParams) (IssuedAPIKey, error) {
	var envelope resourceEnvelope[IssuedAPIKey]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/teams/"+url.PathEscape(teamID)+"/api-keys", nil, params, &envelope)
	if err != nil {
		return IssuedAPIKey{}, err
	}
	return envelope.Data, nil
}

func (s *APIKeysService) List(ctx context.Context, teamID string, params APIKeyListParams) (ListResult[APIKey], error) {
	var envelope resourceListEnvelope[APIKey]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/teams/"+url.PathEscape(teamID)+"/api-keys", map[string]string{
		"limit":  intToString(params.Limit),
		"cursor": params.Cursor,
	}, nil, &envelope)
	if err != nil {
		return ListResult[APIKey]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *APIKeysService) Revoke(ctx context.Context, teamID string, keyID string) error {
	return s.client.doJSON(ctx, http.MethodDelete, "/v1/teams/"+url.PathEscape(teamID)+"/api-keys/"+url.PathEscape(keyID), nil, nil, nil)
}

func (s *APIKeysService) Rotate(ctx context.Context, teamID string, keyID string) (IssuedAPIKey, error) {
	var envelope resourceEnvelope[IssuedAPIKey]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/teams/"+url.PathEscape(teamID)+"/api-keys/"+url.PathEscape(keyID)+"/rotations", nil, nil, &envelope)
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
