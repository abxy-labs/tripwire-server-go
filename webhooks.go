package tripwire

import (
	"context"
	"net/http"
	"net/url"
)

type WebhookEndpoint struct {
	Object        string   `json:"object"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Status        string   `json:"status"`
	EventTypes    []string `json:"event_types"`
	SigningSecret string   `json:"signing_secret,omitempty"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

type WebhookDelivery struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	EventID        string  `json:"event_id"`
	EndpointID     string  `json:"endpoint_id"`
	EventType      string  `json:"event_type"`
	Status         string  `json:"status"`
	Attempts       int     `json:"attempts"`
	ResponseStatus *int    `json:"response_status"`
	ResponseBody   *string `json:"response_body"`
	Error          *string `json:"error"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

type WebhookTest struct {
	Object         string           `json:"object"`
	EventID        string           `json:"event_id"`
	DeliveryIDs    []string         `json:"delivery_ids"`
	LatestDelivery *WebhookDelivery `json:"latest_delivery"`
}

type EventSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Event struct {
	Object            string            `json:"object"`
	ID                string            `json:"id"`
	Type              string            `json:"type"`
	Subject           EventSubject      `json:"subject"`
	Data              map[string]any    `json:"data"`
	WebhookDeliveries []WebhookDelivery `json:"webhook_deliveries"`
	CreatedAt         string            `json:"created_at"`
}

type CreateWebhookEndpointParams struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
}

type UpdateWebhookEndpointParams struct {
	Name       string   `json:"name,omitempty"`
	URL        string   `json:"url,omitempty"`
	Status     string   `json:"status,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
}

type EventListParams struct {
	EndpointID string
	Type       string
	Limit      int
}

type WebhooksService struct {
	client *Client
}

func (s *WebhooksService) ListEndpoints(ctx context.Context, organizationID string) (ListResult[WebhookEndpoint], error) {
	var envelope resourceListEnvelope[WebhookEndpoint]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints", nil, nil, &envelope)
	if err != nil {
		return ListResult[WebhookEndpoint]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *WebhooksService) CreateEndpoint(ctx context.Context, organizationID string, params CreateWebhookEndpointParams) (WebhookEndpoint, error) {
	var envelope resourceEnvelope[WebhookEndpoint]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints", nil, params, &envelope)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return envelope.Data, nil
}

func (s *WebhooksService) UpdateEndpoint(ctx context.Context, organizationID string, endpointID string, params UpdateWebhookEndpointParams) (WebhookEndpoint, error) {
	var envelope resourceEnvelope[WebhookEndpoint]
	err := s.client.doJSON(ctx, http.MethodPatch, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints/"+url.PathEscape(endpointID), nil, params, &envelope)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return envelope.Data, nil
}

func (s *WebhooksService) DisableEndpoint(ctx context.Context, organizationID string, endpointID string) (WebhookEndpoint, error) {
	var envelope resourceEnvelope[WebhookEndpoint]
	err := s.client.doJSON(ctx, http.MethodDelete, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints/"+url.PathEscape(endpointID), nil, nil, &envelope)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return envelope.Data, nil
}

func (s *WebhooksService) RotateSecret(ctx context.Context, organizationID string, endpointID string) (WebhookEndpoint, error) {
	var envelope resourceEnvelope[WebhookEndpoint]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints/"+url.PathEscape(endpointID)+"/rotations", nil, nil, &envelope)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	return envelope.Data, nil
}

func (s *WebhooksService) SendTest(ctx context.Context, organizationID string, endpointID string) (WebhookTest, error) {
	var envelope resourceEnvelope[WebhookTest]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/organizations/"+url.PathEscape(organizationID)+"/webhooks/endpoints/"+url.PathEscape(endpointID)+"/test", nil, nil, &envelope)
	if err != nil {
		return WebhookTest{}, err
	}
	return envelope.Data, nil
}

func (s *WebhooksService) ListEvents(ctx context.Context, organizationID string, params EventListParams) (ListResult[Event], error) {
	var envelope resourceListEnvelope[Event]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/organizations/"+url.PathEscape(organizationID)+"/events", map[string]string{
		"endpoint_id": params.EndpointID,
		"type":        params.Type,
		"limit":       intToString(params.Limit),
	}, nil, &envelope)
	if err != nil {
		return ListResult[Event]{}, err
	}
	return normalizeList(envelope), nil
}

func (s *WebhooksService) RetrieveEvent(ctx context.Context, organizationID string, eventID string) (Event, error) {
	var envelope resourceEnvelope[Event]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/organizations/"+url.PathEscape(organizationID)+"/events/"+url.PathEscape(eventID), nil, nil, &envelope)
	if err != nil {
		return Event{}, err
	}
	return envelope.Data, nil
}
