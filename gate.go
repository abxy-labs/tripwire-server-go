package foil

import (
	"context"
	"net/http"
	"net/url"
)

type GateService struct {
	client        *Client
	Registry      *GateRegistryService
	Services      *GateManagedServicesService
	Sessions      *GateSessionsService
	LoginSessions *GateLoginSessionsService
	AgentTokens   *GateAgentTokensService
}

type GateRegistryService struct {
	client *Client
}

func (s *GateRegistryService) List(ctx context.Context) ([]GateRegistryEntry, error) {
	var envelope resourceEnvelope[[]GateRegistryEntry]
	err := s.client.doJSONWithAuth(ctx, http.MethodGet, "/v1/gate/registry", nil, nil, &envelope, authConfig{Mode: authModeNone})
	if err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

func (s *GateRegistryService) Get(ctx context.Context, serviceID string) (GateRegistryEntry, error) {
	var envelope resourceEnvelope[GateRegistryEntry]
	err := s.client.doJSONWithAuth(ctx, http.MethodGet, "/v1/gate/registry/"+url.PathEscape(serviceID), nil, nil, &envelope, authConfig{Mode: authModeNone})
	if err != nil {
		return GateRegistryEntry{}, err
	}
	return envelope.Data, nil
}

type GateManagedServicesService struct {
	client *Client
}

func (s *GateManagedServicesService) List(ctx context.Context) ([]GateManagedService, error) {
	var envelope resourceEnvelope[[]GateManagedService]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/gate/services", nil, nil, &envelope)
	if err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

func (s *GateManagedServicesService) Get(ctx context.Context, serviceID string) (GateManagedService, error) {
	var envelope resourceEnvelope[GateManagedService]
	err := s.client.doJSON(ctx, http.MethodGet, "/v1/gate/services/"+url.PathEscape(serviceID), nil, nil, &envelope)
	if err != nil {
		return GateManagedService{}, err
	}
	return envelope.Data, nil
}

func (s *GateManagedServicesService) Create(ctx context.Context, params CreateGateServiceParams) (GateManagedService, error) {
	var envelope resourceEnvelope[GateManagedService]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/gate/services", nil, params, &envelope)
	if err != nil {
		return GateManagedService{}, err
	}
	return envelope.Data, nil
}

func (s *GateManagedServicesService) Update(ctx context.Context, serviceID string, params UpdateGateServiceParams) (GateManagedService, error) {
	var envelope resourceEnvelope[GateManagedService]
	err := s.client.doJSON(ctx, http.MethodPatch, "/v1/gate/services/"+url.PathEscape(serviceID), nil, params, &envelope)
	if err != nil {
		return GateManagedService{}, err
	}
	return envelope.Data, nil
}

func (s *GateManagedServicesService) Disable(ctx context.Context, serviceID string) (GateManagedService, error) {
	var envelope resourceEnvelope[GateManagedService]
	err := s.client.doJSON(ctx, http.MethodDelete, "/v1/gate/services/"+url.PathEscape(serviceID), nil, nil, &envelope)
	if err != nil {
		return GateManagedService{}, err
	}
	return envelope.Data, nil
}

type GateSessionsService struct {
	client *Client
}

func (s *GateSessionsService) Create(ctx context.Context, params CreateGateSessionParams) (GateSessionCreate, error) {
	var envelope resourceEnvelope[GateSessionCreate]
	err := s.client.doJSONWithAuth(ctx, http.MethodPost, "/v1/gate/sessions", nil, params, &envelope, authConfig{Mode: authModeNone})
	if err != nil {
		return GateSessionCreate{}, err
	}
	return envelope.Data, nil
}

func (s *GateSessionsService) Poll(ctx context.Context, gateSessionID string, pollToken string) (GateSessionPollData, error) {
	var envelope resourceEnvelope[GateSessionPollData]
	err := s.client.doJSONWithAuth(
		ctx,
		http.MethodGet,
		"/v1/gate/sessions/"+url.PathEscape(gateSessionID),
		nil,
		nil,
		&envelope,
		authConfig{Mode: authModeBearer, Token: pollToken},
	)
	if err != nil {
		return GateSessionPollData{}, err
	}
	return envelope.Data, nil
}

func (s *GateSessionsService) Acknowledge(ctx context.Context, gateSessionID string, params AcknowledgeGateSessionDeliveryParams) (GateSessionDeliveryAcknowledgement, error) {
	var envelope resourceEnvelope[GateSessionDeliveryAcknowledgement]
	err := s.client.doJSONWithAuth(
		ctx,
		http.MethodPost,
		"/v1/gate/sessions/"+url.PathEscape(gateSessionID)+"/ack",
		nil,
		params,
		&envelope,
		authConfig{Mode: authModeBearer, Token: params.PollToken},
	)
	if err != nil {
		return GateSessionDeliveryAcknowledgement{}, err
	}
	return envelope.Data, nil
}

type GateLoginSessionsService struct {
	client *Client
}

func (s *GateLoginSessionsService) Create(ctx context.Context, params CreateGateLoginSessionParams) (GateLoginSession, error) {
	var envelope resourceEnvelope[GateLoginSession]
	err := s.client.doJSONWithAuth(
		ctx,
		http.MethodPost,
		"/v1/gate/login-sessions",
		nil,
		params,
		&envelope,
		authConfig{Mode: authModeBearer, Token: params.AgentToken},
	)
	if err != nil {
		return GateLoginSession{}, err
	}
	return envelope.Data, nil
}

func (s *GateLoginSessionsService) Consume(ctx context.Context, params ConsumeGateLoginSessionParams) (GateDashboardLogin, error) {
	var envelope resourceEnvelope[GateDashboardLogin]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/gate/login-sessions/consume", nil, params, &envelope)
	if err != nil {
		return GateDashboardLogin{}, err
	}
	return envelope.Data, nil
}

type GateAgentTokensService struct {
	client *Client
}

func (s *GateAgentTokensService) Verify(ctx context.Context, params VerifyGateAgentTokenParams) (AgentTokenVerification, error) {
	var envelope resourceEnvelope[AgentTokenVerification]
	err := s.client.doJSON(ctx, http.MethodPost, "/v1/gate/agent-tokens/verify", nil, params, &envelope)
	if err != nil {
		return AgentTokenVerification{}, err
	}
	return envelope.Data, nil
}

func (s *GateAgentTokensService) Revoke(ctx context.Context, params RevokeGateAgentTokenParams) error {
	return s.client.doJSON(ctx, http.MethodPost, "/v1/gate/agent-tokens/revoke", nil, params, nil)
}
