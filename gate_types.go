package tripwire

type GateServiceStatus string

const (
	GateServiceStatusActive   GateServiceStatus = "active"
	GateServiceStatusDisabled GateServiceStatus = "disabled"
)

type GateServiceEnvVar struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Secret bool   `json:"secret"`
}

type GateServiceSDKInstall struct {
	Label   string `json:"label"`
	Install string `json:"install"`
	URL     string `json:"url"`
}

type GateServiceBranding struct {
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
	ASCIIArt       string `json:"ascii_art,omitempty"`
	Verified       bool   `json:"verified"`
}

type GateServiceBrandingInput struct {
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
	ASCIIArt       string `json:"ascii_art,omitempty"`
}

type GateServiceConsent struct {
	TermsURL   string `json:"terms_url,omitempty"`
	PrivacyURL string `json:"privacy_url,omitempty"`
}

type GateRegistryEntry struct {
	ID                string                  `json:"id"`
	Status            GateServiceStatus       `json:"status"`
	Discoverable      bool                    `json:"discoverable"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description"`
	Website           string                  `json:"website"`
	DashboardLoginURL string                  `json:"dashboard_login_url,omitempty"`
	EnvVars           []GateServiceEnvVar     `json:"env_vars"`
	DocsURL           string                  `json:"docs_url"`
	SDKs              []GateServiceSDKInstall `json:"sdks"`
	Branding          GateServiceBranding     `json:"branding"`
	Consent           GateServiceConsent      `json:"consent"`
}

type GateManagedService struct {
	Object            string                  `json:"object"`
	ID                string                  `json:"id"`
	Status            GateServiceStatus       `json:"status"`
	Discoverable      bool                    `json:"discoverable"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description"`
	Website           string                  `json:"website"`
	DashboardLoginURL string                  `json:"dashboard_login_url,omitempty"`
	WebhookURL        string                  `json:"webhook_url"`
	EnvVars           []GateServiceEnvVar     `json:"env_vars"`
	DocsURL           string                  `json:"docs_url"`
	SDKs              []GateServiceSDKInstall `json:"sdks"`
	Branding          GateServiceBranding     `json:"branding"`
	Consent           GateServiceConsent      `json:"consent"`
	CreatedAt         string                  `json:"created_at"`
	UpdatedAt         string                  `json:"updated_at"`
}

type CreateGateServiceParams struct {
	ID                string                    `json:"id"`
	Discoverable      *bool                     `json:"discoverable,omitempty"`
	Name              string                    `json:"name"`
	Description       string                    `json:"description"`
	Website           string                    `json:"website"`
	DashboardLoginURL string                    `json:"dashboard_login_url,omitempty"`
	WebhookURL        string                    `json:"webhook_url"`
	WebhookSecret     string                    `json:"webhook_secret,omitempty"`
	EnvVars           []GateServiceEnvVar       `json:"env_vars,omitempty"`
	DocsURL           string                    `json:"docs_url,omitempty"`
	SDKs              []GateServiceSDKInstall   `json:"sdks,omitempty"`
	Branding          *GateServiceBrandingInput `json:"branding,omitempty"`
	Consent           *GateServiceConsent       `json:"consent,omitempty"`
}

type UpdateGateServiceParams struct {
	Discoverable      *bool                     `json:"discoverable,omitempty"`
	Name              string                    `json:"name,omitempty"`
	Description       string                    `json:"description,omitempty"`
	Website           string                    `json:"website,omitempty"`
	DashboardLoginURL string                    `json:"dashboard_login_url,omitempty"`
	WebhookURL        string                    `json:"webhook_url,omitempty"`
	WebhookSecret     string                    `json:"webhook_secret,omitempty"`
	EnvVars           []GateServiceEnvVar       `json:"env_vars,omitempty"`
	DocsURL           string                    `json:"docs_url,omitempty"`
	SDKs              []GateServiceSDKInstall   `json:"sdks,omitempty"`
	Branding          *GateServiceBrandingInput `json:"branding,omitempty"`
	Consent           *GateServiceConsent       `json:"consent,omitempty"`
}

type GateDeliveryRequest struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type GateDeliveryEnvelope struct {
	Version            int    `json:"version"`
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Salt               string `json:"salt"`
	IV                 string `json:"iv"`
	Ciphertext         string `json:"ciphertext"`
	Tag                string `json:"tag"`
}

type GateDeliveryBundle struct {
	Integrator GateDeliveryEnvelope `json:"integrator"`
	Gate       GateDeliveryEnvelope `json:"gate"`
}

type GateSessionCreate struct {
	Object     string `json:"object"`
	ID         string `json:"id"`
	Status     string `json:"status"`
	PollToken  string `json:"poll_token"`
	ConsentURL string `json:"consent_url"`
	ExpiresAt  string `json:"expires_at"`
}

type GateSessionPollData struct {
	Object         string              `json:"object"`
	ID             string              `json:"id"`
	Status         string              `json:"status"`
	ExpiresAt      string              `json:"expires_at,omitempty"`
	GateAccountID  string              `json:"gate_account_id,omitempty"`
	AccountName    string              `json:"account_name,omitempty"`
	DeliveryBundle *GateDeliveryBundle `json:"delivery_bundle,omitempty"`
	DocsURL        string              `json:"docs_url,omitempty"`
}

type GateSessionDeliveryAcknowledgement struct {
	Object        string `json:"object"`
	GateSessionID string `json:"gate_session_id"`
	Status        string `json:"status"`
}

type CreateGateSessionParams struct {
	ServiceID   string              `json:"service_id"`
	AccountName string              `json:"account_name"`
	Metadata    map[string]any      `json:"metadata,omitempty"`
	Delivery    GateDeliveryRequest `json:"delivery"`
}

type AcknowledgeGateSessionDeliveryParams struct {
	PollToken string `json:"-"`
	AckToken  string `json:"ack_token"`
}

type GateLoginSession struct {
	Object     string `json:"object"`
	ID         string `json:"id"`
	Status     string `json:"status"`
	ConsentURL string `json:"consent_url"`
	ExpiresAt  string `json:"expires_at"`
}

type GateDashboardLogin struct {
	Object        string `json:"object"`
	GateAccountID string `json:"gate_account_id"`
	AccountName   string `json:"account_name"`
}

type CreateGateLoginSessionParams struct {
	ServiceID  string `json:"service_id"`
	AgentToken string `json:"-"`
}

type ConsumeGateLoginSessionParams struct {
	Code string `json:"code"`
}

type AgentTokenVerification struct {
	Valid         bool   `json:"valid"`
	GateAccountID string `json:"gate_account_id,omitempty"`
	Status        string `json:"status,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

type VerifyGateAgentTokenParams struct {
	AgentToken string `json:"agent_token"`
}

type RevokeGateAgentTokenParams struct {
	AgentToken string `json:"agent_token"`
}
