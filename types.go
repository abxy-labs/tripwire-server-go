package tripwire

type ListResult[T any] struct {
	Items      []T
	Limit      int
	HasMore    bool
	NextCursor string
}

type FieldError struct {
	Field    string `json:"field"`
	Issue    string `json:"issue"`
	Expected string `json:"expected,omitempty"`
	Received any    `json:"received,omitempty"`
}

type ErrorDetails struct {
	FieldErrors []FieldError `json:"fieldErrors,omitempty"`
}

type PublicErrorBody struct {
	Code      string       `json:"code"`
	Message   string       `json:"message"`
	Status    int          `json:"status"`
	Retryable bool         `json:"retryable"`
	RequestID string       `json:"requestId"`
	DocsURL   string       `json:"docsUrl,omitempty"`
	Details   ErrorDetails `json:"details,omitempty"`
}

type publicErrorEnvelope struct {
	Error PublicErrorBody `json:"error"`
}

type pagination struct {
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"hasMore"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type resourceEnvelope[T any] struct {
	Data T `json:"data"`
}

type resourceListEnvelope[T any] struct {
	Data       []T        `json:"data"`
	Pagination pagination `json:"pagination"`
}

type ResultSummary struct {
	EventID             string  `json:"eventId"`
	Verdict             string  `json:"verdict"`
	RiskScore           int     `json:"riskScore"`
	Phase               string  `json:"phase,omitempty"`
	Provisional         *bool   `json:"provisional,omitempty"`
	ManipulationScore   *int    `json:"manipulationScore,omitempty"`
	ManipulationVerdict *string `json:"manipulationVerdict,omitempty"`
	EvaluationDuration  *int    `json:"evaluationDuration,omitempty"`
	ScoredAt            string  `json:"scoredAt"`
}

type FingerprintReference struct {
	Object     string  `json:"object"`
	ID         string  `json:"id"`
	Confidence *int    `json:"confidence,omitempty"`
	Timestamp  *string `json:"timestamp,omitempty"`
}

type SessionMetadata struct {
	UserAgent   string  `json:"userAgent"`
	URL         string  `json:"url"`
	ScreenSize  *string `json:"screenSize,omitempty"`
	TouchDevice *bool   `json:"touchDevice,omitempty"`
	ClientIP    string  `json:"clientIp"`
}

type SessionLatestResultDetail struct {
	ResultSummary
	VisitorID *string         `json:"visitorId,omitempty"`
	Metadata  SessionMetadata `json:"metadata"`
}

type SessionSummary struct {
	Object        string                `json:"object"`
	ID            string                `json:"id"`
	CreatedAt     *string               `json:"createdAt,omitempty"`
	LatestEventID string                `json:"latestEventId"`
	LatestResult  ResultSummary         `json:"latestResult"`
	Fingerprint   *FingerprintReference `json:"fingerprint,omitempty"`
	LastScoredAt  string                `json:"lastScoredAt"`
}

type SessionDetail struct {
	Object        string                    `json:"object"`
	ID            string                    `json:"id"`
	CreatedAt     *string                   `json:"createdAt,omitempty"`
	LatestEventID string                    `json:"latestEventId"`
	LatestResult  SessionLatestResultDetail `json:"latestResult"`
	IPIntel       map[string]any            `json:"ipIntel,omitempty"`
	Fingerprint   *FingerprintReference     `json:"fingerprint,omitempty"`
	ResultHistory []ResultSummary           `json:"resultHistory"`
}

type FingerprintSummary struct {
	Object            string  `json:"object"`
	ID                string  `json:"id"`
	FirstSeenAt       string  `json:"firstSeenAt"`
	LastSeenAt        string  `json:"lastSeenAt"`
	SeenCount         int     `json:"seenCount"`
	LastUserAgent     string  `json:"lastUserAgent"`
	LastIP            string  `json:"lastIp"`
	ExpiresAt         string  `json:"expiresAt"`
	AnchorWebglHash   *string `json:"anchorWebglHash,omitempty"`
	AnchorParamsHash  *string `json:"anchorParamsHash,omitempty"`
	AnchorAudioHash   *string `json:"anchorAudioHash,omitempty"`
	FingerprintVector []int   `json:"fingerprintVector,omitempty"`
	HasCookie         bool    `json:"hasCookie,omitempty"`
	HasLs             bool    `json:"hasLs,omitempty"`
	HasIdb            bool    `json:"hasIdb,omitempty"`
	HasSw             bool    `json:"hasSw,omitempty"`
	HasWn             bool    `json:"hasWn,omitempty"`
}

type FingerprintSessionSummary struct {
	EventID        string         `json:"eventId"`
	Verdict        string         `json:"verdict"`
	RiskScore      int            `json:"riskScore"`
	ScoredAt       string         `json:"scoredAt"`
	UserAgent      string         `json:"userAgent"`
	URL            string         `json:"url"`
	ClientIP       string         `json:"clientIp"`
	ScreenSize     *string        `json:"screenSize,omitempty"`
	CategoryScores map[string]int `json:"categoryScores,omitempty"`
}

type FingerprintDetail struct {
	FingerprintSummary
	Sessions []FingerprintSessionSummary `json:"sessions"`
}

type Team struct {
	Object    string  `json:"object"`
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Slug      string  `json:"slug"`
	Status    string  `json:"status"`
	CreatedAt string  `json:"createdAt"`
	UpdatedAt *string `json:"updatedAt,omitempty"`
}

type APIKey struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	IsTest         bool     `json:"isTest"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	RateLimit      *int     `json:"rateLimit,omitempty"`
	Status         string   `json:"status"`
	CreatedAt      string   `json:"createdAt"`
	RotatedAt      *string  `json:"rotatedAt,omitempty"`
	RevokedAt      *string  `json:"revokedAt,omitempty"`
}

type IssuedAPIKey struct {
	APIKey
	SecretKey string `json:"secretKey"`
}

type VerifiedTripwireSignal struct {
	ID         string         `json:"id"`
	Category   string         `json:"category"`
	Confidence string         `json:"confidence"`
	Score      int            `json:"score"`
	Raw        map[string]any `json:"raw,omitempty"`
}

type VerifiedTripwireToken struct {
	EventID             string                   `json:"eventId"`
	SessionID           string                   `json:"sessionId"`
	Verdict             string                   `json:"verdict"`
	Score               int                      `json:"score"`
	ManipulationScore   *int                     `json:"manipulationScore,omitempty"`
	ManipulationVerdict *string                  `json:"manipulationVerdict,omitempty"`
	EvaluationDuration  *int                     `json:"evaluationDuration,omitempty"`
	ScoredAt            int64                    `json:"scoredAt"`
	Metadata            SessionMetadata          `json:"metadata"`
	Signals             []VerifiedTripwireSignal `json:"signals"`
	CategoryScores      map[string]int           `json:"categoryScores"`
	BotAttribution      map[string]any           `json:"botAttribution,omitempty"`
	VisitorID           *string                  `json:"visitorId,omitempty"`
	VisitorIDConfidence *int                     `json:"visitorIdConfidence,omitempty"`
	EmbedContext        map[string]any           `json:"embedContext,omitempty"`
	Phase               *string                  `json:"phase,omitempty"`
	Provisional         *bool                    `json:"provisional,omitempty"`
	Raw                 map[string]any           `json:"raw,omitempty"`
}

type VerificationResult struct {
	OK    bool
	Data  *VerifiedTripwireToken
	Error error
}

type SessionListParams struct {
	Limit   int
	Cursor  string
	Verdict string
	Search  string
}

type FingerprintListParams struct {
	Limit  int
	Cursor string
	Search string
	Sort   string
}

type APIKeyListParams struct {
	Limit  int
	Cursor string
}

type CreateTeamParams struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type UpdateTeamParams struct {
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

type CreateAPIKeyParams struct {
	Name           string   `json:"name,omitempty"`
	IsTest         *bool    `json:"isTest,omitempty"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	RateLimit      *int     `json:"rateLimit,omitempty"`
}
