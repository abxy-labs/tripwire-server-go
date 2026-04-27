package tripwire

type ListResult[T any] struct {
	Items      []T
	Limit      int
	HasMore    bool
	NextCursor string
}

type FieldError struct {
	Name     string `json:"name"`
	Issue    string `json:"issue"`
	Expected string `json:"expected,omitempty"`
	Received any    `json:"received,omitempty"`
}

type ErrorDetails struct {
	Fields []FieldError `json:"fields,omitempty"`
}

type ApiErrorBody struct {
	Code      string       `json:"code"`
	Message   string       `json:"message"`
	Status    int          `json:"status"`
	Retryable bool         `json:"retryable"`
	RequestID string       `json:"request_id"`
	DocsURL   string       `json:"docs_url,omitempty"`
	Details   ErrorDetails `json:"details,omitempty"`
}

type apiErrorEnvelope struct {
	Error ApiErrorBody `json:"error"`
}

type meta struct {
	RequestID string `json:"request_id"`
}

type pagination struct {
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type resourceEnvelope[T any] struct {
	Data T    `json:"data"`
	Meta meta `json:"meta"`
}

type resourceListEnvelope[T any] struct {
	Data       []T        `json:"data"`
	Pagination pagination `json:"pagination"`
	Meta       meta       `json:"meta"`
}

type Manipulation struct {
	Score   *int    `json:"score,omitempty"`
	Verdict *string `json:"verdict,omitempty"`
}

type Decision struct {
	EventID              string        `json:"event_id"`
	Verdict              string        `json:"verdict"`
	RiskScore            int           `json:"risk_score"`
	Phase                string        `json:"phase,omitempty"`
	IsProvisional        *bool         `json:"is_provisional,omitempty"`
	Manipulation         *Manipulation `json:"manipulation,omitempty"`
	EvaluationDurationMS *int          `json:"evaluation_duration_ms,omitempty"`
	EvaluatedAt          string        `json:"evaluated_at"`
}

type SessionDecision struct {
	EventID          string  `json:"event_id"`
	AutomationStatus string  `json:"automation_status"`
	RiskScore        int     `json:"risk_score"`
	EvaluationPhase  *string `json:"evaluation_phase,omitempty"`
	DecisionStatus   string  `json:"decision_status"`
	EvaluatedAt      string  `json:"evaluated_at"`
}

type SessionHighlightEvidence struct {
	Signal string `json:"signal"`
	Name   string `json:"name"`
}

type SessionHighlight struct {
	Key        string                     `json:"key"`
	Effect     string                     `json:"effect"`
	Importance string                     `json:"importance"`
	Summary    string                     `json:"summary"`
	Evidence   []SessionHighlightEvidence `json:"evidence,omitempty"`
}

type SessionAutomationFacet struct {
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	Relation   string  `json:"relation"`
}

type SessionAutomation struct {
	Category         *string                           `json:"category,omitempty"`
	Confidence       *float64                          `json:"confidence,omitempty"`
	Provider         *string                           `json:"provider,omitempty"`
	Product          *string                           `json:"product,omitempty"`
	Framework        *string                           `json:"framework,omitempty"`
	ConcealmentStyle *string                           `json:"concealment_style,omitempty"`
	Organization     *string                           `json:"organization,omitempty"`
	Facets           map[string]SessionAutomationFacet `json:"facets"`
}

type SessionWebBotAuth struct {
	Status *string `json:"status,omitempty"`
	Domain *string `json:"domain,omitempty"`
}

type SessionRuntimeIntegrity struct {
	TamperingDetected         bool `json:"tampering_detected"`
	DeveloperToolsDetected    bool `json:"developer_tools_detected"`
	EmulationSuspected        bool `json:"emulation_suspected"`
	VirtualizationSuspected   bool `json:"virtualization_suspected"`
	PrivacyHardeningSuspected bool `json:"privacy_hardening_suspected"`
}

type VisitorFingerprintLink struct {
	Object       string  `json:"object"`
	ID           string  `json:"id"`
	Confidence   *int    `json:"confidence,omitempty"`
	IdentifiedAt *string `json:"identified_at,omitempty"`
}

type RequestContext struct {
	UserAgent      string  `json:"user_agent"`
	URL            string  `json:"url"`
	ScreenSize     *string `json:"screen_size,omitempty"`
	IsTouchCapable *bool   `json:"is_touch_capable,omitempty"`
	IPAddress      string  `json:"ip_address"`
}

type SessionDetailRequest struct {
	URL       string  `json:"url"`
	Referrer  *string `json:"referrer,omitempty"`
	UserAgent string  `json:"user_agent"`
}

type SessionBrowser struct {
	Name         *string `json:"name,omitempty"`
	Version      *string `json:"version,omitempty"`
	MajorVersion *string `json:"major_version,omitempty"`
	Engine       string  `json:"engine"`
}

type SessionDeviceOperatingSystem struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
}

type SessionDeviceScreen struct {
	Size            *string  `json:"size,omitempty"`
	ColorDepth      *int     `json:"color_depth,omitempty"`
	PixelRatio      *float64 `json:"pixel_ratio,omitempty"`
	OrientationType *string  `json:"orientation_type,omitempty"`
}

type SessionDeviceLocale struct {
	Timezone        *string  `json:"timezone,omitempty"`
	PrimaryLanguage *string  `json:"primary_language,omitempty"`
	Languages       []string `json:"languages"`
}

type SessionDeviceTouchCapabilities struct {
	Available      *bool `json:"available,omitempty"`
	MaxTouchPoints *int  `json:"max_touch_points,omitempty"`
}

type SessionDeviceStorageCapabilities struct {
	Cookies       *bool `json:"cookies,omitempty"`
	LocalStorage  *bool `json:"local_storage,omitempty"`
	IndexedDB     *bool `json:"indexed_db,omitempty"`
	ServiceWorker *bool `json:"service_worker,omitempty"`
	WindowName    *bool `json:"window_name,omitempty"`
}

type SessionDeviceAvailabilityCapability struct {
	Available *bool `json:"available,omitempty"`
}

type SessionDevicePlatformAuthenticatorCapabilities struct {
	Available            *bool `json:"available,omitempty"`
	ConditionalMediation *bool `json:"conditional_mediation,omitempty"`
}

type SessionDeviceCapabilities struct {
	Touch                 SessionDeviceTouchCapabilities                 `json:"touch"`
	Storage               SessionDeviceStorageCapabilities               `json:"storage"`
	WebGPU                SessionDeviceAvailabilityCapability            `json:"webgpu"`
	PlatformAuthenticator SessionDevicePlatformAuthenticatorCapabilities `json:"platform_authenticator"`
	MediaDevices          SessionDeviceAvailabilityCapability            `json:"media_devices"`
	SpeechSynthesis       SessionDeviceAvailabilityCapability            `json:"speech_synthesis"`
}

type SessionDevice struct {
	FormFactor      string                       `json:"form_factor"`
	OperatingSystem SessionDeviceOperatingSystem `json:"operating_system"`
	Architecture    *string                      `json:"architecture,omitempty"`
	Screen          SessionDeviceScreen          `json:"screen"`
	Locale          SessionDeviceLocale          `json:"locale"`
	Capabilities    SessionDeviceCapabilities    `json:"capabilities"`
}

type SessionRawDeviceNavigator struct {
	Platform            *string  `json:"platform,omitempty"`
	Vendor              *string  `json:"vendor,omitempty"`
	HardwareConcurrency *int     `json:"hardware_concurrency,omitempty"`
	DeviceMemory        *float64 `json:"device_memory,omitempty"`
	MaxTouchPoints      *int     `json:"max_touch_points,omitempty"`
	PDFViewerEnabled    *bool    `json:"pdf_viewer_enabled,omitempty"`
	CookieEnabled       *bool    `json:"cookie_enabled,omitempty"`
	ProductSub          *string  `json:"product_sub,omitempty"`
	PrimaryLanguage     *string  `json:"primary_language,omitempty"`
	Languages           []string `json:"languages"`
	MimeTypesCount      *int     `json:"mime_types_count,omitempty"`
	Plugins             []string `json:"plugins"`
}

type SessionRawDeviceStorage struct {
	Cookies        *bool `json:"cookies,omitempty"`
	LocalStorage   *bool `json:"local_storage,omitempty"`
	SessionStorage *bool `json:"session_storage,omitempty"`
	IndexedDB      *bool `json:"indexed_db,omitempty"`
	ServiceWorker  *bool `json:"service_worker,omitempty"`
	WindowName     *bool `json:"window_name,omitempty"`
}

type SessionRawDeviceCanvas struct {
	Hash                any   `json:"hash"`
	GeometryHash        any   `json:"geometry_hash"`
	TextHash            any   `json:"text_hash"`
	Winding             *bool `json:"winding,omitempty"`
	NoiseDetected       *bool `json:"noise_detected,omitempty"`
	OffscreenConsistent *bool `json:"offscreen_consistent,omitempty"`
}

type SessionRawDeviceGraphicsWebGL struct {
	Vendor                  *string `json:"vendor,omitempty"`
	Renderer                *string `json:"renderer,omitempty"`
	Version                 *string `json:"version,omitempty"`
	ShadingLanguageVersion  *string `json:"shading_language_version,omitempty"`
	ParametersHash          any     `json:"parameters_hash"`
	ExtensionsHash          any     `json:"extensions_hash"`
	ExtensionParametersHash any     `json:"extension_parameters_hash"`
	ShaderPrecisionHash     any     `json:"shader_precision_hash"`
}

type SessionRawDeviceGraphicsWebGPU struct {
	Available           *bool   `json:"available,omitempty"`
	AdapterVendor       *string `json:"adapter_vendor,omitempty"`
	AdapterArchitecture *string `json:"adapter_architecture,omitempty"`
	FallbackAdapter     *bool   `json:"fallback_adapter,omitempty"`
	FeaturesHash        any     `json:"features_hash"`
	LimitsHash          any     `json:"limits_hash"`
}

type SessionRawDeviceGraphics struct {
	WebGL  SessionRawDeviceGraphicsWebGL  `json:"webgl"`
	WebGPU SessionRawDeviceGraphicsWebGPU `json:"webgpu"`
}

type SessionRawDeviceAudio struct {
	Hash             any      `json:"hash"`
	SampleRate       *float64 `json:"sample_rate,omitempty"`
	ChannelCount     *int     `json:"channel_count,omitempty"`
	VoiceCount       *int     `json:"voice_count,omitempty"`
	LocalVoiceCount  *int     `json:"local_voice_count,omitempty"`
	DefaultVoiceLang *string  `json:"default_voice_lang,omitempty"`
	NoiseDetected    *bool    `json:"noise_detected,omitempty"`
}

type SessionRawDeviceFonts struct {
	DetectedCount   *int `json:"detected_count,omitempty"`
	TestedCount     *int `json:"tested_count,omitempty"`
	EnumerationHash any  `json:"enumeration_hash"`
	MetricsHash     any  `json:"metrics_hash"`
	PreferencesHash any  `json:"preferences_hash"`
	EmojiHash       any  `json:"emoji_hash"`
}

type SessionRawDeviceMedia struct {
	DeviceCount     *int           `json:"device_count,omitempty"`
	CountsByKind    map[string]int `json:"counts_by_kind"`
	BlankLabelCount *int           `json:"blank_label_count,omitempty"`
	TopologyHash    any            `json:"topology_hash"`
}

type SessionClientTelemetry struct {
	Navigator SessionRawDeviceNavigator `json:"navigator"`
	Storage   SessionRawDeviceStorage   `json:"storage"`
	Canvas    SessionRawDeviceCanvas    `json:"canvas"`
	Graphics  SessionRawDeviceGraphics  `json:"graphics"`
	Audio     SessionRawDeviceAudio     `json:"audio"`
	Fonts     SessionRawDeviceFonts     `json:"fonts"`
	Media     SessionRawDeviceMedia     `json:"media"`
}

type SessionSummary struct {
	Object             string                  `json:"object"`
	ID                 string                  `json:"id"`
	CreatedAt          *string                 `json:"created_at,omitempty"`
	LatestDecision     Decision                `json:"latest_decision"`
	VisitorFingerprint *VisitorFingerprintLink `json:"visitor_fingerprint,omitempty"`
}

type SessionNetworkLocation struct {
	City             *string  `json:"city,omitempty"`
	Region           *string  `json:"region,omitempty"`
	Country          *string  `json:"country,omitempty"`
	CountryCode      *string  `json:"country_code,omitempty"`
	Latitude         *float64 `json:"latitude,omitempty"`
	Longitude        *float64 `json:"longitude,omitempty"`
	Timezone         *string  `json:"timezone,omitempty"`
	PostalCode       *string  `json:"postal_code,omitempty"`
	AccuracyRadiusKm *float64 `json:"accuracy_radius_km,omitempty"`
}

type SessionNetworkRouting struct {
	ASN          *string `json:"asn,omitempty"`
	Organization *string `json:"organization,omitempty"`
}

type SessionNetworkAnonymity struct {
	VPN              bool    `json:"vpn"`
	Proxy            bool    `json:"proxy"`
	Tor              bool    `json:"tor"`
	Relay            bool    `json:"relay"`
	Hosting          bool    `json:"hosting"`
	ResidentialProxy bool    `json:"residential_proxy"`
	CallbackProxy    bool    `json:"callback_proxy"`
	Provider         *string `json:"provider,omitempty"`
}

type SessionNetworkReputation struct {
	Listed            bool     `json:"listed"`
	Categories        []string `json:"categories"`
	SuspiciousNetwork bool     `json:"suspicious_network"`
}

type SessionNetworkEvidence struct {
	RiskSignals  []string `json:"risk_signals"`
	OperatorTags []string `json:"operator_tags"`
	ClientTypes  []string `json:"client_types"`
	ClientCount  *int     `json:"client_count,omitempty"`
}

type SessionNetwork struct {
	IPAddress   *string                  `json:"ip_address,omitempty"`
	IPVersion   *string                  `json:"ip_version,omitempty"`
	Status      string                   `json:"status"`
	Summary     *string                  `json:"summary,omitempty"`
	Location    *SessionNetworkLocation  `json:"location,omitempty"`
	Routing     SessionNetworkRouting    `json:"routing"`
	Anonymity   SessionNetworkAnonymity  `json:"anonymity"`
	Reputation  SessionNetworkReputation `json:"reputation"`
	Evidence    SessionNetworkEvidence   `json:"evidence"`
	EvaluatedAt *string                  `json:"evaluated_at,omitempty"`
}

type SessionDetailVisitorFingerprintLifecycle struct {
	FirstSeenAt *string `json:"first_seen_at,omitempty"`
	LastSeenAt  *string `json:"last_seen_at,omitempty"`
	SeenCount   *int    `json:"seen_count,omitempty"`
}

type SessionDetailVisitorFingerprint struct {
	Object       string                                   `json:"object"`
	ID           string                                   `json:"id"`
	Confidence   *int                                     `json:"confidence,omitempty"`
	IdentifiedAt *string                                  `json:"identified_at,omitempty"`
	Lifecycle    SessionDetailVisitorFingerprintLifecycle `json:"lifecycle"`
}

type SessionConnectionFingerprintJA4 struct {
	Hash          *string `json:"hash,omitempty"`
	Profile       *string `json:"profile,omitempty"`
	Family        *string `json:"family,omitempty"`
	Product       *string `json:"product,omitempty"`
	Confidence    *string `json:"confidence,omitempty"`
	Deterministic *bool   `json:"deterministic,omitempty"`
}

type SessionConnectionFingerprintHTTP2 struct {
	AkamaiFingerprint *string `json:"akamai_fingerprint,omitempty"`
	Profile           *string `json:"profile,omitempty"`
}

type SessionConnectionFingerprint struct {
	JA4                SessionConnectionFingerprintJA4   `json:"ja4"`
	HTTP2              SessionConnectionFingerprintHTTP2 `json:"http2"`
	UserAgentAlignment *string                           `json:"user_agent_alignment,omitempty"`
}

type SessionAnalysisCoverage struct {
	Browser         bool `json:"browser"`
	Device          bool `json:"device"`
	Network         bool `json:"network"`
	Runtime         bool `json:"runtime"`
	Behavioral      bool `json:"behavioral"`
	VisitorIdentity bool `json:"visitor_identity"`
}

type SessionSignalFired struct {
	Signal      string `json:"signal"`
	Role        string `json:"role"`
	Category    string `json:"category"`
	Strength    string `json:"strength"`
	SignalScore int    `json:"signal_score"`
}

type SessionDetail struct {
	Object                 string                           `json:"object"`
	ID                     string                           `json:"id"`
	CreatedAt              *string                          `json:"created_at,omitempty"`
	Decision               SessionDecision                  `json:"decision"`
	Highlights             []SessionHighlight               `json:"highlights"`
	Automation             *SessionAutomation               `json:"automation,omitempty"`
	WebBotAuth             *SessionWebBotAuth               `json:"web_bot_auth,omitempty"`
	Network                SessionNetwork                   `json:"network"`
	RuntimeIntegrity       SessionRuntimeIntegrity          `json:"runtime_integrity"`
	NativeRuntimeIntegrity map[string]any                   `json:"native_runtime_integrity,omitempty"`
	NativeApp              map[string]any                   `json:"native_app,omitempty"`
	NativeCarrier          map[string]any                   `json:"native_carrier,omitempty"`
	NativeMotionPrint      map[string]any                   `json:"native_motion_print,omitempty"`
	DeviceIdentity         map[string]any                   `json:"device_identity,omitempty"`
	InstallID              *string                          `json:"install_id,omitempty"`
	VisitorFingerprint     *SessionDetailVisitorFingerprint `json:"visitor_fingerprint,omitempty"`
	ConnectionFingerprint  SessionConnectionFingerprint     `json:"connection_fingerprint"`
	PreviousDecisions      []SessionDecision                `json:"previous_decisions"`
	Request                SessionDetailRequest             `json:"request"`
	Browser                SessionBrowser                   `json:"browser"`
	Device                 SessionDevice                    `json:"device"`
	AnalysisCoverage       SessionAnalysisCoverage          `json:"analysis_coverage"`
	SignalsFired           []SessionSignalFired             `json:"signals_fired"`
	ClientTelemetry        SessionClientTelemetry           `json:"client_telemetry"`
}

type VisitorFingerprintLifecycle struct {
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
	SeenCount   int    `json:"seen_count"`
	ExpiresAt   string `json:"expires_at"`
}

type VisitorFingerprintLatestRequest struct {
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
}

type VisitorFingerprintStorage struct {
	Cookies       bool `json:"cookies"`
	LocalStorage  bool `json:"local_storage"`
	IndexedDB     bool `json:"indexed_db"`
	ServiceWorker bool `json:"service_worker"`
	WindowName    bool `json:"window_name"`
}

type VisitorFingerprintAnchors struct {
	WebGLHash      *string `json:"webgl_hash,omitempty"`
	ParametersHash *string `json:"parameters_hash,omitempty"`
	AudioHash      *string `json:"audio_hash,omitempty"`
}

type VisitorFingerprintSummary struct {
	Object        string                          `json:"object"`
	ID            string                          `json:"id"`
	Lifecycle     VisitorFingerprintLifecycle     `json:"lifecycle"`
	LatestRequest VisitorFingerprintLatestRequest `json:"latest_request"`
	Storage       VisitorFingerprintStorage       `json:"storage"`
	Anchors       VisitorFingerprintAnchors       `json:"anchors"`
}

type ScoreBreakdown struct {
	Categories map[string]int `json:"categories"`
}

type VisitorFingerprintSessionSummary struct {
	SessionID      string         `json:"session_id"`
	Decision       Decision       `json:"decision"`
	Request        RequestContext `json:"request"`
	ScoreBreakdown ScoreBreakdown `json:"score_breakdown"`
}

type VisitorFingerprintComponents struct {
	Vector []int `json:"vector"`
}

type VisitorFingerprintActivity struct {
	Sessions []VisitorFingerprintSessionSummary `json:"sessions"`
}

type VisitorFingerprintDetail struct {
	VisitorFingerprintSummary
	Components VisitorFingerprintComponents `json:"components"`
	Activity   VisitorFingerprintActivity   `json:"activity"`
}

type Organization struct {
	Object    string  `json:"object"`
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Slug      string  `json:"slug"`
	Status    string  `json:"status"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt *string `json:"updated_at,omitempty"`
}

type APIKey struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Name           string   `json:"name"`
	Environment    string   `json:"environment"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	RateLimit      *int     `json:"rate_limit,omitempty"`
	Status         string   `json:"status"`
	KeyPreview     string   `json:"key_preview"`
	DisplayKey     *string  `json:"display_key,omitempty"`
	LastUsedAt     *string  `json:"last_used_at,omitempty"`
	CreatedAt      string   `json:"created_at"`
	RotatedAt      *string  `json:"rotated_at,omitempty"`
	RevokedAt      *string  `json:"revoked_at,omitempty"`
	GraceExpiresAt *string  `json:"grace_expires_at,omitempty"`
}

type IssuedAPIKey struct {
	APIKey
	RevealedKey string `json:"revealed_key"`
}

type VerifiedTripwireSignal struct {
	ID         string         `json:"id"`
	Category   string         `json:"category"`
	Confidence string         `json:"confidence"`
	Score      int            `json:"score"`
	Raw        map[string]any `json:"raw,omitempty"`
}

type Attribution struct {
	Bot map[string]any `json:"bot,omitempty"`
	Raw map[string]any `json:"raw,omitempty"`
}

type VerifiedTripwireToken struct {
	Object             string                   `json:"object"`
	SessionID          string                   `json:"session_id"`
	Decision           Decision                 `json:"decision"`
	Request            RequestContext           `json:"request"`
	VisitorFingerprint *VisitorFingerprintLink  `json:"visitor_fingerprint,omitempty"`
	Signals            []VerifiedTripwireSignal `json:"signals"`
	ScoreBreakdown     ScoreBreakdown           `json:"score_breakdown"`
	Attribution        Attribution              `json:"attribution"`
	Embed              map[string]any           `json:"embed,omitempty"`
	Raw                map[string]any           `json:"raw,omitempty"`
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

type CreateOrganizationParams struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type UpdateOrganizationParams struct {
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

type CreateAPIKeyParams struct {
	Name           string   `json:"name,omitempty"`
	Type           string   `json:"type,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

type UpdateAPIKeyParams struct {
	Name           string   `json:"name,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}
