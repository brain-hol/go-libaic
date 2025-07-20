package libaic

import "net/http"

type NoIdObject struct {
	Rev *string `json:"_rev,omitempty"`
}

type IdObject struct {
	NoIdObject
	ID   *string `json:"_id,omitempty"`
	Name string  `json:"name"`
}

type ScriptLanguage string

const (
	ScriptLanguageGroovy     ScriptLanguage = "GROOVY"
	ScriptLanguageJavaScript ScriptLanguage = "JAVASCRIPT"
)

type ScriptContext string

const (
	ContextOAuth2AccessTokenModification       ScriptContext = "OAUTH2_ACCESS_TOKEN_MODIFICATION"
	ContextAuthenticationClientSide            ScriptContext = "AUTHENTICATION_CLIENT_SIDE"
	ContextAuthenticationTreeDecisionNode      ScriptContext = "AUTHENTICATION_TREE_DECISION_NODE"
	ContextAuthenticationServerSide            ScriptContext = "AUTHENTICATION_SERVER_SIDE"
	ContextSocialIdpProfileTransformation      ScriptContext = "SOCIAL_IDP_PROFILE_TRANSFORMATION"
	ContextOAuth2ValidateScope                 ScriptContext = "OAUTH2_VALIDATE_SCOPE"
	ContextConfigProviderNode                  ScriptContext = "CONFIG_PROVIDER_NODE"
	ContextOAuth2AuthorizeEndpointDataProvider ScriptContext = "OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER"
	ContextOAuth2EvaluateScope                 ScriptContext = "OAUTH2_EVALUATE_SCOPE"
	ContextPolicyCondition                     ScriptContext = "POLICY_CONDITION"
	ContextOidcClaims                          ScriptContext = "OIDC_CLAIMS"
	ContextSaml2IdpAdapter                     ScriptContext = "SAML2_IDP_ADAPTER"
	ContextSaml2IdpAttributeMapper             ScriptContext = "SAML2_IDP_ATTRIBUTE_MAPPER"
	ContextOAuth2MayAct                        ScriptContext = "OAUTH2_MAY_ACT"
	ContextLibrary                             ScriptContext = "LIBRARY"
)

type ExportEntry struct {
	Arity *int   `json:"arity,omitempty"`
	ID    string `json:"id"`
	Type  string `json:"type"`
}

type ScriptSkeleton struct {
	IdObject

	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Default          bool           `json:"default"`
	Script           string         `json:"script"`
	Language         ScriptLanguage `json:"language"`
	Context          ScriptContext  `json:"context"`
	CreatedBy        string         `json:"createdBy"`
	CreationDate     int64          `json:"creationDate"`
	LastModifiedBy   string         `json:"lastModifiedBy"`
	LastModifiedDate int64          `json:"lastModifiedDate"`
	Exports          []ExportEntry  `json:"exports,omitempty"`
}

func (aic *libAIC) GetScripts() error {
	req, _ := http.NewRequest("GET", "json/alpha/scripts?_queryFilter=true", nil)
	req = withAPIVersion(req, "protocol=2.0,resource=1.0")
	req = withNeedsAuth(req)
	_, err := aic.client.Do(req)
	return err
}
