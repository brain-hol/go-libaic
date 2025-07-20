package libaic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/brain-hol/go-httpkit"
	"github.com/brain-hol/go-httpkit/middleware"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type deploymentType int

const (
	classic deploymentType = iota
	cloud
	forgeops
)

var defaultRealmMap = map[deploymentType]string{
	classic:  "/",
	cloud:    "/alpha",
	forgeops: "/",
}

type authStrategy interface {
	generateMiddleware(opts Opts) (httpkit.Middleware, error)
}

type ZeroPageAuth struct {
	CookieName string
	Username   string
	Password   string
	Service    string
}

var _ authStrategy = &ZeroPageAuth{}

func (strat *ZeroPageAuth) generateMiddleware(opts Opts) (httpkit.Middleware, error) {
	var cookie string
	var once sync.Once
	var fetchErr error

	transport := &httpkit.Transport{}
	transport.Use(
		middleware.BaseURL(opts.BaseURL),
		middleware.DebugLog,
	)
	tokenClient := &http.Client{
		Transport: transport,
	}

	mw := httpkit.NewMiddleware(func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		if !needsAuth(req) {
			return next.RoundTrip(req)
		}
		once.Do(func() {
			cookie, fetchErr = strat.getZeroPageToken(tokenClient)
		})
		if fetchErr != nil {
			return nil, fetchErr
		}
		req.AddCookie(&http.Cookie{
			Name:  strat.CookieName,
			Value: cookie,
		})
		return next.RoundTrip(req)
	})

	return mw, nil
}

// TODO use an api_authenticate or something file for network request
func (strat *ZeroPageAuth) getZeroPageToken(client *http.Client) (string, error) {
	url := fmt.Sprintf("json%s/authenticate?authIndexType=service&authIndexValue=%s", defaultRealmMap[cloud], strat.Service)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-OpenAM-Username", strat.Username)
	req.Header.Set("X-OpenAM-Password", strat.Password)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == strat.CookieName {
			return c.Value, nil
		}
	}

	return "", fmt.Errorf("zero page token not found")
}

type ServiceAccountAuth struct {
	ID  string
	JWK []byte
}

var _ authStrategy = &ServiceAccountAuth{}

func (strat *ServiceAccountAuth) generateMiddleware(opts Opts) (httpkit.Middleware, error) {
	var token string
	var once sync.Once
	var fetchErr error

	transport := &httpkit.Transport{}
	transport.Use(
		middleware.BaseURL(opts.BaseURL),
		middleware.DebugLog,
	)
	tokenClient := &http.Client{
		Transport: transport,
	}

	mw := httpkit.NewMiddleware(func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		if !needsAuth(req) {
			return next.RoundTrip(req)
		}
		once.Do(func() {
			token, fetchErr = strat.fetchAccessToken(tokenClient, opts.BaseURL)
		})
		if fetchErr != nil {
			return nil, fetchErr
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return next.RoundTrip(req)
	})

	return mw, nil
}

func (strat *ServiceAccountAuth) fetchAccessToken(client *http.Client, baseURL *url.URL) (string, error) {
	jwtStr, err := strat.createPayload(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT payload: %w", err)
	}

	form := url.Values{
		"assertion":  {jwtStr},
		"client_id":  {"service-account"},
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"scope":      {"fr:am:* fr:idm:*"},
	}
	req, err := http.NewRequest("POST", "oauth2/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAPIVersion(req, "protocol=2.1,resource=1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d when fetching token", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("token response contained no access_token")
	}

	return result.AccessToken, nil
}

type Payload struct {
	Iss string
	Sub string
	Aud string
	Exp int64
	JTI string
}

func (strat *ServiceAccountAuth) createPayload(baseURL *url.URL) (string, error) {
	port := baseURL.Port()
	if port == "" {
		if baseURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	aud := fmt.Sprintf("%s://%s:%s%s/oauth2/access_token", baseURL.Scheme, baseURL.Hostname(), port, baseURL.EscapedPath())
	exp := time.Now().Add(3 * time.Minute)
	jti := uuid.NewString()

	tok, err := jwt.NewBuilder().
		Issuer(strat.ID).
		Subject(strat.ID).
		Audience([]string{aud}).
		Expiration(exp).
		JwtID(jti).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	private, err := jwk.ParseKey(strat.JWK)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWK: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), private))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

type AmsterAuth struct {
	Subject    string
	KeyBytes   []byte
	CookieName string
}

var _ authStrategy = &AmsterAuth{}

func (strat *AmsterAuth) generateMiddleware(opts Opts) (httpkit.Middleware, error) {
	var cookie string
	var once sync.Once
	var fetchErr error

	transport := &httpkit.Transport{}
	transport.Use(
		middleware.BaseURL(opts.BaseURL),
		middleware.DebugLog,
	)
	client := &http.Client{
		Transport: transport,
	}

	mw := httpkit.NewMiddleware(func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		if !needsAuth(req) {
			return next.RoundTrip(req)
		}
		once.Do(func() {
			cookie, fetchErr = strat.fetchAmsterToken(client)
		})
		if fetchErr != nil {
			return nil, fetchErr
		}
		req.AddCookie(&http.Cookie{
			Name:  strat.CookieName,
			Value: cookie,
		})
		return next.RoundTrip(req)
	})

	return mw, nil
}

func (strat *AmsterAuth) fetchAmsterToken(client *http.Client) (string, error) {
	authURL := "json/authenticate?authIndexType=service&authIndexValue=amsterService"

	// Initial request to get nonce
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// TODO find a way to make this integrated with authenticate api
	var authResp struct {
		AuthID    string `json:"authId"`
		Callbacks []struct {
			Type   string `json:"type"`
			Output []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"output"`
		} `json:"callbacks"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("error decoding nonce response: %w", err)
	}

	var nonce string
	for _, cb := range authResp.Callbacks {
		if cb.Type == "HiddenValueCallback" {
			for _, out := range cb.Output {
				if out.Name == "value" {
					nonce = out.Value
				}
			}
		}
	}

	if nonce == "" {
		return "", fmt.Errorf("nonce not found in auth response")
	}

	jwtStr, err := strat.generateJWT(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// TOOD once we have nice helpers around these, lets just modify the original instead
	payload := map[string]any{
		"authId": authResp.AuthID,
		"callbacks": []map[string]any{
			{
				"type": "HiddenValueCallback",
				"input": []map[string]any{
					{"name": "IDToken1", "value": jwtStr},
				},
				"output": []map[string]any{
					{"name": "value", "value": nonce},
					{"name": "id", "value": "jwt"},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth response: %w", err)
	}

	req, err = http.NewRequest("POST", authURL, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == strat.CookieName {
			return c.Value, nil
		}
	}

	return "", fmt.Errorf("authentication failed, no token returned")
}

func (strat *AmsterAuth) generateJWT(nonce string) (string, error) {
	tok, err := jwt.NewBuilder().
		Subject(strat.Subject).
		Claim("nonce", nonce).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	private, err := parseKeyToJWK(strat.KeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWK: %w", err)
	}

	kid, err := extractBase64SshPublicKey(strat.KeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to extract base64 ssh public key from private key: %w", err)
	}

	err = private.Set(jwk.KeyIDKey, kid)
	if err != nil {
		return "", fmt.Errorf("failed to set kid of private key: %w", err)
	}

	var alg jwa.SignatureAlgorithm

	switch private.KeyType() {
	case jwa.RSA():
		alg = jwa.RS256()
	case jwa.EC():
		alg = jwa.ES256()
	// OKP for Ed25519
	case jwa.OKP():
		alg = jwa.EdDSA()
	default:
		return "", fmt.Errorf("unsupported key type: %s", private.KeyType())
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, private))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}
