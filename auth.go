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
			var jwtStr string
			jwtStr, fetchErr = strat.createPayload(opts.BaseURL)
			if fetchErr != nil {
				return
			}

			scope := "fr:am:* fr:idm:*"
			form := url.Values{}
			form.Set("assertion", jwtStr)
			form.Set("client_id", "service-account")
			form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
			form.Set("scope", scope)

			body := strings.NewReader(form.Encode())
			req, err := http.NewRequest("POST", "oauth2/access_token", body)
			if err != nil {
				fetchErr = err
				return
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAPIVersion(req, "protocol=2.1,resource=1.0")

			resp, err := tokenClient.Do(req)
			if err != nil {
				fetchErr = err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				fetchErr = fmt.Errorf("failed to get access token: %s", resp.Status)
				return
			}

			var result struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				fetchErr = fmt.Errorf("failed to decode token response: %w", err)
				return
			}

			token = result.AccessToken
		})
		if fetchErr != nil {
			return nil, fetchErr
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return next.RoundTrip(req)
	})

	return mw, nil
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
