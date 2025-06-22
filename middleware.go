package libaic

import (
	"context"
	"net/http"

	"github.com/brain-hol/go-httpkit"
)

type contextKey string

const apiVersionKey contextKey = "apiVersion"
const needsAuthKey contextKey = "needsAuth"

// WithAPIVersion returns a copy of the request with the API version set in the context.
func withAPIVersion(req *http.Request, version string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, apiVersionKey, version)
	return req.WithContext(ctx)
}

var acceptApiVersionMiddleware = httpkit.NewMiddleware(func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
	apiVersion, ok := req.Context().Value(apiVersionKey).(string)
	if ok && apiVersion != "" {
		req.Header.Set("Accept-Api-Version", apiVersion)
	}
	return next.RoundTrip(req)
})

func withNeedsAuth(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), needsAuthKey, true)
	return req.WithContext(ctx)
}

func needsAuth(req *http.Request) bool {
	v := req.Context().Value(needsAuthKey)
	b, ok := v.(bool)
	return ok && b
}
