package libaic

import (
	"net/http"
	"net/url"

	"github.com/brain-hol/go-httpkit"
	"github.com/brain-hol/go-httpkit/middleware"
)

type libAIC struct {
	client *http.Client
}

type Opts struct {
	BaseURL *url.URL
	Auth    authStrategy
}

func New(opts Opts) (*libAIC, error) {
	transport := &httpkit.Transport{}
	transport.Use(
		acceptApiVersionMiddleware,
		middleware.BaseURL(opts.BaseURL),
		middleware.DebugLog,
	)
	client := &http.Client{
		Transport: transport,
	}
	if opts.Auth != nil {
		mw, err := opts.Auth.generateMiddleware(opts)
		if err != nil {
			return nil, err
		}
		transport.Use(mw)
	}
	return &libAIC{
		client,
	}, nil
}
