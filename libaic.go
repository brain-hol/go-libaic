package libaic

import (
	"fmt"
	"net/http"

	"github.com/brain-hol/go-httpkit"
	"github.com/brain-hol/go-httpkit/middleware"
)

type libAIC struct {
	client *http.Client
}

type Opts struct {
	BaseURL string
	Auth    authStrategy
}

func New(opts Opts) (*libAIC, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL cannot be blank")
	}

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
		mw, err := opts.Auth.generateMiddleware(client)
		if err != nil {
			return nil, err
		}
		transport.Use(mw)
	}
	return &libAIC{
		client,
	}, nil
}
