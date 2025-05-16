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
	return &libAIC{
		client: &http.Client{
			Transport: transport,
		},
	}, nil
}
