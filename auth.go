package libaic

import (
	"fmt"
	"net/http"

	"github.com/brain-hol/go-httpkit"
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
	generateMiddleware(client *http.Client) (httpkit.Middleware, error)
}

type ZeroPageAuth struct {
	CookieName string
	Username   string
	Password   string
	Service    string
}

// TODO maybe make this be lazy on getting the token when needed not at bootstrap
func (strat *ZeroPageAuth) generateMiddleware(client *http.Client) (httpkit.Middleware, error) {
	cookie, err := strat.getZeroPageToken(client)
	if err != nil {
		return nil, err
	}

	mw := httpkit.NewMiddleware(func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		req.AddCookie(&http.Cookie{
			Name:  strat.CookieName,
			Value: cookie,
		})
		return next.RoundTrip(req)
	})

	return mw, nil
}

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
