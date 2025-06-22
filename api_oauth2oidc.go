package libaic

import (
	"io"
	"net/http"
)

func (aic *libAIC) PostAccessToken(body io.Reader) error {
	req, _ := http.NewRequest("POST", "oauth2/access_token", body)
	req = withAPIVersion(req, "protocol=2.1,resource=1.0")
	_, err := aic.client.Do(req)
	return err
}
