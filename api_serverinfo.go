package libaic

import "net/http"

func (aic *libAIC) GetServerInfo() error {
	req, _ := http.NewRequest("GET", "json/serverinfo/*", nil)
	req = withAPIVersion(req, "resource=1.1")
	req = withNeedsAuth(req)
	_, err := aic.client.Do(req)
	return err
}
