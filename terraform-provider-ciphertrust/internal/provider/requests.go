package provider

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tidwall/gjson"
)

func (c *Client) GetAll(endpoint string) ([]User, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req, nil)
	if err != nil {
		return nil, err
	}

	usersJson := gjson.Get(string(body), "resources").String()

	resp := []User{}
	err = json.Unmarshal([]byte(usersJson), &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
