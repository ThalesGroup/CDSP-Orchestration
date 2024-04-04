package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/tidwall/gjson"
)

func (c *Client) GetAll(
	endpoint string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		return "", err
	}

	body, err := c.doRequest(req, nil)
	if err != nil {
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	return responseJson, nil
}

func (c *Client) PostData(ctx context.Context, endpoint string, data []byte, id string) (string, error) {
	reader := bytes.NewBuffer(data)

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint),
		reader)
	if err != nil {
		return "", err
	}

	body, err := c.doRequest(req, nil)
	if err != nil {
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	return ret, nil
}
