package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-log/tflog"
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

func (c *Client) SaveUser(ctx context.Context, endpoint string, data User) (string, error) {
	payload, err := json.Marshal(data)
	reader := bytes.NewBuffer(payload)

	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

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

	userId := gjson.Get(string(body), "user_id").String()
	tflog.Info(ctx, "*****JSON*****"+userId)

	return userId, nil
}
