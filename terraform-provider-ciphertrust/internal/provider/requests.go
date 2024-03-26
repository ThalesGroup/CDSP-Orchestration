package provider

import (
	"bytes"
	"context"
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

func (c *Client) SaveUser(ctx context.Context, endpoint string, data User) (User, error) {
	payload, err := json.Marshal(data)
	reader := bytes.NewBuffer(payload)

	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return User{}, err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint),
		reader)
	if err != nil {
		return User{}, err
	}

	body, err := c.doRequest(req, nil)
	if err != nil {
		return User{}, err
	}

	usersJson := gjson.Get(string(body), "resources").String()

	resp := User{}
	err = json.Unmarshal([]byte(usersJson), &resp)
	if err != nil {
		return User{}, err
	}

	return resp, nil
}
