package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

func (c *Client) DeleteByID(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> DeleteByID]["+uuid+"]")
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, uuid), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAll]["+uuid+"]")
	return responseJson, nil
}

func (c *Client) GetAll(ctx context.Context, uuid string, endpoint string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> GetAll]["+uuid+"]")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> GetAll]["+uuid+"]")
		return "", err
	}

	responseJson := gjson.Get(string(body), "resources").String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> GetAll]["+uuid+"]")
	return responseJson, nil
}

func (c *Client) PostData(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> PostData]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, "*****POST data for*****"+endpoint+"*****"+reader.String()+"*****")

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, endpoint), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> PostData]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> PostData]["+uuid+"]")
	return ret, nil
}

func (c *Client) UpdateData(ctx context.Context, uuid string, endpoint string, data []byte, id string) (string, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[requests.go -> UpdateData]["+uuid+"]")
	reader := bytes.NewBuffer(data)
	tflog.Debug(ctx, "*****PATCH data for*****"+endpoint+"*****"+reader.String()+"*****")

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/%s/%s", c.CipherTrustURL, endpoint, uuid), reader)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [requests.go -> UpdateData]["+uuid+"]")
		return "", err
	}

	ret := gjson.Get(string(body), id).String()
	tflog.Trace(ctx, MSG_METHOD_END+"[requests.go -> UpdateData]["+uuid+"]")
	return ret, nil
}
