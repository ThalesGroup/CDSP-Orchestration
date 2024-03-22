package provider

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// Default CipherTrust Manager URL
const CipherTrustURL string = "https://10.10.10.10"

// Client
type Client struct {
	CipherTrustURL string
	HTTPClient     *http.Client
	Token          string
	AuthData       AuthStruct
}

// AuthStruct
type AuthStruct struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthDomain string `json:"auth_domain"`
	Domain     string `json:"domain"`
}

// AuthResponse
type AuthResponse struct {
	Token string `json:"jwt"`
}

// Create New Client for CM
func NewClient(address, auth_domain, domain, username, password *string) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := Client{
		HTTPClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
		},
		// Default URL
		CipherTrustURL: CipherTrustURL,
	}

	if address != nil {
		c.CipherTrustURL = *address
	}

	// If username or password not provided, return empty client
	if username == nil || password == nil {
		return &c, nil
	}

	c.AuthData = AuthStruct{
		Username:   *username,
		Password:   *password,
		AuthDomain: *auth_domain,
		Domain:     *domain,
	}

	ar, err := c.SignIn()
	if err != nil {
		return nil, err
	}

	c.Token = ar.Token

	return &c, nil
}

func (c *Client) doRequest(req *http.Request, jwt *string) ([]byte, error) {
	token := c.Token

	if jwt != nil {
		token = *jwt
	}

	var bearer = "Bearer " + token
	req.Header.Set("Authorization", bearer)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, err
}
