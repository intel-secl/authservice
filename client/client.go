/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Client for consuming the AAService API
type Client struct {
	BaseURL string
	// Username used to authenticate with the KMS. Username is only used for obtaining an authorization token, which is automatically used for requests.
	Username string
	// Password to supply for the Username
	Password string
	// Bearer Token
	JWTToken []byte
	// A reference to the underlying http Client.
	// If the value is nil, a default client will be created and used.
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{}
	}
	return c.HTTPClient
}

func (c *Client) resolvePath(path string) (string, error) {
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	rel := baseURL.ResolveReference(&url.URL{Path: path})
	return rel.String(), err
}

func (c *Client) dispatchRequest(req *http.Request) (*http.Response, error) {
	if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	if c.JWTToken != nil {
		req.Header.Add("Authorization", "Bearer "+string(c.JWTToken))
	}
	return c.httpClient().Do(req)
}

func (c *Client) GetJwtSigningCert() ([]byte, error) {
	jwtCertUrl, err := c.resolvePath("noauth/jwtCert")
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, jwtCertUrl, nil)
	req.Header.Set("Accept", "application/x-pem-file")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve JWT signing certificate: HTTP Code: %d", rsp.StatusCode)
	}

	return ioutil.ReadAll(rsp.Body)
}

func (c *Client) GetJwtToken() ([]byte, error) {
	jwtUrl, err := c.resolvePath("token")
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, jwtUrl, nil)
	req.Header.Set("Accept", "application/jwt")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve JWT (json web token): HTTP Code: %d", rsp.StatusCode)
	}

	return ioutil.ReadAll(rsp.Body)
}
