/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"intel/isecl/authservice/types"
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

func (c *Client) GetHost(id string) (*types.Host, error) {
	hosts, err := c.resolvePath("hosts/" + id)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, hosts, nil)
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve host with id %s: HTTP Code: %d", id, rsp.StatusCode)
	}
	var fetched types.Host
	err = json.NewDecoder(rsp.Body).Decode(&fetched)
	if err != nil {
		return nil, err
	}
	return &fetched, nil
}

func (c *Client) AddHost(h types.HostInfo) (*types.HostCreateResponse, error) {
	hosts, err := c.resolvePath("hosts")
	if err != nil {
		return nil, err
	}

	// to fix: you can stream the marshalling directly to HTTP using a buffer
	payload, err := json.Marshal(&h)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodPost, hosts, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusCreated {
		msg, _ := ioutil.ReadAll(rsp.Body)
		return nil, fmt.Errorf("failed to create host: %s: HTTP Code: %d", string(msg), rsp.StatusCode)
	}
	// parse it and return
	var created types.HostCreateResponse
	err = json.NewDecoder(rsp.Body).Decode(&created)
	if err != nil {
		return nil, err
	}
	return &created, nil
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
