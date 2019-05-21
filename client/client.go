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
	req.SetBasicAuth(c.Username, c.Password)
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

func (c *Client) AddReportRaw(report string) error {
	reports, err := c.resolvePath("reports")
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodPost, reports, bytes.NewBufferString(report))
	req.Header.Set("Content-Type", "application/json")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusCreated {
		return err
	}
	return nil
}

func (c *Client) AddReport(r types.Report) error {
	// fix this as well
	payload, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	return c.AddReportRaw(string(payload))
}

func (c *Client) Heartbeat(hb types.HostHeartbeat) (uint16, error) {

	heartbeat, err := c.resolvePath("heartbeat")
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(hb)
	if err != nil {
		return 0, err
	}
	httpBody := string(payload)
	req, _ := http.NewRequest(http.MethodPost, heartbeat, bytes.NewBufferString(httpBody))
	req.Header.Set("Content-Type", "application/json")

	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return 0, err
	}
	if rsp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(rsp.Body)
		return 0, fmt.Errorf("heartbeat error: HTTP %d: %s", rsp.StatusCode, string(msg))
	}
	var heartbeatResp types.HostHeartbeat
	err = json.NewDecoder(rsp.Body).Decode(&heartbeatResp)
	if err != nil {
		return 0, err
	}
	return heartbeatResp.IntervalMins, nil
}
