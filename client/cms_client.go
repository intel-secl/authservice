/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package client

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
)

type CMSClient struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client
}

func (c *CMSClient) httpClient() *http.Client {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{}
	}
	return c.HTTPClient
}

func (c *CMSClient) resolvePath(path string) (string, error) {
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	rel := baseURL.ResolveReference(&url.URL{Path: path})
	return rel.String(), err
}

func (c *CMSClient) dispatchRequest(req *http.Request) (*http.Response, error) {
	if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	return c.httpClient().Do(req)
}

func (c *CMSClient) GetRootCA() (string, error) {

	url, err := c.resolvePath("cms/ca-certificates")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Content-Type", "application/x-pem-file")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve root CA")
	}
	resBuf := new(bytes.Buffer)
	resBuf.ReadFrom(rsp.Body)
	resStr := resBuf.String()
	return resStr, nil
}

func (c *CMSClient) PostCSR() (string, error) {

	url, err := c.resolvePath("cms/certificates")
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	req.Header.Set("Accept", "application/x-pem-file")
	req.Header.Set("Content-Type", "application/x-pem-file")
	rsp, err := c.dispatchRequest(req)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to sign certificate with CMS")
	}
	resBuf := new(bytes.Buffer)
	resBuf.ReadFrom(rsp.Body)
	resStr := resBuf.String()
	return resStr, nil
}
