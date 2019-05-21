/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncoding(t *testing.T) {
	h := Host{
		ID: "1234",
		HostInfo: HostInfo{
			Version: "v1.0",
			HardwareUUID: "1eda8d91-fa26-44bd-85f3-283dc520e658",
			Hostname : "10.105.167.1",
			Build:   "12313131",
			OS:      "Linux",
		},
		Status: "Reserve for future implementation",
	}
	j, _ := json.Marshal(h)
	t.Log(string(j))
	assert.Equal(t, `{"id":"1234","hostname":"10.105.167.1","hardware_uuid":"1eda8d91-fa26-44bd-85f3-283dc520e658","version":"v1.0","build":"12313131","os":"Linux","status":"Reserve for future implementation"}`, string(j))
}

func TestDecoding(t *testing.T) {
	var h Host
	json.Unmarshal([]byte(`{"id":"1234","hostname":"10.105.167.1","hardware_uuid":"1eda8d91-fa26-44bd-85f3-283dc520e658","version":"v1.0","build":"12313131","os":"Linux","status":"Reserve for future implementation"}`), &h)
	assert.Equal(t, "1234", h.ID)
	assert.Equal(t, "v1.0", h.Version)
}
