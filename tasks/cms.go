/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"intel/isecl/lib/common/v2/setup"
	"io"
)

type CMS struct {
	Flags         []string
	ConsoleWriter io.Writer
}

func (cms CMS) Run(c setup.Context) error {

	// save root ca to a file under TrustedCAsStoreDir with SavePemCertWithShortSha1FileName
	// save cert to const.TLSCertFile

	return nil
}

func (cms CMS) Validate(c setup.Context) error {

	return nil
}
