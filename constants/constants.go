/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	"time"
)

const (
	HomeDir                        = "/opt/authservice/"
	ConfigDir                      = "/etc/authservice/"
	ExecutableDir                  = "/opt/authservice/bin/"
	ExecLinkPath                   = "/usr/bin/authservice"
	RunDirPath                     = "/run/authservice"
	LogDir                         = "/var/log/authservice/"
	LogFile                        = LogDir + "authservice.log"
	SecurityLogFile                = LogDir + "authservice-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	TLSCertFile                    = "tls-cert.pem"
	TLSKeyFile                     = "tls.key"
	TokenSignKeysAndCertDir        = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile               = TokenSignKeysAndCertDir + "jwt.key"
	TokenSignCertFile              = TokenSignKeysAndCertDir + "jwtsigncert.pem"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	PIDFile                        = "authservice.pid"
	ServiceRemoveCmd               = "systemctl disable authservice"
	HashingAlgorithm               = crypto.SHA384
	PasswordRandomLength           = 20
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	DefaultDBRotationMaxRowCnt     = 100000
	DefaultDBRotationMaxTableCnt   = 10
	DefaultSSLCertFilePath         = ConfigDir + "aasdbcert.pem"
	ServiceName                    = "AAS"
	AASUserName                    = "aas"
	DefaultHttpPort                = 8444
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultAasTlsSan               = "127.0.0.1,localhost"
	DefaultAasTlsCn                = "AAS TLS Certificate"
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasJwtDurationMins      = 120
	DefaultJwtValidateCacheKeyMins = 60
	CmsTlsCertDigestEnv            = "CMS_TLS_CERT_SHA384"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
)

const (
	RoleAndUserManagerGroupName = "RoleAndUserManager"

	RoleManagerGroupName = "RoleManager"

	UserManagerGroupName = "UserManager"

	UserRoleManagerGroupName = "UserRoleManager"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

func GetDefaultAdministratorRoles() []string {
	return []string{"RoleManager", "UserManager", "UserRoleManager"}
}
