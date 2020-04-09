/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	"intel/isecl/authservice/v2/constants"
	commLog "intel/isecl/lib/common/v2/log"
	"intel/isecl/lib/common/v2/setup"
	"os"
	"path"
	"sync"
	"time"

	errorLog "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// should move this into lib common, as its duplicated across AAS and AAS

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	CmsTlsCertDigest string
	Postgres         struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        log.Level

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}

	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseUrl string
	Subject    struct {
		TLSCertCommonName string
		JWTCertCommonName string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

var mu sync.Mutex

var global *Configuration

func Global() *Configuration {
	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	var err error = nil

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	jwtCertCN, err := c.GetenvString("AAS_JWT_CERT_CN", "AAS JWT Certificate Common Name")
	if err == nil && jwtCertCN != "" {
		conf.Subject.JWTCertCommonName = jwtCertCN
	} else if conf.Subject.JWTCertCommonName == "" {
		conf.Subject.JWTCertCommonName = constants.DefaultAasJwtCn
	}

	tlsCertCN, err := c.GetenvString("AAS_TLS_CERT_CN", "AAS TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultAasTlsCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file/directory where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultAasTlsSan
	}

	jwtTokenDuration, err := c.GetenvInt("AAS_JWT_TOKEN_DURATION_MINS", "AAS JWT token life span")
	if err == nil {
		conf.Token.TokenDurationMins = jwtTokenDuration
	} else {
		conf.Token.TokenDurationMins = constants.DefaultAasJwtDurationMins
	}

	return conf.Save()

}

func (conf *Configuration) Save() error {
	if conf.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(conf.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(conf.configFile)
			os.Chmod(conf.configFile, 0640)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(conf)
}

func Load(path string) *Configuration {
	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}

	c.configFile = path
	return &c
}
