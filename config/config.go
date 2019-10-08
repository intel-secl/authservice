/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	"intel/isecl/authservice/constants"
	"intel/isecl/lib/common/setup"
	"os"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// should move this into lib common, as its duplicated across AAS and AAS

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile string
	Port       int
	Postgres   struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogLevel log.Level

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
		Organization      string
		Country           string
		Province          string
		Locality          string
	}
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

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		log.Error("CMS_BASE_URL is not defined in environment")
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

	certOrg, err := c.GetenvString("AAS_CERT_ORG", "AAS Certificate Organization")
	if err == nil && certOrg != "" {
		conf.Subject.Organization = certOrg
	} else if conf.Subject.Organization == "" {
		conf.Subject.Organization = constants.DefaultAasCertOrganization
	}

	certCountry, err := c.GetenvString("AAS_CERT_COUNTRY", "AAS Certificate Country")
	if err == nil && certCountry != "" {
		conf.Subject.Country = certCountry
	} else if conf.Subject.Country == "" {
		conf.Subject.Country = constants.DefaultAasCertCountry
	}

	certProvince, err := c.GetenvString("AAS_CERT_PROVINCE", "AAS Certificate Province")
	if err == nil && certProvince != "" {
		conf.Subject.Province = certProvince
	} else if err != nil || conf.Subject.Province == "" {
		conf.Subject.Province = constants.DefaultAasCertProvince
	}

	certLocality, err := c.GetenvString("AAS_CERT_LOCALITY", "AAS Certificate Locality")
	if err == nil && certLocality != "" {
		conf.Subject.Locality = certLocality
	} else if conf.Subject.Locality == "" {
		conf.Subject.Locality = constants.DefaultAasCertLocality
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
			os.Chmod(conf.configFile, 0440)
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
