/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/repository/postgres"
	"intel/isecl/authservice/resource"
	"intel/isecl/authservice/tasks"
	"intel/isecl/authservice/version"
	"intel/isecl/lib/common/crypt"
	e "intel/isecl/lib/common/exec"
	jwtauth "intel/isecl/lib/common/jwt"
	commLog "intel/isecl/lib/common/log"
	commLogMsg "intel/isecl/lib/common/log/message"
	commLogInt "intel/isecl/lib/common/log/setup"
	cmw "intel/isecl/lib/common/middleware"
	cos "intel/isecl/lib/common/os"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"io"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	// Import driver for GORM
	_ "github.com/jinzhu/gorm/dialects/postgres"

	"intel/isecl/authservice/types"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	SecLogWriter   io.Writer
	HTTPLogWriter  io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "    authservice <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    -h|--help              Show this help message")
	fmt.Fprintln(w, "    setup <task>           Run setup task")
	fmt.Fprintln(w, "    start                  Start authservice")
	fmt.Fprintln(w, "    status                 Show the status of authservice")
	fmt.Fprintln(w, "    stop                   Stop authservice")
	fmt.Fprintln(w, "    tlscertsha384          Show the SHA384 digest of the certificate used for TLS")
	fmt.Fprintln(w, "    uninstall [--purge]    Uninstall authservice. --purge option needs to be applied to remove configuration and data files")
	fmt.Fprintln(w, "    -v|--version           Show the version of authservice")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Setup command usage:       authservice setup [task] [--arguments=<argument_value>] [--force]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Available Tasks for setup:")
	fmt.Fprintln(w, "    all                   Runs all setup tasks")
	fmt.Fprintln(w, "                          Required env variables:")
	fmt.Fprintln(w, "                              - get required env variables from all the setup tasks")
	fmt.Fprintln(w, "                          Optional env variables:")
	fmt.Fprintln(w, "                              - get optional env variables from all the setup tasks")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    database              Setup authservice database")
	fmt.Fprintln(w, "                          Required env variables if AAS_NOSETUP=true or variables not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Available arguments and Required Env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - db-host    alternatively, set environment variable AAS_DB_HOSTNAME")
	fmt.Fprintln(w, "                              - db-port    alternatively, set environment variable AAS_DB_PORT")
	fmt.Fprintln(w, "                              - db-user    alternatively, set environment variable AAS_DB_USERNAME")
	fmt.Fprintln(w, "                              - db-pass    alternatively, set environment variable AAS_DB_PASSWORD")
	fmt.Fprintln(w, "                              - db-name    alternatively, set environment variable AAS_DB_NAME")
	fmt.Fprintln(w, "                          Available arguments and Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - db-sslmode <disable|allow|prefer|require|verify-ca|verify-full>")
	fmt.Fprintln(w, "                              alternatively, set environment variable AAS_DB_SSLMODE")
	fmt.Fprintln(w, "                              - db-sslcert path to where the certificate file of database. Only applicable")
	fmt.Fprintln(w, "                              for db-sslmode=<verify-ca|verify-full. If left empty, the cert")
	fmt.Fprintln(w, "                              will be copied to /etc/authservice/aasdbcert.pem")
	fmt.Fprintln(w, "                              alternatively, set environment variable AAS_DB_SSLCERT")
	fmt.Fprintln(w, "                              - db-sslcertsrc <path to where the database ssl/tls certificate file>")
	fmt.Fprintln(w, "                              mandatory if db-sslcert does not already exist")
	fmt.Fprintln(w, "                              alternatively, set environment variable AAS_DB_SSLCERTSRC")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    admin                 Setup task to register authservice user with default admin roles to database")
	fmt.Fprintln(w, "                          Required env variables if AAS_NOSETUP=true or variables not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                 : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>     : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Available arguments and required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - user        alternatively, set environment variable AAS_ADMIN_USERNAME")
	fmt.Fprintln(w, "                              - pass        alternatively, set environment variable AAS_ADMIN_PASSWORD")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_ca_cert      Download CMS root CA certificate")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads new root CA cert")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_cert TLS     Generates Key pair and CSR, gets it signed from CMS")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads newly signed TLS cert")
	fmt.Fprintln(w, "                          Required env variable if AAS_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>               : for CMS API url")
	fmt.Fprintln(w, "                              - BEARER_TOKEN=<token>             : for authenticating with CMS")
	fmt.Fprintln(w, "                              - SAN_LIST=<san>                   : list of hosts which needs access to service")
	fmt.Fprintln(w, "                          Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - KEY_PATH=<key_path>              : Path of file where TLS key needs to be stored")
	fmt.Fprintln(w, "                              - CERT_PATH=<cert_path>            : Path of file/directory where TLS certificate needs to be stored")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    jwt                   Create jwt signing key and jwt certificate signed by CMS")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads newly signed JWT cert")
	fmt.Fprintln(w, "                          Required env variable if AAS_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>       : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Available arguments and Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - cms-url    alternatively, set environment variable CMS_BASE_URL")
	fmt.Fprintln(w, "                              - token      alternatively, set environment variable BEARER_TOKEN")
	fmt.Fprintln(w, "                          Available arguments and Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - subj          alternatively, set environment variable AAS_JWT_CERT_CN")
	fmt.Fprintln(w, "                              - keyid         alternatively, set environment variable AAS_JWT_INCLUDE_KEYID")
	fmt.Fprintln(w, "                              - valid-mins    alternatively, set environment variable AAS_JWT_TOKEN_DURATION_MINS")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    server                Setup http server on given port")
	fmt.Fprintln(w, "                          Required env variables if AAS_NOSETUP=true or variables not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                       : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>           : to ensure that AAS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Available argument and Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - port    alternatively, set environment variable AAS_PORT")
	fmt.Fprintln(w, "                              - AAS_SERVER_READ_TIMEOUT=<read timeout in seconds>                    : Auth Service Read Timeout")
	fmt.Fprintln(w, "                              - AAS_SERVER_READ_HEADER_TIMEOUT=<read header timeout in seconds>      : Auth Service Read Header Timeout")
	fmt.Fprintln(w, "                              - AAS_SERVER_WRITE_TIMEOUT=<write timeout in seconds>                  : Auth Service Write Timeout")
	fmt.Fprintln(w, "                              - AAS_SERVER_IDLE_TIMEOUT=<idle timeout in seconds>                    : Auth Service Idle Timeout")
	fmt.Fprintln(w, "                              - AAS_SERVER_MAX_HEADER_BYTES=<max header bytes>                       : Auth Service Max Header Bytes")
	fmt.Fprintln(w, "                              - AAS_LOG_MAX_LENGTH=<log max length>                                  : Auth Service Log maximum length")
	fmt.Fprintln(w, "                              - AAS_ENABLE_CONSOLE_LOG=<bool>                                        : Auth Service Enable standard output")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exec, err := os.Executable()
	if err != nil {
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) configureLogs(stdOut, logFile bool) {

	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.LogWriter)
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.SecLogWriter)

	f := commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	defaultLog.Info(commLogMsg.LogInit)
}

func (a *App) Run(args []string) error {
	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	//bin := args[0]
	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		return errors.New("Unrecognized command: " + args[1])

	case "list":
		if len(args) < 3 {
			a.printUsage()
			os.Exit(1)
		}
		return a.PrintDirFileContents(args[2])
	case "token":
		a.configureLogs(false, true)
		if err := a.TestTokenAuth(); err != nil {
			fmt.Printf("jwt token test create and validate test error: %v ", err)
			return err
		}
		return nil
	case "certreq":
		a.configureLogs(false, true)
		if err := a.GenerateCertRequest(); err != nil {
			fmt.Printf("certificat request error: %v ", err)
			return err
		}
		return nil
	//TODO : Remove added for debug - used to debug db queries
	case "testdb":
		a.configureLogs(false, true)
		a.TestNewDBFunctions()
	case "tlscertsha384":
		a.configureLogs(false, true)
		hash, err := crypt.GetCertHexSha384(config.Global().TLSCertFile)
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		fmt.Println(hash)
		return nil
	case "run":
		a.configureLogs(config.Global().LogEnableStdout, true)
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return err
		}
	case "-h", "--help":
		a.printUsage()
	case "start":
		a.configureLogs(false, true)
		return a.start()
	case "stop":
		a.configureLogs(false, true)
		return a.stop()
	case "status":
		a.configureLogs(false, true)
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		flag.CommandLine.Parse(args[2:])
		a.uninstall(purge)
		os.Exit(0)
	case "--version", "-v":
		fmt.Fprintf(a.consoleWriter(), "Auth Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
	case "setup":
		a.configureLogs(false, true)
		var context setup.Context
		if len(args) <= 2 {
			a.printUsage()
			os.Exit(1)
		}

		if args[2] != "admin" &&
			args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "database" &&
			args[2] != "server" &&
			args[2] != "all" &&
			args[2] != "tls" &&
			args[2] != "jwt" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		valid_err := validateSetupArgs(args[2], args[3:])
		if valid_err != nil {
			return valid_err
		}

		a.Config = config.Global()
		err := a.Config.SaveConfiguration(context)
		if err != nil {
			fmt.Println("Error saving configuration: " + err.Error())
			os.Exit(1)
		}

		task := strings.ToLower(args[2])
		flags := args[3:]
		if args[2] == "download_cert" && len(args) > 3 {
			flags = args[4:]
		}

		a.Config = config.Global()

		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
					Flags:                flags,
					CmsBaseURL:           a.Config.CMSBaseUrl,
					CaCertDirPath:        constants.TrustedCAsStoreDir,
					TrustedTlsCertDigest: a.Config.CmsTlsCertDigest,
					ConsoleWriter:        os.Stdout,
				},
				setup.Download_Cert{
					Flags:              flags,
					KeyFile:            a.Config.TLSKeyFile,
					CertFile:           a.Config.TLSCertFile,
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
					CmsBaseURL:         a.Config.CMSBaseUrl,
					Subject: pkix.Name{
						CommonName: a.Config.Subject.TLSCertCommonName,
					},
					SanList:       a.Config.CertSANList,
					CertType:      "TLS",
					CaCertsDir:    constants.TrustedCAsStoreDir,
					BearerToken:   "",
					ConsoleWriter: os.Stdout,
				},
				tasks.Database{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
				tasks.Admin{
					Flags: flags,
					DatabaseFactory: func() (repository.AASDatabase, error) {
						pg := &a.configuration().Postgres
						p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
						if err != nil {
							defaultLog.WithError(err).Error("failed to open postgres connection for setup task")
							return nil, err
						}
						p.Migrate()
						return p, nil
					},
					ConsoleWriter: os.Stdout,
				},
				tasks.Server{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
				tasks.JWT{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
			},
			AskInput: false,
		}
		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			defaultLog.WithError(err).Error("Error running setup")
			fmt.Fprintf(os.Stderr, "Error running setup: %s\n", err.Error())
			return err
		}

		aasUser, err := user.Lookup(constants.AASUserName)
		if err != nil {
			return errors.Wrapf(err, "Could not find user '%s'", constants.AASUserName)
		}

		uid, err := strconv.Atoi(aasUser.Uid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse aas user uid '%s'", aasUser.Uid)
		}

		gid, err := strconv.Atoi(aasUser.Gid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse aas user gid '%s'", aasUser.Gid)
		}

		//Change the fileownership to aas user for all the files under config directory

		err = cos.ChownR(constants.ConfigDir, uid, gid)
		if err != nil {
			return errors.Wrap(err, "Error while changing ownership of files inside config directory")
		}

		if task == "download_cert" {
			err = os.Chown(a.Config.TLSKeyFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Key file")
			}

			err = os.Chown(a.Config.TLSCertFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Cert file")
			}
		}
	}
	return nil
}

func (a *App) retrieveJWTSigningCerts() error {
	//No implementation is required as AAS will already have the jwt certificate created as part of setup task
	defaultLog.Debug("Callback function to get JWT certs called")
	return nil
}

func (a *App) initJwtTokenFactory() (*jwtauth.JwtFactory, error) {

	defaultLog.Trace("call to initJwtTokenFactory")
	defer defaultLog.Trace("initJwtTokenFactory return")

	// retrieve the private key from file
	privKeyDer, err := crypt.GetPKCS8PrivKeyDerFromFile(constants.TokenSignKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Could not get private key - error : %v", err)
	}

	// retrieve the signing key certificate used to create the file
	cfg := a.configuration()
	var certPemBytes []byte
	if cfg.Token.IncludeKid {
		certPemBytes, err = ioutil.ReadFile(constants.TokenSignCertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read JWT signing certificate file - error : %v", err)
		}
	}

	return jwtauth.NewTokenFactory(privKeyDer,
		cfg.Token.IncludeKid, certPemBytes,
		"AAS JWT Issuer",
		time.Duration(cfg.Token.TokenDurationMins)*time.Minute)
}

func (a *App) startServer() error {
	c := a.configuration()

	defaultLog.Info("Starting server")
	// Open database
	aasDB, err := postgres.Open(c.Postgres.Hostname, c.Postgres.Port, c.Postgres.DBName,
		c.Postgres.Username, c.Postgres.Password, c.Postgres.SSLMode, c.Postgres.SSLCert)
	if err != nil {
		defaultLog.WithError(err).Error("failed to open Postgres database")
		return err
	}
	defer aasDB.Close()
	defaultLog.Trace("Migrating Database")
	aasDB.Migrate()

	jwtFactory, err := a.initJwtTokenFactory()
	if err != nil {
		defaultLog.WithError(err).Error("failed to initialize JWT Token factory")
		return err
	}
	// Create public routes that does not need any authentication
	r := mux.NewRouter()

	// ISECL-8715 - Prevent potential open redirects to external URLs
	r.SkipClean(true)

	// Create Router, set routes
	sr := r.PathPrefix("/aas/noauth").Subrouter()
	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.SetVersion, resource.SetJwtCertificate)

	sr = r.PathPrefix("/aas").Subrouter()
	func(setters ...func(*mux.Router, repository.AASDatabase, *jwtauth.JwtFactory)) {
		for _, setter := range setters {
			setter(sr, aasDB, jwtFactory)
		}
	}(resource.SetJwtToken)

	// Handlers that does not have any http authentication headers
	sr = r.PathPrefix("/aas").Subrouter()
	func(setters ...func(*mux.Router, repository.AASDatabase)) {
		for _, setter := range setters {
			setter(sr, aasDB)
		}
	}(resource.SetUsersNoAuth)

	sr = r.PathPrefix("/aas/test/").Subrouter()
	sr.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCAsStoreDir, a.retrieveJWTSigningCerts,
		time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.SetTestJwt)

	sr = r.PathPrefix("/aas/").Subrouter()
	sr.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCAsStoreDir, a.retrieveJWTSigningCerts,
		time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	func(setters ...func(*mux.Router, repository.AASDatabase)) {
		for _, setter := range setters {
			setter(sr, aasDB)
		}
	}(resource.SetRoles, resource.SetUsers)

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.ReadTimeout,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    c.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		tlsCert := config.Global().TLSCertFile
		tlsKey := config.Global().TLSKeyFile
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			defaultLog.WithError(err).Info("Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)
	// fmt.Fprintln(a.consoleWriter(), "Auth Service is running")
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "authservice"}, os.Environ())
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "authservice"}, os.Environ())
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "authservice"}, os.Environ())
}

func (a *App) uninstall(purge bool) {
	fmt.Println("Uninstalling Auth Service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		defaultLog.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			defaultLog.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		defaultLog.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		defaultLog.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "Auth Service uninstalled")
	a.stop()
}
func removeService() {
	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove Auth Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {

	env_names := make([]string, 0)
	for k, _ := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, valid_err := validation.ValidateEnvList(env_names)
	if valid_err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.New("Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {

	var fs *flag.FlagSet

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
		return nil

	case "database":

		env_names_cmd_opts := map[string]string{
			"AAS_DB_HOSTNAME":   "db-host",
			"AAS_DB_PORT":       "db-port",
			"AAS_DB_USERNAME":   "db-user",
			"AAS_DB_PASSWORD":   "db-pass",
			"AAS_DB_NAME":       "db-name",
			"AAS_DB_SSLMODE":    "db-sslmode",
			"AAS_DB_SSLCERT":    "db-sslcert",
			"AAS_DB_SSLCERTSRC": "db-sslcertsrc",
		}

		fs = flag.NewFlagSet("database", flag.ContinueOnError)
		fs.String("db-host", "", "Database Hostname")
		fs.Int("db-port", 0, "Database Port")
		fs.String("db-user", "", "Database Username")
		fs.String("db-pass", "", "Database Password")
		fs.String("db-name", "", "Database Name")
		fs.String("db-sslmode", "", "Database SSL Mode")
		fs.String("db-sslcert", "", "Database SSL Cert Destination")
		fs.String("db-sslcertsrc", "", "Database SSL Cert Source File")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "admin":

		env_names_cmd_opts := map[string]string{
			"AAS_ADMIN_USERNAME": "user",
			"AAS_ADMIN_PASSWORD": "pass",
		}

		fs = flag.NewFlagSet("admin", flag.ContinueOnError)
		fs.String("user", "", "Username for admin authentication")
		fs.String("pass", "", "Password for admin authentication")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "reghost":

		env_names_cmd_opts := map[string]string{
			"AAS_REG_HOST_USERNAME": "user",
			"AAS_REG_HOST_PASSWORD": "pass",
		}

		fs = flag.NewFlagSet("reghost", flag.ContinueOnError)
		fs.String("user", "", "Username for host registration")
		fs.String("pass", "", "Password for host registration")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "server":
		// this has a default port value on 8443
		return nil

	case "tls":

		env_names_cmd_opts := map[string]string{
			"AAS_TLS_HOST_NAMES": "host_names",
		}

		fs = flag.NewFlagSet("tls", flag.ContinueOnError)
		fs.String("host_names", "", "comma separated list of hostnames to add to TLS self signed cert")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "all":
		if len(args) != 0 {
			return errors.New("Please setup the arguments with env")
		}

	case "jwt":
		return nil
	}

	return nil
}

//TODO : Debug code to be removed. Added for testing database query functions
func (a *App) TestNewDBFunctions() error {
	fmt.Println("Test New DB functions")
	db, err := a.DatabaseFactory()
	if err != nil {
		defaultLog.WithError(err).Error("failed to open database")
		return err
	}
	users, err := db.UserRepository().GetRoles(types.User{Name: "admin"}, nil, true)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Printf("User: %v", users)

	defer db.Close()
	return nil
}

func (a *App) DatabaseFactory() (repository.AASDatabase, error) {
	pg := &a.configuration().Postgres
	p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
	if err != nil {
		fmt.Println("failed to open postgres connection for setup task")
		return nil, err
	}
	return p, nil
}
