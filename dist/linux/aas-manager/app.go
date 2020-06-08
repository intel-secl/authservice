/*
Copyright © 2020 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"intel/isecl/lib/clients/v2"
	claas "intel/isecl/lib/clients/v2/aas"
	"intel/isecl/lib/common/v2/types/aas"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	HELP_NOSETUP          = "Don't add users, roles and user-roles to the Authentication Service"
	HELP_ANSWERFILE       = `Answer file constaining user input`
	HELP_USE_JSON         = "Use Json file as input instead of parsing env file"
	HELP_IN_JSON_FILE     = "Input Json file name - identical to use_json flag but can specify a different file name "
	HELP_OUT_JSON_FILE    = "Output json file name - identical to output_json flag but can specify a different file name"
	HELP_OUTPUT_JSON      = "Boolean value to indicate if the users and roles should be written to a output file"
	HELP_GENPASSWORD      = "Generate passwords if not specified"
	HELP_REGEN_TOKEN_ONLY = "Generate token only"
	HELP_HELP             = "Show Usage - if specified, all other options will be ignored"

	PASSWORD_SIZE = 20
)

type UserAndRolesCreate struct {
	aas.UserCreate                    //embed
	PrintBearerToken bool             `json:"print_bearer_token"`
	Roles            []aas.RoleCreate `json:"roles"`
}

type AasUsersAndRolesSetup struct {
	AasApiUrl        string               `json:"aas_api_url"`
	AasAdminUserName string               `json:"aas_admin_username"`
	AasAdminPassword string               `json:"aas_admin_password"`
	UsersAndRoles    []UserAndRolesCreate `json:"users_and_roles"`
}

type App struct {
	AasAPIUrl        string
	AasAdminUserName string
	AasAdminPassword string

	VsCN       string
	VsSanList  string
	AhCN       string
	AhSanList  string
	WlsCN      string
	WlsSanList string
	TaCN       string
	TaSanList  string
	KmsCN      string
	KmsSanList string

	InstallAdminUserName   string
	InstallAdminPassword   string
	GlobalAdminUserName    string
	GlobalAdminPassword    string
	VsServiceUserName      string
	VsServiceUserPassword  string
	AhServiceUserName      string
	AhServiceUserPassword  string
	WpmServiceUserName     string
	WpmServiceUserPassword string
	WlsServiceUserName     string
	WlsServiceUserPassword string
	WlaServiceUserName     string
	WlaServiceUserPassword string

	Components     map[string]bool
	GenPassword    bool
	RegenTokenOnly bool

	ConsoleWriter io.Writer
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
}

func RandomString(n int) string {
	var letter = []rune("~=+%^*/()[]{}/!@#$?|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	rand.Seed(time.Now().UnixNano())
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func MakeTlsCertificateRole(cn, san string) aas.RoleCreate {
	r := aas.RoleCreate{}
	r.Service = "CMS"
	r.Name = "CertApprover"
	r.Context = "CN=" + cn + ";SAN=" + san + ";certType=TLS"
	return r
}

func NewRole(service, name, context string, perms []string) aas.RoleCreate {
	//r := aas.RoleCreate{aas.RoleInfo{Service: service, Name: name, Context: context}, Permissions:{}}
	r := aas.RoleCreate{}
	r.Service = service
	r.Name = name
	r.Context = context
	if len(perms) > 0 {
		r.Permissions = append([]string(nil), perms...)
	}
	return r
}

func (a *App) GetServiceUsers() []UserAndRolesCreate {

	urs := []UserAndRolesCreate{}
	for k, _ := range a.Components {

		urc := UserAndRolesCreate{}
		urc.Roles = []aas.RoleCreate{}

		switch k {
		case "VS":
			urc.Name = a.VsServiceUserName
			urc.Password = a.VsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("TA", "Administrator", "", []string{"*:*:*"}))
		case "AH":
			urc.Name = a.AhServiceUserName
			urc.Password = a.AhServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("VS", "ReportRetriever", "", []string{"reports:retrieve:*", "reports:search:*", "hosts:search:*", "hosts:retrieve:*"}))
		case "WPM":
			urc.Name = a.WpmServiceUserName
			urc.Password = a.WpmServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("KMS", "KeyManager", "", []string{"keys:create:*", "keys:transfer:*"}))
		case "WLS":
			urc.Name = a.WlsServiceUserName
			urc.Password = a.WlsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("VS", "ReportCreator", "", []string{"reports:create:*"}))
		case "WLA":
			urc.Name = a.WlaServiceUserName
			urc.Password = a.WlaServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("WLS", "FlavorsImageRetrieval", "", []string{"image_flavors:retrieve:*"}))
			urc.Roles = append(urc.Roles, NewRole("WLS", "ReportCreator", "", []string{"reports:create:*"}))
		}
		if urc.Name != "" {
			urs = append(urs, urc)
		}

	}
	return urs

}

func (a *App) GetGlobalAdminUser() *UserAndRolesCreate {

	if a.GlobalAdminUserName == "" {
		return nil
	}

	urc := UserAndRolesCreate{}
	urc.Name = a.GlobalAdminUserName
	urc.Password = a.GlobalAdminPassword
	urc.Roles = []aas.RoleCreate{}

	for k, _ := range a.Components {

		switch k {
		case "VS":
			urc.Roles = append(urc.Roles, NewRole("VS", "Administrator", "", []string{"*:*:*"}))
		case "TA":
			urc.Roles = append(urc.Roles, NewRole("TA", "Administrator", "", []string{"*:*:*"}))
		case "AH":
			urc.Roles = append(urc.Roles, NewRole("AH", "Administrator", "", []string{"*:*:*"}))
		case "KBS":
			urc.Roles = append(urc.Roles, NewRole("KMS", "KeyCRUD", "", []string{"*:*:*"}))
		case "WLS":
			urc.Roles = append(urc.Roles, NewRole("WLS", "Administrator", "", []string{"*:*:*"}))
		case "AAS":
			urc.Roles = append(urc.Roles, NewRole("AAS", "Administrator", "", []string{"*:*:*"}))
		}
	}
	return &urc
}

func (a *App) GetSuperInstallUser() UserAndRolesCreate {

	// set the user
	urc := UserAndRolesCreate{}
	urc.Name = a.InstallAdminUserName
	urc.Password = a.InstallAdminPassword
	urc.PrintBearerToken = true
	urc.Roles = []aas.RoleCreate{}

	// set the roles depending on the components that are to be installed

	for k, _ := range a.Components {
		switch k {
		case "VS":
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=VS Flavor Signing Certificate;certType=Signing", nil))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.VsCN, a.VsSanList))
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=mtwilson-saml;certType=Signing", nil))
		case "TA":
			urc.Roles = append(urc.Roles, NewRole("VS", "AttestationRegister", "",
				[]string{"host_tls_policies:create:*", "hosts:create:*", "hosts:store:*", "hosts:search:*",
					"host_unique_flavors:create:*", "flavors:search:*", "tpm_passwords:retrieve:*",
					"tpm_passwords:create:*", "host_aiks:certify:*", "tpm_endorsements:create:*", "tpm_endorsements:search:*"}))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.TaCN, a.TaSanList))
		case "AH":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.AhCN, a.AhSanList))
		case "KBS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.KmsCN, a.KmsSanList))
		case "WPM":
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=WPM Flavor Signing Certificate;certType=Signing", nil))
		case "WLS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.WlsCN, a.WlsSanList))
		case "WLA":
			urc.Roles = append(urc.Roles, NewRole("VS", "Certifier", "", []string{"host_signing_key_certificates:create:*"}))
		}
	}

	return urc

}

func SetVariable(variable *string, envVarName string, defaultVal string, desc string, mandatory bool, secret bool) error {
	if *variable = os.Getenv(envVarName); *variable == "" {
		if mandatory {
			fmt.Println(envVarName, "-", desc, " is mandatory and cannot be empty")
			return fmt.Errorf("required environment variable missing")
		}

	}
	if *variable == "" && defaultVal != "" {
		*variable = defaultVal
	}

	if secret {
		fmt.Println(desc, "= *******")
	} else {
		fmt.Println(desc, "=", *variable)
	}

	return nil
}

func (a *App) LoadAllVariables(envFile string) error {
	if err := godotenv.Load(envFile); err != nil {
		fmt.Println("could not load environment file :", envFile, ". Will be using existing exported environment variables")
	}

	// mandatory variables

	var installComps string

	type envDesc struct {
		variable    *string
		envVarName  string
		defaultVal  string
		description string
		mandatory   bool
		secret      bool
	}

	envVars := []envDesc{
		{&a.AasAPIUrl, "AAS_API_URL", "", "AAS API URL", true, false},
		{&a.AasAdminUserName, "AAS_ADMIN_USERNAME", "", "AAS ADMIN USERNAME", true, false},
		{&a.AasAdminPassword, "AAS_ADMIN_PASSWORD", "", "AAS ADMIN PASSWORD", true, true},

		{&installComps, "ISECL_INSTALL_COMPONENTS", "", "ISecl Components to be installed", true, true},

		{&a.InstallAdminUserName, "INSTALL_ADMIN_USERNAME", "installadmin", "Installation ADMIN USERNAME", false, false},
		{&a.InstallAdminPassword, "INSTALL_ADMIN_PASSWORD", "", "Installation ADMIN PASSWORD", false, true},

		{&a.VsCN, "VS_CERT_COMMON_NAME", "Mt Wilson TLS Certificate", "Verification Service TLS Certificate Common Name", false, false},
		{&a.VsSanList, "VS_CERT_SAN_LIST", "", "Verification Service TLS Certificate SAN LIST", false, false},

		{&a.AhCN, "AH_CERT_COMMON_NAME", "Attestation Hub TLS Certificate", "Attestation Hub TLS Certificate Common Name", false, false},
		{&a.AhSanList, "AH_CERT_SAN_LIST", "", "Attestation Hub TLS Certificate SAN LIST", false, false},

		{&a.WlsCN, "WLS_CERT_COMMON_NAME", "WLS TLS Certificate", "Workload Service TLS Certificate Common Name", false, false},
		{&a.WlsSanList, "WLS_CERT_SAN_LIST", "", "Workload Service TLS Certificate SAN LIST", false, false},

		{&a.KmsCN, "KBS_CERT_COMMON_NAME", "KMS TLS Certificate", "Key Broker Service TLS Certificate Common Name", false, false},
		{&a.KmsSanList, "KBS_CERT_SAN_LIST", "", "Key Broker Service TLS Certificate SAN LIST", false, false},

		{&a.TaCN, "TA_CERT_COMMON_NAME", "Trust Agent TLS Certificate", "Trust Agent TLS Certificate Common Name", false, false},
		{&a.TaSanList, "TA_CERT_SAN_LIST", "", "Trust Agent TLS Certificate SAN LIST", false, false},

		{&a.GlobalAdminUserName, "GLOBAL_ADMIN_USERNAME", "", "Global Admin User Name", false, false},
		{&a.GlobalAdminPassword, "GLOBAL_ADMIN_PASSWORD", "", "Global Admin User Password", false, true},

		{&a.VsServiceUserName, "VS_SERVICE_USERNAME", "", "Verificaiton Service User Name", false, false},
		{&a.VsServiceUserPassword, "VS_SERVICE_PASSWORD", "", "Verification Service User Password", false, true},

		{&a.AhServiceUserName, "AH_SERVICE_USERNAME", "", "Attestation Hub Service User Name", false, false},
		{&a.AhServiceUserPassword, "AH_SERVICE_PASSWORD", "", "Attestation Hub Service User Password", false, true},

		{&a.WpmServiceUserName, "WPM_SERVICE_USERNAME", "", "Workload Policy Manager Hub Service User Name", false, false},
		{&a.WpmServiceUserPassword, "WPM_SERVICE_PASSWORD", "", "Workload Policy Manager Service User Password", false, true},

		{&a.WlsServiceUserName, "WLS_SERVICE_USERNAME", "", "Workload Service User Name", false, false},
		{&a.WlsServiceUserPassword, "WLS_SERVICE_PASSWORD", "", "Workload Service User Password", false, true},

		{&a.WlaServiceUserName, "WLA_SERVICE_USERNAME", "", "Workload Agent User Name", false, false},
		{&a.WlaServiceUserPassword, "WLA_SERVICE_PASSWORD", "", "Workload Agent User Password", false, true},
	}

	hasError := false

	for _, envVar := range envVars {
		if err := SetVariable(envVar.variable, envVar.envVarName, envVar.defaultVal, envVar.description, envVar.mandatory, envVar.secret); err != nil {
			hasError = true
		}
	}
	if hasError {
		return fmt.Errorf("Missing Required Environment variable(s). Set these in the env file or export them and run again")
	}

	// set up the app map with components that need to be installed
	slc := strings.Split(installComps, ",")
	a.Components = make(map[string]bool)
	for i := range slc {
		a.Components[strings.TrimSpace(slc[i])] = true
	}

	return nil

}

func (a *App) LoadUserAndRolesJson(file string) (*AasUsersAndRolesSetup, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read user role files %s : ", file)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var urc AasUsersAndRolesSetup
	if err := dec.Decode(&urc); err != nil {
		return nil, fmt.Errorf("could not decode json file for user roles - err", err)
	}
	return &urc, nil
}

func (a *App) GetNewOrExistingUserID(name, password string, forceUpdatePassword bool, aascl *claas.Client) (string, error) {

	users, err := aascl.GetUsers(name)
	if err != nil {
		return "", err
	}

	if len(users) == 0 {
		// did not find the user.. so let us create the user.

		// first check if the password is blank. If it is and we have to create a password
		if password == "" {
			return "", fmt.Errorf("User %s password not supplied and no flag to generate password. Use --genpassword flag to generate password")
		}
		newUser, err := aascl.CreateUser(aas.UserCreate{name, password})
		if err != nil {
			return "", err
		}
		return newUser.ID, nil
	}
	if len(users) == 1 && users[0].Name == name {
		// found single record that corresponds to the user.

		// if password is empty and we have to generate password, generate password and set it
		if forceUpdatePassword {
			if err := aascl.UpdateUser(users[0].ID, aas.UserCreate{name, password}); err != nil {
				return "", fmt.Errorf("Could not update the user : %s's password", name)
			}
		}
		return users[0].ID, nil
	}
	// we should not really be here.. we have multiple users with matched name
	return "", fmt.Errorf("Multiple records found when searching for user %s - record - %v", name, users)
}

func (a *App) GetNewOrExistingRoleID(role aas.RoleCreate, aascl *claas.Client) (string, error) {
	roles, err := aascl.GetRoles(role.Service, role.Name, role.Context, "", false)
	if err != nil {
		return "", err
	}

	if len(roles) == 0 {
		// did not find the role.. so create the role
		newRole, err := aascl.CreateRole(role)
		if err != nil {
			return "", err
		}
		return newRole.ID, nil
	}
	if len(roles) != 1 {
		// we should not really be here.. we have multiple users with matched name
		return "", fmt.Errorf("Multiple records found when searching for role %c - record - %v", role)
	}

	// found single record that corresponds to the user.
	return roles[0].ID, nil

}

func (a *App) GetUserToken(apiUrl, apiUserName, apiUserPass string) ([]byte, error) {
	// first create a JWT token for the admin
	jwtcl := claas.NewJWTClient(apiUrl)
	jwtcl.HTTPClient = clients.HTTPClientTLSNoVerify()

	jwtcl.AddUser(apiUserName, apiUserPass)
	err := jwtcl.FetchAllTokens()
	if err != nil {
		return nil, fmt.Errorf("Could not Fetch Token for for user: %s - error: %v", apiUserName, err)
	}

	token, err := jwtcl.GetUserToken(apiUserName)
	if err != nil {
		return nil, fmt.Errorf("Could not obtain token for %s from %s - err - %s", apiUserName, apiUrl, err)

	}

	return token, nil
}

func (a *App) PrintUserTokens(asr *AasUsersAndRolesSetup) error {

	for _, user := range asr.UsersAndRoles {
		if !user.PrintBearerToken {
			continue
		}
		token, err := a.GetUserToken(asr.AasApiUrl, user.Name, user.Password)
		if err != nil {
			return err
		}
		fmt.Println("\nToken for User:", user.Name)
		fmt.Printf("BEARER_TOKEN=%s\n", string(token))
		fmt.Println()
	}
	return nil

}

func (a *App) AddUsersAndRoles(asr *AasUsersAndRolesSetup) error {

	// no create an aas client with the token.

	token, err := a.GetUserToken(asr.AasApiUrl, asr.AasAdminUserName, asr.AasAdminPassword)
	if err != nil {
		return err
	}
	aascl := &claas.Client{asr.AasApiUrl, token, clients.HTTPClientTLSNoVerify()}

	//fmt.Println("BEARER_TOKEN="+string(token))
	for idx, _ := range asr.UsersAndRoles {
		userid := ""
		if a.RegenTokenOnly && !asr.UsersAndRoles[idx].PrintBearerToken {
			continue
		}

		forcePasswordUpdate := false
		if asr.UsersAndRoles[idx].Password == "" && (a.GenPassword || asr.UsersAndRoles[idx].PrintBearerToken) {
			asr.UsersAndRoles[idx].Password = RandomString(PASSWORD_SIZE)
			forcePasswordUpdate = true
		}
		if userid, err = a.GetNewOrExistingUserID(asr.UsersAndRoles[idx].Name, asr.UsersAndRoles[idx].Password, forcePasswordUpdate, aascl); err == nil {
			fmt.Println("\nuser:", asr.UsersAndRoles[idx].Name, "userid:", userid)
		} else {
			return fmt.Errorf("Error while attempting to create/ retrieve user %s - error %v ", asr.UsersAndRoles[idx].Name, err)

		}
		if a.RegenTokenOnly {
			continue
		}
		// we might have the same role appear more than one in the list of roles to be added for a user
		// since different components might need the same roles. The Add user to role function relies on
		// having a unique list of roles. put the roleids into a map and then make a list.

		fmt.Println("\nGetting Roles for user")
		roleMap := make(map[string]bool)
		for _, role := range asr.UsersAndRoles[idx].Roles {
			if roleid, err := a.GetNewOrExistingRoleID(role, aascl); err == nil {
				fmt.Println("role:", role, "roleid:", roleid)
				roleMap[roleid] = true
			} else {
				return fmt.Errorf("Error while attempting to create/ retrieve role %s - error %v ", role.Name, err)
			}

		}
		roleList := []string{}
		for key, _ := range roleMap {
			roleList = append(roleList, key)
		}

		fmt.Println("\nAdding Roles to user RolesIDs :", roleList)
		if err = aascl.AddRoleToUser(userid, aas.RoleIDs{roleList}); err != nil {
			return fmt.Errorf("Could not add roles to user - %s", asr.UsersAndRoles[idx].Name)
		}

	}
	return nil

}

func (a *App) Setup(args []string) error {
	var err error
	setup := true
	var noSetup, useJson, outputJson, printHelp bool
	var envFile, jsonIn, jsonOut string

	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.BoolVar(&noSetup, "nosetup", false, HELP_NOSETUP)
	fs.StringVar(&envFile, "answerfile", "populate-users.env", HELP_ANSWERFILE)
	fs.BoolVar(&useJson, "use_json", false, HELP_USE_JSON)
	fs.StringVar(&jsonIn, "in_json_file", "", HELP_IN_JSON_FILE)
	fs.StringVar(&jsonOut, "out_json_file", "", HELP_OUT_JSON_FILE)
	fs.BoolVar(&outputJson, "output_json", false, HELP_OUTPUT_JSON)
	fs.BoolVar(&a.GenPassword, "genpassword", false, HELP_GENPASSWORD)
	fs.BoolVar(&a.RegenTokenOnly, "regen_token_only", false, HELP_REGEN_TOKEN_ONLY)
	fs.BoolVar(&printHelp, "help", false, HELP_HELP)

	err = fs.Parse(args[1:])
	if err != nil {
		// return err
		return fmt.Errorf("could not parse the command line flags")
	}

	if printHelp || (len(args) == 2 && args[1] == "help") {
		fmt.Println("Usage:\n\n ", args[0], "[--answerfile] [--nosetup] [--genpassword] [--use_json] [--in_json_file] [--output_json] [--out_json_file] [--help]\n")

		fs.PrintDefaults()
		return nil
	}

	var as *AasUsersAndRolesSetup

	if useJson || jsonIn != "" {
		// do what is needed to parse the JSON file to create user and roles
		if jsonIn == "" {
			jsonIn = "./populate-users.json"
		}
		if as, err = a.LoadUserAndRolesJson(jsonIn); err != nil {
			fmt.Println(err)
			return err
		}

	} else {
		// call the method to load all the environment variable values
		fmt.Println("\n\nLoading environment variables\n=============================\n")

		if err := a.LoadAllVariables(envFile); err != nil {
			return fmt.Errorf("Could not find necessary environment variables - error %v ", err)
		}
		as = &AasUsersAndRolesSetup{AasApiUrl: a.AasAPIUrl, AasAdminUserName: a.AasAdminUserName, AasAdminPassword: a.AasAdminPassword}
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetSuperInstallUser())
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetServiceUsers()...)
		if glAdmin := a.GetGlobalAdminUser(); glAdmin != nil {
			as.UsersAndRoles = append(as.UsersAndRoles, *glAdmin)
		}

	}

	if noSetup {
		setup = false
	}

	if setup {
		if !a.RegenTokenOnly {
			fmt.Println("\n\nAdding Users and Roles\n======================\n")
		}
		if err = a.AddUsersAndRoles(as); err != nil {
			return err
		}
		fmt.Println("\n\nPrinting Tokens for specific users\n==================================\n")
		if err = a.PrintUserTokens(as); err != nil {
			return err
		}

	}

	if outputJson || jsonOut != "" {
		if jsonOut == "" {
			jsonOut = "./populate-users.json"
		}
		fmt.Println("\n\nWrting Output to json file - ", jsonOut)
		outFile, err := os.OpenFile(jsonOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
		if err != nil {
			fmt.Errorf("could not open output json file - %s for writing", jsonOut)
		}
		defer outFile.Close()
		enc := json.NewEncoder(outFile)
		enc.SetIndent("", "    ")
		enc.Encode(as)
	}
	return nil

}
func (a *App) Run(args []string) error {

	if err := a.Setup(args); err != nil {
		fmt.Println("Exit with Error!! - Setup not completed successfully. error -", err)
		return err
	}

	return nil
}
