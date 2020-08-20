module intel/isecl/tools/populate-users

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients/v3 v3.0.0
	intel/isecl/lib/common/v3 v3.0.0
)

replace intel/isecl/lib/common/v3 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.0/develop

replace intel/isecl/lib/clients/v3 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v3 v3.0/develop
