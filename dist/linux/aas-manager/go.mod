module intel/isecl/tools/populate-users

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients/v2 v2.0.0
	intel/isecl/lib/common/v2 v2.0.0
)

replace intel/isecl/lib/common/v2 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v2 v2.1/develop

replace intel/isecl/lib/clients/v2 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v2 v2.1/develop
