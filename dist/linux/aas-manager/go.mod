module intel/isecl/tools/populate-users

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients/v2 v2.1.0
	intel/isecl/lib/common/v2 v2.1.0
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.1.0

replace intel/isecl/lib/clients/v2 => github.com/intel-secl/clients/v2 v2.1.0
