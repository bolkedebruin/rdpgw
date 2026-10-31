package provisioning

import "embed"

// templatesFS embeds the configuration templates rendered by the rdpgw-auth
// initializer. The packaged templates express the Samba/Winbind side of the
// deployment: smb.conf sets up the ADS security model around the machine
// account, krb5.conf points kerberos at the domain's KDCs.
//
//go:embed templates/*.tmpl
var templatesFS embed.FS

// templatesDir is the prefix of the embedded template paths.
const templatesDir = "templates/"
