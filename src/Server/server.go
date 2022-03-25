package Server

import (
	"flag"
	"sslt/src/encryption/sm2"
	rsa "sslt/src/encryption/x509"
	//. "sslt/src/encryption/sm2"
)

var (
	caPEM, caKeyPEM,
	caOrganization, caCommonName, caOrganizationalUnit,
	caSerialNumber, caStreetAddress, caPostalCode, caLocality, caProvince, caNotAfter,
	certPEM, certKeyPEM,
	certOrganization, certCommonName, certOrganizationalUnit,
	certSerialNumber, certStreetAddress, certPostalCode, certLocality, certProvince, certNotAfter,
	country, host, protocol string
	err error
)

func init() {
	// import file or content
	flag.StringVar(&caPEM, "r", "sslt/ca.pem", "Import CA")
	flag.StringVar(&certPEM, "s", "sslt/server.pem", "Import Cert CA")
	flag.StringVar(&caKeyPEM, "rk", "sslt/ca.key.pe", "Import CA Key")
	flag.StringVar(&certKeyPEM, "sk", "sslt/server.key.pe", "Import Cert CA Key")

	/* RSA ARGS >>> */
	flag.StringVar(&caCommonName, "rc", "GTS Root R1", "Specified Root CommonName")
	flag.StringVar(&caOrganization, "ro", "Google Trust Services LLC", "Specified Root Organization")
	flag.StringVar(&certCommonName, "sc", "GTS CA 1C3", "Specified Server CommonName")
	flag.StringVar(&certOrganization, "so", "Google Trust Services LLC", "Specified Server Organization")
	flag.StringVar(&country, "c", "US", "Specified Country")
	flag.StringVar(&host, "host", "localhost", "Specified domain name")
	flag.StringVar(&protocol, "p", "rsa", "Specified encryption protocol")
	// No default configuration
	flag.StringVar(&caOrganizationalUnit, "rou", "", "Specified Root OrganizationalUnit")
	flag.StringVar(&caSerialNumber, "rsn", "", "Specified Root SerialNumber")
	flag.StringVar(&caStreetAddress, "rst", "", "Specified Root StreetAddress")
	flag.StringVar(&caPostalCode, "rpc", "", "Specified Root PostalCode")
	flag.StringVar(&caLocality, "rlc", "", "Specified Root Locality")
	flag.StringVar(&caProvince, "rpr", "", "Specified Root Province")
	flag.StringVar(&caNotAfter, "rna", "", "Specified Root NotAfter")
	flag.StringVar(&certOrganizationalUnit, "sou", "", "Specified Server OrganizationalUnit")
	flag.StringVar(&certSerialNumber, "ssn", "", "Specified Server SerialNumber")
	flag.StringVar(&certStreetAddress, "sst", "", "Specified Server StreetAddress")
	flag.StringVar(&certPostalCode, "spc", "", "Specified Server PostalCode")
	flag.StringVar(&certLocality, "slc", "", "Specified Server Locality")
	flag.StringVar(&certProvince, "spr", "", "Specified Server Province")
	flag.StringVar(&certNotAfter, "sna", "", "Specified Server NotAfter")
	/* <<< RSA ARGS */

}

func Server(api bool) (string, string, string, string) {
	switch protocol {
	case "rsa":
		caPEM, caKeyPEM, certPEM, certKeyPEM = rsa.Setup(caOrganization, caCommonName, caOrganizationalUnit, caSerialNumber, caStreetAddress, caPostalCode, caLocality, caProvince, caNotAfter, certOrganization, certCommonName, certOrganizationalUnit, certSerialNumber, certStreetAddress, certPostalCode, certLocality, certProvince, certNotAfter, country, host, protocol, api)
		return caPEM, caKeyPEM, certPEM, certKeyPEM
	case "sm2":
		sm2.Setup()
	default:
		caPEM, caKeyPEM, certPEM, certKeyPEM = rsa.Setup(caOrganization, caCommonName, caOrganizationalUnit, caSerialNumber, caStreetAddress, caPostalCode, caLocality, caProvince, caNotAfter, certOrganization, certCommonName, certOrganizationalUnit, certSerialNumber, certStreetAddress, certPostalCode, certLocality, certProvince, certNotAfter, country, host, protocol, api)
		return caPEM, caKeyPEM, certPEM, certKeyPEM
	}
	return caPEM, caKeyPEM, certPEM, certKeyPEM
}
