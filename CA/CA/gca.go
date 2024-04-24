package certificates

import (
	"crypto"
	"crypto/x509"

	"ca/db"
	"ca/models"
)

// CA represents the basic CA data
type CA struct {
	CommonName string        // Certificate Authority Common Name
	Data       models.CAData // Certificate Authority Data (CAData{})
}

//
// Certificate Authority
//

// Load an existent Certificate Authority from $CAPATH
func Load(commonName string) (ca CA, err error) {
	ca = CA{
		CommonName: commonName,
	}

	err = ca.loadCA(commonName)
	if err != nil {
		return CA{}, err
	}

	return ca, nil

}

// List list all existent Certificate Authorities in $CAPATH
func List() (*[]db.CA, error) {
	return db.ListCAs()
}

// New creat new Certificate Authority
func New(commonName string, identity models.Identity) (ca CA, err error) {
	ca, err = NewCA(commonName, "", identity)
	return ca, err
}

// New create a new Certificate Authority
func NewCA(commonName, parentCommonName string, identity models.Identity) (ca CA, err error) {
	ca = CA{
		CommonName: commonName,
	}

	err = ca.create(commonName, parentCommonName, identity)
	if err != nil {
		return ca, err
	}

	return ca, nil
}

// GetPublicKey returns the PublicKey as string
func (c *CA) GetPublicKey() string {
	return c.Data.PublicKey
}

// GetPrivateKey returns the Private Key as string
func (c *CA) GetPrivateKey() string {
	return c.Data.PrivateKey
}

// GoPrivateKey returns the Private Key as Go bytes crypto.PrivateKey
func (c *CA) GoPrivateKey() crypto.PrivateKey {
	return c.Data.Privatekey
}

// GoPublicKey returns the Public Key as Go bytes crypto.PublicKey
func (c *CA) GoPublicKey() crypto.PublicKey {
	return c.Data.Publickey
}

// GetCSR returns the Certificate Signing Request as string
func (c *CA) GetCSR() string {
	return c.Data.CSR
}

// GoCSR return the Certificate Signing Request as Go bytes *x509.CertificateRequest
func (c *CA) GoCSR() *x509.CertificateRequest {
	return c.Data.Csr
}

// GetCertificate returns Certificate Authority Certificate as string
func (c *CA) GetCertificate() string {
	return c.Data.Certificate
}

// GoCertificate returns Certificate Authority Certificate as Go bytes *x509.Certificate
func (c *CA) GoCertificate() *x509.Certificate {
	return c.Data.Ccertificate
}

// GetCRL returns Certificate Revocation List as x509 CRL string
func (c *CA) GetCRL() string {
	return c.Data.CRL
}

// GoCRL returns Certificate Revocation List as Go bytes *x509.RevocationList
func (c *CA) GoCRL() *x509.RevocationList {
	return c.Data.Crl
}

// IsIntermediate returns if the CA is Intermediate CA (true)
func (c *CA) IsIntermediate() bool {
	return c.Data.IsIntermediate

}

// ListCertificates returns all certificates in the CA
func (c *CA) ListCertificates() (*[]db.Certificate, error) {
	return db.ListCertificates(c.CommonName)
}

// Status get details about Certificate Authority status.
func (c *CA) Status() string {
	if c.Data.CSR != "" && c.Data.Certificate == "" {
		return "Intermediate Certificate Authority not ready, missing Certificate."

	} else if c.Data.CSR != "" && c.Data.Certificate != "" {
		return "Intermediate Certificate Authority is ready."

	} else if c.Data.CSR == "" && c.Data.Certificate != "" {
		return "Certificate Authority is ready."

	} else {
		return "CA is inconsistent."
	}
}

// SignCSR perform a creation of certificate from a CSR (x509.CertificateRequest) and returns *x509.Certificate
func (c *CA) SignCSR(csr x509.CertificateRequest, valid int) (certificate models.Certificate, err error) {

	certificate, err = c.signCSR(csr, valid)

	return certificate, err

}

// IssueCertificate creates a new certificate
//
// It is import create an Identity{} with Certificate Client/Server information.
func (c *CA) IssueCertificate(commonName string, id models.Identity) (certificate models.Certificate, err error) {

	certificate, err = c.issueCertificate(commonName, id)

	return certificate, err
}

// LoadCertificate loads a certificate managed by the Certificate Authority
//
// The method ListCertificates can be used to list all available certificates.
func (c *CA) LoadCertificate(commonName string) (certificate models.Certificate, err error) {
	certificate, err = c.loadCertificate(commonName)

	return certificate, err
}

// RevokeCertificate revokes a certificate managed by the Certificate Authority
//
// The method ListCertificates can be used to list all available certificates.
func (c *CA) RevokeCertificate(commonName string) error {

	certToRevoke, err := c.loadCertificate(commonName)
	if err != nil {
		return err
	}

	err = c.revokeCertificate(certToRevoke.Ccertificate)
	if err != nil {
		return err
	}

	return nil
}
