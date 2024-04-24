package certificates

import (
	"bytes"
	"ca/db"
	"ca/models"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"gorm.io/gorm"
)

// Const
const (
	certExtension string = ".crt"
	csrExtension  string = ".csr"
	crlExtension  string = ".crl"
)

// ErrCAMissingInfo means that all information goca.Information{} is required
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCAGenerateExists means that the CA with the same Common Name exists in
// the $CAPATH.
var ErrCAGenerateExists = errors.New("a Certificate Authority with this common name already exists")

// ErrCALoadNotFound means that CA was not found in $CAPATH to be loaded.
var ErrCALoadNotFound = errors.New("the requested Certificate Authority does not exist")

// ErrCertLoadNotFound means that certificate was not found in $CAPATH to be loaded.
var ErrCertLoadNotFound = errors.New("the requested Certificate does not exist")

// ErrCertRevoked means that certificate was not found in $CAPATH to be loaded.
var ErrCertRevoked = errors.New("the requested Certificate is already revoked")

var ErrParentCommonNameNotSpecified = errors.New("parent common name is empty when creating an intermediate CA certificate")

func (c *CA) create(commonName, parentCommonName string, id models.Identity) error {
	caData := models.CAData{}

	// verifies if the CA, based in the 'common name', exists
	caStorage := db.CAStorage(commonName)
	if caStorage {
		return ErrCAGenerateExists
	}

	var (
		keyString       []byte
		publicKeyString []byte
		certBytes       []byte
		certString      []byte
		crlString       []byte
		err             error
	)

	if id.Organization == "" || id.OrganizationalUnit == "" || id.Country == "" || id.Locality == "" || id.Province == "" {
		return ErrCAMissingInfo
	}

	caKeys, err := CreateKeys(commonName, commonName, db.CreationTypeCA, id.KeyBitSize, id.Algorithm)
	if err != nil {
		return err
	}
	b, err := x509.MarshalPKCS8PrivateKey(caKeys.Key)
	if err != nil {
		slog.Error("error while unmarshaling priv key", "error", err)
		return err
	}
	var privateKeyBytes = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	asn1Bytes, err := x509.MarshalPKIXPublicKey(caKeys.PublicKey)
	if err != nil {
		slog.Error("error while unmarshaling public key", "error", err)
		return err
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	keyString = pem.EncodeToMemory(privateKeyBytes)
	publicKeyString = pem.EncodeToMemory(pemkey)
	privKey := &caKeys.Key
	pubKey := &caKeys.PublicKey

	caData.Privatekey = caKeys.Key
	caData.PrivateKey = string(keyString)
	caData.Publickey = caKeys.PublicKey
	caData.PublicKey = string(publicKeyString)

	if !id.Intermediate {
		caData.IsIntermediate = false
		certBytes, err = CreateRootCert(
			commonName,
			commonName,
			id.Country,
			id.Province,
			id.Locality,
			id.Organization,
			id.OrganizationalUnit,
			id.EmailAddresses,
			id.Valid,
			id.DNSNames,
			id.IPAddresses,
			privKey,
			pubKey,
			db.CreationTypeCA,
		)
	} else {
		if parentCommonName == "" {
			return ErrParentCommonNameNotSpecified
		}
		var (
			parentCertificate *x509.Certificate
			parentPrivateKey  crypto.PrivateKey
		)
		caData.IsIntermediate = true
		parentCertificate, parentPrivateKey, err = LoadParentCACertificate(parentCommonName)
		if err != nil {
			return nil
		}

		certBytes, err = CreateCACert(
			commonName,
			commonName,
			id.Country,
			id.Province,
			id.Locality,
			id.Organization,
			id.OrganizationalUnit,
			id.EmailAddresses,
			id.Valid,
			id.DNSNames,
			id.IPAddresses,
			privKey,
			parentPrivateKey,
			parentCertificate,
			pubKey,
			db.CreationTypeCA,
		)
	}
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certString = pem.EncodeToMemory(pemCert)
	caData.Ccertificate = certificate
	caData.Certificate = string(certString)
	crlBytes, err := RevokeCertificate(c.CommonName, []x509.RevocationListEntry{}, certificate, privKey)
	if err != nil {
		slog.Error("error", "error", err)
		return err
	} else {
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			caData.Crl = crl
		}
	}
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crlBytes}
	crlString = pem.EncodeToMemory(pemCRL)
	caData.CRL = string(crlString)
	c.Data = caData
	return db.SaveCA(commonName, keyString, publicKeyString, certString, []byte{}, crlString)
}

func CreateCA(a, country, commonName, email, organisation, state, city, organisationUnit string, valid int) (*db.Certificate, error) {
	_, err := db.GetCA(commonName)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	} else if err == gorm.ErrRecordNotFound {

		cert, err := db.GenerateCACertificate(a, country, commonName, email, organisation, state, city, organisation, valid)
		if err != nil {
			return nil, err
		}
		//log.Println(cert)
		err = db.SaveCA(commonName, cert.PrivateKey, cert.PublicKey, cert.CRT, cert.CSR, cert.CRL)
		return cert, err
	} else {
		return nil, ErrCAGenerateExists
	}

}

func CreateServerCertificate(ca db.CA, a, country, commonName, email, organisation, state, city, organisationUnit string, valid int, certType string) (*db.Certificate, error) {
	if db.CheckCertExists(ca.Name, commonName) {
		return nil, ErrCertExists
	}

	cert, err := db.GenerateServerCertificate(&ca, a, country, commonName, email, organisation, state, city, organisation, valid)
	if err != nil {
		return nil, err
	}
	//log.Println(cert)
	if err := db.SaveCert(ca.Name, commonName, cert.PrivateKey, cert.PublicKey, cert.CRT, cert.CSR, cert.CRL, valid, certType); err != nil {
		return nil, err
	}
	cert.Valid = valid
	cert.ValidTill = time.Now().Add(24 * time.Hour * time.Duration(valid))
	return cert, err

}

func RenewServerCertificate(ca db.CA,cert *db.Certificate,commonName, subject string, valid int, certType string, priv []byte) (*db.Certificate, error) {
	if !db.CheckCertExists(ca.Name, commonName) {
		return nil, ErrCertLoadNotFound
	}

	cert1, err := db.RenewServerCertificate(&ca, commonName, subject, valid, priv)
	if err != nil {
		return nil, err
	}
	cert.Valid = valid
	cert.ValidTill = time.Now().Add(24 * time.Hour * time.Duration(valid))
	cert.CSR = cert1.CSR
	cert.CRT = cert1.CRT
	cert.UpdatedAt = time.Now()
	if err := db.UpdateCert(cert); err != nil {
		return nil, err
	}
	
	return cert, err

}

func RevokeServerCertificate(ca db.CA,cert db.Certificate) (*db.Certificate, error) {
	
	crl, err := db.RevokeServerCertificate(&ca, cert.CRT)
	if err != nil {
		return nil, err
	}
	
	cert.UpdatedAt = time.Now()
	cert.UpdatedAt = time.Now()
	cert.RevocationDate = time.Now()
	if err := db.UpdateCert(&cert); err != nil {
		return nil, err
	}
	ca.CRL = crl
	if err := db.UpdateCA(db.CAUpdate{Name:ca.Name, CRL: &crl}); err != nil {
		return nil, err
	}
	return &cert, err

}
func (c *CA) loadCA(commonName string) error {
	caData := models.CAData{}
	var (
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
		certString      []byte
		crlString       []byte
	)
	ca, err := db.GetCA(commonName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrCALoadNotFound
		}
		return err
	}
	keyString = ca.PrivateKey
	if string(keyString) != "" {
		privateKey, err := LoadPrivateKey(keyString)
		if err != nil {
			slog.Info("pk")
			return err
		}
		caData.PrivateKey = string(keyString)
		caData.Privatekey = privateKey
	}
	publicKeyString = ca.PublicKey
	if string(publicKeyString) != "" {
		publicKey, err := LoadPublicKey(publicKeyString)
		if err != nil {
			slog.Info("pk")
			return err
		}
		caData.PublicKey = string(publicKeyString)
		caData.Publickey = publicKey
	}
	csrString = ca.CSR
	if string(csrString) != "" {
		slog.Info(commonName)
		csr, _ := LoadCSR(csrString)
		/*if err != nil {
			slog.Info("pk", "csr", csrString)
			return err
		}*/
		caData.CSR = string(csrString)
		caData.Csr = csr
	}
	certString = ca.CRT
	if string(certString) != "" {
		cert, err := LoadCert(certString)
		if err != nil {
			return err
		}
		caData.Certificate = string(certString)
		caData.Ccertificate = cert
	}
	crlString = ca.CRL
	if string(crlString) != "" {
		crl, err := LoadCRL(crlString)
		if err != nil {
			return err
		}
		caData.CRL = string(crlString)
		caData.Crl = crl
	}

	c.Data = caData

	return nil
}

func (c *CA) signCSR(csr x509.CertificateRequest, valid int) (certificate models.Certificate, err error) {

	certificate = models.Certificate{
		CommonName:    csr.Subject.CommonName,
		Csr:           csr,
		CaCertificate: c.Data.Ccertificate,
		CACertificate: c.Data.Certificate,
	}

	/*if csrString, err := db.LoadFile(c.CommonName, "cert", certificate.CommonName+csrExtension); err == nil {
		_, err := LoadCSR(csrString)
		if err != nil {
			return certificate, err
		}
		certificate.CSR = string(csrString)
	}*/

	certBytes, err := CASignCSR(c.CommonName, csr, c.Data.Ccertificate, &c.Data.Privatekey, valid, db.CreationTypeCertificate)
	if err != nil {
		return certificate, err
	}

	var certRow bytes.Buffer
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	_ = pem.Encode(&certRow, pemCert)

	certificate.Certificate = string(certRow.String())

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return certificate, err
	}

	certificate.Ccertificate = cert

	// if we are signing another CA, we need to make sure the certificate file also
	// exists under the signed CA's $CAPATH directory, not just the signing CA's directory.
	//c, _ :=
	knownCAs, _ := List()
	for _, knownCA := range *knownCAs {
		if knownCA.Name == certificate.CommonName {
			srcPath := filepath.Join(c.CommonName, "certs", certificate.CommonName, certificate.CommonName+certExtension)
			destPath := filepath.Join(certificate.CommonName, "ca", certificate.CommonName+certExtension)

			err = db.CopyFile(srcPath, destPath)
			if err != nil {
				return certificate, err
			}

			break
		}
	}

	return certificate, err

}

func (c *CA) issueCertificate(commonName string, id models.Identity) (certificate models.Certificate, err error) {

	var (
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
	)

	certificate.CACertificate = c.Data.Certificate
	certificate.CaCertificate = c.Data.Ccertificate

	certKeys, err := CreateKeys(c.CommonName, commonName, db.CreationTypeCertificate, id.KeyBitSize, id.Algorithm)
	if err != nil {
		slog.Info("err k")
		return certificate, err
	}
	b, err := x509.MarshalPKCS8PrivateKey(certKeys.Key)
	if err != nil {
		slog.Error("error while unmarshaling priv key", "error", err)
		return certificate, err
	}
	var privateKeyBytes = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	asn1Bytes, err := x509.MarshalPKIXPublicKey(certKeys.PublicKey)
	if err != nil {
		slog.Error("error while unmarshaling public key", "error", err)
		return certificate, err
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	keyString = pem.EncodeToMemory(privateKeyBytes)
	publicKeyString = pem.EncodeToMemory(pemkey)

	privKey := &certKeys.Key
	pubKey := &certKeys.PublicKey

	certificate.Privatekey = *privKey
	certificate.PrivateKey = string(keyString)
	certificate.Publickey = *pubKey
	certificate.PublicKey = string(publicKeyString)

	csrBytes, err := CreateCSR(c.CommonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.DNSNames, id.IPAddresses, privKey, db.CreationTypeCertificate, id.Algorithm)
	if err != nil {
		slog.Error("error while creating csr", "error", err)
		return certificate, err
	}
	var pemCSR = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	csrString = pem.EncodeToMemory(pemCSR)
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		slog.Error("pasrse cert")
		return certificate, err
	}

	certificate.Csr = *csr
	certificate.CSR = string(csrString)
	certBytes, err := CASignCSR(c.CommonName, *csr, c.Data.Ccertificate, &c.Data.Privatekey, id.Valid, db.CreationTypeCertificate, id)
	if err != nil {
		slog.Error("error while signing cert", "error", err)
		return certificate, err
	}

	var certRow bytes.Buffer
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	err = pem.Encode(&certRow, pemCert)
	if err != nil {
		slog.Error("err encoding")
		return certificate, err
	}
	certificate.Certificate = string(certRow.String())

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		slog.Error("err encoding")
		return certificate, err
	}

	certificate.Ccertificate = cert
	if err := db.SaveCert(c.CommonName, commonName, keyString, publicKeyString, pem.EncodeToMemory(pemCert), csrString, []byte{}, 365, "server"); err != nil {
		return certificate, nil
	}
	//certificate.Valid()
	return certificate, nil

}

// func GetServerCertificate()
func (c *CA) loadCertificate(commonName string) (certificate models.Certificate, err error) {

	var (
		//caCertsDir string = filepath.Join(c.CommonName, "certs", commonName)
		keyString       []byte
		publicKeyString []byte
		csrString       []byte
		certString      []byte
		//loadErr         error
	)

	cc, err := db.GetCert(c.CommonName, commonName)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return certificate, ErrCertLoadNotFound
		}
		return certificate, err
	}

	certificate.CACertificate = c.Data.Certificate
	certificate.CaCertificate = c.Data.Ccertificate
	keyString = cc.PrivateKey
	if string(keyString) != "" {
		privateKey, _ := LoadPrivateKey(keyString)
		certificate.PrivateKey = string(keyString)
		certificate.Privatekey = privateKey
	}
	publicKeyString = cc.PublicKey
	if string(publicKeyString) != "" {
		publicKey, _ := LoadPublicKey(publicKeyString)
		certificate.PublicKey = string(publicKeyString)
		certificate.Publickey = publicKey
	}
	csrString = cc.CSR
	if string(csrString) != "" {
		csr, _ := LoadCSR(csrString)
		certificate.CSR = string(csrString)
		certificate.Csr = *csr
	}
	certString = cc.CRT
	if string(certString) != "" {
		cert, err := LoadCert(certString)
		if err != nil {
			return certificate, err
		}
		certificate.Certificate = string(certString)
		certificate.Ccertificate = cert
	}

	return certificate, nil
}

func (c *CA) revokeCertificate(certificate *x509.Certificate) error {

	var revokedCerts []x509.RevocationListEntry
	var crlString []byte

	currentCRL := c.GoCRL()
	if currentCRL != nil {
		for _, serialNumber := range currentCRL.RevokedCertificateEntries {
			if serialNumber.SerialNumber.String() == certificate.SerialNumber.String() {
				return ErrCertRevoked
			}
		}

		revokedCerts = currentCRL.RevokedCertificateEntries
	}

	newCertRevoke := x509.RevocationListEntry{
		SerialNumber:   certificate.SerialNumber,
		RevocationTime: time.Now(),
	}

	revokedCerts = append(revokedCerts, newCertRevoke)

	crlByte, err := RevokeCertificate(c.CommonName, revokedCerts, c.Data.Ccertificate, &c.Data.Privatekey)
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(crlByte)
	if err != nil {
		return err
	}
	c.Data.Crl = crl

	/*if crlString, err = db.LoadFile(caDir, c.CommonName+crlExtension); err != nil {
		crlString = []byte{}
	}*/

	c.Data.CRL = string(crlString)

	return nil
}
