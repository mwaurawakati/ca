// This package makes easy to generate and certificates from files to be used
// by GoLang applications.
//
// Generating Certificates (even by Signing), the files will be saved in the
// $CAPATH by default.
// For $CAPATH, please check out the GoCA documentation.
package certificates

import (
	"ca/db"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"reflect"
	"strings"
	"time"

	"ca/models"
)

const (
	// MinValidCert is the minimal valid time: 1 day
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time: 825 day
	MaxValidCert int = 825
	// DefaultValidCert is the default valid time: 397 days
	DefaultValidCert int = 397
	// Certificate file extension

)

// ErrCertExists means that the certificate requested already exists
var ErrCertExists = errors.New("certificate already exists")

var ErrParentCANotFound = errors.New("parent CA not found")

func newSerialNumber() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber
}

// CreateCSR creates a Certificate Signing Request returning certData with CSR.
// The CSR is also stored in $CAPATH with extension .csr
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, ipAddresses []net.IP, priv crypto.PrivateKey, creationType db.CreationType, al string) (csr []byte, err error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{province},
		Locality:           []string{locality},
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
	}

	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	var sa x509.SignatureAlgorithm
	switch strings.ToUpper(al) {
	case "RSA", "":
		sa = x509.SHA512WithRSA
	case "ECDSA":
		sa = x509.ECDSAWithSHA512
	case "ED25519":
		sa = x509.PureEd25519
	}

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		slog.Info("err")
		return []byte{}, err
	}
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddresses},
		SignatureAlgorithm: sa,
		IPAddresses:        ipAddresses,
	}

	dnsNames = append(dnsNames, commonName)
	template.DNSNames = dnsNames
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		csr, err = x509.CreateCertificateRequest(rand.Reader, &template, k)
	case *crypto.PrivateKey:
		switch k := (*k).(type) {
		case *ecdsa.PrivateKey:
			csr, err = x509.CreateCertificateRequest(rand.Reader, &template, k)
		case *rsa.PrivateKey:
			csr, err = x509.CreateCertificateRequest(rand.Reader, &template, k)
		default:
			slog.Info("default", "t", reflect.TypeOf(k))
		}
	default:
		slog.Info("default", "t", reflect.TypeOf(k))
	}

	if err != nil {
		slog.Debug("error creating csr", "error", err)
		return csr, err
	}

	return csr, nil
}

// LoadCSR loads a Certificate Signing Request from a read file.
// Using ioutil.ReadFile() satisfyies the read file.
func LoadCSR(csrString []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(string(csrString)))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	return csr, err
}

// LoadCRL loads a Certificate Revocation List from a read file.
//
// Using ioutil.ReadFile() satisfyies the read file.
func LoadCRL(crlString []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode([]byte(string(crlString)))
	crl, err := x509.ParseRevocationList(block.Bytes)

	return crl, err
}

// LoadParentCACertificate loads parent CA's certificate and private key
// TODO maybe make this more generic, something like LoadCACertificate that
// returns the certificate and private/public key
func LoadParentCACertificate(commonName string) (certificate *x509.Certificate, privateKey crypto.PrivateKey, err error) {
	caStorage := db.CAStorage(commonName)
	if !caStorage {
		return nil, nil, ErrParentCANotFound
	}

	//var caDir = filepath.Join(commonName, "ca")

	if keyString, loadErr := db.LoadFile(db.CAT, commonName, db.PRIVATE); loadErr == nil {
		privateKey, err = LoadPrivateKey(keyString)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, loadErr
	}

	if certString, loadErr := db.LoadFile(db.CAT, commonName, db.CRT); loadErr == nil {
		certificate, err = LoadCert(certString)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, loadErr
	}
	return certificate, privateKey, nil
}

// CreateRootCert creates a Root CA Certificate (self-signed)
func CreateRootCert(
	CACommonName,
	commonName,
	country,
	province,
	locality,
	organization,
	organizationalUnit,
	emailAddresses string,
	valid int,
	dnsNames []string,
	ipAddresses []net.IP,
	privateKey crypto.PrivateKey,
	publicKey crypto.PublicKey,
	creationType db.CreationType,
) (cert []byte, err error) {
	cert, err = CreateCACert(
		CACommonName,
		commonName,
		country,
		province,
		locality,
		organization,
		organizationalUnit,
		emailAddresses,
		valid,
		dnsNames,
		ipAddresses,
		privateKey,
		nil, // parentPrivateKey
		nil, // parentCertificate
		publicKey,
		creationType)
	return cert, err
}

// CreateCACert creates a CA Certificate
// Root certificates are self-signed. When creating a root certificate, leave
// parentPrivateKey and parentCertificate parameters as nil. When creating an
// intermediate CA certificates, provide parentPrivateKey and parentCertificate
func CreateCACert(
	CACommonName,
	commonName,
	country,
	province,
	locality,
	organization,
	organizationalUnit,
	emailAddresses string,
	validDays int,
	dnsNames []string,
	ipAddresses []net.IP,
	privateKey,
	parentPrivateKey crypto.PrivateKey,
	parentCertificate *x509.Certificate,
	publicKey crypto.PublicKey,
	creationType db.CreationType,
) (cert []byte, err error) {
	if validDays == 0 {
		validDays = DefaultValidCert
	}
	caCert := &x509.Certificate{
		SerialNumber: newSerialNumber(),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			// TODO: StreetAddress: []string{"ADDRESS"},
			// TODO: PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IPAddresses:           ipAddresses,
	}
	dnsNames = append(dnsNames, commonName)
	caCert.DNSNames = dnsNames

	signingPrivateKey := privateKey
	if parentPrivateKey != nil {
		signingPrivateKey = parentPrivateKey
	}
	signingCertificate := caCert
	if parentCertificate != nil {
		signingCertificate = parentCertificate
	}
	//var key any
	switch k := (signingPrivateKey).(type) {
	case *crypto.PrivateKey:
		switch k := (*k).(type) {
		case *rsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), k)
			if err != nil {
				slog.Debug("error creating certificate", "error", err)
				return nil, err
			}
			slog.Debug("cert", "cert", string(cert))
		case rsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), &k)
			if err != nil {
				slog.Debug("error creating certificate", "error", err)
				return nil, err
			}
			slog.Debug("cert", "cert", string(cert))
		case ecdsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), &k)
			if err != nil {
				slog.Debug("error creating certificate", "error", err)
				return nil, err
			}
			slog.Debug("cert", "cert", string(cert))
		case *ecdsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), k)
			if err != nil {
				slog.Debug("error creating certificate", "error", err)
				return nil, err
			}
			slog.Debug("cert", "cert", string(cert))
		case ed25519.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), k)
			if err != nil {
				slog.Debug("error creating certificate", "error", err)
				return nil, err
			}
			slog.Debug("cert", "cert", string(cert))
		default:
			slog.Info("type", "type", reflect.TypeOf(k), "t2", reflect.TypeOf(privateKey))
			slog.Debug("default cert")
		}
	case *rsa.PrivateKey:
		cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), &k)
		if err != nil {
			slog.Debug("error creating certificate", "error", err)
			return nil, err
		}
		slog.Debug("cert", "cert", string(cert))
	case ecdsa.PrivateKey:
		cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), &k)
		if err != nil {
			slog.Debug("error creating certificate", "error", err)
			return nil, err
		}
		slog.Debug("cert", "cert", string(cert))
	case *ecdsa.PrivateKey:
		cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), k)
		if err != nil {
			slog.Debug("error creating certificate", "error", err)
			return nil, err
		}
		slog.Debug("cert", "cert", string(cert))
	case ed25519.PrivateKey:
		cert, err = x509.CreateCertificate(rand.Reader, caCert, signingCertificate, k.Public(), k)
		if err != nil {
			slog.Debug("error creating certificate", "error", err)
			return nil, err
		}
		slog.Debug("cert", "cert", string(cert))
	default:
		slog.Info("type", "type", reflect.TypeOf(k), "t2", reflect.TypeOf(privateKey))
		slog.Debug("default cert")
	}

	fileData := db.File{
		CA:           CACommonName,
		CommonName:   commonName,
		FileType:     db.FileTypeCertificate,
		CertData:     cert,
		CreationType: creationType,
	}
	err = db.SaveFile(fileData)
	if err != nil {
		return nil, err
	}

	// When creating intermediate CA certificates, store the certificates to its
	// parent CA's cert dir
	if parentCertificate != nil {
		fileData := db.File{
			CA:           parentCertificate.Subject.CommonName,
			CommonName:   commonName,
			FileType:     db.FileTypeCertificate,
			CreationType: db.CreationTypeCertificate,
			CertData:     cert,
		}
		err = db.SaveFile(fileData)
		if err != nil {
			return nil, err
		}
	}

	return cert, nil
}

// LoadCert loads a certifiate from a read file (bytes).
// Using ioutil.ReadFile() satisfyies the read file.
func LoadCert(certString []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(string(certString)))
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert, nil
}

// CASignCSR signs an Certificate Signing Request and returns the Certificate as Go bytes.
func CASignCSR(CACommonName string, csr x509.CertificateRequest, caCert *x509.Certificate, privKey crypto.PrivateKey, valid int, creationType db.CreationType, id ...models.Identity) (cert []byte, err error) {
	if valid == 0 {
		valid = DefaultValidCert

	} else if valid > MaxValidCert || valid < MinValidCert {
		return nil, errors.New("the certificate valid (min/max) is not between 1 - 825")
	}

	if db.CheckCertExists(CACommonName, csr.Subject.CommonName) {
		return nil, ErrCertExists
	}
	var eku []x509.ExtKeyUsage
	if len(id) > 0 {
		switch strings.ToUpper(id[0].CertType) {
		case "SERVER":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "CLIENT":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		default:
			eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}
	} else {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}

	csrTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: newSerialNumber(),
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, valid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		IPAddresses:  csr.IPAddresses,
	}

	csrTemplate.DNSNames = csr.DNSNames
	switch k := privKey.(type) {
	case *crypto.PrivateKey:
		switch k := (*k).(type) {
		case *ecdsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, &csrTemplate, caCert, csrTemplate.PublicKey, k)
		case *rsa.PrivateKey:
			cert, err = x509.CreateCertificate(rand.Reader, &csrTemplate, caCert, csrTemplate.PublicKey, k)
		default:
			slog.Info("r", "t", reflect.TypeOf(k))
		}
	case *rsa.PrivateKey:
		cert, err = x509.CreateCertificate(rand.Reader, &csrTemplate, caCert, csrTemplate.PublicKey, k)
	default:
		slog.Info("r", "t", reflect.TypeOf(k))
	}

	if err != nil {
		return nil, err
	}

	return cert, nil

}

// RevokeCertificate is used to revoke a certificate (added to the revoked list)
func RevokeCertificate(CACommonName string, certificateList []x509.RevocationListEntry, caCert *x509.Certificate, privKey any) ([]byte, error) {
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		RevokedCertificateEntries: certificateList,
		Number:                    newSerialNumber(),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}

	var crlByte []byte
	var err error

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, key)
	case *ecdsa.PrivateKey:
		crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, key)
	case ed25519.PrivateKey:
		crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, key)
	case *crypto.PrivateKey:
		switch k := (*key).(type) {
		case ed25519.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		case *rsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		case rsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, &k)
		case *ecdsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		default:
			slog.Debug("type", "reflected type", reflect.TypeOf(k))
			return nil, errors.New("unsupported private key type")
		}
	case crypto.PrivateKey:
		switch k := (key).(type) {
		case ed25519.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		case *rsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		case rsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, &k)
		case *ecdsa.PrivateKey:
			crlByte, err = x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, k)
		default:
			slog.Debug("type", "reflected type", reflect.TypeOf(k))
			return nil, errors.New("unsupported private key type")
		}

	default:
		slog.Debug("type", "reflected type", reflect.TypeOf(key))
		return nil, errors.New("unsupported private key type")
	}

	if err != nil {
		return nil, err
	}
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crlByte}
	crlString := pem.EncodeToMemory(pemCRL)
	db.UpdateCA(db.CAUpdate{Name: CACommonName, CRL: &crlString})
	return crlByte, nil
}
