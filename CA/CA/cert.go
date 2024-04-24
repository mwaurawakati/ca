package certificates

import (
	"ca/models"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type CertificateType int

const (
	SSL CertificateType = iota
	Client
	Server
	CAuth
)

type Algorithm int

const Organization = ""

type CertificateOptions struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	ExtKeyUsage        []x509.ExtKeyUsage
	Validity           time.Duration
	Length             int
}
type Certificatee struct {
	Data       []byte
	PrivateKey []byte
	Type       CertificateType
	ValidFrom  time.Time
	ValidTo    time.Time
}

func CreateCertificate(ctx context.Context, ct CertificateType, options CertificateOptions) (*models.Certificate, error) {
	// Verify that algorithms are compartible
	if checkAlgorithmsCompatible(options.SignatureAlgorithm, options.PublicKeyAlgorithm) {
		return nil, errors.New("incompatible signature algorithm and public key algorithm")
	}
	switch options.PublicKeyAlgorithm {
	case x509.RSA:
		// Generate RSA private key
		privateKey, err := rsa.GenerateKey(rand.Reader, options.Length)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}
		// Define certificate template
		template := x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{Organization: []string{Organization}},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(options.Validity),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           options.ExtKeyUsage,
			BasicConstraintsValid: true,
			IsCA:                  ct == CAuth,
		}
		// Create certificate
		certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %v", err)
		}
		// Encode certificate to PEM format
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		if certPEM == nil {
			return nil, errors.New("failed to encode certificate to PEM format")
		}
		// Return the new certificate
		return &models.Certificate{
			/*Type:      ct,
			Data:      certPEM,
			ValidFrom: time.Now(),
			ValidTo:   time.Now().Add(options.Validity),*/
		}, nil
	}
	return &models.Certificate{}, nil
}

// This function checks if the private key and public key algoriths are compatible
func checkAlgorithmsCompatible(sa x509.SignatureAlgorithm, pa x509.PublicKeyAlgorithm) bool {
	switch pa {
	case x509.RSA:
		switch sa {
		case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return true
		default:
			return false
		}
	case x509.ECDSA:
		switch sa {
		case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return true
		default:
			return false
		}
	case x509.Ed25519:
		switch sa {
		case x509.PureEd25519:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

