package db

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// File name constants
const (
	PEMFile       = "key.pem"
	PublicPEMFile = "key.pub"
)

type T int

const (
	CAT T = iota
	CERTT
)

type F int

const (
	PUB F = iota
	PRIVATE
	CSR
	CRL
	CRT
)

var ErrIncompleteCopy = errors.New("file copy was incomplete")

/*func savePEMKey(fileName string, key crypto.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	var privateKeyBytes = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	// Create a new PrivateKey record
	privateKey := &models.PrivateKey{
		Name: fileName,
		Data: pem.EncodeToMemory(privateKeyBytes),
	}

	// Save the PrivateKey record to the database
	result := db.Create(privateKey)

	// Check for errors
	if err := result.Error; err != nil {
		return err
	}

	return nil
}

func savePublicPEMKey(fileName string, pubkey crypto.PublicKey) error {
	// Marshal the public key to ASN.1 DER format
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	// Create a new PublicKey record
	publicKey := &models.PublicKey{
		Name: fileName,
		Data: pem.EncodeToMemory(pemkey),
	}

	// Save the PublicKey record to the database
	result := db.Create(publicKey)

	// Check for errors
	if err := result.Error; err != nil {
		return err
	}

	return nil
}

func saveCSR(fileName string, csr []byte) error {
	var pemCSR = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	// Create a new CSR record
	csrRecord := &models.CSR{
		Name: fileName,
		Data: pem.EncodeToMemory(pemCSR),
	}

	// Save the CSR record to the database
	result := db.Create(csrRecord)

	// Check for errors
	if err := result.Error; err != nil {
		return err
	}

	return nil
}*/

type CA struct {
	gorm.Model
	Name       string
	CRT        []byte        `json:"crt"`
	CSR        []byte        `json:"csr"`
	CRL        []byte        `json:"crl"`
	PrivateKey []byte        `json:"private_key"`
	PublicKey  []byte        `json:"public_key"`
	Certs      []Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
}

type Certificate struct {
	gorm.Model
	Name           string
	CRT            []byte
	CSR            []byte
	CRL            []byte
	PrivateKey     []byte
	PublicKey      []byte
	Type           string
	Valid          int
	ValidTill      time.Time
	RevocationDate time.Time
}

/*func saveCert(fileName string, cert []byte) error {
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	// Create a new Certificate record
	certRecord := &models.CertificateData{
		Name: fileName,
		Data: pem.EncodeToMemory(pemCert),
	}

	// Save the Certificate record to the database
	result := db.Create(certRecord)

	// Check for errors
	if err := result.Error; err != nil {
		return err
	}

	return nil
}

func saveCRL(fileName string, crl []byte) error {
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crl}
	// Create a new CRL record
	crlRecord := &models.CRL{
		Name: fileName,
		Data: pem.EncodeToMemory(pemCRL),
	}

	// Save the CRL record to the database
	result := db.Create(crlRecord)

	// Check for errors
	if err := result.Error; err != nil {
		return err
	}

	return nil
}
*/
// File has the content to save a file
type File struct {
	CA             string
	CommonName     string
	FileType       FileType
	PrivateKeyData crypto.PrivateKey
	PublicKeyData  crypto.PublicKey
	CSRData        []byte
	CertData       []byte
	CRLData        []byte
	CreationType   CreationType
}

// CheckCertExists returns if a certificate exists or not
func CheckCertExists(CAname, commonName string) bool {
	var ca CA
	err := db.Where("name = ?", CAname).Preload("Certs").First(&ca).Error
	if err != nil {
		// Return error if any other error occurs
		return false
	}
	var cert Certificate
	for _, c := range ca.Certs {
		if c.Name == commonName {
			cert = c
			break
		}
	}
	return cert.ID != 0
}

func CAStorage(commonName string) bool {
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", commonName).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return false
	}
	if err == gorm.ErrRecordNotFound {
		return false
	}
	return true
}

// CreationType represents if CA or Certificate owns the file
type CreationType int

const (
	// CreationTypeCA owned by CA
	CreationTypeCA CreationType = 1 << iota
	// CreationTypeCertificate owned by Certificate
	CreationTypeCertificate
)

// FileType represents what type of file
type FileType int

const (
	// FileTypeKey is Key files
	FileTypeKey FileType = 1 << iota
	// FileTypeCSR is a Certificate Signging Request file
	FileTypeCSR
	// FileTypeCertificate is a Certificate file
	FileTypeCertificate
	// FileTypeCRL is a Certificate Revoking List file
	FileTypeCRL
)

// SaveFile saves a File{}
func SaveFile(f File) error {
	// Creation type
	switch f.CreationType {
	case CreationTypeCA:
		/*switch f.FileType {
			case FileTypeKey:
				if err := SaveCAPEMKey(f.CA, f); err != nil {
					return err
				}
				return nil

			case FileTypeCSR:
				if err := SaveCACSR(f.CA, f.CSRData); err != nil {
					slog.Debug("error saving csr", "error", err)
					return err
				}
				return nil

			case FileTypeCertificate:
				slog.Debug("saving cert", "cert", string(f.CertData))
				if err := SaveCACert(f.CA, f.CertData); err != nil {
					slog.Debug("error saving cert", "error", err)
					return err
				}
				return nil

			case FileTypeCRL:
				if err := SaveCACRL(f.CA, f.CRLData); err != nil {
					slog.Debug("error save crl", "error", err)
				}
			}

		/*case CreationTypeCertificate:
			/switch f.FileType {
			case FileTypeKey:
				slog.Debug("key file", "file", f)
				if err := SaveCertPEMKey(f.CommonName, f.CA, f); err != nil {
					slog.Debug("error saving keys", "e", err)
					return err
				}
				return nil

			case FileTypeCSR:
				if err := SaveCACSR(f.CA, f.CSRData); err != nil {
					slog.Debug("error saving csr", "error", err)
					return err
				}
				return nil

			case FileTypeCertificate:
				slog.Debug("saving cert", "cert", string(f.CertData))
				if err := SaveCACert(f.CA, f.CertData); err != nil {
					slog.Debug("error saving cert", "error", err)
					return err
				}
				return nil

			case FileTypeCRL:
				if err := SaveCACRL(f.CA, f.CRLData); err != nil {
					slog.Debug("error save crl", "error", err)
				}
			}*/
	}

	return nil

}
func GetCA(name string) (CA, error) {
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	return record, err
}

// LoadFile loads a file by file name from $CAPATH
func LoadFile(t T, name string, f F) ([]byte, error) {
	switch t {
	case CAT:
		var record CA
		err := db.Where("name = ?", name).First(&record).Error
		//slog.Info("","",record)
		if err != nil {
			// Return error if any other error occurs
			return []byte{}, err
		}
		switch f {
		case PRIVATE:
			return record.PrivateKey, nil
		case PUB:
			return record.PublicKey, nil
		case CRT:
			if len(record.CRT) > 0 {
				return record.CRT, nil
			} else {
				return []byte{}, errors.New("empty")
			}

		case CRL:
			if len(record.CRL) > 0 {
				return record.CRL, nil
			} else {
				return []byte{}, errors.New("empty")
			}
		case CSR:
			if len(record.CSR) > 0 {
				return record.CSR, nil
			} else {
				return []byte{}, errors.New("empty")
			}

		}
	}
	/*var fileName = filepath.Join(filePath...)
	caPath, err := CAPathIsReady()
	if err != nil {
		return nil, err
	}

	fileData, err := os.ReadFile(filepath.Join(caPath, fileName))
	if err != nil {
		return []byte{}, err
	}

	return fileData, nil*/
	return nil, nil

}

// CopyFile copies the specified src file to the given destination.
// Both paths are relative to the $CAPATH hierarchy.
func CopyFile(src, dest string) error {
	caPath := "" /*, err := CAPathIsReady()
	if err != nil {
		return err
	}*/

	srcPath := filepath.Join(caPath, src)
	destPath := filepath.Join(caPath, dest)

	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	inStat, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE, inStat.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, in)
	if err != nil {
		return err
	}

	if written != inStat.Size() {
		return ErrIncompleteCopy
	}

	return nil
}

// ListCertificates return a list of certificates folders
func ListCertificates(CACommonName string) (*[]Certificate, error) {
	var ca *CA = &CA{}
	err := db.Preload("Certs").Where("name =?", CACommonName).First(ca).Error
	if err != nil {
		return nil, err
	}
	return &ca.Certs, nil
}

func LoadedCA(CACommonName string) (*CA, error) {
	var ca *CA = &CA{}
	err := db.Preload("Certs").Where("name =?", CACommonName).First(ca).Error
	if err != nil {
		return nil, err
	}
	return ca, nil
}
// ListCAs return a list of certificates folders
func ListCAs() (*[]CA, error) {
	var ca *[]CA
	if err := db.Preload("Certs").Find(&ca).Error; err != nil {
		return nil, err
	}
	return ca, nil
}

func SaveCAPEMKey(name string, f File) error {
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return err
	}

	// If the record doesn't exist, create it
	if err == gorm.ErrRecordNotFound {
		b, err := x509.MarshalPKCS8PrivateKey(f.PrivateKeyData)
		if err != nil {
			slog.Error("error while unmarshaling priv key", "error", err)
			return err
		}
		var privateKeyBytes = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
		asn1Bytes, err := x509.MarshalPKIXPublicKey(f.PublicKeyData)
		if err != nil {
			slog.Error("error while unmarshaling public key", "error", err)
			return err
		}
		var pemkey = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
		record = CA{Name: name, PrivateKey: pem.EncodeToMemory(privateKeyBytes), PublicKey: pem.EncodeToMemory(pemkey)}
		if err := db.Create(&record).Error; err != nil {
			return err
		}
	} else {
		// If the record exists, update it
		b, err := x509.MarshalPKCS8PrivateKey(f.PrivateKeyData)
		if err != nil {
			return err
		}
		var privateKeyBytes = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
		asn1Bytes, err := x509.MarshalPKIXPublicKey(f.PublicKeyData)
		if err != nil {
			return err
		}
		var pemkey = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
		if err := db.Model(&record).Updates(CA{PrivateKey: pem.EncodeToMemory(privateKeyBytes), PublicKey: pem.EncodeToMemory(pemkey)}).Error; err != nil {
			return err
		}
	}

	return nil
}

func SaveCAPublicPEMKey(name string, data crypto.PublicKey) error {
	slog.Debug("saving public key")
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return err
	}

	// If the record doesn't exist, create it
	if err == gorm.ErrRecordNotFound {
		asn1Bytes, err := asn1.Marshal(data)
		if err != nil {
			return err
		}
		var pemkey = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
		record = CA{Name: name, PublicKey: pem.EncodeToMemory(pemkey)}
		if err := db.Create(&record).Error; err != nil {
			return err
		}
	} else {
		// If the record exists, update it
		asn1Bytes, err := asn1.Marshal(data)
		if err != nil {
			return err
		}
		var pemkey = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}

		if err := db.Model(&record).Update("public_key", pem.EncodeToMemory(pemkey)).Error; err != nil {
			return err
		}
	}

	return nil
}

func SaveCACSR(name string, csr []byte) error {
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return err
	}

	// If the record doesn't exist, create it
	if err == gorm.ErrRecordNotFound {
		var pemCSR = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
		record = CA{Name: name, CSR: pem.EncodeToMemory(pemCSR)}
		if err := db.Create(&record).Error; err != nil {
			return err
		}
	} else {
		// If the record exists, update it
		var pemCSR = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
		if err := db.Model(&record).Update("csr", pem.EncodeToMemory(pemCSR)).Error; err != nil {
			return err
		}
	}

	return nil
}

func SaveCACert(name string, cert []byte) error {
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return err
	}

	// If the record doesn't exist, create it
	if err == gorm.ErrRecordNotFound {
		var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: cert}
		record = CA{Name: name, CRT: pem.EncodeToMemory(pemCert)}
		if err := db.Create(&record).Error; err != nil {
			return err
		}
	} else {
		// If the record exists, update it
		var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: cert}
		if err := db.Model(&record).Update("crt", pem.EncodeToMemory(pemCert)).Error; err != nil {
			return err
		}
	}

	return nil
}

func SaveCACRL(name string, crl []byte) error {
	// Check if the record already exists
	var record CA
	err := db.Where("name = ?", name).First(&record).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		// Return error if any other error occurs
		return err
	}

	// If the record doesn't exist, create it
	if err == gorm.ErrRecordNotFound {
		var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crl}
		record = CA{Name: name, CRL: pem.EncodeToMemory(pemCRL)}
		if err := db.Create(&record).Error; err != nil {
			return err
		}
	} else {
		// If the record exists, update it
		var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crl}
		if err := db.Model(&record).Update("crl", pem.EncodeToMemory(pemCRL)).Error; err != nil {
			return err
		}
	}

	return nil
}

func SaveCertPEMKey(name string, CAname string, f File) error {
	// Check if the record already exists
	var ca CA
	err := db.Where("name = ?", CAname).Preload("Certs").First(&ca).Error
	if err != nil {
		// Return error if any other error occurs
		return err
	}
	// Check if certificate "a" exists for CA "a"
	var cert Certificate
	for _, c := range ca.Certs {
		if c.Name == "a" {
			cert = c
			break
		}
	}
	b, err := x509.MarshalPKCS8PrivateKey(f.PrivateKeyData)
	if err != nil {
		slog.Error("error while unmarshaling priv key", "error", err)
		return err
	}
	var privateKeyBytes = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	asn1Bytes, err := x509.MarshalPKIXPublicKey(f.PublicKeyData)
	if err != nil {
		slog.Error("error while unmarshaling public key", "error", err)
		return err
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	// Update or create the certificate
	if cert.ID == 0 {
		// Create a new certificate
		cert = Certificate{Name: name, PrivateKey: pem.EncodeToMemory(privateKeyBytes), PublicKey: pem.EncodeToMemory(pemkey)}
		ca.Certs = append(ca.Certs, cert)
		if err := db.Save(&ca).Error; err != nil {
			panic(err)
		}
	} else {
		// Update existing certificate fields
		cert.PrivateKey = pem.EncodeToMemory(privateKeyBytes)
		cert.PublicKey = pem.EncodeToMemory(pemkey)
		if err := db.Save(&cert).Error; err != nil {
			panic(err)
		}
	}

	return nil
}

func SaveCert(CAName, commonName string, privateKey, publicKey, crt, csr, crl []byte, valid int, certType string) error {
	// Check if the record already exists
	var ca CA
	err := db.Where("name = ?", CAName).Preload("Certs").First(&ca).Error
	if err != nil {
		// Return error if any other error occurs
		return err
	}
	// Check if certificate "a" exists for CA "a"
	var cert Certificate
	for _, c := range ca.Certs {
		if c.Name == commonName {
			cert = c
			break
		}
	}

	if cert.ID == 0 {
		// Create a new certificate
		cert = Certificate{Name: commonName, PrivateKey: privateKey, PublicKey: publicKey, CRT: crt, CSR: csr, CRL: crl, Valid: valid, ValidTill: time.Now().Add(24 * time.Hour * time.Duration(valid)), Type: certType}
		ca.Certs = append(ca.Certs, cert)
		if err := db.Save(&ca).Error; err != nil {
			return err
		}
	} else {
		return errors.New("certificate exists")
	}

	return nil
}

func UpdateCert(crt *Certificate) error {
	return db.Save(&crt).Error
}
func GetCert(CAName, commonName string) (Certificate, error) {
	// Check if the record already exists
	var ca CA
	err := db.Where("name = ?", CAName).Preload("Certs").First(&ca).Error
	if err != nil {
		// Return error if any other error occurs
		return Certificate{}, err
	}
	// Check if certificate "a" exists for CA "a"
	var cert Certificate
	for _, c := range ca.Certs {
		if c.Name == commonName {
			cert = c
			break
		}
	}
	if cert.ID == 0 {
		return cert, gorm.ErrRecordNotFound
	}
	return cert, nil
}

func SaveCA(commonName string, privateKey, publicKey, crt, csr, crl []byte) error {
	record := CA{Name: commonName, PrivateKey: privateKey, PublicKey: publicKey, CRT: crt, CRL: crl, CSR: csr}
	if err := db.Create(&record).Error; err != nil {
		return err
	}
	return nil
}

func UpdateCA(ca CAUpdate) error {
	oldCA := CA{}
	updatedCA := db.First(&oldCA).Where("name = ?", ca.Name)
	if updatedCA.Error != nil {
		return updatedCA.Error
	}
	if ca.PrivateKey != nil {
		oldCA.PrivateKey = *ca.PrivateKey
	}
	if ca.PublicKey != nil {
		oldCA.PublicKey = *ca.PublicKey
	}
	if ca.CRT != nil {
		oldCA.CRT = *ca.CRT
	}
	if ca.CRL != nil {
		oldCA.CRL = *ca.CRL
	}
	if ca.CSR != nil {
		oldCA.CSR = *ca.CSR
	}
	updatedCA = db.Save(&oldCA)
	return updatedCA.Error

}

type CAUpdate struct {
	Name       string
	PrivateKey *[]byte
	PublicKey  *[]byte
	CRT        *[]byte
	CRL        *[]byte
	CSR        *[]byte
}

// GenerateCACertificate generates a self-signed CA certificate
func GenerateCACertificate(a, country, commonName, email, organisation, state, city, organisationUnit string, valid int) (*Certificate, error) {
	//check validity
	if valid == 0 {
		valid = 500
	}
	validstr := strconv.Itoa(valid)
	var cert Certificate
	var privateKeyCmd *exec.Cmd
	var publicKeyCmd *exec.Cmd
	n := uuid.New().String()
	defer os.Remove(n + ".key")
	defer os.Remove(n + ".pem")
	defer os.Remove(n + "_public.key")
	// Generate private key
	switch strings.ToUpper(a) {
	case "RSA", "":
		privateKeyCmd = exec.Command("openssl", "genrsa", "-out", n+".key", "4096")
	case "DSA":
		n1 := uuid.New().String()
		defer os.Remove(n1 + ".pem")
		privateKeyCmd = exec.Command("openssl", "dsaparam", "-out", n1+".pem", "2048")
		_, err := privateKeyCmd.Output()
		if err != nil {
			slog.Error("error creating private key", "error", err)
			return nil, fmt.Errorf("error generating private key: %v", err)
		}
		privateKeyCmd = exec.Command("openssl", "gendsa", "-out", n+".key", n1+".pem")
	case "ECDSA", "ECDH":
		privateKeyCmd = exec.Command("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-out", n+".key")
	case "ED25519", "EDDSA":
		privateKeyCmd = exec.Command("openssl", "genpkey", "-out", n+".key", "-algorithm", "Ed25519")
	default:
		privateKeyCmd = exec.Command("openssl", "genrsa", "-out", n+".key", "4096")

	}

	_, err := privateKeyCmd.Output()
	if err != nil {
		slog.Error("error creating private key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	b, err := os.ReadFile(n + ".key")
	if err != nil {
		slog.Error("error reading private key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.PrivateKey = b
	// Public Key
	switch strings.ToUpper(a) {
	case "RSA", "":
		//openssl rsa -in private.key -pubout -out public.key
		publicKeyCmd = exec.Command("openssl", "rsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "DSA":
		publicKeyCmd = exec.Command("openssl", "dsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "ECDSA", "ECDH":
		publicKeyCmd = exec.Command("openssl", "ec", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "ED25519", "EDDSA":
		publicKeyCmd = exec.Command("openssl", "pkey", "-in", n+".key", "-pubout", "-out", n+"_public.key")
	default:
		publicKeyCmd = exec.Command("openssl", "rsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")

	}

	_, err = publicKeyCmd.Output()
	if err != nil {
		slog.Error("error creating public key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	b, err = os.ReadFile(n + "_public.key")
	if err != nil {
		slog.Error("error reading private key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.PublicKey = b

	// Generate CSR (Certificate Signing Request)
	csrCmd := exec.Command("openssl", "req", "-new", "-key", n+".key", "-subj",
		fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email))
	csrOut, err := csrCmd.Output()
	if err != nil {
		slog.Error("error creating csr", "error", err)
		return nil, fmt.Errorf("error generating CSR: %v", err)
	}
	cert.CSR = csrOut

	// Generate self-signed certificate
	certCmd := exec.Command("openssl", "req", "-x509", "-new", "-nodes", "-key", n+".key", "-sha256", "-days", validstr, "-out", n+".pem", "-subj",
		fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email))
	_, err = certCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %v", err)
	}
	b, err = os.ReadFile(n + ".pem")
	if err != nil {
		slog.Error("error reading cert", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	cert.CRT = b

	return &cert, nil
}

func GenerateServerCertificate(ca *CA, a, country, commonName, email, organisation, state, city, organisationUnit string, valid int) (*Certificate, error) {
	//check validity
	if valid == 0 {
		valid = 500
	}
	validstr := strconv.Itoa(valid)
	// save Certfificate authothority cert and key
	var (
		cak           string
		cac           string
		privateKeyCmd *exec.Cmd
		publicKeyCmd  *exec.Cmd
		cert          Certificate
	)
	n := uuid.NewString()
	caCRT, err := os.CreateTemp("", n+"_ca.pem")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caCRT.Name())
	if _, err := caCRT.Write(ca.CRT); err != nil {
		return nil, err
	}
	cac = caCRT.Name()
	if err := caCRT.Close(); err != nil {
		return nil, err
	}
	caKey, err := os.CreateTemp("", n+"_ca.key")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caKey.Name())
	if _, err := caKey.Write(ca.PrivateKey); err != nil {
		return nil, err
	}
	cak = caKey.Name()
	if err := caKey.Close(); err != nil {
		return nil, err
	}
	defer os.Remove(n + ".key")
	defer os.Remove(n + ".pem")
	defer os.Remove(n + ".csr")
	defer os.Remove(n + "_public.key")
	defer os.Remove(n + ".crt")

	// Generate private key
	switch strings.ToUpper(a) {
	case "RSA", "":
		privateKeyCmd = exec.Command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", n+".key", "-out", n+".csr", "-subj",
			fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email), "-passin", "pass:")
	case "DSA":
		privateKeyCmd = exec.Command("openssl", "req", "-newkey", "dsa:2048", "-nodes", "-keyout", n+".key", "-out", n+".csr", "-subj",
			fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email))
	case "ECDSA", "ECDH":
		args := fmt.Sprintf("openssl req -newkey ec:<(openssl ecparam -name prime256v1) -nodes -keyout %s.key -out %s.csr -subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", n, n, country, state, city, organisation, organisationUnit, commonName, email)
		privateKeyCmd = exec.Command("bash", "-c", args)
	case "ED25519", "EDDSA":
		//args := fmt.Sprintf("openssl req -newkey ed25519 -passout pass: -keyout %s.key -out %s.csr -subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s",n,n, country, state, city, organisation, organisationUnit, commonName, email)
		//privateKeyCmd = exec.Command("bash", "-c", args)
		privateKeyCmd = exec.Command("openssl", "req", "-newkey", "ed25519", "-passout", "pass:", "-keyout", n+".key", "-out", n+".csr", "-subj", fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email))
		privateKeyCmd.Stdin = bytes.NewReader([]byte{})
	default:
		privateKeyCmd = exec.Command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", n+".key", "-out", n+".csr", "-subj",
			fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, state, city, organisation, organisationUnit, commonName, email))
	}
	o, err := privateKeyCmd.Output()
	if err != nil {
		slog.Error("error creating private key", "error", err, "output", o)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	b, err := os.ReadFile(n + ".key")
	if err != nil {
		slog.Error("error reading private key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.PrivateKey = b

	// Public Key
	switch strings.ToUpper(a) {
	case "RSA", "":
		//openssl rsa -in private.key -pubout -out public.key
		publicKeyCmd = exec.Command("openssl", "rsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "DSA":
		publicKeyCmd = exec.Command("openssl", "dsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "ECDSA", "ECDH":
		publicKeyCmd = exec.Command("openssl", "ec", "-pubout", "-out", n+"_public.key", "-in", n+".key")
	case "ED25519", "EDDSA":
		publicKeyCmd = exec.Command("openssl", "pkey", "-in", n+".key", "-pubout", "-out", n+"_public.key")
	default:
		publicKeyCmd = exec.Command("openssl", "rsa", "-pubout", "-out", n+"_public.key", "-in", n+".key")

	}

	_, err = publicKeyCmd.Output()
	if err != nil {
		slog.Error("error creating public key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	b, err = os.ReadFile(n + "_public.key")
	if err != nil {
		slog.Error("error reading private key", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.PublicKey = b
	b, err = os.ReadFile(n + ".csr")
	if err != nil {
		slog.Error("error reading csr", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.CSR = b

	// Generate self-signed certificate
	certCmd := exec.Command("openssl", "x509", "-req", "-in", n+".csr", "-CA", cac, "-CAkey", cak, "-CAcreateserial", "-out", n+".crt", "-days", validstr, "-sha256")
	o, err = certCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %v, output: %v", err, o)
	}
	b, err = os.ReadFile(n + ".crt")
	if err != nil {
		slog.Error("error reading cert", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	cert.CRT = b

	return &cert, nil
}

func RevokeServerCertificate(ca *CA, crt []byte) ([]byte, error) {
	
	var (
		cak       string
		cac       string
		ccert     string
		csrKeyCmd *exec.Cmd
	)
	n := uuid.NewString()
	caCRT, err := os.CreateTemp("", n+"_ca.pem")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caCRT.Name())
	if _, err := caCRT.Write(ca.CRT); err != nil {
		return nil, err
	}
	cac = caCRT.Name()
	if err := caCRT.Close(); err != nil {
		return nil, err
	}
	caKey, err := os.CreateTemp("", n+"_ca.key")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caKey.Name())
	if _, err := caKey.Write(ca.PrivateKey); err != nil {
		return nil, err
	}
	cak = caKey.Name()
	if err := caKey.Close(); err != nil {
		return nil, err
	}

	cKey, err := os.CreateTemp("", n+".cert")
	if err != nil {
		return nil, err
	}
	defer os.Remove(cKey.Name())
	if _, err := cKey.Write(crt); err != nil {
		return nil, err
	}
	ccert = cKey.Name()
	if err := cKey.Close(); err != nil {
		return nil, err
	}

	defer os.Remove(n + ".csr")
	defer os.Remove(n + ".pem")

	// New Certfificate revocation list
	csrKeyCmd = exec.Command("openssl", "ca", "-keyfile", cak, "-out", n+".pem", "-cert", cac)
	o, err := csrKeyCmd.CombinedOutput()
	if err != nil {
		slog.Error("error creating csr", "error", err, "output", o)
		return nil, fmt.Errorf("error creating revocation list %v, output: %#v", err, o)
	}

	//Revoke a specific certificate:
	certCmd := exec.Command("openssl", "ca", "-revoke", ccert, "-cert", cac, "-keyfile", cak)
	o, err = certCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error revoking certificate: %v, output: %v", err, o)
	}
	
	// Update the CRL after revocation:
	certCmd = exec.Command("openssl", "ca", "-gencrl","-out",n+".pem", "-cert", cac, "-keyfile", cak)
	o, err = certCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error revoking certificate: %v, output: %v", err, o)
	}
	b, err := os.ReadFile(n + ".pem")
	if err != nil {
		slog.Error("error reading csr", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	return b, nil
}

func RenewServerCertificate(ca *CA, commonName, subject string, valid int, priv []byte) (*Certificate, error) {
	//check validity
	if valid == 0 {
		valid = 500
	}
	validstr := strconv.Itoa(valid)
	// save Certfificate authothority cert and key
	var (
		cak       string
		cac       string
		cpriv     string
		csrKeyCmd *exec.Cmd
		//publicKeyCmd  *exec.Cmd
		cert Certificate
	)
	n := uuid.NewString()
	caCRT, err := os.CreateTemp("", n+"_ca.pem")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caCRT.Name())
	if _, err := caCRT.Write(ca.CRT); err != nil {
		return nil, err
	}
	cac = caCRT.Name()
	if err := caCRT.Close(); err != nil {
		return nil, err
	}
	caKey, err := os.CreateTemp("", n+"_ca.key")
	if err != nil {
		return nil, err
	}
	defer os.Remove(caKey.Name())
	if _, err := caKey.Write(ca.PrivateKey); err != nil {
		return nil, err
	}
	cak = caKey.Name()
	if err := caKey.Close(); err != nil {
		return nil, err
	}

	cKey, err := os.CreateTemp("", n+".key")
	if err != nil {
		return nil, err
	}
	defer os.Remove(cKey.Name())
	if _, err := cKey.Write(priv); err != nil {
		return nil, err
	}
	cpriv = cKey.Name()
	if err := cKey.Close(); err != nil {
		return nil, err
	}

	defer os.Remove(n + ".csr")
	//defer os.Remove(n + "_public.key")
	defer os.Remove(n + ".crt")

	slog.Info(subject)
	csrKeyCmd = exec.Command("openssl", "req", "-new", "-key", cpriv, "-out", n+".csr", "-subj", subject)
	o, err := csrKeyCmd.CombinedOutput()
	if err != nil {
		slog.Error("error creating csr", "error", err, "output", o)
		return nil, fmt.Errorf("error generating csr: %v, output: %#v", err, o)
	}

	b, err := os.ReadFile(n + ".csr")
	if err != nil {
		slog.Error("error reading csr", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	cert.CSR = b

	// Generate self-signed certificate
	certCmd := exec.Command("openssl", "x509", "-req", "-in", n+".csr", "-CA", cac, "-CAkey", cak, "-CAcreateserial", "-out", n+".crt", "-days", validstr, "-sha256")
	o, err = certCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %v, output: %v", err, o)
	}
	b, err = os.ReadFile(n + ".crt")
	if err != nil {
		slog.Error("error reading cert", "error", err)
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	cert.CRT = b

	return &cert, nil
}


func DeleteCert(c Certificate) error {
	return db.Delete(&c).Error
}