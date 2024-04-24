package controllers

import (
	certificates "ca/CA"
	"ca/db"
	"ca/models"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	//storage "ca/_storage"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Map[T, U any](ts []T, f func(T) U) []U {
	us := make([]U, len(ts))
	for i := range ts {
		us[i] = f(ts[i])
	}
	return us
}

var Client *casdoorsdk.Client

func getCAData(ca certificates.CA) (body models.CABody) {

	caType := ca.IsIntermediate()

	body.CommonName = ca.CommonName
	body.Intermediate = caType
	body.Status = ca.Status()

	certificate := ca.GoCertificate()
	csr := ca.GoCSR()
	certs, _ := ca.ListCertificates()
	c := Map(*certs, func(c db.Certificate) string { return string(c.CRT) })
	log.Println(c)
	body.Certificates = c

	if csr != nil {
		body.CSR = true
	}

	if certificate != nil {
		body.DNSNames = certificate.DNSNames
		body.IssueDate = certificate.NotBefore.String()
		body.ExpireDate = certificate.NotAfter.String()
		crl := ca.GoCRL()
		body.SerialNumber = certificate.SerialNumber.String()
		if crl != nil {
			var revokedCertificates []string
			for _, serialNumber := range crl.RevokedCertificateEntries {
				revokedCertificates = append(revokedCertificates, serialNumber.SerialNumber.String())
			}
			body.CertificateRevocationList = revokedCertificates
		}
	}

	body.Files = ca.Data

	return body
}

func getCertificateData(certificate models.Certificate) (body models.CertificateBody) {

	cert := certificate.GoCert()

	body.CommonName = cert.Subject.CommonName
	body.DNSNames = cert.DNSNames
	body.SerialNumber = cert.SerialNumber.String()
	body.IssueDate = cert.NotBefore.String()
	body.ExpireDate = cert.NotAfter.String()
	body.Files = certificate

	return body

}

func payloadInit(json models.Payload) (commonName, parentCommonName string, identity models.Identity) {
	return json.CommonName, json.ParentCommonName, json.Identity
}

// GetCA is the handler of Certificate Authorities endpoint
// @Summary List Certificate Authorities (CA)
// @Description list all the Certificate Authorities
// @Tags CA
// @Produce json
// @Success 200 {object} models.ResponseList
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca [get]

func GetCA(c *gin.Context) {
	caList, err := certificates.List()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": caList})
}

// AddCA is the handler of Certificate Authorities endpoint
// @Summary Create new Certificate Authorities (CA) or Intermediate Certificate Authorities (ICA)
// @Description create a new Certificate Authority Root or Intermediate
// @Tags CA
// @Accept json
// @Produce json
// @Param json_payload body models.Payload true "Add new Certificate Authority or Intermediate Certificate Authority"
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca [post]
func AddCA(c *gin.Context) {

	var (
		json models.Payload
		ca   certificates.CA
		err  error
	)
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	commonName, parentCommonName, identity := payloadInit(json)
	slog.Info(parentCommonName)
	if parentCommonName == "" {
		ca, err = certificates.New(commonName, identity)
	} else {
		ca, err = certificates.NewCA(commonName, parentCommonName, identity)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var caData models.CABody = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"Data": caData})

}

// AddCA is the handler of Certificate Authorities endpoint
// @Summary Create new Certificate Authorities (CA) or Intermediate Certificate Authorities (ICA)
// @Description create a new Certificate Authority Root or Intermediate
// @Tags CA
// @Accept json
// @Produce json
// @Param json_payload body models.Payload true "Add new Certificate Authority or Intermediate Certificate Authority"
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/certificates/generate/ca/ [post]
func CreateCACertificate(c *gin.Context) {
	var (
		json models.Payload
		//ca   certificates.CA
		err error
	)
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cert, err := certificates.CreateCA(json.Identity.Algorithm, json.Identity.Country, json.CommonName,
		json.Identity.EmailAddresses, json.Identity.Organization, json.Identity.Province, json.Identity.Locality, json.Identity.OrganizationalUnit, json.Identity.Valid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       cert.Name,
		CRT:        string(cert.CRT),
		CSR:        string(cert.CSR),
		CRL:        string(cert.CRL),
		PrivateKey: string(cert.PrivateKey),
		PublicKey:  string(cert.PublicKey),
		//Certs: cert.Certs,
	}
	c.JSON(http.StatusOK, gin.H{"Data": d})

}

func CreateServerCertificate(c *gin.Context) {
	var (
		json models.Payload
		err error
	)
	cert, err := db.GetCA(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error reading request body": err.Error()})
		return
	}

	endpointParts := strings.Split(c.Request.URL.Path, "/")
	if len(endpointParts) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endpoint"})
		return
	}
	certificateType := endpointParts[len(endpointParts)-1]
	crt, err := certificates.CreateServerCertificate(cert, json.Identity.Algorithm, json.Identity.Country, json.CommonName,
		json.Identity.EmailAddresses, json.Identity.Organization, json.Identity.Province, json.Identity.Locality, json.Identity.OrganizationalUnit, json.Identity.Valid, certificateType)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error creating vertificate": err.Error()})
		return
	}
	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       crt.Name,
		CRT:        string(crt.CRT),
		CSR:        string(crt.CSR),
		CRL:        string(crt.CRL),
		PrivateKey: string(crt.PrivateKey),
		PublicKey:  string(crt.PublicKey),

		//Certs: cert.Certs,
	}
	d.CreatedAt = time.Now()
	d.UpdatedAt = time.Now()
	d.Name = json.CommonName
	c.JSON(http.StatusOK, gin.H{"Data": d})

}

func RenewServerCertificate(c *gin.Context) {
	var (
		json models.RenewPayload
		//ca   certificates.CA
		err error
	)
	ca, err := db.GetCA(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	cert, err := db.GetCert(c.Param("common-name"), c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + "or the server certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error reading request body": err.Error()})
		return
	}
	// Parse certificate

	block, _ := pem.Decode([]byte(cert.CRT))
	// Parse the certificate data
	certp, err := parseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate: " + err.Error()})
		return
	}
	crt, err := certificates.RenewServerCertificate(ca, &cert, cert.Name, pkixNameToOpenSSLSubject(certp.Subject), json.Valid, cert.Type, cert.PrivateKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error creating certificate": err.Error()})
		return
	}
	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       crt.Name,
		CRT:        string(crt.CRT),
		CSR:        string(crt.CSR),
		CRL:        string(crt.CRL),
		PrivateKey: string(crt.PrivateKey),
		PublicKey:  string(crt.PublicKey),

		//Certs: cert.Certs,
	}
	d.CreatedAt = cert.CreatedAt
	d.UpdatedAt = cert.UpdatedAt
	c.JSON(http.StatusOK, gin.H{"Data": d})

}

func RevokeServerCertificate(c *gin.Context) {
	_, err := db.GetCA(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	cert, err := db.GetCert(c.Param("common-name"), c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + " or the  certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := db.DeleteCert(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	/*if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error CA not found": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	//log.Printf("%#v\n", ca.Certs)
	if len(ca.Certs) > 0 {
		index, exist := slices.BinarySearchFunc(ca.Certs, c.Param("cn"), func(a db.Certificate, b string) int {
			log.Println(a.Name, b)
			return cmp.Compare(b,a.Name)
		})
		if !exist {
			c.JSON(http.StatusNotFound, gin.H{"error cert not found": certificates.ErrCALoadNotFound})
			return
		}
		cert = ca.Certs[index]
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error cert not found": certificates.ErrCALoadNotFound})
		return
	}

	_, err = certificates.RevokeServerCertificate(*ca, cert)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error creating certificate": err.Error()})
		return
	}*/

	c.JSON(http.StatusOK, gin.H{"Data": "Revocation successful"})

}

// GetCACommonName is the handler of Certificate Authorities endpoint
// @Summary Certificate Authorities (CA) Information based in Common Name
// @Description list the Certificate Authorities data
// @Tags CA
// @Produce json
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/certificates/generate/ca/{common-name} [get]
func GetCACertificate(c *gin.Context) {

	//var body models.CABody

	cert, err := db.GetCA(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	d := struct {
		gorm.Model
		Name       string
		CRT        string           `json:"crt"`
		CSR        string           `json:"csr"`
		CRL        string           `json:"crl"`
		PrivateKey string           `json:"private_key"`
		PublicKey  string           `json:"public_key"`
		Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       cert.Name,
		CRT:        string(cert.CRT),
		CSR:        string(cert.CSR),
		CRL:        string(cert.CRL),
		PrivateKey: string(cert.PrivateKey),
		PublicKey:  string(cert.PublicKey),
		Certs:      cert.Certs,
		//CreatedAt:cert.CreatedAt,
	}

	c.JSON(http.StatusOK, gin.H{"data": d})
}

func GetServerCertificates(c *gin.Context) {
	cert, err := db.GetCert(c.Param("common-name"), c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + " or the server certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	/*block, _ := pem.Decode([]byte(cert.CRT))
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode certificate"})
		return
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))*/

	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		ValidTill  time.Time
		Valid      int
		Type       string
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       cert.Name,
		CRT:        string(cert.CRT),
		CSR:        string(cert.CSR),
		CRL:        string(cert.CRL),
		PrivateKey: string(cert.PrivateKey),
		PublicKey:  string(cert.PublicKey),
		ValidTill:  cert.ValidTill,
		Valid:      cert.Valid,
		Type:       cert.Type,
	}
	d.CreatedAt = cert.CreatedAt
	d.UpdatedAt = cert.UpdatedAt

	c.JSON(http.StatusOK, gin.H{"data": d})
}

// GetCACommonName is the handler of Certificate Authorities endpoint
// @Summary Certificate Authorities (CA) Information based in Common Name
// @Description list the Certificate Authorities data
// @Tags CA
// @Produce json
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn} [get]
func GetCACommonName(c *gin.Context) {

	var body models.CABody

	ca, err := certificates.Load(c.Param("cn"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	body = getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// UploadCertificateICA is the handler of Intermediate Certificate Authorities endpoint
// @Summary Upload a Certificate to an Intermediate CA
// @Description Upload a Certificate to a ICA pending certificate
// @Tags CA
// @Produce json
// @Param file formData file true "Attached signed Certificate file"
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/upload [post]
func UploadCertificateICA(c *gin.Context) {
	/*
		var body models.CABody
		caCN := c.Param("cn")
		ca, err := certificates.Load(caCN)
		if err != nil {
			if err == certificates.ErrCALoadNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}

			return
		}

		if ca.Status() != "Intermediate Certificate Authority not ready, missing Certificate." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The Intermediate Certificate Authority is not pending certificate"})
			return
		}

		certUploaded, _ := c.FormFile("file")
		fileName := uuid.New().String()
		fileNameFull := filepath.Join(os.Getenv("CAPATH"), fileName)
		if err := c.SaveUploadedFile(certUploaded, fileNameFull); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		certFile, err := storage.LoadFile(fileName)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fileData := storage.File{
			CA:           caCN,
			CommonName:   caCN,
			FileType:     storage.FileTypeCertificate,
			CertData:     certFile,
			CreationType: storage.CreationTypeCA,
		}
		err = storage.SaveFile(fileData)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		}

		ca, err = certificates.Load(caCN)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		os.Remove(fileNameFull)

		// Generate the initial CRL
		privKey := ca.GoPrivateKey()
		_, err = certificates.RevokeCertificate(ca.CommonName, []x509.RevocationListEntry{}, ca.GoCertificate(), &privKey)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		body = getCAData(ca)

		c.JSON(http.StatusOK, gin.H{"data": body})*/
}

// SignCSR is the handler of Certificate Authorities endpoint
// @Summary Certificate Authorities (CA) Signer for Certificate Sigining Request (CSR)
// @Description create a new certificate signing a Certificate Sigining Request (CSR)
// @Tags CA
// @Accept json
// @Produce json
// @Param file formData file true "Attached CSR file"
// @Param valid query int false "Number certificate valid days"
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/sign [post]
func SignCSR(c *gin.Context) {
	/*
		var body models.CertificateBody
		var valid int = 0

		csrUploaded, _ := c.FormFile("file")

		if c.Query("valid") != "" {
			valid, err := strconv.Atoi(c.Query("valid"))
			if err != nil {
				fmt.Println(valid)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

		}

		fileName := uuid.New().String()
		fileNameFull := filepath.Join(os.Getenv("CAPATH"), fileName)
		if err := c.SaveUploadedFile(csrUploaded, fileNameFull); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		csrFile, err := storage.LoadFile(fileName)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		csr, err := certificates.LoadCSR(csrFile)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ca, err := certificates.Load(c.Param("cn"))
		if err != nil {
			if err == certificates.ErrCALoadNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}

			return
		}
		certificate, err := ca.SignCSR(*csr, valid)
		if err != nil {
			os.Remove(fileNameFull)
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		}
		os.Remove(fileNameFull)

		body = getCertificateData(certificate)

		c.JSON(http.StatusOK, gin.H{"data": body})*/
}

// GetCertificates is the handler of Certificates by Authorities Certificates endpoint
// @Summary List all Certificates managed by a certain Certificate Authority
// @Description list all certificates managed by a certain Certificate Authority (cn)
// @Tags CA/{CN}/Certificates
// @Produce json
// @Success 200 {object} models.ResponseCA
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates [get]
func GetCertificates(c *gin.Context) {

	ca, err := certificates.Load(c.Param("cn"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	certs, err := ca.ListCertificates()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": certs})
}

// AddCertificates is the handler of Certificates by Authorities Certificates endpoint
// @Summary CA issue new certificate
// @Description the Certificate Authority issues a new Certificate
// @Tags CA/{CN}/Certificates
// @Produce json
// @Accept json
// @Param ca body models.Payload true "Add new Certificate Authority or Intermediate Certificate Authority"
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates [post]
func IssueCertificates(c *gin.Context) {

	ca, err := certificates.Load(c.Param("cn"))
	if err != nil {
		slog.Error("error loading ca")
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	if !strings.Contains(ca.Status(), "is ready") {
		c.JSON(http.StatusBadRequest, gin.H{"error": ca.Status()})
		return
	}

	var json models.Payload

	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	commonName, _, identity := payloadInit(json)

	certificate, err := ca.IssueCertificate(commonName, identity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body := getCertificateData(certificate)

	c.JSON(http.StatusOK, gin.H{"data": body})
}

// GetCertificatesCommonName is the handler of Certificates by Authorities Certificates endpoint
// @Summary Get information about a Certificate
// @Description get information about a certificate issued by a certain CA
// @Tags CA/{CN}/Certificates
// @Produce json
// @Success 200 {object} models.ResponseCertificates
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates/{certificate_cn} [get]
func GetCertificatesCommonName(c *gin.Context) {

	ca, err := certificates.Load(c.Param("cn"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	certificate, err := ca.LoadCertificate(c.Param("cert_cn"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	body := getCertificateData(certificate)

	c.JSON(http.StatusOK, gin.H{"data": body})

}

// RevokeCertificate is the handler of Certificates by Authorities Certificates endpoint
// @Summary CA revoke a existent certificate managed by CA
// @Description the Certificate Authority revokes a managed Certificate
// @Tags CA/{CN}/Certificates
// @Produce json
// @Accept json
// @Success 200 {object} models.CABody
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates/{certificate_cn} [delete]
func RevokeCertificate(c *gin.Context) {

	ca, err := certificates.Load(c.Param("cn"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	err = ca.RevokeCertificate(c.Param("cert_cn"))
	if err != nil {
		if err == certificates.ErrCertRevoked {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	body := getCAData(ca)

	c.JSON(http.StatusOK, gin.H{"data": body})

}

// RevokeCertificate is the handler of Certificates by Authorities Certificates endpoint
// @Summary CA revoke a existent certificate managed by CA
// @Description the Certificate Authority revokes a managed Certificate
// @Tags CA/{CN}/Certificates
// @Produce json
// @Accept json
// @Success 200 {object} models.CABody
// @Failure 404 {object} models.ResponseError
// @Failure 500 Internal Server Error
// @Router /api/v1/ca/{cn}/certificates/{certificate_cn} [delete]
func SignUpl(c *gin.Context) {

}

func SignUp(c *gin.Context) {

	code := c.Query("code")
	state := c.Query("state")
	if code == "" && state == "" {
		c.Redirect(http.StatusTemporaryRedirect, casdoorsdk.GetSignupUrl(false, "http://localhost:8080/api/v1/signup"))
	} else {
		token, err := Client.GetOAuthToken(code, state)
		if err != nil {
			slog.Error("GetOAuthToken() error", "error", err)
			c.JSON(http.StatusInternalServerError, map[string]any{"message": "GetOAuthToken() error", "error": http.StatusInternalServerError})
			return
		}

		c.Header("Content-Type", "application/json")
		/*claims, err := casdoorsdk.ParseJwtToken(token.AccessToken)
		if err != nil {
			slog.Error("ParseJwtToken() error", "error", err)
			c.JSON(http.StatusInternalServerError, map[string]any{"message": "ParseJwtToken() error", "error": http.StatusInternalServerError})
			return
		}
		//Persist user in the db
		/*u := models.CasdoorToCA(&claims.User)
		//log.Println(u)
		if err := db.CreateUser(u); err != nil {
			slog.Error("Error creating user", "error", err)
			c.JSON(http.StatusInternalServerError, map[string]any{"message": "db.CreateUser() error", "error": http.StatusInternalServerError})
			return
		}*/
		c.JSON(http.StatusOK, map[string]interface{}{
			"status": "ok",
			"data":   token,
		})
	}

}
func userinfo(c *gin.Context) (*casdoorsdk.User, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, errors.New("authHeader is empty")
	}
	//slog.Info(authHeader)
	token := strings.Split(authHeader, "Bearer ")
	if len(token) != 2 {
		return nil, errors.New("token is not valid Bearer token")
	}
	parts := strings.Split(token[1], ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}

	// Decode and print the header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %#v", err)
	}
	fmt.Println("Header:", string(headerData))

	// Decode and print the payload
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %#v", err)
	}
	var u casdoorsdk.User
	if err := json.Unmarshal(payloadData, &u); err != nil {
		return nil, errors.New("error unmarshaling json")
	}
	/*claims, err := casdoorsdk.ParseJwtToken(token[1])
	if err != nil {
		return nil, errors.New("ParseJwtToken() error" + err.Error())
	}*/
	uu, err := Client.GetUser(u.Name)
	if err != nil {
		return &u, err
	}
	if uu == nil {
		return nil, errors.New("user not found")
	}

	return uu, nil
}

func AccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := userinfo(c)
		if err != nil {
			slog.Error("Error creating user", "error", err)
			c.AbortWithStatusJSON(http.StatusForbidden, map[string]any{"message": "Wrong or absent Authentication key", "error": err.Error()})
			return
		}
		if c.Request.URL.Path == "/api/v1/users/me/get" {
			c.AbortWithStatusJSON(http.StatusOK, map[string]interface{}{
				"status": "ok",
				"data":   claims,
			})
			return
		}

		if c.Request.URL.Path == "/api/v1/users/me" && c.Request.Method == "DELETE" {
			success, err := Client.DeleteUser(claims)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]any{"message": "Error deleting user", "error": http.StatusBadRequest})
				return
			}
			if success {
				c.AbortWithStatusJSON(http.StatusOK, map[string]interface{}{
					"status": "ok",
					"data":   "Deletion successful",
				})
				return
			} else {
				c.AbortWithStatusJSON(http.StatusNotModified, map[string]interface{}{
					"status": "ok",
					"data":   "Deletion successful failed",
				})
				return
			}

		}
		c.Set("user", claims)
		c.Next()

	}
}
func SignIn(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if code == "" && state == "" {
		c.Redirect(http.StatusTemporaryRedirect, casdoorsdk.GetSigninUrl("http://localhost:8080/api/v1/signin"))
	} else {
		token, err := Client.GetOAuthToken(code, state)
		if err != nil {
			slog.Error("GetOAuthToken() error", "error", err)
			c.JSON(http.StatusInternalServerError, map[string]any{"message": "GetOAuthToken() error", "error": http.StatusInternalServerError})
			return
		}

		c.Header("Content-Type", "application/json")
		/*claims, err := casdoorsdk.ParseJwtToken(token.AccessToken)
		if err != nil {
			slog.Error("ParseJwtToken() error", "error", err)
			c.JSON(http.StatusInternalServerError, map[string]any{"message": "ParseJwtToken() error", "error": http.StatusInternalServerError})
			return
		}
		uu, err := db.GetUserByName(claims.User.Name)
		if err != nil {
			slog.Error("Error retrieving user", "error", err)
		}
		if uu == nil {
			//Persist user in the db
			u := models.CasdoorToCA(&claims.User)
			//log.Println(u)
			if err := db.CreateUser(u); err != nil {
				slog.Error("Error creating user", "error", err)
				c.JSON(http.StatusInternalServerError, map[string]any{"message": "db.CreateUser() error", "error": http.StatusInternalServerError})
				return
			}
		}*/
		token.SetAuthHeader(c.Request)
		c.JSON(http.StatusOK, map[string]interface{}{
			"status": "ok",
			"data":   token,
		})
	}
}

func GetUser(c *gin.Context) {
	name := c.Param("name")
	slog.Info(name)
	u, err := Client.GetUser(name)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, map[string]any{"message": "User not found", "error": err})
			return
		}
		slog.Error("Error creating user", "error", err)
		c.JSON(http.StatusForbidden, map[string]any{"message": "Error Getting user", "error": err})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"data":   u,
	})

}

func GetUserPermissions(c *gin.Context) {
	name := c.Param("name")
	slog.Info(name)
	u, err := Client.GetUser(name)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, map[string]any{"message": "User not found", "error": err})
			return
		}
		slog.Error("Error creating user", "error", err)
		c.JSON(http.StatusForbidden, map[string]any{"message": "Error Getting user", "error": err})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"data":   u.Permissions,
	})

}
func GetUserRoles(c *gin.Context) {
	name := c.Param("name")
	slog.Info(name)
	u, err := Client.GetUser(name)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, map[string]any{"message": "User not found", "error": err})
			return
		}
		slog.Error("Error creating user", "error", err)
		c.JSON(http.StatusForbidden, map[string]any{"message": "Error Getting user", "error": err})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"data":   u.Roles,
	})

}
func GetUserMe(c *gin.Context) {
	name := c.Param("name")
	slog.Info(name)
	u, err := Client.GetUser(name)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, map[string]any{"message": "User not found", "error": err})
			return
		}
		slog.Error("Error creating user", "error", err)
		c.JSON(http.StatusForbidden, map[string]any{"message": "Error Getting user", "error": err})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "ok",
		"data":   u,
	})

}

func UpdateUser(c *gin.Context) {
	user := c.MustGet("user").(*casdoorsdk.User)
	var json *casdoorsdk.User
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updateUser(user, json)
	success, err := Client.UpdateUser(user)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]any{"message": "Error updating user", "error": err.Error()})
		return
	}
	if success {
		c.AbortWithStatusJSON(http.StatusOK, map[string]interface{}{
			"status": "ok",
			"data":   "update successful",
		})
		return
	} else {
		c.AbortWithStatusJSON(http.StatusNotModified, map[string]interface{}{
			"status": "ok",
			"data":   "update failed",
		})
		return
	}

}

func DeleteUser(c *gin.Context) {
	name := c.Param("name")
	/*slog.Info(name)
	casUser, err := casdoorsdk.GetUserByUserId(name)
	/*if err != nil {
		c.AbortWithStatusJSON(200, map[string]any{"message": "Error Deleting user", "error": err})
		return
	}
	if casUser == nil {

		c.AbortWithStatusJSON(200, map[string]any{"message": "Error Deleting user", "error": "user not found"})
		return
	}*/
	//slog.Info("", "user",*casUser)
	//caUser := models.User{Name: name}
	if err := db.DeleteUser(name); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusBadRequest, map[string]any{"message": "User not found", "error": err})
			return
		}
		c.AbortWithStatusJSON(500, map[string]any{"message": "Error Deleting user", "error": err})
		return
	}
	c.JSON(200, map[string]any{"message": "Error Deleting user", "status": "ok"})
	/*if d, err := casdoorsdk.DeleteUser(casUser); err != nil {
		c.AbortWithError(500, err)
	} else {
		if d {
			c.JSON(200, map[string]any{"message": "User deleted successfully"})
		} else {
			c.JSON(200, map[string]any{"message": "User deleted unsuccessfully"})
		}

	}*/
}

func VerifyCertificate(c *gin.Context) {
	// Parse the form data
	err := c.Request.ParseMultipartForm(10 << 20) // 10 MB maximum
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse form: " + err.Error()})
		return
	}

	// Retrieve the certificate data
	certificateData := c.Request.FormValue("certificate")
	if certificateData == "" {
		// Try to get certificate data from file attachment
		file, _, err := c.Request.FormFile("certificate")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate data is missing"})
			return
		}
		defer file.Close()

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file: " + err.Error()})
			return
		}
		certificateData = string(fileBytes)
	}
	/*var byteSlice []byte
	for _, ch := range certificateData {
		if ch != '\n' {
			byteSlice = append(byteSlice, byte(ch))
		}
	}*/
	block, _ := pem.Decode([]byte(certificateData))
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode the certificate. Make sure the certficate is well formarted "})
		return
	}

	// Parse the certificate data
	cert, err := parseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate: " + err.Error()})
		return
	}

	// Return JSON response
	c.JSON(http.StatusOK, map[string]any{"valid":time.Now().Before(cert.NotAfter)})
}

func CheckCertificate(c *gin.Context) {
	// Parse the form data
	err := c.Request.ParseMultipartForm(10 << 20) // 10 MB maximum
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse form: " + err.Error()})
		return
	}

	// Retrieve the certificate data
	certificateData := c.Request.FormValue("certificate")
	if certificateData == "" {
		// Try to get certificate data from file attachment
		file, _, err := c.Request.FormFile("certificate")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate data is missing"})
			return
		}
		defer file.Close()

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file: " + err.Error()})
			return
		}
		certificateData = string(fileBytes)
	}
	/*var byteSlice []byte
	for _, ch := range certificateData {
		if ch != '\n' {
			byteSlice = append(byteSlice, byte(ch))
		}
	}*/
	block, _ := pem.Decode([]byte(certificateData))
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode the certificate. Make sure the certficate is well formarted "})
		return
	}

	// Parse the certificate data
	cert, err := parseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate: " + err.Error()})
		return
	}

	// Extract data from the certificate
	data := CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.Format("2006-01-02"),
		NotAfter:           cert.NotAfter.Format("2006-01-02"),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsage:           getKeyUsageStrings(cert.KeyUsage),
		Valid:              time.Now().Before(cert.NotAfter),
	}

	// Return JSON response
	c.JSON(http.StatusOK, data)
}

// parseCertificate parses a PEM encoded certificate
func parseCertificate(certData []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// getKeyUsageStrings returns a slice of key usage strings
func getKeyUsageStrings(keyUsage x509.KeyUsage) []string {
	usages := []string{}
	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	// Add other key usages as needed
	return usages
}

type CertificateInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	KeyUsage           []string `json:"key_usage"`
	Valid              bool
}

func GetCertificatesL(c *gin.Context) {
	certs, err := db.ListCertificates(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}

	// query params
	// Time
	t := c.Query("valid_before_time")
	if t != ""{
		t1, err:=time.Parse(time.DateOnly, t)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error":err.Error()})
			return
		}
		*certs = filter(*certs, func(c db.Certificate) bool{
			return c.ValidTill.After(t1)
		})
	}
	// Time number


	// type
	certType := c.Query("type")
	if certType != ""{
		switch strings.ToLower(certType){
		case "server", "client", "ssl":
			*certs = filter(*certs, func(c db.Certificate)bool{
				return c.Type == strings.ToLower(certType)
			})
		default:
			c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error":"Invalid certificate type"})
			return
		}
	}


	c.JSON(http.StatusOK, gin.H{"data": certs})
}

func pkixNameToOpenSSLSubject(name pkix.Name) string {
	var components []string = []string{""}

	for _, country := range name.Country {
		components = append(components, fmt.Sprintf("C=%s", country))
	}
	for _, province := range name.Province {
		components = append(components, fmt.Sprintf("ST=%s", province))
	}
	for _, locality := range name.Locality {
		components = append(components, fmt.Sprintf("L=%s", locality))
	}
	for _, org := range name.Organization {
		components = append(components, fmt.Sprintf("O=%s", org))
	}
	for _, orgUnit := range name.OrganizationalUnit {
		components = append(components, fmt.Sprintf("OU=%s", orgUnit))
	}
	//for _, commonName := range name.CommonName {
	components = append(components, fmt.Sprintf("CN=%s", name.CommonName))
	//}
	for _, email := range name.ExtraNames {
		if email.Type.Equal([]int{1}) {
			components = append(components, fmt.Sprintf("emailAddress=%s", email.Value))
		}
	}

	return strings.Join(components, "/")
}


func updateUser(userold, usernew interface{}) error {
	oldValue := reflect.ValueOf(userold).Elem()
	newValue := reflect.ValueOf(usernew).Elem()

	for i := 0; i < newValue.NumField(); i++ {
		field := newValue.Field(i)
		fieldName := newValue.Type().Field(i).Name

		if !isEmpty(field) {
			oldField := oldValue.FieldByName(fieldName)
			if oldField.IsValid() && oldField.CanSet() {
				oldField.Set(field)
			}
		}
	}

	return nil
}

func isEmpty(field reflect.Value) bool {
	// Check if the field is a zero value or nil
	switch field.Kind() {
	case reflect.String:
		return field.String() == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return field.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return field.IsNil()
	default:
		zero := reflect.Zero(field.Type())
		return reflect.DeepEqual(field.Interface(), zero.Interface())
	}
}


func CreateServerCertificateQ(c *gin.Context) {
	var (
		json models.Payload
		err error
	)
	ca_name := c.Query("ca_name")
	if ca_name == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest,gin.H{"error": "make sure you have set the ca_name query parameter"} )
		return
	}
	cert, err := db.GetCA(ca_name)
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error reading request body": err.Error()})
		return
	}

	endpointParts := strings.Split(c.Request.URL.Path, "/")
	if len(endpointParts) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endpoint"})
		return
	}
	certificateType := endpointParts[len(endpointParts)-1]
	crt, err := certificates.CreateServerCertificate(cert, json.Identity.Algorithm, json.Identity.Country, json.CommonName,
		json.Identity.EmailAddresses, json.Identity.Organization, json.Identity.Province, json.Identity.Locality, json.Identity.OrganizationalUnit, json.Identity.Valid, certificateType)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error creating vertificate": err.Error()})
		return
	}
	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       crt.Name,
		CRT:        string(crt.CRT),
		CSR:        string(crt.CSR),
		CRL:        string(crt.CRL),
		PrivateKey: string(crt.PrivateKey),
		PublicKey:  string(crt.PublicKey),

		//Certs: cert.Certs,
	}
	d.CreatedAt = time.Now()
	d.UpdatedAt = time.Now()
	d.Name = json.CommonName
	c.JSON(http.StatusOK, gin.H{"Data": d})

}

func filter[T any](ss []T, test func(T) bool) (ret []T) {
    for _, s := range ss {
        if test(s) {
            ret = append(ret, s)
        }
    }
    return
}


func GetServerCertificatesQ(c *gin.Context) {
	ca_name := c.Query("ca_name")
	if ca_name == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest,gin.H{"error": "make sure you have set the ca_name query parameter"} )
		return
	}
	cert, err := db.GetCert(ca_name, c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + " or the server certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		ValidTill  time.Time
		Valid      int
		Type       string
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       cert.Name,
		CRT:        string(cert.CRT),
		CSR:        string(cert.CSR),
		CRL:        string(cert.CRL),
		PrivateKey: string(cert.PrivateKey),
		PublicKey:  string(cert.PublicKey),
		ValidTill:  cert.ValidTill,
		Valid:      cert.Valid,
		Type:       cert.Type,
	}
	d.CreatedAt = cert.CreatedAt
	d.UpdatedAt = cert.UpdatedAt

	c.JSON(http.StatusOK, gin.H{"data": d})
}

func RenewServerCertificateQ(c *gin.Context) {
	var (
		json models.RenewPayload
		err error
	)
	ca_name := c.Query("ca_name")
	if ca_name == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest,gin.H{"error": "make sure you have set the ca_name query parameter"} )
		return
	}
	ca, err := db.GetCA(ca_name)
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	cert, err := db.GetCert(ca_name, c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + "or the server certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error reading request body": err.Error()})
		return
	}
	// Parse certificate

	block, _ := pem.Decode([]byte(cert.CRT))
	// Parse the certificate data
	certp, err := parseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate: " + err.Error()})
		return
	}
	crt, err := certificates.RenewServerCertificate(ca, &cert, cert.Name, pkixNameToOpenSSLSubject(certp.Subject), json.Valid, cert.Type, cert.PrivateKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error creating certificate": err.Error()})
		return
	}
	d := struct {
		gorm.Model
		Name       string
		CRT        string `json:"crt"`
		CSR        string `json:"csr"`
		CRL        string `json:"crl"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		//Certs      []db.Certificate `gorm:"many2many:certs;association_jointable_key:cert_id"`
	}{
		Name:       crt.Name,
		CRT:        string(crt.CRT),
		CSR:        string(crt.CSR),
		CRL:        string(crt.CRL),
		PrivateKey: string(crt.PrivateKey),
		PublicKey:  string(crt.PublicKey),

		//Certs: cert.Certs,
	}
	d.CreatedAt = cert.CreatedAt
	d.UpdatedAt = cert.UpdatedAt
	c.JSON(http.StatusOK, gin.H{"Data": d})

}

func RevokeServerCertificateQ(c *gin.Context) {
	_, err := db.GetCA(c.Param("common-name"))
	if err != nil {
		if err == certificates.ErrCALoadNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	cert, err := db.GetCert(c.Param("common-name"), c.Param("cn"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": certificates.ErrCALoadNotFound.Error() + " or the  certificate is not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		return
	}
	if err := db.DeleteCert(cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	

	c.JSON(http.StatusOK, gin.H{"Data": "Revocation successful"})

}