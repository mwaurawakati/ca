package main

import (
	"ca/logs"
	"ca/rest-api/controllers"
	"flag"
	"fmt"
	"log/slog"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-gonic/gin"
)

// @title GoCA API
// @description GoCA Certificate Authority Management API.
// @schemes http https
// @securityDefinitions.basic BasicAuth

// @contact.name GoCA API Issues Report
// @contact.url http://github.com/kairoaraujo/goca/issues

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
func main() {
	logLevel := flag.String("logLevel", "DEBUG", "LogLevel")
	addLogSource := flag.Bool("addSource", true, "Log SOurce")

	var port int

	flag.IntVar(&port, "p", 8080, "Port to listen, default is 80")
	flag.Parse()
	logConfig := []byte(fmt.Sprintf(`{"elastic_enabled" : false,"level" : "%s","elastic_level" : "trace","add_source" : %t,"elastic_configuration" :{"username" :"", "password" :"","api_key" :"","addresses" :[],"cloud_id" :""}}`, *logLevel, *addLogSource))
	logs.InitLogger(logConfig)
	logs.Notice("Just Testing")
	slog.Info(string(logConfig))
	err := LoadConfig("app.yaml")
	if err != nil {
		panic(err)
	}

	initAuthConfig()
	slog.Info("Initialized casdoor config")
	router := gin.Default()
	// Set a lower memory limit for multipart forms (default is 32 MiB)
	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.Use(gin.Logger())

	api := router.Group("/api")
	v1 := api.Group("/v1")
	certificates := api.Group("/certificates")

	//Create certificates
	certificates.POST("/generate/ca", controllers.CreateCACertificate)
	certificates.POST("/generate/server", controllers.CreateServerCertificateQ)
	certificates.POST("/generate/client", controllers.CreateServerCertificateQ)
	certificates.POST("/generate/ssl", controllers.CreateServerCertificateQ)

	// GET certificates (ca and its certficates)
	certificates.GET("/ca/:common-name", controllers.GetCACertificate)
	certificates.GET("/ca/:common-name/certificates", controllers.GetCertificatesL)

	// GET client server and ssl and client.
	certificates.GET("/:cn", controllers.GetServerCertificatesQ)

	// Renew client, server and ssl certificates
	certificates.PATCH("/:cn", controllers.RenewServerCertificateQ)

	// Revoke 
	certificates.DELETE("/:cn", controllers.RevokeServerCertificateQ)

	// Check
	certificates.POST("/verify", controllers.VerifyCertificate)
	certificates.POST("/check", controllers.CheckCertificate)
	//certificates.POST("/chain-verification", controllers.VerifyCertificate)

	certificates.POST("/ca/:common-name/client", controllers.CreateServerCertificate)
	certificates.POST("/ca/:common-name/server", controllers.CreateServerCertificate)
	certificates.POST("/ca/:common-name/ssl", controllers.CreateServerCertificate)
	certificates.POST("/ca/:common-name", controllers.CreateServerCertificate)
	certificates.GET("/ca/:common-name/certificates/:cn", controllers.GetServerCertificates)
	certificates.PATCH("/ca/:common-name/certificates/:cn", controllers.RenewServerCertificate)
	certificates.DELETE("/ca/:common-name/certificates/:cn", controllers.RevokeServerCertificate)
	certificates.POST("/validity-check", controllers.VerifyCertificate)
	certificates.POST("/chain-verification", controllers.VerifyCertificate)
	// Routes
	v1.Any("/signup", controllers.SignUp)
	v1.Any("/signin", controllers.SignIn)
	users := v1.Group("/users")
	users.Use(controllers.AccessMiddleware())
	users.GET("/:name", controllers.GetUser)
	users.GET("/:name/permissions", controllers.GetUserPermissions)
	users.GET("/:name/roles", controllers.GetUserRoles)
	users.GET("/me/get")
	users.DELETE("/me")
	users.PATCH("/me", controllers.UpdateUser)
	users.PUT("/:name", controllers.UpdateUser)
	users.DELETE("/:name", controllers.DeleteUser)
	//ca := v1.Group("/ca")
	v1.GET("/ca", controllers.GetCA)
	v1.POST("/ca", controllers.AddCA)
	v1.GET("/ca/:cn", controllers.GetCACommonName)
	v1.POST("/ca/:cn/sign", controllers.SignCSR)
	v1.POST("/ca/:cn/upload", controllers.UploadCertificateICA)
	v1.GET("/ca/:cn/certificates", controllers.GetCertificates)
	v1.POST("/ca/:cn/certificates", controllers.IssueCertificates)
	v1.DELETE("/ca/:cn/certificates/:cert_cn", controllers.RevokeCertificate)
	v1.GET("/ca/:cn/certificates/:cert_cn", controllers.GetCertificatesCommonName)

	// Run the server
	err = router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
}

func initAuthConfig() {
	controllers.Client = casdoorsdk.NewClient("http://casdoor:8000", GlobalConfig.Server.ClientID,
		GlobalConfig.Server.ClientSecret,
		GlobalConfig.Certificate,
		GlobalConfig.Server.Organization,
		GlobalConfig.Server.Application)
	casdoorsdk.InitConfig(
		GlobalConfig.Server.Endpoint,
		GlobalConfig.Server.ClientID,
		GlobalConfig.Server.ClientSecret,
		GlobalConfig.Certificate,
		GlobalConfig.Server.Organization,
		GlobalConfig.Server.Application,
	)
}

