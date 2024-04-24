package models

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"gorm.io/gorm"
)

// User
type User struct {
	gorm.Model
	Owner             string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name              string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime       string `xorm:"varchar(100) index" json:"createdTime"`
	UpdatedTime       string `xorm:"varchar(100)" json:"updatedTime"`
	Idd               string `xorm:"varchar(100) index" json:"idd"`
	Type              string `xorm:"varchar(100)" json:"type"`
	Password          string `xorm:"varchar(100)" json:"password"`
	PasswordSalt      string `xorm:"varchar(100)" json:"passwordSalt"`
	PasswordType      string `xorm:"varchar(100)" json:"passwordType"`
	DisplayName       string `xorm:"varchar(100)" json:"displayName"`
	FirstName         string `xorm:"varchar(100)" json:"firstName"`
	LastName          string `xorm:"varchar(100)" json:"lastName"`
	Avatar            string `xorm:"varchar(500)" json:"avatar"`
	AvatarType        string `xorm:"varchar(100)" json:"avatarType"`
	PermanentAvatar   string `xorm:"varchar(500)" json:"permanentAvatar"`
	Email             string `xorm:"varchar(100) index" json:"email"`
	EmailVerified     bool   `json:"emailVerified"`
	Phone             string `xorm:"varchar(20) index" json:"phone"`
	CountryCode       string `xorm:"varchar(6)" json:"countryCode"`
	Region            string `xorm:"varchar(100)" json:"region"`
	Location          string `xorm:"varchar(100)" json:"location"`
	Affiliation       string `xorm:"varchar(100)" json:"affiliation"`
	Title             string `xorm:"varchar(100)" json:"title"`
	IdCardType        string `xorm:"varchar(100)" json:"idCardType"`
	IdCard            string `xorm:"varchar(100) index" json:"idCard"`
	Homepage          string `xorm:"varchar(100)" json:"homepage"`
	Bio               string `xorm:"varchar(100)" json:"bio"`
	Tag               string `xorm:"varchar(100)" json:"tag"`
	Language          string `xorm:"varchar(100)" json:"language"`
	Gender            string `xorm:"varchar(100)" json:"gender"`
	Birthday          string `xorm:"varchar(100)" json:"birthday"`
	Education         string `xorm:"varchar(100)" json:"education"`
	Score             int    `json:"score"`
	Karma             int    `json:"karma"`
	Ranking           int    `json:"ranking"`
	IsDefaultAvatar   bool   `json:"isDefaultAvatar"`
	IsOnline          bool   `json:"isOnline"`
	IsAdmin           bool   `json:"isAdmin"`
	IsForbidden       bool   `json:"isForbidden"`
	IsDeleted         bool   `json:"isDeleted"`
	SignupApplication string `xorm:"varchar(100)" json:"signupApplication"`
	Hash              string `xorm:"varchar(100)" json:"hash"`
	PreHash           string `xorm:"varchar(100)" json:"preHash"`
	AccessKey         string `xorm:"varchar(100)" json:"accessKey"`
	AccessSecret      string `xorm:"varchar(100)" json:"accessSecret"`
	CreatedIp         string `xorm:"varchar(100)" json:"createdIp"`
	LastSigninTime    string `xorm:"varchar(100)" json:"lastSigninTime"`
	LastSigninIp      string `xorm:"varchar(100)" json:"lastSigninIp"`
	GitHub            string `xorm:"github varchar(100)" json:"github"`
	Google            string `xorm:"varchar(100)" json:"google"`
	QQ                string `xorm:"qq varchar(100)" json:"qq"`
	WeChat            string `xorm:"wechat varchar(100)" json:"wechat"`
	Facebook          string `xorm:"facebook varchar(100)" json:"facebook"`
	DingTalk          string `xorm:"dingtalk varchar(100)" json:"dingtalk"`
	Weibo             string `xorm:"weibo varchar(100)" json:"weibo"`
	Gitee             string `xorm:"gitee varchar(100)" json:"gitee"`
	LinkedIn          string `xorm:"linkedin varchar(100)" json:"linkedin"`
	Wecom             string `xorm:"wecom varchar(100)" json:"wecom"`
	Lark              string `xorm:"lark varchar(100)" json:"lark"`
	Gitlab            string `xorm:"gitlab varchar(100)" json:"gitlab"`
	Adfs              string `xorm:"adfs varchar(100)" json:"adfs"`
	Baidu             string `xorm:"baidu varchar(100)" json:"baidu"`
	Alipay            string `xorm:"alipay varchar(100)" json:"alipay"`
	Casdoor           string `xorm:"casdoor varchar(100)" json:"casdoor"`
	Infoflow          string `xorm:"infoflow varchar(100)" json:"infoflow"`
	Apple             string `xorm:"apple varchar(100)" json:"apple"`
	AzureAD           string `xorm:"azuread varchar(100)" json:"azuread"`
	Slack             string `xorm:"slack varchar(100)" json:"slack"`
	Steam             string `xorm:"steam varchar(100)" json:"steam"`
	Bilibili          string `xorm:"bilibili varchar(100)" json:"bilibili"`
	Okta              string `xorm:"okta varchar(100)" json:"okta"`
	Douyin            string `xorm:"douyin varchar(100)" json:"douyin"`
	Line              string `xorm:"line varchar(100)" json:"line"`
	Amazon            string `xorm:"amazon varchar(100)" json:"amazon"`
	Auth0             string `xorm:"auth0 varchar(100)" json:"auth0"`
	BattleNet         string `xorm:"battlenet varchar(100)" json:"battlenet"`
	Bitbucket         string `xorm:"bitbucket varchar(100)" json:"bitbucket"`
	Box               string `xorm:"box varchar(100)" json:"box"`
	CloudFoundry      string `xorm:"cloudfoundry varchar(100)" json:"cloudfoundry"`
	Dailymotion       string `xorm:"dailymotion varchar(100)" json:"dailymotion"`
	Deezer            string `xorm:"deezer varchar(100)" json:"deezer"`
	DigitalOcean      string `xorm:"digitalocean varchar(100)" json:"digitalocean"`
	Discord           string `xorm:"discord varchar(100)" json:"discord"`
	Dropbox           string `xorm:"dropbox varchar(100)" json:"dropbox"`
	EveOnline         string `xorm:"eveonline varchar(100)" json:"eveonline"`
	Fitbit            string `xorm:"fitbit varchar(100)" json:"fitbit"`
	Gitea             string `xorm:"gitea varchar(100)" json:"gitea"`
	Heroku            string `xorm:"heroku varchar(100)" json:"heroku"`
	InfluxCloud       string `xorm:"influxcloud varchar(100)" json:"influxcloud"`
	Instagram         string `xorm:"instagram varchar(100)" json:"instagram"`
	Intercom          string `xorm:"intercom varchar(100)" json:"intercom"`
	Kakao             string `xorm:"kakao varchar(100)" json:"kakao"`
	Lastfm            string `xorm:"lastfm varchar(100)" json:"lastfm"`
	Mailru            string `xorm:"mailru varchar(100)" json:"mailru"`
	Meetup            string `xorm:"meetup varchar(100)" json:"meetup"`
	MicrosoftOnline   string `xorm:"microsoftonline varchar(100)" json:"microsoftonline"`
	Naver             string `xorm:"naver varchar(100)" json:"naver"`
	Nextcloud         string `xorm:"nextcloud varchar(100)" json:"nextcloud"`
	OneDrive          string `xorm:"onedrive varchar(100)" json:"onedrive"`
	Oura              string `xorm:"oura varchar(100)" json:"oura"`
	Patreon           string `xorm:"patreon varchar(100)" json:"patreon"`
	Paypal            string `xorm:"paypal varchar(100)" json:"paypal"`
	SalesForce        string `xorm:"salesforce varchar(100)" json:"salesforce"`
	Shopify           string `xorm:"shopify varchar(100)" json:"shopify"`
	Soundcloud        string `xorm:"soundcloud varchar(100)" json:"soundcloud"`
	Spotify           string `xorm:"spotify varchar(100)" json:"spotify"`
	Strava            string `xorm:"strava varchar(100)" json:"strava"`
	Stripe            string `xorm:"stripe varchar(100)" json:"stripe"`
	TikTok            string `xorm:"tiktok varchar(100)" json:"tiktok"`
	Tumblr            string `xorm:"tumblr varchar(100)" json:"tumblr"`
	Twitch            string `xorm:"twitch varchar(100)" json:"twitch"`
	Twitter           string `xorm:"twitter varchar(100)" json:"twitter"`
	Typetalk          string `xorm:"typetalk varchar(100)" json:"typetalk"`
	Uber              string `xorm:"uber varchar(100)" json:"uber"`
	VK                string `xorm:"vk varchar(100)" json:"vk"`
	Wepay             string `xorm:"wepay varchar(100)" json:"wepay"`
	Xero              string `xorm:"xero varchar(100)" json:"xero"`
	Yahoo             string `xorm:"yahoo varchar(100)" json:"yahoo"`
	Yammer            string `xorm:"yammer varchar(100)" json:"yammer"`
	Yandex            string `xorm:"yandex varchar(100)" json:"yandex"`
	Zoom              string `xorm:"zoom varchar(100)" json:"zoom"`
	MetaMask          string `xorm:"metamask varchar(100)" json:"metamask"`
	Web3Onboard       string `xorm:"web3onboard varchar(100)" json:"web3onboard"`
	Custom            string `xorm:"custom varchar(100)" json:"custom"`
}

func CasdoorToCA(oldUser *casdoorsdk.User) (newUser User) {
	newUser.Idd = oldUser.Id
	newUser.Owner = oldUser.Owner
	newUser.Name = oldUser.Name
	newUser.Type = oldUser.Type
	newUser.Password = oldUser.Password
	newUser.PasswordSalt = oldUser.PasswordSalt
	newUser.PasswordType = oldUser.PasswordType
	newUser.DisplayName = oldUser.DisplayName
	newUser.FirstName = oldUser.FirstName
	newUser.LastName = oldUser.LastName
	newUser.Avatar = oldUser.Avatar
	newUser.AvatarType = oldUser.AvatarType
	newUser.PermanentAvatar = oldUser.PermanentAvatar
	newUser.Email = oldUser.Email
	newUser.EmailVerified = oldUser.EmailVerified
	newUser.Phone = oldUser.Phone
	newUser.CountryCode = oldUser.CountryCode
	newUser.Region = oldUser.Region
	newUser.Location = oldUser.Location
	//newUser.Address = oldUser.Address
	newUser.Affiliation = oldUser.Affiliation
	newUser.Title = oldUser.Title
	newUser.IdCardType = oldUser.IdCardType
	newUser.IdCard = oldUser.IdCard
	newUser.Homepage = oldUser.Homepage
	newUser.Bio = oldUser.Bio
	newUser.Tag = oldUser.Tag
	newUser.Language = oldUser.Language
	newUser.Gender = oldUser.Gender
	newUser.Birthday = oldUser.Birthday
	newUser.Education = oldUser.Education
	newUser.Score = oldUser.Score
	newUser.Karma = oldUser.Karma
	newUser.Ranking = oldUser.Ranking
	newUser.IsDefaultAvatar = oldUser.IsDefaultAvatar
	newUser.IsOnline = oldUser.IsOnline
	newUser.IsAdmin = oldUser.IsAdmin
	newUser.IsForbidden = oldUser.IsForbidden
	newUser.IsDeleted = oldUser.IsDeleted
	newUser.SignupApplication = oldUser.SignupApplication
	newUser.Hash = oldUser.Hash
	newUser.PreHash = oldUser.PreHash
	newUser.AccessKey = oldUser.AccessKey
	newUser.AccessSecret = oldUser.AccessSecret
	newUser.CreatedIp = oldUser.CreatedIp
	newUser.LastSigninTime = oldUser.LastSigninTime
	newUser.LastSigninIp = oldUser.LastSigninIp
	newUser.GitHub = oldUser.GitHub
	newUser.Google = oldUser.Google
	newUser.QQ = oldUser.QQ
	newUser.WeChat = oldUser.WeChat
	newUser.Facebook = oldUser.Facebook
	newUser.DingTalk = oldUser.DingTalk
	newUser.Weibo = oldUser.Weibo
	newUser.Gitee = oldUser.Gitee
	newUser.LinkedIn = oldUser.LinkedIn
	newUser.Wecom = oldUser.Wecom
	newUser.Lark = oldUser.Lark
	newUser.Gitlab = oldUser.Gitlab
	newUser.Adfs = oldUser.Adfs
	newUser.Baidu = oldUser.Baidu
	newUser.Alipay = oldUser.Alipay
	newUser.Casdoor = oldUser.Casdoor
	newUser.Infoflow = oldUser.Infoflow
	newUser.Apple = oldUser.Apple
	newUser.AzureAD = oldUser.AzureAD
	newUser.Slack = oldUser.Slack
	newUser.Steam = oldUser.Steam
	newUser.Bilibili = oldUser.Bilibili
	newUser.Okta = oldUser.Okta
	newUser.Douyin = oldUser.Douyin
	newUser.Line = oldUser.Line
	newUser.Amazon = oldUser.Amazon
	newUser.Auth0 = oldUser.Auth0
	newUser.BattleNet = oldUser.BattleNet
	newUser.Bitbucket = oldUser.Bitbucket
	newUser.Box = oldUser.Box
	newUser.CloudFoundry = oldUser.CloudFoundry
	newUser.Dailymotion = oldUser.Dailymotion
	newUser.Deezer = oldUser.Deezer
	newUser.DigitalOcean = oldUser.DigitalOcean
	newUser.Discord = oldUser.Discord
	newUser.Dropbox = oldUser.Dropbox
	newUser.EveOnline = oldUser.EveOnline
	newUser.Fitbit = oldUser.Fitbit
	newUser.Gitea = oldUser.Gitea
	newUser.Heroku = oldUser.Heroku
	newUser.InfluxCloud = oldUser.InfluxCloud
	newUser.Instagram = oldUser.Instagram
	newUser.Intercom = oldUser.Intercom
	newUser.Kakao = oldUser.Kakao
	newUser.Lastfm = oldUser.Lastfm
	newUser.Mailru = oldUser.Mailru
	newUser.Meetup = oldUser.Meetup
	newUser.MicrosoftOnline = oldUser.MicrosoftOnline
	newUser.Naver = oldUser.Naver
	newUser.Nextcloud = oldUser.Nextcloud
	newUser.OneDrive = oldUser.OneDrive
	newUser.Oura = oldUser.Oura
	newUser.Patreon = oldUser.Patreon
	newUser.Paypal = oldUser.Paypal
	newUser.SalesForce = oldUser.SalesForce
	newUser.Shopify = oldUser.Shopify
	newUser.Soundcloud = oldUser.Soundcloud
	newUser.Spotify = oldUser.Spotify
	newUser.Strava = oldUser.Strava
	newUser.Stripe = oldUser.Stripe
	newUser.TikTok = oldUser.TikTok
	newUser.Tumblr = oldUser.Tumblr
	newUser.Twitch = oldUser.Twitch
	newUser.Twitter = oldUser.Twitter
	newUser.Typetalk = oldUser.Typetalk
	newUser.Uber = oldUser.Uber
	newUser.VK = oldUser.VK
	newUser.Wepay = oldUser.Wepay
	newUser.Xero = oldUser.Xero
	newUser.Yahoo = oldUser.Yahoo
	newUser.Yammer = oldUser.Yammer
	newUser.Yandex = oldUser.Yandex
	newUser.Zoom = oldUser.Zoom
	newUser.MetaMask = oldUser.MetaMask
	newUser.Web3Onboard = oldUser.Web3Onboard
	newUser.Custom = oldUser.Custom
	/*newUser.PreferredMfaType = oldUser.PreferredMfaType
	newUser.RecoveryCodes = oldUser.RecoveryCodes
	newUser.TotpSecret = oldUser.TotpSecret
	newUser.MfaPhoneEnabled = oldUser.MfaPhoneEnabled
	newUser.MfaEmailEnabled = oldUser.MfaEmailEnabled
	newUser.Ldap = oldUser.Ldap
	newUser.Properties = oldUser.Properties
	newUser.Roles = oldUser.Roles
	newUser.Permissions = oldUser.Permissions
	newUser.Groups = oldUser.Groups
	newUser.LastSigninWrongTime = oldUser.LastSigninWrongTime
	newUser.SigninWrongTimes = oldUser.SigninWrongTimes
	newUser.ManagedAccounts = oldUser.ManagedAccounts*/
	return
}

// CA represents the basic CA data
type CA struct {
	CommonName string // Certificate Authority Common Name
	Data       CAData // Certificate Authority Data (CAData{})
}

// Certificate represents a Certificate data
type Certificate struct {
	CommonName    string                  // Certificate Common Name
	Certificate   string                  `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`         // Certificate certificate string
	CSR           string                  `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"` // Certificate Signing Request string
	PrivateKey    string                  `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`         // Certificate Private Key string
	PublicKey     string                  `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`            // Certificate Public Key string
	CACertificate string                  `json:"ca_certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`      // CA Certificate as string
	Privatekey    crypto.PrivateKey       // Certificate Private Key object rsa.PrivateKey
	Publickey     crypto.PublicKey        // Certificate Private Key object rsa.PublicKey
	Csr           x509.CertificateRequest // Certificate Sigining Request object x509.CertificateRequest
	Ccertificate  *x509.Certificate       // Certificate certificate *x509.Certificate
	CaCertificate *x509.Certificate       // CA Certificate *x509.Certificate
}

// A Identity represents the Certificate Authority Identity Information
type Identity struct {
	Organization       string   `json:"organization" example:"Company"`                         // Organization name
	OrganizationalUnit string   `json:"organization_unit" example:"Security Management"`        // Organizational Unit name
	Country            string   `json:"country" example:"NL"`                                   // Country (two letters)
	Locality           string   `json:"locality" example:"Noord-Brabant"`                       // Locality name
	Province           string   `json:"province" example:"Veldhoven"`                           // Province name
	EmailAddresses     string   `json:"email" example:"sec@company.com"`                        // Email Address
	DNSNames           []string `json:"dns_names" example:"ca.example.com,root-ca.example.com"` // DNS Names list
	IPAddresses        []net.IP `json:"ip_addresses,omitempty" example:"127.0.0.1,192.168.0.1"` // IP Address list
	Intermediate       bool     `json:"intermediate" example:"false"`                           // Intermendiate Certificate Authority (default is false)
	KeyBitSize         int      `json:"key_size" example:"2048"`                                // Key Bit Size (defaul: 2048)
	Valid              int      `json:"valid" example:"365"`                                    // Minimum 1 day, maximum 825 days -- Default: 397
	Algorithm          string   `json:"algorithm"`
	CertType           string   `json:"cert_type"`
}

// A CAData represents all the Certificate Authority Data as
// RSA Keys, CRS, CRL, Certificates etc
type CAData struct {
	CRL            string `json:"crl" example:"-----BEGIN X509 CRL-----...-----END X509 CRL-----\n"`                       // Revocation List string
	Certificate    string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`         // Certificate string
	CSR            string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"` // Certificate Signing Request string
	PrivateKey     string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`         // Private Key string
	PublicKey      string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`            // Public Key string
	Privatekey     crypto.PrivateKey
	Ccertificate   *x509.Certificate
	Publickey      crypto.PublicKey
	Csr            *x509.CertificateRequest
	Crl            *x509.RevocationList
	IsIntermediate bool
}

type ResponseError struct {
	Error string `json:"error" example:"error message"`
}

type ResponseCA struct {
	Data CABody `json:"data"`
}

type ResponseCertificates struct {
	Data CertificateBody `json:"data"`
}

type ResponseList struct {
	Data []string `json:"data" example:"cn1,cn2,cn3"`
}
type AlgorithmPayload struct {
	Algorithm string `json:"algorithm" default:"RSA"`
	Size      int    `json:"size"`
}
type Payload struct {
	CommonName       string   `json:"common_name" example:"root-ca" binding:"required"`
	ParentCommonName string   `json:"parent_common_name" example:"root-ca"`
	Identity         Identity `json:"identity" binding:"required"`
}

type RenewPayload struct{
	Valid int `json:"valid" binding:"required"`
}
type CABody struct {
	CommonName                string   `json:"common_name" example:"root-ca"`
	Intermediate              bool     `json:"intermediate"`
	Status                    string   `json:"status" example:"Certificate Authority is ready."`
	SerialNumber              string   `json:"serial_number" example:"271064285308788403797280326571490069716"`
	IssueDate                 string   `json:"issue_date" example:"2021-01-06 10:31:43 +0000 UTC"`
	ExpireDate                string   `json:"expire_date" example:"2022-01-06 10:31:43 +0000 UTC"`
	DNSNames                  []string `json:"dns_names" example:"ca.example.ca,root-ca.example.com"`
	CSR                       bool     `json:"csr" example:"false"`
	Certificates              []string `json:"certificates" example:"intranet.example.com,w3.example.com"`
	CertificateRevocationList []string `json:"revoked_certificates" example:"38188836191244388427366318074605547405,338255903472757769326153358304310617728"`
	Files                     CAData   `json:"files"`
}

type CertificateBody struct {
	CommonName   string      `json:"common_name" example:"intranet.go-root"`
	SerialNumber string      `json:"serial_number" example:"338255903472757769326153358304310617728"`
	IssueDate    string      `json:"issue_date" example:"2021-01-06 10:31:43 +0000 UTC"`
	ExpireDate   string      `json:"expire_date" example:"2022-01-06 10:31:43 +0000 UTC"`
	DNSNames     []string    `json:"dns_names" example:"w3.intranet.go-root.ca,intranet.go-root.ca"`
	Files        Certificate `json:"files"`
}

type PrivateKey struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	Data []byte
}

type PublicKey struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	Data []byte
}

type CSR struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	Data []byte
}

type CertificateData struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	Data []byte
}

type CRL struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	Data []byte
}

//
// Certificates
//

// GetCertificate returns the certificate as string.
func (c *Certificate) GetCertificate() string {
	return c.Certificate
}

// GoCert returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCert() *x509.Certificate {
	return c.Ccertificate
}

// GetCSR returns the certificate as string.
func (c *Certificate) GetCSR() string {
	return c.CSR
}

// GoCSR returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCSR() x509.CertificateRequest {
	return c.Csr
}

// GetCACertificate returns the certificate as string.
func (c *Certificate) GetCACertificate() string {
	return c.CACertificate
}

// GoCACertificate returns the certificate *x509.Certificate.
func (c *Certificate) GoCACertificate() x509.Certificate {
	return *c.CaCertificate
}

func (c *Certificate) ChangeValidity(timestamp int64) error {
	if time.Now().Before(time.Unix(timestamp, 0).Local()) {
		return errors.New("validity can not be in the past")
	}
	return nil
}

func (c *Certificate) Valid() bool {
	return false
}
