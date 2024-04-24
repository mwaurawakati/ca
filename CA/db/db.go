package db

import (
	"ca/models"
	"log/slog"
	"os"

	"embed"

	"gopkg.in/yaml.v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

//go:embed db.yaml
var f embed.FS
type Config struct {
	DB       string `yaml:"db"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

var GlobalConfig *Config

func LoadConfig(configPath string) error {
	data, err := f.ReadFile("db.yaml")
	if err != nil {
		return err
	}
	
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return err
	}

	GlobalConfig = &cfg

	return nil
}

func init() {
	if err := LoadConfig("db.yaml"); err != nil {
		slog.Error("Error loading db config", "error", err, "config", GlobalConfig)
	}
	//os.Getenv("My")
	dsn := "root:123456@tcp(mysql_ca:3306)/ca?charset=utf8mb4&parseTime=True&loc=Local"
	DB, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		slog.Error("failed to connect database", "error", err)
		slog.Warn("Exiting Application")
		os.Exit(1)
	}
	db = DB
	// Migrate the schema
	db.AutoMigrate(&models.User{}, &models.PrivateKey{}, &models.PublicKey{}, &models.CSR{}, &models.CertificateData{}, &models.CRL{}, CA{}, Certificate{})
}

func CreateUser(u models.User) error {
	return db.Create(&u).Error
}

func GetUserByName(name string) (*models.User, error) {
	var user models.User
	err := db.First(&user, "name = ?", name).Error
	return &user, err
}

func GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := db.First(&user, "email = ?", email).Error
	return &user, err
}

func GetUserByPhone(phone string) (*models.User, error) {
	var user models.User
	err := db.First(&user, "phone = ?", phone).Error
	return &user, err
}

func GetUserByID(id string) (*models.User, error) {
	var user models.User
	err := db.First(&user, "id = ?", id).Error
	return &user, err
}

func UpdateUser(u *models.User) error {
	var user models.User
	return db.Model(&user).Updates(*u).Error
}

func DeleteUser(name string) error {
	result := db.Where("name = ?", name).Delete(&models.User{})

    // Check for errors
    if err := result.Error; err != nil {
        return err
    }
    // Check for rows affected
    if rowsAffected := result.RowsAffected; rowsAffected == 0 {
        return gorm.ErrRecordNotFound // No user found with the given name
    }
    return nil // User deleted successfully
}
