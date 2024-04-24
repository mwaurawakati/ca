package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"

	"ca/db"
)


type KeysData struct {
	Key       crypto.PrivateKey
	PublicKey crypto.PublicKey
}

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
// The files are stored in the DB
func CreateRSAKeys(CACommonName, commonName string, creationType db.CreationType, bitSize int) (KeysData, error) {
	reader := rand.Reader
	if bitSize == 0 {
		bitSize = 2048
	}

	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return KeysData{}, err
	}

	publicKey := key.Public()
	slog.Debug("created private and public keys", "private", key, "pub", publicKey)
	fileData := db.File{
		CA:             CACommonName,
		CommonName:     commonName,
		FileType:       db.FileTypeKey,
		PrivateKeyData: key,
		PublicKeyData:  publicKey,
		CreationType:   creationType,
	}

	err = db.SaveFile(fileData)
	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: publicKey,
	}

	return keys, nil
}

// LoadPrivateKey loads a RSA Private Key from a read file.
//
// Using ioutil.ReadFile() satisfyies it.
func LoadPrivateKey(keyString []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(string(keyString)))
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return v, nil
	case *ecdsa.PrivateKey:
		return v, nil
	case ed25519.PrivateKey:
		return v, nil
	default:
		return nil, errors.New("algorithm not supported")
	}
}

// LoadPublicKey loads a CRypto Public Key from a read file.
func LoadPublicKey(keyString []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(string(keyString)))
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch v := k.(type) {
	case *rsa.PublicKey:
		return v, nil
	case *ecdsa.PublicKey:
		return v, nil
	case ed25519.PublicKey:
		return v, nil
	default:
		return nil, errors.New("algroithm not supported")
	}
}

func CreateECDSAKeys(CACommonName, commonName string, creationType db.CreationType, bitSize int) (KeysData, error) {
	reader := rand.Reader
	var curve elliptic.Curve

	switch bitSize {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521, 0:
		curve = elliptic.P521()
	default:
		return KeysData{}, errors.New("unsupported bit size for ECDSA")
	}

	// Generate ECDSA private key
	key, err := ecdsa.GenerateKey(curve, reader) 
	slog.Debug("created ecdsa private and public keys", "private", key, "pub", key.Public())
	if err != nil {
		return KeysData{}, err
	}

	fileData := db.File{
		CA:             CACommonName,
		CommonName:     commonName,
		FileType:       db.FileTypeKey,
		PrivateKeyData: key,
		PublicKeyData:  key.Public(),
		CreationType:   creationType,
	}

	err = db.SaveFile(fileData)
	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: &key.PublicKey,
	}

	return keys, nil
}

// CreateKeys creates Ed25519 private and public keys and returns a KeysData struct containing the keys.
func CreateED25519Keys(CACommonName, commonName string, creationType db.CreationType, bitSize int) (KeysData, error) {
	// Check if the bitSize is valid for Ed25519 keys
	if bitSize != 0 && bitSize != ed25519.PrivateKeySize {
		return KeysData{}, errors.New("bitSize must be 0 or equal to ed25519.PrivateKeySize (32 bytes)")
	}

	// Generate Ed25519 private key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeysData{}, err
	}


	// Create file data for saving to the database (if needed)
	fileData := db.File{
		CA:             CACommonName,
		CommonName:     commonName,
		FileType:       db.FileTypeKey,
		PrivateKeyData: privateKey,
		PublicKeyData:  privateKey.Public(),
		CreationType:   creationType,
	}

	// Save file data to the database (if needed)
	err = db.SaveFile(fileData)
	if err != nil {
		return KeysData{}, err
	}

	// Create KeysData struct containing the keys
	keys := KeysData{
		Key:       privateKey,
		PublicKey: privateKey.Public(),
	}

	return keys, nil
}

func CreateKeys(CACommonName, commonName string, creationType db.CreationType, bitSize int, algorithm string) (KeysData, error) {
	switch strings.ToUpper(algorithm) {
	case "RSA", "":
		return CreateRSAKeys(CACommonName, commonName, creationType, bitSize)
	case "ECDSA":
		return CreateECDSAKeys(CACommonName, commonName, creationType, bitSize)
	case "ED25519":
		return CreateED25519Keys(CACommonName, commonName, creationType, bitSize)
	default:
		return KeysData{}, errors.New("unsuported algorithm")
	}
}
