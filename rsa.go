package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultDotKeys  = ".keys"
	DefaultIDRsa    = "id_rsa"
	DefaultIDRsaPub = "id_rsa.pub"
	DefaultKeySize  = 1024
)

// Config stores key pair file path and key size.
type Config struct {
	DotKeys  string // DotKeys represents the parent dir of IDRsa and IDRsaPub
	IDRsa    string // IDRsa represents private key file
	IDRsaPub string // IDRsaPub represents public key file
	KeySize  int    // KeySize represents the bit size of key pair
}

// NewDefaultConfig return Config with default params.
func NewDefaultConfig() *Config {
	return &Config{
		DotKeys:  DefaultDotKeys,
		IDRsa:    filepath.Join(DefaultDotKeys, DefaultIDRsa),
		IDRsaPub: filepath.Join(DefaultDotKeys, DefaultIDRsaPub),
		KeySize:  DefaultKeySize,
	}
}

// NewConfig return a Config object with user defined params.
func NewConfig(dotKeys, idRsa, idRsaPub string, keySize int) *Config {
	return &Config{
		DotKeys:  dotKeys,
		IDRsa:    filepath.Join(dotKeys, idRsa),
		IDRsaPub: filepath.Join(dotKeys, idRsaPub),
		KeySize:  keySize,
	}
}

// GenerateKeyPair generates a pair of rsa key pair with the given key size defined in Config.
func (c *Config) GenerateKeyPair() (*rsa.PrivateKey, error) {
	// Generate key pair
	privateKey, err := generateKeyPair(c.KeySize)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// KeyPair stores key pair object
type KeyPair struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// SaveKeyPair save key pair to local path defined in Config.
func (c *Config) SaveKeyPair(keyPair *rsa.PrivateKey) error {
	// Make parent dir
	if err := os.MkdirAll(c.DotKeys, os.ModePerm); err != nil {
		return err
	}
	// Save private key
	if err := saveIDRsa(c.IDRsa, keyPair); err != nil {
		return err
	}
	// Save public key
	if err := saveIDRsaPub(c.IDRsaPub, keyPair); err != nil {
		return err
	}
	return nil
}

// LoadPublicKey return a KeyPair object contains public key from Config.IDRsaPub
func (c *Config) LoadPublicKey() (*KeyPair, error) {
	publicKey, err := getIDRsaPub(c.IDRsaPub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{publicKey: publicKey}, nil
}

// LoadPrivateKey return a KeyPair object contains private key from Config.IDRsa
func (c *Config) LoadPrivateKey() (*KeyPair, error) {
	privateKey, err := getIDRsa(c.IDRsa)
	if err != nil {
		return nil, err
	}
	return &KeyPair{privateKey: privateKey}, nil
}

// EncryptPKCS1v15 encrypts the given message with RSA and the padding scheme from PKCS #1 v1.5
func (p *KeyPair) EncryptPKCS1v15(plainText string) (string, error) {
	cipherText, err := encryptPKCS1v15(plainText, p.publicKey)
	if err != nil {
		return "", err
	}
	return cipherText, nil
}

// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
func (p *KeyPair) DecryptPKCS1v15(cipherText string) (string, error) {
	plainText, err := decryptPKCS1v15(cipherText, p.privateKey)
	if err != nil {
		return "", err
	}
	return plainText, nil
}

// EncryptOAEP encrypts the given message with RSA-OAEP.
func (p *KeyPair) EncryptOAEP(plainText string) (string, error) {
	cipherText, err := encryptOAEP(plainText, p.publicKey)
	if err != nil {
		return "", err
	}
	return cipherText, nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
func (p *KeyPair) DecryptOAEP(cipherText string) (string, error) {
	plainText, err := decryptOAEP(cipherText, p.privateKey)
	if err != nil {
		return "", err
	}
	return plainText, nil
}

// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.
func (p *KeyPair) SignPKCS1v15(payload string) (string, error) {
	signature, err := signPKCS1v15(payload, p.privateKey)
	if err != nil {
		return "", err
	}
	return signature, nil
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
func (p *KeyPair) VerifyPKCS1v15(payload, signature64 string) error {
	return verifyPKCS1v15(payload, signature64, p.publicKey)
}

// SignPSS calculates the signature of digest using PSS.
func (p *KeyPair) SignPSS(payload string) (string, error) {
	signature, err := signPSS(payload, p.privateKey)
	if err != nil {
		return "", err
	}
	return signature, nil
}

// VerifyPSS verifies a PSS signature.
func (p *KeyPair) VerifyPSS(payload, signature64 string) error {
	return verifyPSS(payload, signature64, p.publicKey)
}

// generateKeyPair generates an RSA keypair of the given bit size.
func generateKeyPair(keySize int) (*rsa.PrivateKey, error) {
	// Generate key pair
	keyPair, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	// Validate key
	err = keyPair.Validate()
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

// saveIDRsa save private key to filename.
func saveIDRsa(fileName string, keyPair *rsa.PrivateKey) error {
	// Private key stream
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	// Create file
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}

	return pem.Encode(f, privateKeyBlock)
}

// saveIDRsaPub save public key to filename.
func saveIDRsaPub(fileName string, keyPair *rsa.PrivateKey) error {
	// Public key stream
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Create file
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}

	return pem.Encode(f, publicKeyBlock)
}

// getIDRsaPub get public key from filename.
func getIDRsaPub(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, errors.New("ERROR: fail get public key, invalid key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key, nil
	default:
		return nil, nil
	}
}

// getIDRsa get private key from filename.
func getIDRsa(filename string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, errors.New("ERROR: fail get rsa private key, invalid key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encryptPKCS1v15 the given message with RSA and the padding scheme from PKCS #1 v1.5.
func encryptPKCS1v15(plainText string, key *rsa.PublicKey) (string, error) {
	partLen := key.Size() - 11
	chunks := split([]byte(plainText), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(encrypted)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// decryptPKCS1v15 the cipher text using RSA and the padding scheme from PKCS #1 v1.5.
func decryptPKCS1v15(cipherText string, key *rsa.PrivateKey) (string, error) {
	partLen := key.Size()
	raw, err := base64.RawURLEncoding.DecodeString(cipherText)
	chunks := split(raw, partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, key, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// encryptOAEP encrypts the given message with RSA-OAEP.
func encryptOAEP(plainText string, key *rsa.PublicKey) (string, error) {
	// Params
	rnd := rand.Reader
	hash := sha256.New()
	maxSize := key.Size() - 2*hash.Size() - 2 // from rsa.go
	chunks := split([]byte(plainText), maxSize)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		// Encrypt with OAEP
		encrypted, err := rsa.EncryptOAEP(hash, rnd, key, chunk, nil)
		if err != nil {
			return "", err
		}
		buffer.Write(encrypted)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// decryptOAEP decrypts cipher text using RSA-OAEP.
func decryptOAEP(cipherText string, key *rsa.PrivateKey) (string, error) {
	// Params
	rnd := rand.Reader
	hash := sha256.New()
	partLen := key.Size()
	raw, err := base64.RawURLEncoding.DecodeString(cipherText)
	chunks := split(raw, partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		// Decrypt with OAEP
		decrypted, err := rsa.DecryptOAEP(hash, rnd, key, chunk, nil)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// signPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.
func signPKCS1v15(payload string, key *rsa.PrivateKey) (string, error) {
	// Remove unwanted characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha256.Sum256([]byte(msg))

	// Sign the hashed payload
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	// Return base64 encoded string
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
func verifyPKCS1v15(payload string, signature64 string, key *rsa.PublicKey) error {
	// Decode base64 encoded signature
	signature, err := base64.StdEncoding.DecodeString(signature64)
	if err != nil {
		return err
	}

	// Remove unwanted characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha256.Sum256([]byte(msg))

	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
}

// signPSS calculates the signature of digest using PSS.
func signPSS(payload string, key *rsa.PrivateKey) (string, error) {
	// Remove unwanted characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))

	// Prepare params
	hash := crypto.SHA256
	h := hash.New()
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	// Sign the hashed payload
	signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, nil)
	if err != nil {
		return "", err
	}

	// Return base64 encoded string
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyPSS verifies a PSS signature.
func verifyPSS(payload, signature64 string, key *rsa.PublicKey) error {
	// Decode base64 encoded signature
	signature, err := base64.StdEncoding.DecodeString(signature64)
	if err != nil {
		return err
	}

	// Remove unwanted characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))

	// Prepare params
	hash := crypto.SHA256
	h := hash.New()
	h.Write([]byte(msg))
	hashed := h.Sum(nil)
	return rsa.VerifyPSS(key, hash, hashed, signature, nil)
}

// split divides buf into limit size.
func split(buf []byte, limit int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/limit+1)
	for len(buf) >= limit {
		chunk, buf = buf[:limit], buf[limit:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
