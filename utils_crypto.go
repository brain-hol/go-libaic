package libaic

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/ssh"
)

func extractBase64SshPublicKey(privateKeyPEM []byte) (string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	var privKey any
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		privKey, err = ssh.ParseRawPrivateKey(privateKeyPEM)
	default:
		err = fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	var signer ssh.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ed25519.PrivateKey:
		signer, err = ssh.NewSignerFromKey(k)
	default:
		return "", fmt.Errorf("unsupported private key type %T", privKey)
	}

	if err != nil {
		return "", fmt.Errorf("failed to create SSH signer: %w", err)
	}

	pubKey := signer.PublicKey()
	base64Key := base64.StdEncoding.EncodeToString(pubKey.Marshal())

	return base64Key, nil
}

func parseKeyToJWK(keyBytes []byte) (jwk.Key, error) {
	// Try parsing as PEM first (existing behavior)
	key, err := jwk.ParseKey(keyBytes, jwk.WithPEM(true))
	if err == nil {
		return key, nil
	}

	// If PEM parsing failed, try OpenSSH parsing
	rawKey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key as PEM or OpenSSH: %w", err)
	}

	switch k := rawKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return jwk.Import(k)
	case *ed25519.PrivateKey:
		return jwk.Import(*k)
	default:
		return nil, fmt.Errorf("unsupported key type extracted from SSH key: %T", k)
	}
}
