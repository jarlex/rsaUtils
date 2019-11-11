package rsaKey

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "strings"
)

// GenerateRsaKeyPair generate a random pair of RSA keys.
// It returns both keys in rsa package type
func GenerateRsaKeyPair(bytes int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
    privKey, err := rsa.GenerateKey(rand.Reader, bytes)
    if err != nil {
        return nil, nil, err
    }
    return privKey, &privKey.PublicKey, nil
}

// ExportRsaPrivateKeyAsPemStr read a private key in rsa package type
// It returns a string that represent the PEM file of the key
func ExportRsaPrivateKeyAsPemStr(privKey *rsa.PrivateKey) string {
    privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
    privKeyPem := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: privKeyBytes,
        },
    )
    return string(privKeyPem)
}

// ParseRsaPrivateKeyFromPemStr read a private key in PEM format
// It returns a private key in rsa package type
func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    privPEM = strings.Replace(privPEM, "\\n", "\n", -1)
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the key")
    }
    
    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, errors.New("key value not is a valid Private RSA key")
    }
    
    return priv, nil
}

// ParseRsaPrivateKeyPassFromPemStr read a private key in PEM format with passphrase
// It returns a private key in rsa package type
func ParseRsaPrivateKeyPassFromPemStr(privPEM, pass string) (*rsa.PrivateKey, error) {
    privPEM = strings.Replace(privPEM, "\\n", "\n", -1)
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the key")
    }
    
    decryptedBlock, err := x509.DecryptPEMBlock(block, []byte(pass))
    priv, err := x509.ParsePKCS1PrivateKey(decryptedBlock)
    if err != nil {
        return nil, errors.New("key value not is a valid Private RSA key")
    }
    
    return priv, nil
}

// ExportRsaPublicKeyAsPemStr read a public key in rsa package type
// It returns a string that represent the PEM file of the key
func ExportRsaPublicKeyAsPemStr(pubKey *rsa.PublicKey) (string, error) {
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        return "", err
    }
    pubKeyPem := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PUBLIC KEY",
            Bytes: pubKeyBytes,
        },
    )
    
    return string(pubKeyPem), nil
}

// ParseRsaPublicKeyFromPemStr read a public key in PEM format
// It returns a public key in rsa package type
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    pubPEM = strings.Replace(pubPEM, "\\n", "\n", -1)
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the key")
    }
    
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, errors.New("key value not is a valid Public RSA key")
    }
    
    switch pub := pub.(type) {
    case *rsa.PublicKey:
        return pub, nil
    default:
        break
    }
    return nil, errors.New("key type is not RSA")
}

// ParseRsaPublicKeyFromPemStr read a public key in PEM format
// It returns a public key in rsa package type
func Parsex509CertificateFromPemStr(certPEM string) (*x509.Certificate, error) {
    certPEM = strings.Replace(certPEM, "\\n", "\n", -1)
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the certificate")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, errors.New("key value not is a valid x509 cert")
    }
    
    return cert, nil
}
