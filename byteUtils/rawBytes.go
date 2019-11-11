package byteUtils

import (
    "crypto/rand"
    "encoding/hex"
)

// GenerateNRandomBytes generate a random n bytes.
// It returns both keys in rsa package type
func GenerateNRandomBytes(n int) ([]byte, error) {
    bytes := make([]byte, n)
    if _, err := rand.Read(bytes); err != nil {
        return nil, err
    }
    return bytes, nil
}

// GenerateStringHexRandom generate n randoms bytes and represent it in a hex string.
// It returns both keys in rsa package type
func GenerateStringHexRandom(n int) (string, error) {
    byt, err := GenerateNRandomBytes(n)
    
    if err != nil {
        return "", err
    }
    
    return hex.EncodeToString(byt), nil
    
}
