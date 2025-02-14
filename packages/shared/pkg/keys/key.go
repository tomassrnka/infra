package keys

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	keySuffixLength = 4

	keyLength = 20
)

var hasher Hasher = NewSHA256Hashing()

type Key struct {
	PrefixedRawValue string
	HashedValue      string
	MaskedValue      string
}

func MaskKey(prefix string, value string) (string, error) {
	suffixOffset := len(value) - keySuffixLength

	if suffixOffset < 0 {
		return "", fmt.Errorf("mask value length is less than key suffix length (%d)", keySuffixLength)
	}

	lastFour := value[suffixOffset:]
	stars := strings.Repeat("*", suffixOffset)
	return prefix + stars + lastFour, nil
}

func GenerateKey(prefix string) (Key, error) {
	keyBytes := make([]byte, keyLength)

	_, err := rand.Read(keyBytes)
	if err != nil {
		return Key{}, err
	}

	generatedToken := hex.EncodeToString(keyBytes)

	mask, err := MaskKey(prefix, generatedToken)
	if err != nil {
		return Key{}, err
	}

	return Key{
		PrefixedRawValue: prefix + generatedToken,
		HashedValue:      hasher.Hash(keyBytes),
		MaskedValue:      mask,
	}, nil
}

func VerifyKey(prefix string, key string) (string, error) {
	parts := strings.Split(key, prefix)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid key prefix")
	}

	keyValue := parts[1]
	keyBytes, err := hex.DecodeString(keyValue)
	if err != nil {
		return "", fmt.Errorf("invalid key")
	}

	return hasher.Hash(keyBytes), nil
}
