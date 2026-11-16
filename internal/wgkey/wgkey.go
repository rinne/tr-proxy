// Package wgkey handles WireGuard keys in their base64 text form.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func decode(key string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("not a base64 32-byte key")
	}
	return b, nil
}

// Generate returns a new secret key and its public key.
func Generate() (secret, public string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Public derives the public key of a secret key.
func Public(secret string) (string, error) {
	b, err := decode(secret)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Hex converts a key to the hex form the WireGuard UAPI wants.
func Hex(key string) (string, error) {
	b, err := decode(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
