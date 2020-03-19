package jwk

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

type KeyType uint

func ECPrivateKeyKeyFromPem(r io.Reader) (*ecdsa.PrivateKey, error) {
	return ecPrivateKeyKeyFromPem(r)
}

func ecPrivateKeyKeyFromPem(r io.Reader) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error data read err_msg=%w", err)
	}
	var block, _ = pem.Decode(data)
	return x509.ParseECPrivateKey(block.Bytes)
}

func ECPublicKeyKeyFromPem(r io.Reader) (*ecdsa.PublicKey, error) {
	return ecPublicKeyKeyFromPem(r)
}

func ecPublicKeyKeyFromPem(r io.Reader) (*ecdsa.PublicKey, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error data read err_msg=%w", err)
	}
	var block, _ = pem.Decode(data)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}
