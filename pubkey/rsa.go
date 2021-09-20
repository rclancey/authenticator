package pubkeyauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/pkg/errors"
)

type RSAKeyPair struct {
	priv *rsa.PrivateKey
	pub *rsa.PublicKey
}

func NewRSAKeyPair(bits int) (*RSAKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &RSAKeyPair{
		priv: key,
		pub: &key.PublicKey,
	}, nil
}

func (k *RSAKeyPair) ImportPublicKey(key string) error {
	data, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		return errors.WithStack(err)
	}
	pk, err := x509.ParsePKCS1PublicKey(data)
	if err != nil {
		return errors.WithStack(err)
	}
	k.priv = nil
	k.pub = pk
	return nil
}

func (k *RSAKeyPair) ImportPrivateKey(key string) error {
	data, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		return errors.WithStack(err)
	}
	pk, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return errors.WithStack(err)
	}
	k.priv = pk
	k.pub = &pk.PublicKey
	return nil
}

func (k *RSAKeyPair) ExportPublicKey() (string, error) {
	if k.pub == nil {
		return "", errors.New("no public key to export")
	}
	data := x509.MarshalPKCS1PublicKey(k.pub)
	key := base64.RawStdEncoding.EncodeToString(data)
	return key, nil
}

func (k *RSAKeyPair) ExportPrivateKey() (string, error) {
	if k.priv == nil {
		return "", errors.New("no private key to export")
	}
	data := x509.MarshalPKCS1PrivateKey(k.priv)
	key := base64.RawStdEncoding.EncodeToString(data)
	return key, nil
}

func (k *RSAKeyPair) PublicKeyEquals(key string) bool {
	pub, err := k.ExportPublicKey()
	if err != nil {
		return false
	}
	return pub == key
}

func (k *RSAKeyPair) Sign(message string) (string, error) {
	if k.priv == nil {
		return "", errors.New("no private key to sign with")
	}
	hashed := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", errors.WithStack(err)
	}
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

func (k *RSAKeyPair) Verify(message, sig string) error {
	if k.pub == nil {
		return errors.New("no public key to verify with")
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return errors.Wrap(err, "can't decode signature")
	}
	hashed := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, hashed[:], sigBytes)
	return errors.WithStack(err)
}
