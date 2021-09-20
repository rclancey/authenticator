package pubkeyauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

type NaClKeyPair struct {
	priv *[64]byte
	pub *[32]byte
}

func NewNaClKeyPair() (*NaClKeyPair, error) {
	pub, priv, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &NaClKeyPair{
		priv: priv,
		pub: pub,
	}, nil
}

func (k *NaClKeyPair) ImportPublicKey(key string) error {
	data, err := hex.DecodeString(key)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(data) != 32 {
		return errors.New("invalid public key")
	}
	pub := [32]byte{}
	copy(pub[:], data)
	k.pub = &pub
	k.priv = nil
	return nil
}

func (k *NaClKeyPair) ImportPrivateKey(key string) error {
	data, err := hex.DecodeString(key)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(data) != 96 {
		return errors.New("invalid private key")
	}
	priv := [64]byte{}
	pub := [32]byte{}
	copy(priv[:], data[:64])
	copy(pub[:], data[64:])
	k.priv = &priv
	k.pub = &pub
	return nil
}

func (k *NaClKeyPair) ExportPublicKey() (string, error) {
	if k.pub == nil {
		return "", errors.New("no public key to export")
	}
	key := hex.EncodeToString((*k.pub)[:])
	return key, nil
}

func (k *NaClKeyPair) ExportPrivateKey() (string, error) {
	if k.priv == nil {
		return "", errors.New("no private key to export")
	}
	data := append(k.priv[:], k.pub[:]...)
	key := hex.EncodeToString(data)
	return key, nil
}

func (k *NaClKeyPair) PublicKeyEquals(key string) bool {
	pub, err := k.ExportPublicKey()
	if err != nil {
		return false
	}
	return pub == key
}

func (k *NaClKeyPair) Sign(message string) (string, error) {
	if k.priv == nil {
		return "", errors.New("no private key to sign with")
	}
	out := sign.Sign([]byte{}, []byte(message), k.priv)
	return base64.RawStdEncoding.EncodeToString(out[:sign.Overhead]), nil
}

func (k *NaClKeyPair) Verify(message, sig string) error {
	if k.pub == nil {
		return errors.New("no public key to verify with")
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return errors.WithStack(err)
	}
	signed := append(sigBytes, []byte(message)...)
	_, ok := sign.Open([]byte{}, signed, k.pub)
	if ok {
		return nil
	}
	return errors.New("invalid signature")
}
