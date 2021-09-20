package pubkeyauth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rclancey/authenticator"
)

const (
	AlgoRSA = "rsa"
	AlgoNaCl = "nacl"
)

type KeyPair interface {
	ImportPublicKey(key string) error
	ImportPrivateKey(key string) error
	ExportPublicKey() (string, error)
	ExportPrivateKey() (string, error)
	PublicKeyEquals(string) bool
	Sign(sessionId string) (code string, err error)
	Verify(message, code string) error
}

type PublicKeyAuthenticator struct {
	Algo string `json:"algo"`
	PublicKeys []string `json:"public_keys"`
	Sessions map[string]time.Time `json:"sessions"`
	SessionTTL int `json:"session_ttl"`
	isDirty bool
	keyPair KeyPair
}

func NewPublicKeyAuthenticator(algo string, sessionTTL time.Duration) *PublicKeyAuthenticator {
	return &PublicKeyAuthenticator{
		Algo: algo,
		PublicKeys: []string{},
		Sessions: map[string]time.Time{},
		SessionTTL: int(sessionTTL.Milliseconds()),
	}
}

func (auth *PublicKeyAuthenticator) GetAlgo() (KeyPair, error) {
	if auth.keyPair != nil {
		return auth.keyPair, nil
	}
	switch auth.Algo {
	case AlgoRSA:
		auth.keyPair = &RSAKeyPair{}
	case AlgoNaCl:
		auth.keyPair = &NaClKeyPair{}
	default:
		return nil, errors.New("unknown public key algorithm")
	}
	return auth.keyPair, nil
}

func (auth *PublicKeyAuthenticator) IsDirty() bool {
	return auth.isDirty
}

func (auth *PublicKeyAuthenticator) AddPublicKey(key string) {
	auth.PublicKeys = append(auth.PublicKeys, key)
	auth.isDirty = true
}

func (auth *PublicKeyAuthenticator) CleanupSessions() {
	toDelete := []string{}
	minTime := time.Now().Add(-1 * time.Duration(auth.SessionTTL) * time.Millisecond)
	for k, v := range auth.Sessions {
		if v.Before(minTime) {
			toDelete = append(toDelete, k)
		}
	}
	if len(toDelete) > 0 {
		for _, k := range toDelete {
			delete(auth.Sessions, k)
		}
		auth.isDirty = true
	}
}

func (auth *PublicKeyAuthenticator) CreateSession() (string, error) {
	sesIdBytes := make([]byte, 32)
	n, err := rand.Read(sesIdBytes)
	if err != nil {
		return "", errors.Wrap(err, "can't generate session id")
	}
	if n < len(sesIdBytes) {
		return "", errors.Wrap(err, "can't generate session id")
	}
	sesId := hex.EncodeToString(sesIdBytes)
	auth.Sessions[sesId] = time.Now()
	auth.isDirty = true
	auth.CleanupSessions()
	return sesId, nil
}

func (auth *PublicKeyAuthenticator) GenerateCode(privateKey, sessionId string) (string, error) {
	algo, err := auth.GetAlgo()
	if err != nil {
		return "", errors.WithStack(err)
	}
	err = algo.ImportPrivateKey(privateKey)
	if err != nil {
		return "", errors.WithStack(err)
	}
	pub, err := algo.ExportPublicKey()
	if err != nil {
		return "", errors.WithStack(err)
	}
	parts := []string{
		sessionId,
		pub,
	}
	message := strings.Join(parts, ".")
	sig, err := algo.Sign(message)
	parts = append(parts, sig)
	return strings.Join(parts, "."), nil
}

func (auth *PublicKeyAuthenticator) Authenticate(code string) error {
	parts := strings.Split(code, ".")
	if len(parts) != 3 {
		return errors.WithStack(authenticator.ErrInvalidPassword)
	}
	sessionId := parts[0]
	pubKey := parts[1]
	sig := parts[2]
	message := strings.Join(parts[:2], ".")
	algo, err := auth.GetAlgo()
	if err != nil {
		return errors.WithStack(err)
	}
	err = algo.ImportPublicKey(pubKey)
	if err != nil {
		return errors.WithStack(err)
	}
	err = algo.Verify(message, sig)
	if err != nil {
		return errors.Wrap(authenticator.ErrInvalidPassword, err.Error())
	}
	auth.CleanupSessions()
	_, ok := auth.Sessions[sessionId]
	if !ok {
		// invalid session id
		return errors.WithStack(authenticator.ErrInvalidPassword)
	}
	delete(auth.Sessions, sessionId)
	auth.isDirty = true
	for _, k := range auth.PublicKeys {
		if algo.PublicKeyEquals(k) {
			// public key is authorized
			return nil
		}
	}
	// public key is not authorized
	return errors.WithStack(authenticator.ErrInvalidPassword)
}

