package pubkeyauth

import (
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type AuthenticatorSuite struct {}
var _ = Suite(&AuthenticatorSuite{})

func (s *AuthenticatorSuite) TestNewNaClAuth(c *C) {
	auth := NewPublicKeyAuthenticator(AlgoNaCl, time.Minute)
	key, err := NewNaClKeyPair()
	c.Check(err, IsNil)
	pkey, err := key.ExportPublicKey()
	c.Check(err, IsNil)
	auth.AddPublicKey(pkey)
	sessionId, err := auth.CreateSession()
	c.Check(err, IsNil)
	prkey, err := key.ExportPrivateKey()
	c.Check(err, IsNil)
	code, err := auth.GenerateCode(prkey, sessionId)
	c.Check(err, IsNil)
	err = auth.Authenticate(code)
	c.Check(err, IsNil)

	key, err = NewNaClKeyPair()
	c.Check(err, IsNil)
	sessionId, err = auth.CreateSession()
	c.Check(err, IsNil)
	prkey, err = key.ExportPrivateKey()
	c.Check(err, IsNil)
	code, err = auth.GenerateCode(prkey, sessionId)
	c.Check(err, IsNil)
	err = auth.Authenticate(code)
	c.Check(err, Not(IsNil))
}

func (s *AuthenticatorSuite) TestNewRSAAuth(c *C) {
	auth := NewPublicKeyAuthenticator(AlgoRSA, time.Minute)
	key, err := NewRSAKeyPair(2048)
	c.Check(err, IsNil)
	pkey, err := key.ExportPublicKey()
	c.Check(err, IsNil)
	auth.AddPublicKey(pkey)
	sessionId, err := auth.CreateSession()
	c.Check(err, IsNil)
	prkey, err := key.ExportPrivateKey()
	c.Check(err, IsNil)
	code, err := auth.GenerateCode(prkey, sessionId)
	c.Check(err, IsNil)
	err = auth.Authenticate(code)
	c.Check(err, IsNil)

	key, err = NewRSAKeyPair(2048)
	c.Check(err, IsNil)
	sessionId, err = auth.CreateSession()
	c.Check(err, IsNil)
	prkey, err = key.ExportPrivateKey()
	c.Check(err, IsNil)
	code, err = auth.GenerateCode(prkey, sessionId)
	c.Check(err, IsNil)
	err = auth.Authenticate(code)
	c.Check(err, Not(IsNil))
}
