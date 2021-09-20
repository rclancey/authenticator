package authenticator

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alexandrevicenzi/unchained"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type AuthenticatorSuite struct {}
var _ = Suite(&AuthenticatorSuite{})

func (s *AuthenticatorSuite) TestNewPasswordAuthenticator(c *C) {
	_, err := NewPasswordAuthenticator("foobar")
	c.Check(err, Not(IsNil))
	_, err = NewPasswordAuthenticator("G$W%ginA83*")
	c.Check(err, IsNil)
}

func (s *AuthenticatorSuite) TestPAAuthenticate(c *C) {
	auth, err := NewPasswordAuthenticator("G$W%ginA83*")
	c.Check(err, IsNil)
	err = auth.Authenticate("G$W%ginA83")
	c.Check(err, Not(IsNil))
	err = auth.Authenticate("G$W%ginA83*")
	c.Check(err, IsNil)
}

func (s *AuthenticatorSuite) TestPAAuthenticateHashers(c *C) {
	pw := "G$W%ginA83*"
	auth, err := NewPasswordAuthenticator(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.Argon2Hasher
	pw = "H#^W%g4g5oj"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.BCryptHasher
	pw = "gweo8@#%s"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.BCryptSHA256Hasher
	pw = "GQ354oIfe$5"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.MD5Hasher
	pw = "Q#$TFaFA$a"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.PBKDF2SHA1Hasher
	pw = "%Agac5v%%!d"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.PBKDF2SHA256Hasher
	pw = "vabvarEWR##f"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.SHA1Hasher
	pw = "vaeo9#FW#"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.UnsaltedMD5Hasher
	pw = "VARVVF!@fds"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)

	auth.Hasher = unchained.UnsaltedSHA1Hasher
	pw = "ival4vae4rcE"
	auth.SetPassword(pw)
	err = auth.Authenticate(pw)
	c.Check(err, IsNil)
}

func (s *AuthenticatorSuite) TestPAAuthenticateReset(c *C) {
	pw := "G$W%ginA83*"
	auth, err := NewPasswordAuthenticator(pw)
	c.Check(err, IsNil)
	code, err := auth.ResetPassword(time.Second)
	c.Check(err, IsNil)
	c.Check(len(code), Not(Equals), 0)
	err = auth.CheckResetCode(pw)
	c.Check(err, Not(IsNil))
	err = auth.CheckResetCode(code)
	c.Check(err, IsNil)
	err = auth.CheckResetCode(code)
	c.Check(err, Not(IsNil))
	code, err = auth.ResetPassword(time.Second)
	time.Sleep(2 * time.Second)
	err = auth.CheckResetCode(code)
	c.Check(err, Not(IsNil))
}

func (s *AuthenticatorSuite) TestNew2FAAuthenticator(c *C) {
	auth, err := NewTwoFactorAuthenticator("jlennon", "beatles.com")
	c.Check(err, IsNil)
	c.Check(auth.Username, Equals, "jlennon")
	c.Check(auth.Domain, Equals, "beatles.com")
}

func (s *AuthenticatorSuite) Test2FAAuthenticate(c *C) {
	auth, err := NewTwoFactorAuthenticator("jlennon", "beatles.com")
	c.Check(err, IsNil)
	code := auth.GenCode()
	err = auth.Authenticate("123456")
	c.Check(err, Not(IsNil))
	err = auth.Authenticate(code)
	c.Check(err, IsNil)
	c.Check(auth.IsDirty(), Equals, false)
	c.Check(len(auth.RecoveryKeys), Equals, 8)
	code = auth.RecoveryKeys[3]
	err = auth.Authenticate(code)
	c.Check(err, IsNil)
	c.Check(auth.IsDirty(), Equals, true)
	c.Check(len(auth.RecoveryKeys), Equals, 7)
	err = auth.Authenticate(code)
	c.Check(err, Not(IsNil))
}

func (a *AuthenticatorSuite) Test2FAConfigure(c *C) {
	auth, err := NewTwoFactorAuthenticator("jlennon", "beatles.com")
	cfg, err := auth.Configure()
	c.Check(err, IsNil)
	exp := fmt.Sprintf("otpauth://totp/beatles.com:jlennon?issuer=beatles.com&secret=%s", auth.Secret)
	c.Check(cfg.Domain, Equals, "beatles.com")
	c.Check(cfg.Username, Equals, "jlennon")
	c.Check(cfg.URI, Equals, exp)
	c.Check(strings.HasPrefix(cfg.QRCode, "data:image/png;base64,"), Equals, true)
	c.Check(len(cfg.RecoveryKeys), Equals, 8)
	for i, code := range auth.RecoveryKeys {
		c.Check(cfg.RecoveryKeys[i], Equals, code)
	}
}
