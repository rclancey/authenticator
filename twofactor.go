package authenticator

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/dgryski/dgoogauth"
	"github.com/gofrs/uuid/v3"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
)

type TwoFactorAuthenticator struct {
	Domain       string   `json:"domain"`
	Username     string   `json:"username"`
	Secret       string   `json:"secret"`
	RecoveryKeys []string `json:"recovery_keys"`
	isDirty      bool
}

type TwoFactorConfig struct {
	Domain       string   `json:"domain"`
	Username     string   `json:"username"`
	URI          string   `json:"uri"`
	QRCode       string   `json:"qr_code"`
	RecoveryKeys []string `json:"recovery_keys"`
}

func makeRecoveryKey() (string, error) {
	u := uuid.UUID{}
	_, err := io.ReadFull(rand.Reader, u[:])
	if err != nil {
		return "", err
	}
	u.SetVersion(uuid.V4)
	u.SetVariant(uuid.VariantRFC4122)
	return u.String(), nil
}

func NewTwoFactorAuthenticator(username, domain string) (*TwoFactorAuthenticator, error) {
	secretBytes := make([]byte, 10)
	n, err := rand.Read(secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, "can't generate secret")
	}
	if n < len(secretBytes) {
		return nil, errors.Wrap(err, "can't generate secret")
	}
	secret := base32.StdEncoding.EncodeToString(secretBytes)
	recoveryKeys := make([]string, 8)
	for i := range recoveryKeys {
		recoveryKeys[i], err = makeRecoveryKey()
		if err != nil {
			return nil, errors.Wrap(err, "can't generate recovery key")
		}
	}
	return &TwoFactorAuthenticator{
		Domain: domain,
		Username: username,
		Secret: secret,
		RecoveryKeys: recoveryKeys,
	}, nil
}

func (auth *TwoFactorAuthenticator) URI() string {
	config := &dgoogauth.OTPConfig{
		Secret: auth.Secret,
		WindowSize: 2,
		HotpCounter: 0,
		DisallowReuse: nil,
		ScratchCodes: nil,
		UTC: true,
	}
	return config.ProvisionURIWithIssuer(auth.Username, auth.Domain)
}

func (auth *TwoFactorAuthenticator) QRCode() ([]byte, error) {
	uri := auth.URI()
	pngdata, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return pngdata, nil
}

func (auth *TwoFactorAuthenticator) QRCodeDataURI() (string, error) {
	pngdata, err := auth.QRCode()
	if err != nil {
		return "", err
	}
	b64data := base64.StdEncoding.EncodeToString(pngdata)
	return "data:image/png;base64," + b64data, nil
}

func (auth *TwoFactorAuthenticator) Configure() (*TwoFactorConfig, error) {
	qrcode, err := auth.QRCodeDataURI()
	if err != nil {
		return nil, err
	}
	codes := make([]string, len(auth.RecoveryKeys))
	copy(codes, auth.RecoveryKeys)
	return &TwoFactorConfig{
		Domain: auth.Domain,
		Username: auth.Username,
		URI: auth.URI(),
		QRCode: qrcode,
		RecoveryKeys: codes,
	}, nil
}

func (auth *TwoFactorAuthenticator) GenCode() string {
	t := int64(time.Now().UTC().Unix() / 30)
	code := dgoogauth.ComputeCode(auth.Secret, t)
	return fmt.Sprintf("%06d", code)
}

func (auth *TwoFactorAuthenticator) ConsumeRecoveryKey(code string) bool {
	keep := []string{}
	found := false
	for _, rec := range auth.RecoveryKeys {
		if rec == code {
			found = true
		} else {
			keep = append(keep, rec)
		}
	}
	if found {
		auth.RecoveryKeys = keep
		auth.isDirty = true
		return true
	}
	return false
}

func (auth *TwoFactorAuthenticator) IsDirty() bool {
	return auth.isDirty
}

func (auth *TwoFactorAuthenticator) Authenticate(code string) error {
	if len(code) > 12 {
		ok := auth.ConsumeRecoveryKey(code)
		if !ok {
			return errors.WithStack(ErrInvalidPassword)
		}
		return nil
	}
	config := &dgoogauth.OTPConfig{
		Secret: auth.Secret,
		WindowSize: 5,
		HotpCounter: 0,
		DisallowReuse: nil,
		ScratchCodes: nil,
		UTC: true,
	}
	ok, err := config.Authenticate(code)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return errors.WithStack(ErrInvalidPassword)
	}
	return nil
}
