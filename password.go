package authenticator

import (
	"database/sql/driver"
	"encoding/base32"
	"encoding/json"
	"math/rand"
	"strings"
	"time"

	"github.com/alexandrevicenzi/unchained"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type PasswordAuthenticator struct {
	Hasher           string     `json:"hasher"`
	HashedPassword   string     `json:"password"`
	ResetCode        *string    `json:"reset_code"`
	ResetCodeExpires *time.Time `json:"reset_code_expires"`
	isDirty          bool
}

func NewPasswordAuthenticator(password string) (*PasswordAuthenticator, error) {
	auth := &PasswordAuthenticator{}
	err := auth.SetPassword(password)
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func (auth *PasswordAuthenticator) Value() (driver.Value, error) {
	data, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

func (auth *PasswordAuthenticator) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		return json.Unmarshal([]byte(v), auth)
	case []byte:
		return json.Unmarshal(v, auth)
	}
	return errors.Errorf("don't know how to convert %T into %T", value, *auth)
}

func (auth *PasswordAuthenticator) SetPassword(password string, inputs ...string) error {
	if password == "" {
		return errors.WithStack(ErrEmptyPassword)
	}
	score := zxcvbn.PasswordStrength(password, inputs)
	if score.Score < 3 {
		return errors.WithStack(ErrPasswordTooSimple)
	}
	if auth.Hasher != "" {
		hash, err := unchained.MakePassword(password, "", auth.Hasher)
		if err != nil {
			return errors.Wrap(err, "can't hash password with " + auth.Hasher)
		}
		auth.HashedPassword = hash
	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
		if err != nil {
			return errors.Wrap(err, "can't hash password")
		}
		auth.HashedPassword = string(hash)
	}
	auth.ResetCode = nil
	auth.ResetCodeExpires = nil
	auth.isDirty = true
	return nil
}

func (auth *PasswordAuthenticator) ResetPassword(dur time.Duration) (string, error) {
	data := make([]byte, 25)
	_, err := rand.Read(data)
	if err != nil {
		return "", errors.Wrap(err, "can't make reset token")
	}
	code := base32.StdEncoding.EncodeToString(data)
	expires := time.Now().Add(dur).UTC()
	auth.ResetCode = &code
	auth.ResetCodeExpires = &expires
	auth.isDirty = true
	return code, nil
}

func (auth *PasswordAuthenticator) CheckResetCode(code string) error {
	if auth.ResetCode == nil || auth.ResetCodeExpires == nil {
		return errors.WithStack(ErrInvalidResetCode)
	}
	if auth.ResetCodeExpires.Before(time.Now()) {
		auth.ResetCode = nil
		auth.ResetCodeExpires = nil
		auth.isDirty = true
		return errors.WithStack(ErrInvalidResetCode)
	}
	if code != *auth.ResetCode {
		return errors.WithStack(ErrInvalidResetCode)
	}
	auth.ResetCode = nil
	auth.ResetCodeExpires = nil
	auth.isDirty = true
	return nil
}

func (auth *PasswordAuthenticator) IsDirty() bool {
	return auth.isDirty
}

func (auth *PasswordAuthenticator) Authenticate(password string) error {
	if auth.CheckResetCode(password) == nil {
		return nil
	}
	if strings.HasPrefix(auth.HashedPassword, "$") {
		err := bcrypt.CompareHashAndPassword([]byte(auth.HashedPassword), []byte(password))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return errors.WithStack(ErrInvalidPassword)
			}
			return errors.WithStack(err)
		}
		return nil
	}
	ok, err := unchained.CheckPassword(password, auth.HashedPassword)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return errors.WithStack(ErrInvalidPassword)
	}
	return nil
}
