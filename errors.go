package authenticator

import (
	"errors"
)

var ErrNotEnoughSystemEntropy = errors.New("not enough system entropy")
var ErrEmptyPassword = errors.New("empty password")
var ErrPasswordTooSimple = errors.New("password too simple")
var ErrInvalidPassword = errors.New("invalid login credentials")
var ErrInvalidResetCode = errors.New("invalid reset code")
var ErrTwoFactorNotConfigured = errors.New("two factor authentication not configured")
var ErrInvalid2FACode = errors.New("invalid two factor authentication code")

