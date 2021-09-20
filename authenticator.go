package authenticator

type Authenticator interface {
	Authenticate(password string) error
}
