package sshauth

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHAuthenticator struct {
	username string
}

func NewSSHAuthenticator(username string) *SSHAuthenticator {
	return &SSHAuthenticator{
		username: username,
	}
}

func (auth *SSHAuthenticator) IsDirty() bool {
	return false
}

func (auth *SSHAuthenticator) Authenticate(password string) error {
	cfg := &ssh.ClientConfig{
		User: auth.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "localhost:22", cfg)
	if client != nil {
		client.Close()
	}
	if err != nil {
		return errors.Wrap(ErrInvalidPassword)
	}
	return true
}
