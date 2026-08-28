package ssh

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func prepareServer(config ServerConfig) (time.Duration, *gossh.ServerConfig, error) {
	signer, err := parseHostSigner(config.HostKey, config.HostKeyPassphrase)
	if err != nil {
		return 0, nil, err
	}
	passwordCallback, publicKeyCallback, hasBuiltInPassword, hasBuiltInPublicKey, err := builtInAuthentication(config.Users)
	if err != nil {
		return 0, nil, err
	}
	if config.PasswordCallback != nil && hasBuiltInPassword {
		return 0, nil, errors.New("ssh: configure either Users passwords or PasswordCallback")
	}
	if config.PublicKeyCallback != nil && hasBuiltInPublicKey {
		return 0, nil, errors.New("ssh: configure either Users authorized keys or PublicKeyCallback")
	}
	if config.PasswordCallback != nil {
		passwordCallback = config.PasswordCallback
	}
	if config.PublicKeyCallback != nil {
		publicKeyCallback = config.PublicKeyCallback
	}
	if config.NoClientAuth {
		if passwordCallback != nil || publicKeyCallback != nil || config.KeyboardInteractiveCallback != nil {
			return 0, nil, errors.New("ssh: NoClientAuth cannot be combined with authentication methods")
		}
	} else if passwordCallback == nil && publicKeyCallback == nil && config.KeyboardInteractiveCallback == nil {
		return 0, nil, errors.New("ssh: at least one server authentication method is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if timeout < 0 {
		return 0, nil, errors.New("ssh: timeout cannot be negative")
	}
	sshConfig := &gossh.ServerConfig{
		NoClientAuth:                config.NoClientAuth,
		PasswordCallback:            passwordCallback,
		PublicKeyCallback:           publicKeyCallback,
		KeyboardInteractiveCallback: config.KeyboardInteractiveCallback,
		ServerVersion:               config.ServerVersion,
	}
	sshConfig.AddHostKey(signer)
	return timeout, sshConfig, nil
}

func parseHostSigner(privateKey, passphrase []byte) (gossh.Signer, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("ssh: server host private key is required")
	}
	var signer gossh.Signer
	var err error
	if len(passphrase) == 0 {
		signer, err = gossh.ParsePrivateKey(privateKey)
	} else {
		signer, err = gossh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}
	if err != nil {
		return nil, fmt.Errorf("ssh: parse server host private key: %w", err)
	}
	return signer, nil
}

func builtInAuthentication(users map[string]ServerUser) (
	func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error),
	func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error),
	bool,
	bool,
	error,
) {
	passwords := make(map[string]string)
	authorizedKeys := make(map[string][][]byte)
	for user, account := range users {
		if strings.TrimSpace(user) == "" {
			return nil, nil, false, false, errors.New("ssh: server user cannot be empty")
		}
		if account.Password != "" {
			passwords[user] = account.Password
		}
		for _, encoded := range account.AuthorizedKeys {
			key, _, _, _, err := gossh.ParseAuthorizedKey(encoded)
			if err != nil {
				return nil, nil, false, false, fmt.Errorf("ssh: parse authorized key for %q: %w", user, err)
			}
			authorizedKeys[user] = append(authorizedKeys[user], key.Marshal())
		}
	}

	var passwordCallback func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error)
	if len(passwords) != 0 {
		passwordCallback = func(metadata gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			expected, ok := passwords[metadata.User()]
			if !ok || subtle.ConstantTimeCompare(password, []byte(expected)) != 1 {
				return nil, errors.New("ssh: password authentication rejected")
			}
			return nil, nil
		}
	}

	var publicKeyCallback func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error)
	if len(authorizedKeys) != 0 {
		publicKeyCallback = func(metadata gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			for _, expected := range authorizedKeys[metadata.User()] {
				if bytes.Equal(expected, key.Marshal()) {
					return nil, nil
				}
			}
			return nil, errors.New("ssh: public key authentication rejected")
		}
	}
	return passwordCallback, publicKeyCallback, len(passwords) != 0, len(authorizedKeys) != 0, nil
}
