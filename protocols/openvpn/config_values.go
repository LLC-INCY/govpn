package openvpn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func readCredentials(path string) (string, string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	return parseCredentials(value)
}

func parseCredentials(value []byte) (string, string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", "", err
		}
		return "", "", errors.New("credentials file is empty")
	}
	username := strings.TrimSuffix(scanner.Text(), "\r")
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", "", err
		}
		return "", "", errors.New("credentials file has no password line")
	}
	password := strings.TrimSuffix(scanner.Text(), "\r")
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return username, password, nil
}

func setInline(config *Config, name string, value []byte) error {
	switch name {
	case "ca":
		config.CA = append([]byte(nil), value...)
	case "cert":
		config.Cert = append([]byte(nil), value...)
	case "key":
		config.Key = append([]byte(nil), value...)
	case "tls-auth":
		config.TLSAuth = append([]byte(nil), value...)
	case "tls-crypt":
		config.TLSCrypt = append([]byte(nil), value...)
	case "auth-user-pass":
		username, password, err := parseCredentials(value)
		if err != nil {
			return err
		}
		config.Username, config.Password = username, password
	default:
		return fmt.Errorf("unsupported inline block <%s>", name)
	}
	return nil
}

func resolvePath(directory, value string) string {
	value = strings.Trim(value, "\"")
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(directory, value)
}
