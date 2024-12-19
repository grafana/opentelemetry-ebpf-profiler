package pyroscope

import (
	"context"
	"encoding/base64"
	"google.golang.org/grpc"
	"os"
	"strings"
	"sync"
)

func newBasicAuth(user string, passwordFile string) *basicAuthRPCCreds {
	basicAuth := func(username, password string) string {
		auth := username + ":" + password
		return base64.StdEncoding.EncodeToString([]byte(auth))
	}
	password, _ := os.ReadFile(passwordFile)
	return &basicAuthRPCCreds{
		header: "Basic " + basicAuth(user, strings.TrimSpace(string(password))),
	}
}

type basicAuthRPCCreds struct {
	header string
}

func (b *basicAuthRPCCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": b.header,
	}, nil
}

func (b *basicAuthRPCCreds) RequireTransportSecurity() bool {
	return false
}

var once sync.Once
var opt grpc.CallOption = nil

func GetCloudAuth() grpc.CallOption { //todo
	once.Do(func() {
		user := os.Getenv("PYROSCOPE_BASIC_AUTH_USER")
		passwordFile := os.Getenv("PYROSCOPE_BASIC_AUTH_PASSWORD_FILE")
		opt = grpc.PerRPCCredentials(newBasicAuth(user, passwordFile))
	})
	return opt
}
