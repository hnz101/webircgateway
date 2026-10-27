package webircgateway

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

type LEManager struct {
	// ensure only one instance of the manager and handler is running
	// while allowing multiple listeners to use it
	Mutex   sync.Mutex
	Manager *autocert.Manager
	gateway *Gateway
}

func NewLetsEncryptManager(gateway *Gateway) *LEManager {
	return &LEManager{gateway: gateway}
}

func (le *LEManager) Get(certCacheDir string, allowedHosts []string) *autocert.Manager {
	le.Mutex.Lock()
	defer le.Mutex.Unlock()

	// Create it if it doesn't already exist
	if le.Manager == nil {
		var hostPolicy autocert.HostPolicy
		if len(allowedHosts) > 0 {
			hostPolicy = autocert.HostWhitelist(allowedHosts...)
		} else {
			hostPolicy = func(ctx context.Context, host string) error {
				if len(le.gateway.Config.RemoteOrigins) > 0 &&
					!le.gateway.IsClientOriginAllowed("https://"+host) &&
					!le.gateway.IsClientOriginAllowed(host) {
					return fmt.Errorf("host %s is not permitted for certificate issuance", host)
				}
				le.gateway.Log(2, "Automatically requesting a HTTPS certificate for %s", host)
				return nil
			}
		}

		le.Manager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(strings.TrimRight(certCacheDir, "/")),
			HostPolicy: hostPolicy,
		}
		le.gateway.HttpRouter.Handle("/.well-known/", le.Manager.HTTPHandler(nil))
	}

	return le.Manager
}
