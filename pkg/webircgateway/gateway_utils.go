package webircgateway

import (
	"errors"
	"math/rand"
	"net"
	"net/http"
	"strings"
)

var v4LoopbackAddr = net.ParseIP("127.0.0.1")

func (s *Gateway) NewClient() *Client {
	return NewClient(s)
}

func (s *Gateway) IsClientOriginAllowed(originHeader string) bool {
	s.Config.RLock()
	origins := s.Config.RemoteOrigins
	s.Config.RUnlock()

	// Empty list of origins = all origins allowed
	if len(origins) == 0 {
		return true
	}

	// No origin header = running on the same page
	if originHeader == "" {
		return true
	}

	originLower := strings.ToLower(originHeader)
	foundMatch := false

	for _, originMatch := range origins {
		if originMatch.Match(originLower) {
			foundMatch = true
			break
		}
	}

	return foundMatch
}

func (s *Gateway) isIrcAddressAllowed(addr string) bool {
	if addr == "" {
		return false
	}

	addrLower := strings.ToLower(strings.TrimSpace(addr))
	if addrLower == "localhost" || strings.HasSuffix(addrLower, ".localhost") {
		return false
	}

	if ip := net.ParseIP(addrLower); ip != nil {
		if isInternalOrRestrictedIP(ip) {
			return false
		}
	} else if ips, err := net.LookupIP(addrLower); err == nil {
		for _, ip := range ips {
			if isInternalOrRestrictedIP(ip) {
				return false
			}
		}
	}

	s.Config.RLock()
	whitelist := s.Config.GatewayWhitelist
	s.Config.RUnlock()

	// Empty whitelist = all public destinations allowed
	if len(whitelist) == 0 {
		return true
	}

	foundMatch := false

	for _, addrMatch := range whitelist {
		if addrMatch.Match(addrLower) {
			foundMatch = true
			break
		}
	}

	return foundMatch
}

func (s *Gateway) findUpstream() (ConfigUpstream, error) {
	var ret ConfigUpstream

	s.Config.RLock()
	defer s.Config.RUnlock()

	if len(s.Config.Upstreams) == 0 {
		return ret, errors.New("No upstreams available")
	}

	randIdx := rand.Intn(len(s.Config.Upstreams))
	ret = s.Config.Upstreams[randIdx]

	return ret, nil
}

func (s *Gateway) findWebircPassword(ircHost string) string {
	s.Config.RLock()
	defer s.Config.RUnlock()

	pass, exists := s.Config.GatewayWebircPassword[strings.ToLower(ircHost)]
	if !exists {
		pass = ""
	}

	return pass
}

func (s *Gateway) GetRemoteAddressFromRequest(req *http.Request) net.IP {
	remoteIP := remoteIPFromRequest(req)

	// If the remoteIP is not in a whitelisted reverse proxy range, don't trust
	// the headers and use the remoteIP as the users IP
	if !s.isTrustedProxy(remoteIP) {
		return remoteIP
	}

	headerVal := req.Header.Get("x-forwarded-for")
	if headerVal != "" {
		ips := strings.Split(headerVal, ",")
		// Walk backwards from right to left to find the first untrusted IP
		for i := len(ips) - 1; i >= 0; i-- {
			ipStr := strings.TrimSpace(ips[i])
			if ip := net.ParseIP(ipStr); ip != nil {
				if !s.isTrustedProxy(ip) || i == 0 {
					return ip
				}
			}
		}
	}

	return remoteIP
}

func (s *Gateway) isRequestSecure(req *http.Request) bool {
	remoteIP := remoteIPFromRequest(req)

	// If the remoteIP is not in a whitelisted reverse proxy range, don't trust
	// the headers and check the request directly
	if !s.isTrustedProxy(remoteIP) {
		return req.TLS != nil
	}

	fwdProto := req.Header.Get("x-forwarded-proto")
	return req.TLS != nil || strings.EqualFold(fwdProto, "https")
}

func (s *Gateway) isTrustedProxy(remoteIP net.IP) bool {
	if remoteIP == nil {
		return false
	}

	s.Config.RLock()
	defer s.Config.RUnlock()

	for _, cidrRange := range s.Config.ReverseProxies {
		if cidrRange.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func remoteIPFromRequest(req *http.Request) net.IP {
	if req.RemoteAddr == "@" {
		// remote address is unix socket, treat it as loopback interface
		return v4LoopbackAddr
	}

	remoteAddr, _, _ := net.SplitHostPort(req.RemoteAddr)
	return net.ParseIP(remoteAddr)
}
