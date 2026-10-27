package webircgateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
	"golang.org/x/time/rate"
)

const maxIrcLineLen = 8192

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isInternalOrRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return isPrivateIP(ip) ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func sanitizeIrcText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\x00' {
			return -1
		}
		return r
	}, s)
}

func sanitizeIrcToken(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\x00' || r == ' ' {
			return -1
		}
		return r
	}, s)
	cleaned = strings.TrimLeft(cleaned, ":")
	return cleaned
}

func splitClientLines(raw string) []string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	parts := strings.Split(normalized, "\n")
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		part = sanitizeIrcText(part)
		if part != "" {
			lines = append(lines, part)
		}
	}
	return lines
}

// readBoundedLine reads a line up to the buffer size of reader, discarding any excess bytes on overlong lines.
func readBoundedLine(reader *bufio.Reader) (string, error) {
	slice, err := reader.ReadSlice('\n')
	if err == nil {
		return string(slice), nil
	}
	if errors.Is(err, bufio.ErrBufferFull) {
		line := string(slice)
		// Discard the rest of the overlong line until '\n' or error
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = reader.ReadSlice('\n')
		}
		if err != nil {
			return line, err
		}
		return line, nil
	}
	return string(slice), err
}

// Username / realname / webirc hostname can all have configurable replacements
func makeClientReplacements(format string, client *Client) string {
	ret := format
	ret = strings.Replace(ret, "%a", sanitizeIrcToken(client.RemoteAddr), -1)
	ret = strings.Replace(ret, "%i", Ipv4ToHex(client.RemoteAddr), -1)
	ret = strings.Replace(ret, "%h", sanitizeIrcToken(client.RemoteHostname), -1)
	ret = strings.Replace(ret, "%n", sanitizeIrcToken(client.IrcState.Nick), -1)
	return ret
}

func Ipv4ToHex(ip string) string {
	var ipParts [4]int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &ipParts[0], &ipParts[1], &ipParts[2], &ipParts[3])
	ipHex := fmt.Sprintf("%02x%02x%02x%02x", ipParts[0], ipParts[1], ipParts[2], ipParts[3])
	return ipHex
}

func ensureUtf8(s string, fromEncoding string) string {
	if utf8.ValidString(s) {
		return s
	}

	encoding, encErr := charset.Lookup(fromEncoding)
	if encoding == nil {
		println("encErr:", encErr)
		return ""
	}

	d := encoding.NewDecoder()
	s2, _ := d.String(s)
	return s2
}

func utf8ToOther(s string, toEncoding string) string {
	if toEncoding == "UTF-8" && utf8.ValidString(s) {
		return s
	}

	encoding, _ := charset.Lookup(toEncoding)
	if encoding == nil {
		return ""
	}

	e := encoding.NewEncoder()
	s2, _ := e.String(s)
	return s2
}

func containsOneOf(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}

	return false
}

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func stringInSliceOrDefault(s, def string, validStrings []string) string {
	if stringInSlice(s, validStrings) {
		return s
	}
	return def
}

type ThrottledStringChannel struct {
	in     chan string
	Input  chan<- string
	out    chan string
	Output <-chan string
	*rate.Limiter
}

func NewThrottledStringChannel(wrappedChan chan string, limiter *rate.Limiter) *ThrottledStringChannel {
	out := make(chan string, 50)

	c := &ThrottledStringChannel{
		in:      wrappedChan,
		Input:   wrappedChan,
		out:     out,
		Output:  out,
		Limiter: limiter,
	}

	go c.run()

	return c
}

func (c *ThrottledStringChannel) run() {
	for msg := range c.in {
		// start := time.Now()
		c.Wait(context.Background())
		c.out <- msg
		// elapsed := time.Since(start)
		// fmt.Printf("waited %v to send %v\n", elapsed, msg)
	}

	close(c.out)
}
