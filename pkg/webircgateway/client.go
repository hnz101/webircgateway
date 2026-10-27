package webircgateway

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/kiwiirc/webircgateway/pkg/dnsbl"
	"github.com/kiwiirc/webircgateway/pkg/irc"
	"github.com/kiwiirc/webircgateway/pkg/proxy"
)

const (
	// ClientStateIdle - Client connected and just sat there
	ClientStateIdle = "idle"
	// ClientStateConnecting - Connecting upstream
	ClientStateConnecting = "connecting"
	// ClientStateRegistering - Registering to the IRC network
	ClientStateRegistering = "registering"
	// ClientStateConnected - Connected upstream
	ClientStateConnected = "connected"
	// ClientStateEnding - Client is ending its connection
	ClientStateEnding = "ending"
)

type ClientSignal [3]string

// Client - Connecting client struct
type Client struct {
	Gateway          *Gateway
	Id               uint64
	State            string
	EndWG            sync.WaitGroup
	shuttingDownLock sync.Mutex
	shuttingDown     bool
	SeenQuit         bool
	Recv             chan string
	ThrottledRecv    *ThrottledStringChannel
	upstreamLock     sync.Mutex
	upstream         io.ReadWriteCloser
	UpstreamRecv     chan string
	UpstreamSend     chan string
	UpstreamStarted  bool
	UpstreamConfig   *ConfigUpstream
	RemoteAddr       string
	RemoteHostname   string
	RemotePort       int
	DestHost         string
	DestPort         int
	DestTLS          bool
	IrcState         *irc.State
	Encoding         string
	// Tags get passed upstream via the WEBIRC command
	Tags map[string]string
	// Captchas may be needed to verify a client
	RequiresVerification bool
	Verified             bool
	SentPass             bool
	// Signals for the transport to make use of (data, connection state, etc)
	Signals  chan ClientSignal
	Features struct {
		Messagetags bool
		Metadata    bool
		ExtJwt      bool
	}
	// The specific message-tags CAP that the client has requested if we are wrapping it
	RequestedMessageTagsCap string
	// Prefix used by the server when sending its own messages
	ServerMessagePrefix irc.Mask
}

var nextClientID uint64 = 1

// NewClient - Makes a new client
func NewClient(gateway *Gateway) *Client {
	thisID := atomic.AddUint64(&nextClientID, 1)

	recv := make(chan string, 50)
	c := &Client{
		Gateway:        gateway,
		Id:             thisID,
		State:          ClientStateIdle,
		Recv:           recv,
		ThrottledRecv:  NewThrottledStringChannel(recv, rate.NewLimiter(rate.Inf, 1)),
		UpstreamSend:   make(chan string, 50),
		UpstreamRecv:   make(chan string, 50),
		Encoding:       "UTF-8",
		Signals:        make(chan ClientSignal, 50),
		Tags:           make(map[string]string),
		IrcState:       irc.NewState(),
		UpstreamConfig: &ConfigUpstream{},
	}

	// Auto enable some features by default. They may be disabled later on
	gateway.Config.RLock()
	c.Features.ExtJwt = gateway.Config.Secret != ""
	c.RequiresVerification = gateway.Config.RequiresVerification
	gateway.Config.RUnlock()

	// Handles data to/from the client and upstreams
	go c.clientLineWorker()

	// This Add(1) will be ended once the client starts shutting down in StartShutdown()
	c.EndWG.Add(1)

	// Add to the clients maps and wait until everything has been marked
	// as completed (several routines add themselves to EndWG so that we can catch
	// when they are all completed)
	gateway.Clients.Set(strconv.FormatUint(c.Id, 10), c)
	go func() {
		c.EndWG.Wait()
		gateway.Clients.Remove(strconv.FormatUint(c.Id, 10))

		hook := &HookClientState{
			Client:    c,
			Connected: false,
		}
		hook.Dispatch("client.state")
	}()

	hook := &HookClientState{
		Client:    c,
		Connected: true,
	}
	hook.Dispatch("client.state")

	return c
}

// Log - Log a line of text with context of this client
func (c *Client) Log(level int, format string, args ...interface{}) {
	prefix := fmt.Sprintf("client:%d ", c.Id)
	c.Gateway.Log(level, prefix+format, args...)
}

// TrafficLog - Log out raw IRC traffic
func (c *Client) TrafficLog(isUpstream bool, toGateway bool, traffic string) {
	label := ""
	if isUpstream && toGateway {
		label = "Upstream->"
	} else if isUpstream && !toGateway {
		label = "->Upstream"
	} else if !isUpstream && toGateway {
		label = "Client->"
	} else if !isUpstream && !toGateway {
		label = "->Client"
	}
	c.Log(1, "Traffic (%s) %s", label, traffic)
}

func (c *Client) Ready() {
	c.Gateway.Config.RLock()
	dnsblAction := c.Gateway.Config.DnsblAction
	dnsblServers := c.Gateway.Config.DnsblServers
	requiresVerification := c.Gateway.Config.RequiresVerification
	c.Gateway.Config.RUnlock()

	validAction := dnsblAction == "verify" || dnsblAction == "deny"
	dnsblTookAction := ""

	if len(dnsblServers) > 0 && c.RemoteAddr != "" && !c.Verified && validAction {
		dnsblTookAction = c.checkDnsBl()
	}

	if dnsblTookAction == "" && requiresVerification && !c.Verified {
		c.SendClientSignal("data", "CAPTCHA NEEDED")
	}
}

func (c *Client) checkDnsBl() (tookAction string) {
	c.Gateway.Config.RLock()
	dnsblServers := c.Gateway.Config.DnsblServers
	dnsblAction := c.Gateway.Config.DnsblAction
	c.Gateway.Config.RUnlock()

	dnsResult := dnsbl.Lookup(dnsblServers, c.RemoteAddr)
	if dnsResult.Listed && dnsblAction == "deny" {
		c.SendIrcError("Blocked by DNSBL")
		c.SendClientSignal("state", "closed", "dnsbl_listed")
		c.StartShutdown("dnsbl")
		tookAction = "deny"
	} else if dnsResult.Listed && dnsblAction == "verify" {
		c.RequiresVerification = true
		c.SendClientSignal("data", "CAPTCHA NEEDED")
		tookAction = "verify"
	}

	return
}

func (c *Client) IsShuttingDown() bool {
	c.shuttingDownLock.Lock()
	defer c.shuttingDownLock.Unlock()
	return c.shuttingDown
}

func (c *Client) setUpstream(u io.ReadWriteCloser) {
	c.upstreamLock.Lock()
	c.upstream = u
	c.upstreamLock.Unlock()
}

func (c *Client) getUpstream() io.ReadWriteCloser {
	c.upstreamLock.Lock()
	u := c.upstream
	c.upstreamLock.Unlock()
	return u
}

func (c *Client) closeUpstream() {
	c.upstreamLock.Lock()
	u := c.upstream
	c.upstream = nil
	c.upstreamLock.Unlock()
	if u != nil {
		_ = u.Close()
	}
}

func (c *Client) StartShutdown(reason string) {
	c.shuttingDownLock.Lock()
	defer c.shuttingDownLock.Unlock()

	c.Log(1, "StartShutdown(%s) ShuttingDown=%t", reason, c.shuttingDown)
	if !c.shuttingDown {
		c.shuttingDown = true
		c.State = ClientStateEnding

		switch reason {
		case "upstream_closed":
			c.Log(2, "Upstream closed the connection")
		case "err_connecting_upstream":
		case "err_no_upstream":
			// Error has been logged already
		case "client_closed":
			c.Log(2, "Client disconnected")
		default:
			c.Log(2, "Closed: %s", reason)
		}

		close(c.Signals)
		c.EndWG.Done()
	}
}

func (c *Client) SendClientSignal(signal string, args ...string) {
	c.shuttingDownLock.Lock()
	defer c.shuttingDownLock.Unlock()

	if !c.shuttingDown {
		switch len(args) {
		case 0:
			c.Signals <- ClientSignal{signal}
		case 1:
			c.Signals <- ClientSignal{signal, args[0]}
		case 2:
			c.Signals <- ClientSignal{signal, args[0], args[1]}
		}
	}
}

func (c *Client) SendIrcError(message string) {
	c.SendClientSignal("data", "ERROR :"+message)
}

func (c *Client) SendIrcFail(params ...string) {
	failMessage := irc.Message{
		Command: "FAIL",
		Params:  params,
	}
	c.SendClientSignal("data", failMessage.ToLine())
}

func (c *Client) connectUpstream() {
	client := c

	c.UpstreamStarted = true

	var upstreamConfig ConfigUpstream

	if client.DestHost == "" {
		client.Log(2, "Using configured upstream")
		var err error
		upstreamConfig, err = c.Gateway.findUpstream()
		if err != nil {
			client.Log(3, "No upstreams available")
			client.SendIrcError("The server has not been configured")
			client.StartShutdown("err_no_upstream")
			return
		}
	} else {
		if !c.Gateway.isIrcAddressAllowed(client.DestHost) || client.DestPort < 1024 || client.DestPort > 65535 {
			client.Log(2, "Server %s:%d is not allowed. Closing connection", client.DestHost, client.DestPort)
			client.SendIrcError("Not allowed to connect to " + client.DestHost)
			client.SendClientSignal("state", "closed", "err_forbidden")
			client.StartShutdown("err_no_upstream")
			return
		}

		client.Log(2, "Using client given upstream")
		upstreamConfig = c.configureUpstream()
	}

	c.UpstreamConfig = &upstreamConfig

	hook := &HookIrcConnectionPre{
		Client:         client,
		UpstreamConfig: &upstreamConfig,
	}
	hook.Dispatch("irc.connection.pre")
	if hook.Halt {
		client.SendClientSignal("state", "closed", "err_forbidden")
		client.StartShutdown("err_connecting_upstream")
		return
	}

	client.State = ClientStateConnecting

	upstream, upstreamErr := client.makeUpstreamConnection()
	if upstreamErr != nil {
		// Error handling was already managed in makeUpstreamConnection()
		return
	}

	client.State = ClientStateRegistering

	client.setUpstream(upstream)
	client.readUpstream()
	client.writeWebircLines(upstream)
	client.maybeSendPass(upstream)
	client.SendClientSignal("state", "connected")
}

func (c *Client) makeUpstreamConnection() (io.ReadWriteCloser, error) {
	client := c
	upstreamConfig := c.UpstreamConfig

	var connection io.ReadWriteCloser

	if upstreamConfig.Proxy == nil {
		// Connect directly to the IRCd
		dialer := net.Dialer{}
		dialer.Timeout = time.Second * time.Duration(upstreamConfig.Timeout)

		if upstreamConfig.LocalAddr != "" {
			parsedIP := net.ParseIP(upstreamConfig.LocalAddr)
			if parsedIP != nil {
				dialer.LocalAddr = &net.TCPAddr{
					IP:   parsedIP,
					Port: 0,
				}
			} else {
				client.Log(3, "Failed to parse localaddr for upstream connection \"%s\"", upstreamConfig.LocalAddr)
			}
		}

		if client.DestHost != "" {
			dialer.Control = func(network, address string, c syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip := net.ParseIP(host)
				if isInternalOrRestrictedIP(ip) {
					return errors.New("connection to internal or restricted IP is not allowed")
				}
				return nil
			}
		}

		var conn net.Conn
		var connErr error
		if upstreamConfig.Protocol == "unix" {
			conn, connErr = dialer.Dial("unix", upstreamConfig.Hostname)
		} else {
			upstreamStr := net.JoinHostPort(upstreamConfig.Hostname, strconv.Itoa(upstreamConfig.Port))
			conn, connErr = dialer.Dial(upstreamConfig.Protocol, upstreamStr)
		}

		if connErr != nil {
			client.Log(3, "Error connecting to the upstream IRCd. %s", connErr.Error())
			errString := ""
			if errString = typeOfErr(connErr); errString != "" {
				errString = "err_" + errString
			}
			client.SendClientSignal("state", "closed", errString)
			client.StartShutdown("err_connecting_upstream")
			return nil, errors.New("error connecting upstream")
		}

		// Add the ports into the identd before possible TLS handshaking. If we do it after then
		// there's a good chance the identd lookup will occur before the handshake has finished
		c.Gateway.Config.RLock()
		identdEnabled := c.Gateway.Config.Identd
		c.Gateway.Config.RUnlock()
		if identdEnabled {
			// Keep track of the upstreams local and remote port numbers
			_, lPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
			client.IrcState.LocalPort, _ = strconv.Atoi(lPortStr)
			_, rPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
			client.IrcState.RemotePort, _ = strconv.Atoi(rPortStr)

			c.Gateway.identdServ.AddIdent(client.IrcState.LocalPort, client.IrcState.RemotePort, client.IrcState.Username, "")
		}

		if upstreamConfig.TLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: !upstreamConfig.TLSVerify,
				ServerName:         upstreamConfig.Hostname,
			}
			tlsConn := tls.Client(conn, tlsConfig)
			if upstreamConfig.Timeout > 0 {
				_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(upstreamConfig.Timeout)))
			}
			err := tlsConn.Handshake()
			_ = conn.SetDeadline(time.Time{})
			if err != nil {
				conn.Close()
				if identdEnabled && client.IrcState.RemotePort > 0 {
					c.Gateway.identdServ.RemoveIdent(client.IrcState.LocalPort, client.IrcState.RemotePort, "")
				}
				client.Log(3, "Error connecting to the upstream IRCd. %s", err.Error())
				client.SendClientSignal("state", "closed", "err_tls")
				client.StartShutdown("err_connecting_upstream")
				return nil, errors.New("error connecting upstream")
			}

			conn = net.Conn(tlsConn)
		}

		connection = conn
	}

	if upstreamConfig.Proxy != nil {
		// Connect to the IRCd via a proxy
		conn := proxy.MakeKiwiProxyConnection()
		conn.DestHost = upstreamConfig.Hostname
		conn.DestPort = upstreamConfig.Port
		conn.DestTLS = upstreamConfig.TLS
		conn.DestTLSVerify = upstreamConfig.TLSVerify
		conn.Username = upstreamConfig.Proxy.Username
		conn.ProxyInterface = upstreamConfig.Proxy.Interface

		dialErr := conn.Dial(net.JoinHostPort(
			upstreamConfig.Proxy.Hostname,
			strconv.Itoa(upstreamConfig.Proxy.Port),
		))

		if dialErr != nil {
			errString := ""
			if errString = typeOfErr(dialErr); errString != "" {
				errString = "err_" + errString
			} else {
				errString = "err_proxy"
			}
			client.Log(3,
				"Error connecting to the kiwi proxy, %s:%d. %s",
				upstreamConfig.Proxy.Hostname,
				upstreamConfig.Proxy.Port,
				dialErr.Error(),
			)

			client.SendClientSignal("state", "closed", errString)
			client.StartShutdown("err_connecting_upstream")
			return nil, errors.New("error connecting upstream")
		}

		connection = conn
	}

	return connection, nil
}

func (c *Client) writeWebircLines(upstream io.ReadWriteCloser) {
	// Send any WEBIRC lines
	if c.UpstreamConfig.WebircPassword == "" {
		c.Log(1, "No webirc to send")
		return
	}

	c.Gateway.Config.RLock()
	cfgGatewayName := c.Gateway.Config.GatewayName
	cfgClientHostname := c.Gateway.Config.ClientHostname
	c.Gateway.Config.RUnlock()

	gatewayName := "webircgateway"
	if cfgGatewayName != "" {
		gatewayName = cfgGatewayName
	}
	if c.UpstreamConfig.GatewayName != "" {
		gatewayName = c.UpstreamConfig.GatewayName
	}
	gatewayName = sanitizeIrcToken(gatewayName)
	if gatewayName == "" {
		gatewayName = "webircgateway"
	}

	webircTags := c.buildWebircTags()
	if strings.Contains(webircTags, " ") {
		webircTags = ":" + webircTags
	}

	clientHostname := c.RemoteHostname
	if cfgClientHostname != "" {
		clientHostname = makeClientReplacements(cfgClientHostname, c)
	}
	clientHostname = sanitizeIrcToken(clientHostname)
	if clientHostname == "" {
		clientHostname = sanitizeIrcToken(c.RemoteAddr)
	}

	remoteAddr := sanitizeIrcToken(c.RemoteAddr)
	// Prefix IPv6 addresses that start with a : so they can be sent as an individual IRC
	//  parameter. eg. ::1 would not parse correctly as a parameter, while 0::1 will
	if strings.HasPrefix( c.RemoteAddr, ":") {
		remoteAddr = "0" + sanitizeIrcText(strings.ReplaceAll(c.RemoteAddr, " ", ""))
	}

	webircLine := fmt.Sprintf(
		"WEBIRC %s %s %s %s %s\n",
		sanitizeIrcToken(c.UpstreamConfig.WebircPassword),
		gatewayName,
		clientHostname,
		remoteAddr,
		webircTags,
	)
	c.Log(1, "->upstream: %s", webircLine)
	upstream.Write([]byte(webircLine))
}

func (c *Client) maybeSendPass(upstream io.ReadWriteCloser) {
	if c.UpstreamConfig.ServerPassword == "" {
		return
	}
	c.SentPass = true
	passLine := fmt.Sprintf(
		"PASS %s\n",
		sanitizeIrcText(c.UpstreamConfig.ServerPassword),
	)
	c.Log(1, "->upstream: %s", passLine)
	upstream.Write([]byte(passLine))
}

func (c *Client) processLineToUpstream(data string) {
	client := c
	upstreamConfig := c.UpstreamConfig

	data = sanitizeIrcText(data)
	message, parseErr := irc.ParseLine(data)
	if parseErr == nil {
		cmdUpper := strings.ToUpper(message.Command)
		if cmdUpper == "PASS" && c.SentPass {
			// Hijack the PASS command if we already sent a pass command
			return
		} else if cmdUpper == "USER" {
			// Hijack the USER command as we may have some overrides
			username := sanitizeIrcToken(client.IrcState.Username)
			if username == "" {
				username = "webirc"
			}
			realname := sanitizeIrcText(client.IrcState.RealName)
			data = fmt.Sprintf(
				"USER %s 0 * :%s",
				username,
				realname,
			)
			message, _ = irc.ParseLine(data)
		} else if cmdUpper == "QUIT" {
			client.SeenQuit = true
		}
	}

	hook := &HookIrcLine{
		Client:         client,
		UpstreamConfig: upstreamConfig,
		Line:           data,
		Message:        message,
		ToServer:       true,
	}
	hook.Dispatch("irc.line")
	if hook.Halt {
		return
	}

	// Plugins may have modified the data
	data = hook.Line

	c.TrafficLog(true, false, data)
	data = utf8ToOther(data, client.Encoding)
	if data == "" {
		client.Log(1, "Failed to encode into '%s'. Dropping data", c.Encoding)
		return
	}

	if u := client.getUpstream(); u != nil {
		u.Write([]byte(data + "\r\n"))
	} else {
		client.Log(2, "Tried sending data upstream before connected")
	}
}

func (c *Client) handleLineFromUpstream(data string) {
	client := c
	upstreamConfig := c.UpstreamConfig

	message, _ := irc.ParseLine(data)

	hook := &HookIrcLine{
		Client:         client,
		UpstreamConfig: upstreamConfig,
		Line:           data,
		Message:        message,
		ToServer:       false,
	}
	hook.Dispatch("irc.line")
	if hook.Halt {
		return
	}

	// Plugins may have modified the data
	data = hook.Line

	if data == "" {
		return
	}

	data = ensureUtf8(data, client.Encoding)
	if data == "" {
		client.Log(1, "Failed to decode as 'UTF-8'. Dropping data")
		return
	}

	data = client.ProcessLineFromUpstream(data)
	if data == "" {
		return
	}

	client.SendClientSignal("data", data)
}

func typeOfErr(err error) string {
	if err == nil {
		return ""
	}

	if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return "timeout"
	}

	switch t := err.(type) {
	case *proxy.ConnError:
		switch t.Type {
		case "conn_reset":
			return ""
		case "conn_refused":
			return "refused"
		case "not_found":
			return "unknown_host"
		case "conn_timeout":
			return "timeout"
		default:
			return ""
		}

	case *net.OpError:
		if t.Op == "dial" {
			return "unknown_host"
		} else if t.Op == "read" {
			return "refused"
		}

	case syscall.Errno:
		if t == syscall.ECONNREFUSED {
			return "refused"
		}
	}

	return ""
}

func (c *Client) readUpstream() {
	client := c
	upstream := client.getUpstream()
	if upstream == nil {
		return
	}

	// Data from upstream to client
	go func() {
		reader := bufio.NewReaderSize(upstream, maxIrcLineLen)
		for {
			data, err := readBoundedLine(reader)
			if err != nil {
				break
			}

			data = strings.Trim(data, "\n\r")
			client.UpstreamRecv <- data
		}

		close(client.UpstreamRecv)
		client.closeUpstream()

		if client.IrcState.RemotePort > 0 {
			c.Gateway.identdServ.RemoveIdent(client.IrcState.LocalPort, client.IrcState.RemotePort, "")
		}
	}()
}

// Handle lines sent from the client
func (c *Client) clientLineWorker() {
	for {
		shouldQuit, _ := c.handleDataLine()
		if shouldQuit {
			break
		}

	}

	c.Log(1, "leaving clientLineWorker")
}

func (c *Client) handleDataLine() (shouldQuit bool, hadErr bool) {
	defer func() {
		if err := recover(); err != nil {
			c.Log(3, fmt.Sprint("Error handling data ", err))
			fmt.Println("Error handling data", err)
			debug.PrintStack()
			shouldQuit = false
			hadErr = true
		}
	}()

	// We only want to send data upstream if we have an upstream connection
	upstreamSend := c.UpstreamSend
	if c.getUpstream() == nil {
		upstreamSend = nil
	}

	select {
	case clientData, ok := <-c.ThrottledRecv.Output:
		if !ok {
			c.Log(1, "client.Recv closed")
			c.Gateway.Config.RLock()
			quitMsg := c.Gateway.Config.SendQuitOnClientClose
			c.Gateway.Config.RUnlock()

			if !c.SeenQuit && quitMsg != "" && (c.State == ClientStateConnected || c.State == ClientStateEnding) {
				c.processLineToUpstream("QUIT :" + quitMsg)
			}

			c.StartShutdown("client_closed")
			c.closeUpstream()
			return true, false
		}
		c.Log(1, "in c.ThrottledRecv.Output")
		c.TrafficLog(false, true, clientData)

		clientLine, err := c.ProcessLineFromClient(clientData)
		if err == nil && clientLine != "" {
			select {
			case c.UpstreamSend <- clientLine:
			default:
				c.Log(3, "UpstreamSend queue full. Dropping data")
			}
		}

	case line, ok := <-upstreamSend:
		if !ok {
			c.Log(1, "client.UpstreamSend closed")
			return true, false
		}
		c.Log(1, "in .UpstreamSend")
		c.processLineToUpstream(line)

	case upstreamData, ok := <-c.UpstreamRecv:
		if !ok {
			c.Log(1, "client.UpstreamRecv closed")
			c.SendClientSignal("state", "closed")
			c.StartShutdown("upstream_closed")
			return true, false
		}
		c.Log(1, "in .UpstreamRecv")
		c.TrafficLog(true, true, upstreamData)

		c.handleLineFromUpstream(upstreamData)
	}

	return false, false
}

// configureUpstream - Generate an upstream configuration from the information set on the client instance
func (c *Client) configureUpstream() ConfigUpstream {
	c.Gateway.Config.RLock()
	tlsVerify := c.Gateway.Config.GatewayTLSVerify
	timeout := c.Gateway.Config.GatewayTimeout
	throttle := c.Gateway.Config.GatewayThrottle
	protocol := c.Gateway.Config.GatewayProtocol
	localAddr := c.Gateway.Config.GatewayLocalAddr
	c.Gateway.Config.RUnlock()

	upstreamConfig := ConfigUpstream{}
	upstreamConfig.Hostname = c.DestHost
	upstreamConfig.Port = c.DestPort
	upstreamConfig.TLS = c.DestTLS
	upstreamConfig.TLSVerify = tlsVerify
	upstreamConfig.Timeout = timeout
	upstreamConfig.Throttle = throttle
	upstreamConfig.WebircPassword = c.Gateway.findWebircPassword(c.DestHost)
	upstreamConfig.Protocol = protocol
	upstreamConfig.LocalAddr = localAddr

	return upstreamConfig
}

func (c *Client) buildWebircTags() string {
	str := ""
	for key, val := range c.Tags {
		cleanKey := sanitizeIrcToken(key)
		if cleanKey == "" {
			continue
		}
		cleanVal := sanitizeIrcToken(val)

		if str != "" {
			str += " "
		}

		if cleanVal == "" {
			str += cleanKey
		} else {
			str += cleanKey + "=" + cleanVal
		}
	}

	return str
}
