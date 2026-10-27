package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kiwiirc/webircgateway/pkg/identd"
)

const (
	ResponseError       = "0"
	ResponseOK          = "1"
	ResponseReset       = "2"
	ResponseRefused     = "3"
	ResponseUnknownHost = "4"
	ResponseTimeout     = "5"
)

var identdRpc *identd.RpcClient
var Server net.Listener

type HandshakeMeta struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TLS       bool   `json:"ssl"`
	TLSVerify bool   `json:"tls_verify"`
	Username  string `json:"username"`
	Interface string `json:"interface"`
}

func MakeClient(conn net.Conn) *Client {
	return &Client{
		Client: conn,
	}
}

type Client struct {
	Client       net.Conn
	ClientReader io.Reader
	Upstream     net.Conn
	UpstreamAddr *net.TCPAddr
	Host         string
	Username     string
	BindAddr     *net.TCPAddr
	TLS          bool
	TLSVerify    bool
}

func (c *Client) Run() {
	var err error

	err = c.Handshake()
	if err != nil {
		log.Println(err.Error())
		c.Client.Close()
		return
	}

	err = c.ConnectUpstream()
	if err != nil {
		log.Println(err.Error())
		c.Client.Close()
		return
	}

	c.Pipe()
}

func (c *Client) Handshake() error {
	_ = c.Client.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.Client.SetDeadline(time.Time{})

	// Read the first line - it should be JSON (bounded to 4096 bytes)
	reader := bufio.NewReaderSize(c.Client, 4096)
	c.ClientReader = reader
	line, readErr := reader.ReadSlice('\n')
	if readErr != nil {
		c.Client.Write([]byte(ResponseError))
		return readErr
	}

	var meta = HandshakeMeta{
		Username:  "user",
		Port:      6667,
		Interface: "0.0.0.0",
		TLSVerify: true,
	}
	unmarshalErr := json.Unmarshal(line, &meta)
	if unmarshalErr != nil {
		c.Client.Write([]byte(ResponseError))
		return unmarshalErr
	}

	if meta.Host == "" || meta.Port < 1024 || meta.Port > 65535 || meta.Username == "" || meta.Interface == "" {
		c.Client.Write([]byte(ResponseError))
		return fmt.Errorf("missing or invalid args")
	}

	c.Host = meta.Host
	c.Username = meta.Username
	c.TLS = meta.TLS
	c.TLSVerify = meta.TLSVerify

	bindAddr, bindAddrErr := net.ResolveTCPAddr("tcp", meta.Interface+":")
	if bindAddrErr != nil {
		c.Client.Write([]byte(ResponseError))
		return fmt.Errorf("interface: %w", bindAddrErr)
	}
	c.BindAddr = bindAddr

	hostStr := net.JoinHostPort(meta.Host, strconv.Itoa(meta.Port))
	addr, addrErr := net.ResolveTCPAddr("tcp", hostStr)
	if addrErr != nil {
		c.Client.Write([]byte(ResponseUnknownHost))
		return fmt.Errorf("remote host: %w", addrErr)
	}
	if addr.IP == nil || addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() || addr.IP.IsMulticast() || addr.IP.IsUnspecified() {
		c.Client.Write([]byte(ResponseError))
		return fmt.Errorf("restricted remote host: %s", meta.Host)
	}
	c.UpstreamAddr = addr

	return nil
}

func (c *Client) ConnectUpstream() error {
	dialer := &net.Dialer{}
	dialer.LocalAddr = c.BindAddr
	dialer.Timeout = time.Second * 10

	conn, err := dialer.Dial("tcp", c.UpstreamAddr.String())
	if err != nil {
		response := ResponseError
		errType := typeOfErr(err)
		switch errType {
		case "timeout":
			response = ResponseTimeout
		case "unknown_host":
			response = ResponseUnknownHost
		case "refused":
			response = ResponseRefused
		}

		c.Client.Write([]byte(response))
		return err
	}

	if identdRpc != nil {
		lAddr, lPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
		lPort, _ := strconv.Atoi(lPortStr)
		identdRpc.AddIdent(lPort, c.UpstreamAddr.Port, c.Username, lAddr)
	}

	if c.TLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !c.TLSVerify,
			ServerName:         c.Host,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		err := tlsConn.Handshake()
		_ = conn.SetDeadline(time.Time{})
		if err != nil {
			conn.Close()
			if identdRpc != nil {
				lAddr, lPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
				lPort, _ := strconv.Atoi(lPortStr)
				identdRpc.RemoveIdent(lPort, c.UpstreamAddr.Port, c.Username, lAddr)
			}
			c.Client.Write([]byte(ResponseReset))
			return err
		}

		conn = net.Conn(tlsConn)
	}

	c.Upstream = conn
	c.Client.Write([]byte(ResponseOK))
	return nil
}

func (c *Client) Pipe() {
	wg := sync.WaitGroup{}
	wg.Add(2)

	clientReader := c.ClientReader
	if clientReader == nil {
		clientReader = c.Client
	}

	go func() {
		io.Copy(c.Client, c.Upstream)
		c.Client.Close()
		wg.Done()
	}()

	go func() {
		io.Copy(c.Upstream, clientReader)
		c.Upstream.Close()
		wg.Done()
	}()

	wg.Wait()

	if identdRpc != nil {
		lAddr, lPortStr, _ := net.SplitHostPort(c.Upstream.LocalAddr().String())
		lPort, _ := strconv.Atoi(lPortStr)
		identdRpc.RemoveIdent(lPort, c.UpstreamAddr.Port, c.Username, lAddr)
	}
}

func Start(laddr string) {
	srv, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Expose the server
	Server = srv
	log.Printf("Kiwi proxy listening on %s", srv.Addr().String())

	identdRpc = identd.MakeRpcClient("kiwiproxy" + laddr)
	go identdRpc.ConnectAndReconnect("127.0.0.1:1133")

	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Print(err.Error())
			break
		}

		c := MakeClient(conn)
		go c.Run()
	}
}

func typeOfErr(err error) string {
	if err == nil {
		return ""
	}

	if netError, ok := err.(net.Error); ok && netError.Timeout() {
		return "timeout"
	}

	switch t := err.(type) {
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
