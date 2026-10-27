package identd

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func MakeRpcClient(appName string) *RpcClient {
	return &RpcClient{AppName: appName}
}

type RpcClient struct {
	mu      sync.Mutex
	AppName string
	Conn    *net.Conn
}

func (rpc *RpcClient) ConnectAndReconnect(serverAddress string) {
	for {
		rpc.mu.Lock()
		isNil := rpc.Conn == nil
		rpc.mu.Unlock()

		if isNil {
			println("Connecting to identd RPC...")
			_ = rpc.Connect(serverAddress)
		}

		time.Sleep(time.Second * 3)
	}
}

func (rpc *RpcClient) Connect(serverAddress string) error {
	conn, err := net.DialTimeout("tcp", serverAddress, 5*time.Second)
	if err != nil {
		return err
	}

	rpc.mu.Lock()
	if rpc.Conn != nil {
		_ = (*rpc.Conn).Close()
	}
	rpc.Conn = &conn
	rpc.mu.Unlock()

	_ = rpc.Write("id " + sanitizeIdent(rpc.AppName))

	return nil
}

func (rpc *RpcClient) Write(line string) error {
	rpc.mu.Lock()
	defer rpc.mu.Unlock()

	if rpc.Conn == nil {
		return fmt.Errorf("not connected")
	}

	conn := *rpc.Conn
	_, err := conn.Write([]byte(line + "\n"))
	if err != nil {
		rpc.Conn = nil
		_ = conn.Close()
	}
	return err
}

func (rpc *RpcClient) AddIdent(lport int, rport int, username string, iface string) {
	_ = rpc.Write(fmt.Sprintf("add %s %d %d %s", sanitizeIdent(username), lport, rport, sanitizeIdent(iface)))
}

func (rpc *RpcClient) RemoveIdent(lport int, rport int, username string, iface string) {
	_ = rpc.Write(fmt.Sprintf("del %d %d %s", lport, rport, sanitizeIdent(iface)))
}
