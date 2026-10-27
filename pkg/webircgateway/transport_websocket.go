package webircgateway

import (
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

type TransportWebsocket struct {
	gateway  *Gateway
	upgrader websocket.Upgrader
}

func (t *TransportWebsocket) Init(g *Gateway) {
	t.gateway = g
	t.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return t.gateway.IsClientOriginAllowed(origin)
		},
		Subprotocols: []string{"text.ircv3.net", "binary.ircv3.net"},
	}
	t.gateway.HttpRouter.HandleFunc("/webirc/websocket/", t.websocketHandler)
}

func (t *TransportWebsocket) websocketHandler(w http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if !t.gateway.IsClientOriginAllowed(origin) {
		t.gateway.Log(2, "Origin %#v not allowed. Closing connection", origin)
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	ws, err := t.upgrader.Upgrade(w, req, nil)
	if err != nil {
		t.gateway.Log(2, "Websocket upgrade failed: %s", err.Error())
		return
	}
	defer ws.Close()

	client := t.gateway.NewClient()

	client.RemoteAddr = t.gateway.GetRemoteAddressFromRequest(req).String()

	clientHostnames, err := net.LookupAddr(client.RemoteAddr)
	if err != nil || len(clientHostnames) == 0 {
		client.RemoteHostname = client.RemoteAddr
	} else {
		// FQDNs include a . at the end. Strip it out
		potentialHostname := strings.Trim(clientHostnames[0], ".")

		// Must check that the resolved hostname also resolves back to the users IP
		addr, err := net.LookupIP(potentialHostname)
		if err == nil && len(addr) == 1 && addr[0].String() == client.RemoteAddr {
			client.RemoteHostname = potentialHostname
		} else {
			client.RemoteHostname = client.RemoteAddr
		}
	}

	if t.gateway.isRequestSecure(req) {
		client.Tags["secure"] = ""
	}

	_, remoteAddrPort, _ := net.SplitHostPort(req.RemoteAddr)
	client.Tags["remote-port"] = remoteAddrPort

	client.Log(2, "New websocket client on %s from %s %s", req.Host, client.RemoteAddr, client.RemoteHostname)
	client.Ready()

	// Read from websocket
	go func() {
		for {
			_, p, err := ws.ReadMessage()
			if err != nil {
				client.Log(1, "Websocket connection closed (%s)", err.Error())
				break
			}
			if len(p) > 0 {
				message := string(p)
				client.Log(1, "client->: %s", message)
				select {
				case client.Recv <- message:
				default:
					client.Log(3, "Recv queue full. Dropping data")
				}
			}
		}

		close(client.Recv)
	}()

	// Process signals for the client
	for {
		signal, ok := <-client.Signals
		if !ok {
			break
		}

		if signal[0] == "data" {
			line := strings.Trim(signal[1], "\r\n")
			client.Log(1, "->ws: %s", line)
			err := ws.WriteMessage(websocket.TextMessage, []byte(line))
			if err != nil {
				client.Log(2, "Error writing to websocket: %s", err.Error())
				break
			}
		}

		if signal[0] == "state" && signal[1] == "closed" {
			ws.Close()
		}
	}
}
