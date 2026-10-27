package main

import (
	"sync"

	"github.com/hnz101/webircgateway/pkg/webircgateway"
)

func Start(gateway *webircgateway.Gateway, pluginsQuit *sync.WaitGroup) {
	gateway.Log(1, "Example gateway plugin %s", webircgateway.Version)
}