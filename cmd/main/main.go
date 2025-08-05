package main

import "github.com/uber/krakenfs/cmd/krakenfs"

func main() {
	krakenfs.Run(krakenfs.ParseFlags())
}
