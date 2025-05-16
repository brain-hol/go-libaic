package main

import (
	"fmt"
	"os"

	"github.com/brain-hol/go-libaic"
)

func main() {
	aic, err := libaic.New(libaic.Opts{
		BaseURL: "https://openam-trivir.forgeblocks.com/am",
	})
	if err != nil {
		fmt.Printf("Error initializing LibAIC: %s\n", err)
		os.Exit(1)
	}
	aic.GetServerInfo()
}
