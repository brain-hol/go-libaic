package main

import (
	"fmt"
	"os"

	"github.com/brain-hol/go-libaic"
)

func main() {
	aic, err := libaic.New(libaic.Opts{
		BaseURL: "https://openam-trivir-demo1.forgeblocks.com/am",
		Auth: &libaic.ZeroPageAuth{
			CookieName: "d3c8064e230d6c2",
			Username:   "brian_test",
			Password:   "Password123!",
			Service:    "ZeroPage",
		},
	})
	if err != nil {
		fmt.Printf("Error initializing LibAIC: %s\n", err)
		os.Exit(1)
	}
	aic.GetServerInfo()
}
