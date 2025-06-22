package main

import (
	"fmt"
	"net/url"
	"os"

	"github.com/brain-hol/go-libaic"
)

func main() {
	baseURL, _ := url.Parse("https://openam-trivir-demo1.forgeblocks.com/am")
	jwk, _ := os.ReadFile("./testdata/privatekey.jwk")
	aic, err := libaic.New(libaic.Opts{
		BaseURL: baseURL,
		// Auth: &libaic.ZeroPageAuth{
		// 	CookieName: "d3c8064e230d6c2",
		// 	Username:   "brian_test",
		// 	Password:   "Password123!",
		// 	Service:    "ZeroPage",
		// },
		Auth: &libaic.ServiceAccountAuth{
			ID:  "7beb8417-9ef3-4c12-bf9c-e8e5cc836801",
			JWK: jwk,
		},
	})
	if err != nil {
		fmt.Printf("Error initializing LibAIC: %s\n", err)
		os.Exit(1)
	}
	// aic.GetServerInfo()
	
	aic.GetScripts()
}
