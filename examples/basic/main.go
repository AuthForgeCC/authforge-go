package main

import (
	"fmt"
	"os"

	"github.com/AuthForgeCC/authforge-go"
)

func main() {
	client, err := authforge.New(authforge.Config{
		AppID:         "your-app-id",
		AppSecret:     "your-app-secret",
		HeartbeatMode: "server",
		OnFailure: func(errMsg string) {
			fmt.Fprintf(os.Stderr, "Auth failed: %s\n", errMsg)
			os.Exit(1)
		},
	})
	if err != nil {
		panic(err)
	}

	result, err := client.Login("XXXX-XXXX-XXXX-XXXX")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authenticated! Expires: %d\n", result.ExpiresIn)
	select {}
}
