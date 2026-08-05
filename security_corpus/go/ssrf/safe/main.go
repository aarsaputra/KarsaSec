package main

import (
    "fmt"
    "net/http"
)

// Safe: Fixed internal URL endpoint
func handleSafeRequest() {
    resp, err := http.Get("https://api.internal.local/health")
    if err != nil {
        fmt.Println(err)
    }
    _ = resp
}
