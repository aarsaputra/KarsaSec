package main

import (
    "fmt"
    "net/http"
)

// Vulnerable: Unvalidated target URL in http.Get
func handleRequest(target string) {
    resp, err := http.Get(target)
    if err != nil {
        fmt.Println(err)
    }
    _ = resp
}
