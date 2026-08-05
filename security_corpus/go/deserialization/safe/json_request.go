package main

import (
    "encoding/json"
    "net/http"
)

type Payload struct {
    Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
    var payload Payload
    _ = json.NewDecoder(r.Body).Decode(&payload)
    w.Write([]byte(payload.Name))
}
