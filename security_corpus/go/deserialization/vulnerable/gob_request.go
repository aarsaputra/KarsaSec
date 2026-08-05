package main

import (
    "encoding/gob"
    "net/http"
)

type Payload struct {
    Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
    var payload Payload
    decoder := gob.NewDecoder(r.Body)
    _ = decoder.Decode(&payload)
    w.Write([]byte(payload.Name))
}
