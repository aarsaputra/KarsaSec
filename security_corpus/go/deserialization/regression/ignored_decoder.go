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
    if err := decoder.Decode(&payload); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    w.Write([]byte(payload.Name))
}
