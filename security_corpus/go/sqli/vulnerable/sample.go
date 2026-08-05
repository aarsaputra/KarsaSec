package main

import (
    "database/sql"
    "fmt"
    "os"
)

func getUser(db *sql.DB) {
    username := os.Args[1]
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
    db.Query(query)
}
