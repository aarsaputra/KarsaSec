package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, username string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
	db.Query(query)
}
