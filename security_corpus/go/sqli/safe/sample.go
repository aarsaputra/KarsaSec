package main

import "database/sql"

func getUserSafe(db *sql.DB, username string) {
	db.Query("SELECT * FROM users WHERE name = ?", username)
}
