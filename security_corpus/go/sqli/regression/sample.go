package main

import "database/sql"

func execUserRegression(db *sql.DB, rawQuery string) {
	db.Exec(rawQuery)
}
