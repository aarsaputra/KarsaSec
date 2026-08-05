package main

import (
    "database/sql"
    "os"
)

func execUserRegression(db *sql.DB) {
    rawQuery := os.Args[1]
    db.Exec(rawQuery)
}
