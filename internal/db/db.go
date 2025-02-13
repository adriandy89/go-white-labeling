package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB(connString string) error {
	var err error
	DB, err = sql.Open("postgres", connString)
	if err != nil {
		return fmt.Errorf("no se pudo abrir la conexión: %w", err)
	}
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("no se pudo hacer ping a la DB: %w", err)
	}

	log.Println("Conexión a PostgreSQL exitosa")

	// Crear tabla si no existe
	schema := `
    CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY,
        email TEXT,
        domain TEXT,
        cert_path TEXT,
        key_path TEXT,
        created_at TIMESTAMP
    );
    `
	if _, err = DB.Exec(schema); err != nil {
		return fmt.Errorf("error al crear la tabla: %w", err)
	}

	return nil
}

func CloseDB() {
	if DB != nil {
		DB.Close()
	}
}
