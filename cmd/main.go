package main

import (
	"go-certificate-test/internal/acme"
	"go-certificate-test/internal/db"
	"go-certificate-test/internal/server"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// Carga variables desde .env
	if err := godotenv.Load(); err != nil {
		log.Println("No se pudo cargar .env:", err)
	}

	// Obtén tus variables
	connString := os.Getenv("DB_CONN_STRING")
	if connString == "" {
		connString = "postgres://postgres:postgres@localhost:5432/gocert?sslmode=disable"
	}

	if err := db.InitDB(connString); err != nil {
		log.Fatalf("Error conectando a la base de datos: %v", err)
	}
	defer db.CloseDB()

	go acme.StartAutoRenewalLoop()

	srv := server.NewServer()
	if err := srv.Start(); err != nil {
		log.Fatalf("Error iniciando servidor HTTPS: %v", err)
	}
}
