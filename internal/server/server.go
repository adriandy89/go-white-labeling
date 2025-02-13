package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"go-certificate-test/internal/acme"
	"go-certificate-test/internal/handler"
)

type Server struct {
	httpServer *http.Server
}

func NewServer() *Server {
	// Genera un certificado TLS por defecto
	defaultTLSCert, err := acme.GenerateDefaultTLSCertificate()
	if err != nil {
		log.Fatalf("Error generando el certificado default: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/generate-cert", handler.GenerateCertHandler)
	mux.HandleFunc("/test", handler.TestHandler)

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			domain := hello.ServerName
			if domain == "" {
				return &defaultTLSCert, nil
			}
			certPath := filepath.Join("certs", fmt.Sprintf("%s.crt", domain))
			keyPath := filepath.Join("certs", fmt.Sprintf("%s.key", domain))

			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				log.Printf("Usando el certificado default para %s: %v", domain, err)
				return &defaultTLSCert, nil
			}
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	return &Server{
		httpServer: &http.Server{
			Addr:      ":443",
			Handler:   mux,
			TLSConfig: tlsConfig,
		},
	}
}

func (s *Server) Start() error {
	log.Println("Servidor HTTPS iniciado en :443")
	return s.httpServer.ListenAndServeTLS("", "")
}
