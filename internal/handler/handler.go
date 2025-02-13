package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"go-certificate-test/internal/acme"
	"go-certificate-test/internal/db"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// GenerateCertHandler crea el certificado con Let's Encrypt para el dominio solicitado.
func GenerateCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var req acme.CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error al parsear JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Domain = strings.TrimSpace(req.Domain)
	if req.Email == "" || req.Domain == "" {
		http.Error(w, "Email y dominio son requeridos", http.StatusBadRequest)
		return
	}

	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "Error generando la clave: "+err.Error(), http.StatusInternalServerError)
		return
	}
	myUser := &acme.MyUser{Email: req.Email, Key: userKey}

	config := lego.NewConfig(myUser)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		http.Error(w, "Error creando el cliente lego: "+err.Error(), http.StatusInternalServerError)
		return
	}

	provider := http01.NewProviderServer("", "80")
	if err = client.Challenge.SetHTTP01Provider(provider); err != nil {
		http.Error(w, "Error asignando el proveedor HTTP-01: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		http.Error(w, "Error en el registro ACME: "+err.Error(), http.StatusInternalServerError)
		return
	}
	myUser.Registration = reg

	obtainRequest := certificate.ObtainRequest{
		Domains: []string{req.Domain},
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(obtainRequest)
	if err != nil {
		http.Error(w, "Error obteniendo el certificado: "+err.Error(), http.StatusInternalServerError)
		return
	}

	certDir := "certs"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		http.Error(w, "Error al crear directorio de certificados: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certPath := filepath.Join(certDir, fmt.Sprintf("%s.crt", req.Domain))
	keyPath := filepath.Join(certDir, fmt.Sprintf("%s.key", req.Domain))

	if err = os.WriteFile(certPath, certs.Certificate, 0644); err != nil {
		http.Error(w, "Error escribiendo el certificado: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err = os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		http.Error(w, "Error escribiendo la clave: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	insertQuery := `INSERT INTO certificates (email, domain, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err = db.DB.ExecContext(ctx, insertQuery, req.Email, req.Domain, certPath, keyPath, time.Now())
	if err != nil {
		http.Error(w, "Error guardando en la BD: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"message":   "Certificado creado correctamente",
		"domain":    req.Domain,
		"email":     req.Email,
		"cert_path": certPath,
		"key_path":  keyPath,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// TestHandler verifica si el dominio (header Host) está registrado.
func TestHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}

	var id int
	query := "SELECT id FROM certificates WHERE domain = $1 LIMIT 1"
	err := db.DB.QueryRow(query, host).Scan(&id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Dominio %s no registrado", host), http.StatusNotFound)
		return
	}

	resp := map[string]string{
		"message": fmt.Sprintf("Dominio %s está activo y registrado", host),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("TestHandler ejecutado para %s", host)
}
