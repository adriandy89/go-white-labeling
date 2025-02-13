package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"go-certificate-test/internal/db"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// MyUser representa la cuenta ACME.
type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// CertRequest para parsear JSON.
type CertRequest struct {
	Email  string `json:"email"`
	Domain string `json:"domain"`
}

// GenerateDefaultTLSCertificate crea un certificado TLS autofirmado para iniciar el servidor.
func GenerateDefaultTLSCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Default Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// StartAutoRenewalLoop inicia un bucle cada 24 horas para revisar certificados y renovarlos.
func StartAutoRenewalLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			<-ticker.C
			renewCertificatesIfNeeded()
		}
	}()
}

// renewCertificatesIfNeeded renueva certificados que expiran en menos de 15 días.
func renewCertificatesIfNeeded() {
	rows, err := db.DB.Query("SELECT email, domain FROM certificates")
	if err != nil {
		log.Printf("Error consultando dominios: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var email, domain string
		if err := rows.Scan(&email, &domain); err != nil {
			continue
		}

		certPath := filepath.Join("certs", fmt.Sprintf("%s.crt", domain))
		data, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if time.Until(parsed.NotAfter) < (15 * 24 * time.Hour) {
			log.Printf("Renovando certificado para %s (expira pronto)...", domain)
			if err := renewCertificate(email, domain); err != nil {
				log.Printf("Error renovando certificado para %s: %v", domain, err)
			}
		}
	}
}

// renewCertificate renueva un certificado usando parte de la lógica de generación inicial.
func renewCertificate(email, domain string) error {
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	myUser := &MyUser{Email: email, Key: userKey}

	config := lego.NewConfig(myUser)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	provider := http01.NewProviderServer("", "80")
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	myUser.Registration = reg

	obtainReq := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(obtainReq)
	if err != nil {
		return err
	}

	certPath := filepath.Join("certs", fmt.Sprintf("%s.crt", domain))
	keyPath := filepath.Join("certs", fmt.Sprintf("%s.key", domain))

	if err = os.WriteFile(certPath, certs.Certificate, 0644); err != nil {
		return err
	}
	if err = os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = db.DB.ExecContext(ctx, "UPDATE certificates SET created_at=$1 WHERE domain=$2", time.Now(), domain)
	return err
}
