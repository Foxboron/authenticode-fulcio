package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	fulcioUrl    = "https://v1.fulcio.sigstore.dev"
	oidcIssuer   = "https://oauth2.sigstore.dev/auth"
	oidcClientID = "sigstore"
)

// Some of this is just ripped from cosign
func GetCert(priv *rsa.PrivateKey, fc api.Client, oidcIssuer string, oidcClientID string) (*api.CertificateResponse, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: "rsa4096",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}
	return fc.SigningCert(cr, tok.RawString)
}

func NewClient(fulcioURL string) (api.Client, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	fClient := api.NewClient(fulcioServer, api.WithUserAgent("test Foxboron"))
	return fClient, nil
}

func WritePEM(filename string, b []byte) {
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
		log.Fatal(err)
	}
	os.WriteFile(filename, certOut.Bytes(), 0644)
}

func WritePrivateKey(filename string, priv *rsa.PrivateKey) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		log.Fatal(err)
	}
	os.WriteFile(filename, keyOut.Bytes(), 0644)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: <file>")
		os.Exit(1)
	}
	uefiFile = os.Args[1]

	signer, priv, err := signature.NewDefaultRSAPKCS1v15SignerVerifier()
	if err != nil {
		log.Fatal(err)
	}

	fClient, err := NewClient(fulcioUrl)
	if err != nil {
		log.Fatal(err)
	}

	certResp, err := GetCert(priv, fClient, oidcIssuer, oidcClientID)
	if err != nil {
		log.Fatal(err)
	}

	clientPEM, _ := pem.Decode([]byte(certResp.CertPEM))
	cert, err := x509.ParseCertificate(clientPEM.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received signing cerificate with serial number: ", cert.SerialNumber)

	WritePEM("test.pem", clientPEM.Bytes)
	WritePrivateKey("test.priv", priv)

	b, _ := os.ReadFile(uefiFile)
	sigCtx := pecoff.PECOFFChecksum(b)

	sig, err := pecoff.CreateSignature(sigCtx, cert, signer)
	if err != nil {
		log.Fatal(err)
	}
	b, err = pecoff.AppendToBinary(sigCtx, sig)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.WriteFile(fmt.Sprintf("%s.signed", uefiFile), b, 0644); err != nil {
		log.Fatal(err)
	}
}
