package openssl

import (
	"io/ioutil"
	"math/big"
	"testing"
	"time"
)

func TestPKCS7Sign(t *testing.T) {

	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}

	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.Sign(key, EVP_SHA256); err != nil {
		t.Fatal(err)
	}

	dataBytes, err := ioutil.ReadFile("pkcs7_test.go")
	if err != nil {
		t.Fatal(err)
	}

	pkcs7, err := PKCS7Sign(cert, key, dataBytes, PKCS7_DETACHED|PKCS7_BINARY|PKCS7_PARTIAL)
	if err != nil {
		t.Fatal(err)
	}
	pkcs7, err = PKCS7Final(pkcs7, dataBytes, PKCS7_DETACHED|PKCS7_BINARY|PKCS7_PARTIAL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pkcs7.MarshalPKCS7DER()
	if err != nil {
		t.Fatal(err)
	}
}
