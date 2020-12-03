package openssl

/*
#include <openssl/pkcs7.h>
#include <openssl/pkcs7err.h>
#include "shim.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"io/ioutil"
	"unsafe"
)

const (
	PKCS7_TEXT            = 0x1
	PKCS7_NOCERTS         = 0x2
	PKCS7_NOSIGS          = 0x4
	PKCS7_NOCHAIN         = 0x8
	PKCS7_NOINTERN        = 0x10
	PKCS7_NOVERIFY        = 0x20
	PKCS7_DETACHED        = 0x40
	PKCS7_BINARY          = 0x80
	PKCS7_NOATTR          = 0x100
	PKCS7_NOSMIMECAP      = 0x200
	PKCS7_NOOLDMIMETYPE   = 0x400
	PKCS7_CRLFEOL         = 0x800
	PKCS7_STREAM          = 0x1000
	PKCS7_NOCRL           = 0x2000
	PKCS7_PARTIAL         = 0x4000
	PKCS7_REUSE_DIGEST    = 0x8000
	PKCS7_NO_DUAL_CONTENT = 0x10000
)

type PKCS7 struct {
	pkcs7 *C.PKCS7
}

func PKCS7Sign(certificate *Certificate, key PrivateKey, data []byte, flags int) (*PKCS7, error) {

	if certificate == nil {
		return nil, errors.New("sign certificate not found")
	}

	if len(data) == 0 {
		return nil, errors.New("empty data block")
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]),
		C.int(len(data)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	pkcs7 := C.PKCS7_sign(certificate.x, key.evpPKey(), nil, bio, C.int(flags))
	if pkcs7 == nil {
		return nil, errors.New("failed create signature pkcs7")
	}

	p := &PKCS7{pkcs7: pkcs7}

	return p, nil
}

func PKCS7Final(pkcs7 *PKCS7, data []byte, flags int) (*PKCS7, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]),
		C.int(len(data)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	status := C.PKCS7_final(pkcs7.pkcs7, bio, C.int(flags))
	if status != 1 {
		return nil, errors.New("can't finalize pcks7 signature")
	}

	p := &PKCS7{pkcs7: pkcs7.pkcs7}

	return p, nil
}

func (pkcs7 *PKCS7) MarshalPKCS7DER() (der_block []byte, err error) {
	var status C.int

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(out)

	status = C.i2d_PKCS7_bio(out, pkcs7.pkcs7)
	if status != 1 {
		return nil, fmt.Errorf("failed convert PKCS7 to DER got error %d", status)
	}

	return ioutil.ReadAll(asAnyBio(out))
}

func (pkcs7 *PKCS7) SMIMEWritePKCS7(data []byte, flags int) (der_block []byte, err error) {

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(out)

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]),
		C.int(len(data)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	status := C.SMIME_write_PKCS7(out, pkcs7.pkcs7, bio, C.int(flags))
	if status != 1 {
		return nil, fmt.Errorf("failed write PKCS7 to SMIME %d", status)
	}

	return ioutil.ReadAll(asAnyBio(out))
}

func PKCS7Encrypt(certs []*Certificate, data []byte, cipher Cipher, flags int) (*PKCS7, error) {

	if len(certs) == 0 {
		return nil, errors.New("recipient certificates not found")
	}

	if len(data) == 0 {
		return nil, errors.New("empty data block")
	}

	//	var sk *C.struct_stack_st_X509

	sk := C.X_sk_X509_new_null()
	if sk == nil {
		return nil, errors.New("can't create new stack")
	}

	for _, cert := range certs {
		res := C.X_sk_X509_push(sk, cert.x)
		if res == 0 {
			return nil, errors.New("can't add cert into stack")
		}
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]),
		C.int(len(data)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	pkcs7 := C.PKCS7_encrypt(sk, bio, cipher.ptr, C.int(flags))
	if pkcs7 == nil {
		return nil, errors.New("failed create signature pkcs7")
	}

	p := &PKCS7{pkcs7: pkcs7}

	return p, nil
}

// int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store, BIO *indata, BIO *out, int flags);
// PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher, int flags);
// int PK	CS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags);
// int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);
// PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
// BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7);
