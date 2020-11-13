package openssl

import (
	"io/ioutil"
	"testing"
)

func TestCmsSign(t *testing.T) {

	//engine, err := EngineById("gostengy")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//err = EngineSetDefault(engine)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//key, err := LoadPrivateKeyFromEngine(engine, "c:OOO_GETNET_1595311686391")
	//if err != nil {
	//	t.Fatal(err)
	//}

	keyBytes, err := ioutil.ReadFile("id.get-net.ru.key")
	if err != nil {
		t.Fatal(err)
	}

	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := ioutil.ReadFile("id.get-net.ru.cert")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := LoadCertificateFromPEM(certBytes)

	if err != nil {
		t.Fatal(err)
	}

	dataBytes, err := ioutil.ReadFile("cms_test.go")
	if err != nil {
		t.Fatal(err)
	}

	cms, err := CmsSign(cert, key, dataBytes, CmsDetached|CmsStream)
	if err != nil {
		t.Fatal(err)
	}

	sMime, err := SmimeWriteCms(cms, dataBytes, CmsDetached|CmsStream)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile("cms_test.go.sgn", sMime, 0644)
	if err != nil {
		t.Fatal(err)
	}
}
