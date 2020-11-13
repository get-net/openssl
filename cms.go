package openssl

/*
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"io/ioutil"
	"unsafe"
)

const (
	CmsText     = 0x1
	CmsDetached = 0x40
	CmsBinary   = 0x80
	CmsStream   = 0x1000
)

type CmsContentInfo struct {
	cmsContentInfo *C.CMS_ContentInfo
}

func CmsSign(signcert *Certificate, pkey PrivateKey, data []byte, flags uint) (*CmsContentInfo, error) {

	if signcert == nil {
		return nil, errors.New("sign cert not found")
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

	CMS_content_info := C.CMS_sign(signcert.x, pkey.evpPKey(), nil, bio, C.uint(flags))

	c := &CmsContentInfo{cmsContentInfo: CMS_content_info}
	return c, nil
}

func SmimeWriteCms(cms *CmsContentInfo, data []byte, flags uint) ([]byte, error) {
	var status C.int

	out := C.BIO_new(C.BIO_s_mem())
	if out == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	//out := C.BIO_new_file(C.CString("smout.txt"),C.CString("w"))
	//if out == nil {
	//	return nil, errors.New("can't open file")
	//}
	defer C.BIO_free(out)

	if len(data) != 0 {
		in := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data)))
		status = C.SMIME_write_CMS(out, cms.cmsContentInfo, in, C.int(flags))
		defer C.BIO_free(in)
	} else {
		status = C.SMIME_write_CMS(out, cms.cmsContentInfo, nil, C.int(flags))
	}

	if status != 0 {
		return nil, fmt.Errorf("cms write failed %d", status)
	}

	return ioutil.ReadAll(asAnyBio(out))
}
