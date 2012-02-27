cimport ossl_typ
cdef extern from "openssl/evp.h":
    ossl_typ.EVP_PKEY* EVP_PKEY_new()
    
    ossl_typ.RSA* EVP_PKEY_get1_RSA(ossl_typ.EVP_PKEY *pkey)
    void EVP_PKEY_free(ossl_typ.EVP_PKEY *pkey)
