cimport ossl_typ
from libc.stdio cimport FILE

cdef extern from "openssl/pem.h":
    #/* "userdata": new with OpenSSL 0.9.4 */
    ctypedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata)
    ossl_typ.RSA* PEM_read_RSAPrivateKey(
        FILE *fp, ossl_typ.RSA **x, pem_password_cb *cb, void *u
    )
    ossl_typ.RSA* PEM_read_RSAPublicKey(
        FILE *fp, ossl_typ.EVP_PKEY **x, pem_password_cb *cb, void *u
    )

    ossl_typ.EVP_PKEY* PEM_read_PUBKEY(
        FILE *fp, ossl_typ.EVP_PKEY **x, pem_password_cb *cb, void *u
    )
