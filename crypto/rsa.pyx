from libc.stdlib cimport malloc, free
from libc.stdio cimport FILE, const_char
cimport ossl_typ
cimport rsa
cimport evp
cimport pem
cimport err

__doc__ = """RSA Public/Private key encryption/decryption routines"""

__author__ = "Justin Venus <justin.venus@gmail.com>"

cdef extern from "fileobject.h": 
    cdef FILE* PyFile_AsFile(object)

#this isn't strictly necessary, but it makes the rest of the code
#a lot cleaner to read.
ctypedef int (*RSACallback)(
    int, unsigned char *, unsigned char * ,ossl_typ.RSA *, int
)


#the real magic happens here
cdef object _process(object source, RSACallback func, ossl_typ.RSA* key):
    """process the source using the provided callback method and rsa key"""
    if not isinstance(source, str):
        raise TypeError("only string data is supported")
    dest = str()
    cdef int read_len
    cdef int i

    cdef int dest_buf_size = rsa.RSA_size(key)
    cdef unsigned char *dest_buf 
    dest_buf = <unsigned char*>malloc( dest_buf_size )

    if dest_buf is NULL:
        raise MemoryError()

    try:
        while source:
            read_len = min(len(source), dest_buf_size)
            i = func(
                read_len, source, dest_buf,
                key, rsa.RSA_PKCS1_PADDING
            )
            if i == -1 or err.ERR_peek_error():
                err.ERR_clear_error()
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        return dest
    finally:
        free( dest_buf )


cdef class PublicKey:
    """Encrypt text or decrypt data using RSA public key"""
    cdef ossl_typ.RSA *_rsa

    def __cinit__(self):
        self._rsa = NULL

    def __dealloc__(self):
        if self._rsa is not NULL:
            rsa.RSA_free(self._rsa)

    def __init__(self, path):
        """__init__(path)

           Initialize rsa public key with full path to the public rsa key.
        """
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL:
            raise MemoryError()

        cdef ossl_typ.EVP_PKEY *evpk
        evpk = pem.PEM_read_PUBKEY(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file

        if err.ERR_peek_error() != 0 or evpk is NULL:
            err.ERR_clear_error()
            if evpk is not NULL:
                evp.EVP_PKEY_free(evpk)
            raise Exception("Failed to read RSA public key %s" % path)

        self._rsa = evp.EVP_PKEY_get1_RSA(evpk)
        if err.ERR_peek_error() != 0 or self._rsa is NULL:
            err.ERR_clear_error()
            evp.EVP_PKEY_free(evpk)
            raise Exception("Failed to extract RSA key from the EVP_PKEY at %s" % path) 

        #increment the internal rsa struct reference
        rsa.RSA_up_ref(self._rsa)
        #release the evp structure
        evp.EVP_PKEY_free(evpk)

    def encrypt(self, source):
        """encrypt(source) -> string

           encrypt text with the rsa public key.
        """
        return _process(source, <RSACallback>rsa.RSA_public_encrypt, self._rsa)

    def decrypt(self, source):
        """decrypt(source) -> string

           decrypt data with the rsa public key.
        """
        return _process(source, <RSACallback>rsa.RSA_public_decrypt, self._rsa)


cdef class PrivateKey:
    """Encrypt text or decrypt data using RSA private key"""
    cdef ossl_typ.RSA *_rsa

    def __cinit__(self):
        self._rsa = NULL

    def __dealloc__(self):
        if self._rsa is not NULL:
            rsa.RSA_free(self._rsa)

    def __init__(self, path):
        """__init__(path)

           Initialize rsa private key with full path to the private rsa key.
        """
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL:
            raise MemoryError()

        self._rsa = pem.PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file

        #check for library errors before null pointers
        if err.ERR_peek_error() != 0:
            err.ERR_clear_error()
            raise Exception("Failed to read RSA private key %s" % path)

        if self._rsa is NULL:
            raise MemoryError()

    def encrypt(self, source):
        """encrypt(source) -> string

           encrypt text with the rsa private key.
        """
        return _process(source, <RSACallback>rsa.RSA_private_encrypt, self._rsa)

    def decrypt(self, source):
        """decrypt(source) -> string

           decrypt data with the rsa private key.
        """
        return _process(source, <RSACallback>rsa.RSA_private_decrypt, self._rsa)


__all__ = ['PrivateKey', 'PublicKey']
