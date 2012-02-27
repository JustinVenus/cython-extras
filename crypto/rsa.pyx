from libc.stdlib cimport malloc, free
from libc.stdio cimport FILE, const_char
cimport ossl_typ
cimport rsa
cimport evp
cimport pem
import os

#Author: Justin Venus <justin.venus@gmail.com>

cdef extern from "fileobject.h": 
    cdef FILE* PyFile_AsFile(object)


cdef class PublicKey(object):
    cdef ossl_typ.RSA *_rsa
    cdef int padding
    def __cinit__(self):
        self._rsa = NULL
        self.padding = rsa.RSA_PKCS1_PADDING

    def __dealloc__(self):
        if self._rsa is not NULL:
            rsa.RSA_free(self._rsa)

    def __init__(self, path):
        os.stat(path)
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL:
            raise MemoryError()
        cdef ossl_typ.EVP_PKEY *evpk
        evpk = pem.PEM_read_PUBKEY(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file
        if evpk is NULL:
            raise MemoryError()
        self._rsa = evp.EVP_PKEY_get1_RSA(evpk)
        if self._rsa is NULL:
            evp.EVP_PKEY_free(evpk)
            raise Exception("Failed to extract RSA key from the EVP_PKEY at %s" % path) 

        rsa.RSA_up_ref(self._rsa)
        evp.EVP_PKEY_free(evpk)

    cpdef encrypt(self, source):
        cdef int dest_buf_size = rsa.RSA_size(self._rsa)
        cdef unsigned char* dest_buf
        dest_buf = <unsigned char*>malloc( dest_buf_size )
        if dest_buf is NULL: raise MemoryError()
        dest = ""
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), dest_buf_size)
            i = rsa.RSA_public_encrypt(
                read_len, source, dest_buf,
                self._rsa, self.padding
            )
            if i == -1:
                free(dest_buf)
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        free(dest_buf)
        return dest

    cpdef decrypt(self, source):
        cdef int dest_buf_size = rsa.RSA_size(self._rsa)
        cdef unsigned char* dest_buf
        dest_buf = <unsigned char*>malloc( dest_buf_size )
        if dest_buf is NULL: raise MemoryError()
        dest = ""
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), dest_buf_size)
            i = rsa.RSA_public_decrypt(
                read_len, source, dest_buf,
                self._rsa, self.padding
            )
            if i == -1:
                free(dest_buf)
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        free(dest_buf)
        return dest


cdef class PrivateKey(object):
    cdef ossl_typ.RSA *_rsa
    cdef int padding
    def __cinit__(self):
        self._rsa = NULL
        self.padding = rsa.RSA_PKCS1_PADDING

    def __dealloc__(self):
        if self._rsa is not NULL:
            rsa.RSA_free(self._rsa)

    def __init__(self, path):
        os.stat(path)
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL: raise MemoryError()
        self._rsa = pem.PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file
        if self._rsa is NULL: raise MemoryError()

    cpdef encrypt(self, source):
        cdef int dest_buf_size = rsa.RSA_size(self._rsa)
        cdef unsigned char* dest_buf
        dest_buf = <unsigned char*>malloc( dest_buf_size )
        if dest_buf is NULL: raise MemoryError()
        dest = ""
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), dest_buf_size)
            i = rsa.RSA_private_encrypt(
                read_len, source, dest_buf,
                self._rsa, self.padding
            )
            if i == -1:
                free(dest_buf)
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        free(dest_buf)
        return dest

    cpdef decrypt(self, source):
        cdef int dest_buf_size = rsa.RSA_size(self._rsa)
        cdef unsigned char* dest_buf
        dest_buf = <unsigned char*>malloc( dest_buf_size )
        if dest_buf is NULL: raise MemoryError()
        dest = ""
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), dest_buf_size)
            i = rsa.RSA_private_decrypt(
                read_len, source, dest_buf,
                self._rsa, self.padding
            )
            if i == -1:
                free(dest_buf)
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        free(dest_buf)
        return dest

__all__ = ['PrivateKey', 'PublicKey']
