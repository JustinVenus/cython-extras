from libc.stdlib cimport malloc, free
from libc.stdio cimport FILE, const_char
cimport ossl_typ
cimport rsa
cimport evp
cimport pem
cimport err

#Author: Justin Venus <justin.venus@gmail.com>

cdef extern from "fileobject.h": 
    cdef FILE* PyFile_AsFile(object)


cdef class RSA_object(object):
    cdef ossl_typ.RSA *_rsa
    cdef int padding
    cdef int dest_buf_size
    cdef unsigned char* dest_buf

    property _error:
        "get/clear internal errors"
        def __get__(self):
            result = err.ERR_peek_error()
            return result
        def __set__(self, value):
            raise AttributeError('This property is not setable')
        def __del__(self):
            err.ERR_clear_error()

    def __cinit__(self):
        self._rsa = NULL
        self.padding = rsa.RSA_PKCS1_PADDING
        self.dest_buf = NULL
        self.dest_buf_size = 0

    def __dealloc__(self):
        if self._rsa is not NULL:
            rsa.RSA_free(self._rsa)
        if self.dest_buf is not NULL:
            free(self.dest_buf)


cdef class PublicKey(RSA_object):
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

        if self._error != 0 or evpk is NULL:
            del self._error
            if evpk is not NULL:
                evp.EVP_PKEY_free(evpk)
            raise Exception("Failed to read RSA public key %s" % path)

        self._rsa = evp.EVP_PKEY_get1_RSA(evpk)
        if self._error != 0 or self._rsa is NULL:
            del self._error
            evp.EVP_PKEY_free(evpk)
            raise Exception("Failed to extract RSA key from the EVP_PKEY at %s" % path) 

        #increment the internal rsa struct reference
        rsa.RSA_up_ref(self._rsa)
        #release the evp structure
        evp.EVP_PKEY_free(evpk)

        #malloc can be slow so let's preallocate the buffer as soon as we can
        self.dest_buf_size = rsa.RSA_size(self._rsa)
        self.dest_buf = <unsigned char*>malloc( self.dest_buf_size )
        if self.dest_buf is NULL: raise MemoryError()

    cpdef encrypt(self, source) with gil: #protect the memory
        """encrypt(source) -> string

           encrypt text with the rsa public key.
        """
        if not isinstance(source, str):
            raise TypeError("only string data is supported")
        dest = str()
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), self.dest_buf_size)
            i = rsa.RSA_public_encrypt(
                read_len, source, self.dest_buf,
                self._rsa, self.padding
            )
            if i == -1 or self._error:
                del self._error
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>self.dest_buf
            dest += tmp[:i]
            source = source[read_len:]
        return dest

    cpdef decrypt(self, source) with gil: #protect the memory
        """decrypt(source) -> string

           decrypt data with the rsa public key.
        """
        if not isinstance(source, str):
            raise TypeError("only string data is supported")
        dest = str()
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), self.dest_buf_size)
            i = rsa.RSA_public_decrypt(
                read_len, source, self.dest_buf,
                self._rsa, self.padding
            )
            if i == -1 or self._error:
                del self._error
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>self.dest_buf
            dest += tmp[:i]
            source = source[read_len:]
        return dest


cdef class PrivateKey(RSA_object):
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
        if self._error != 0:
            del self._error
            raise Exception("Failed to read RSA private key %s" % path)

        if self._rsa is NULL:
            raise MemoryError()

        #malloc can be slow so let's preallocate the buffer as soon as we can
        self.dest_buf_size = rsa.RSA_size(self._rsa)
        self.dest_buf = <unsigned char*>malloc( self.dest_buf_size )
        if self.dest_buf is NULL: raise MemoryError()

    cpdef encrypt(self, source) with gil: #protect the memory
        """encrypt(source) -> string

           encrypt text with the rsa private key.
        """
        dest = str()
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), self.dest_buf_size)
            i = rsa.RSA_private_encrypt(
                read_len, source, self.dest_buf,
                self._rsa, self.padding
            )
            if i == -1 or self._error:
                del self._error
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>self.dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        return dest

    cpdef decrypt(self, source) with gil: #protect the memory
        """decrypt(source) -> string

           decrypt data with the rsa private key.
        """
        dest = str()
        cdef int read_len
        cdef int i

        while source:
            read_len = min(len(source), self.dest_buf_size)
            i = rsa.RSA_private_decrypt(
                read_len, source, self.dest_buf,
                self._rsa, self.padding
            )
            if i == -1 or self._error:
                del self._error
                raise ValueError("Operation failed due to invalid input")
            tmp = <bytes>self.dest_buf
            dest += tmp[:i]
            source = source[read_len:]

        return dest

__all__ = ['PrivateKey', 'PublicKey']
