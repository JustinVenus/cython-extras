from libc.stdlib cimport malloc, free
from libc.stdio cimport FILE, const_char

__doc__ = """RSA Public/Private key encryption/decryption routines"""
__author__ = "Justin Venus <justin.venus@gmail.com>"
__all__ = ['PrivateKey', 'PublicKey']

###############################################################################
# Start Header definitions
###############################################################################
cdef extern from "fileobject.h": 
    cdef FILE* PyFile_AsFile(object)
cdef extern from "openssl/ossl_typ.h":
    ctypedef struct EVP_PKEY:
        pass
    ctypedef struct RSA:
        pass
cdef extern from "openssl/rsa.h":
    #work around for needing const
    ctypedef unsigned char* const_unsigned_char_ptr "const unsigned char*"
    ctypedef RSA* const_RSA_ptr "const RSA *"
    enum: RSA_PKCS1_PADDING
    int RSA_public_encrypt(
        int flen, const_unsigned_char_ptr frm, 
        unsigned char *to, const_RSA_ptr rsa,int padding)
    int RSA_private_encrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, const_RSA_ptr rsa,int padding)
    int RSA_public_decrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, const_RSA_ptr rsa,int padding)
    int RSA_private_decrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, const_RSA_ptr rsa,int padding)
    int RSA_up_ref(RSA *r)
    void RSA_free (RSA *r)
    int RSA_size(const_RSA_ptr)
cdef extern from "openssl/evp.h":
    RSA* EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
    void EVP_PKEY_free(EVP_PKEY *pkey)
cdef extern from "openssl/err.h":
    unsigned long ERR_peek_error()
    void ERR_clear_error()
cdef extern from "openssl/pem.h":
    RSA* PEM_read_RSAPrivateKey(FILE *fp, RSA **x, void *cb, void *u)
    EVP_PKEY* PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, void *cb, void *u)
###############################################################################
# End Header definitions
###############################################################################

#the following typedef and prototype are for convenience
ctypedef int (*RSACallback)(
    int, unsigned char *, unsigned char *, const_RSA_ptr, int)
cdef extern object _process(object, RSACallback, const_RSA_ptr, bint)

###############################################################################
# Public Python class definitions follow
###############################################################################
        
import os #too useful not to use the python builtin

cdef class PublicKey:
    """Encrypt text or decrypt data using RSA public key"""
    cdef RSA *_rsa
    cdef public object id
    cdef public object path

    def __cinit__(self):
        self._rsa = NULL

    def __dealloc__(self):
        if self._rsa is not NULL:
            RSA_free(self._rsa)

    def __init__(self, path):
        """__init__(path)
           Initialize rsa public key with full path to the public rsa key.

           @type path C{str}
           @param path - full path to public rsa key.

           @raises MemoryError - on null file pointer
           @raises Exception - on failing reading the public key or 
               failing to extract the EVP_PKEY from the RSA key.
        """
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL:
            raise MemoryError()

        self.path = path
        self.id = os.path.basename(path)

        cdef EVP_PKEY *evpk
        evpk = PEM_read_PUBKEY(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file

        if ERR_peek_error() != 0 or evpk is NULL:
            ERR_clear_error()
            if evpk is not NULL:
                EVP_PKEY_free(evpk)
            raise Exception("Failed to read RSA public key %s" % (path,))

        self._rsa = EVP_PKEY_get1_RSA(evpk)
        if ERR_peek_error() != 0 or self._rsa is NULL:
            ERR_clear_error()
            EVP_PKEY_free(evpk)
            raise Exception(
                "Failed to extract RSA key from the EVP_PKEY at %s" % (path,))

        #increment the internal rsa struct reference
        #we had a nice crash b/c this was forgotten.
        RSA_up_ref(self._rsa)
        #release the evp structure
        #we had a nice memory leak b/c this was forgotten.
        EVP_PKEY_free(evpk)

    def encrypt(self, text):
        """encrypt(text) -> data
           encrypt text with the rsa public key.

           @raises TypeError - if ``text`` is not a C{str}
           @raises ValueError - if internal RSA library error occurs.
           @raises MemoryError - if memory error occurs.

           @rtype C{str}
           @return - encrypted data
        """
        return _process(
            text, <RSACallback>RSA_public_encrypt,
            <const_RSA_ptr>self._rsa, True)

    def decrypt(self, data):
        """decrypt(data) -> text
           decrypt data with the rsa public key.

           @raises TypeError - if ``data`` is not a C{str}
           @raises ValueError - if internal RSA library error occurs.
           @raises MemoryError - if memory error occurs.

           @rtype C{str}
           @return - decrypted text
        """
        return _process(
            data, <RSACallback>RSA_public_decrypt,
            <const_RSA_ptr>self._rsa, False)


cdef class PrivateKey:
    """Encrypt text or decrypt data using RSA private key"""
    cdef RSA *_rsa
    cdef public object id
    cdef public object path

    def __cinit__(self):
        self._rsa = NULL

    def __dealloc__(self):
        if self._rsa is not NULL:
            RSA_free(self._rsa)

    def __init__(self, path):
        """__init__(path)
           Initialize rsa private key with full path to the private rsa key.

           @type path C{str}
           @param path - full path to private rsa key.

           @raises MemoryError - on null file pointer or rsa key memory
               allocation failure.
           @raises Exception - on failing reading the private key.
        """
        cdef FILE *fp
        x = open(path, "r")
        fp = PyFile_AsFile(x)
        if fp is NULL:
            raise MemoryError()

        self._rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)
        x.close() #make sure we close the file

        #check for library errors before null pointers
        if ERR_peek_error() != 0:
            ERR_clear_error()
            raise Exception("Failed to read RSA private key %s" % (path,))

        if self._rsa is NULL:
            raise MemoryError()

        self.path = path
        self.id = os.path.basename(path).split('.',1)[0]

    def encrypt(self, text):
        """encrypt(text) -> data
           encrypt text with the rsa private key.

           @raises TypeError - if ``text`` is not a C{str}
           @raises ValueError - if internal RSA library error occurs.
           @raises MemoryError - if memory error occurs.

           @rtype C{str}
           @return - encrypted data
        """
        return _process(
            text, <RSACallback>RSA_private_encrypt,
            <const_RSA_ptr>self._rsa, True)

    def decrypt(self, data):
        """decrypt(data) -> text
           decrypt data with the rsa private key.
       
           @raises TypeError - if ``data`` is not a C{str}
           @raises ValueError - if internal RSA library error occurs.
           @raises MemoryError - if memory error occurs.

           @rtype C{str}
           @return - decrypted text
        """
        return _process(
            data, <RSACallback>RSA_private_decrypt,
            <const_RSA_ptr>self._rsa, False)

###############################################################################
# All the magic happens to encrypt and decrypt happens in here.
###############################################################################
cdef object _process(
        object source, RSACallback func, const_RSA_ptr key, bint encrypt):
    """process the source using the provided callback method and rsa key

       @type source C{str}
       @param source - this is either text or encrypted data

       @type func <RSACallback>
       @param func - one of RSA_private_decrypt, RSA_private_encrypt,
           RSA_public_decrypt, or RSA_public_encrypt.

       @type key <const RSA *>
       @param key - public/private key pointer for encrypt/decrypt

       @type encrypt C{bool}
       @param encrypt - hint to this function on what the callback ``func`` is
          intended to do, b/c there is a difference between encrypt/decrypt.


       @raises TypeError - if ``source`` is not a C{str}
       @raises ValueError - if ``func`` results in a RSA library error.
       @raises MemoryError - if this function cannot allocate scratch memory.

       @rtype C{str}
       @return - encrypted bytes or decrypted text
    """
    if not isinstance(source, str):
        raise TypeError("only string data is supported")
    dest = str()
    cdef int read_len
    cdef int actual = 0
    cdef int i

    cdef int dest_buf_size = RSA_size(key)
    # flen must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based
    # padding mode.  This caused encryption failures on long messages.
    #
    # see http://www.openssl.org/docs/crypto/RSA_public_encrypt.html
    # see http://www.openssl.org/docs/crypto/RSA_private_encrypt.html
    cdef int reserved = dest_buf_size - 11
    cdef unsigned char *dest_buf 
    dest_buf = <unsigned char*>malloc(dest_buf_size)

    # make sure this doesn't find it's way into the try/block below
    if dest_buf is NULL:
        raise MemoryError()

    try:
        while source:
            read_len = min(len(source), dest_buf_size)
            if encrypt and bool(read_len > reserved):
                read_len = reserved
            #blindly call our RSA callback function
            i = func(
                read_len, <unsigned char*><char*>source,
                dest_buf, <RSA *>key, RSA_PKCS1_PADDING)

            if i == -1 or ERR_peek_error():
                ERR_clear_error()
                raise ValueError("Operation failed due to invalid input")
    # Cython doesn't make the unsigned char* to object syntax very clear
            tmp = <unsigned char*><char*>dest_buf
            if encrypt:
                actual += i
                dest += tmp[:bool(read_len < i) and i or read_len]
            else:
                actual += read_len
                dest += tmp[:i]
            source = source[read_len:]
        return dest[0:actual]
    finally:
        free(dest_buf)
