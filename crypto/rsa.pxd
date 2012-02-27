cimport ossl_typ
cdef extern from "openssl/rsa.h":
    #work around for needing const
    ctypedef unsigned char* const_unsigned_char_ptr "const unsigned char*"
    ctypedef ossl_typ.RSA* const_RSA_ptr "const RSA *"

    enum: RSA_PKCS1_PADDING

    int RSA_public_encrypt(
        int flen, const_unsigned_char_ptr frm, 
        unsigned char *to, ossl_typ.RSA *rsa,int padding
    )

    int RSA_private_encrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, ossl_typ.RSA *rsa,int padding
    )

    int RSA_public_decrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, ossl_typ.RSA *rsa,int padding
    )
    int RSA_private_decrypt(
        int flen, const_unsigned_char_ptr frm,
        unsigned char *to, ossl_typ.RSA *rsa,int padding
    )

    ossl_typ.RSA* RSA_new()
    int RSA_up_ref(ossl_typ.RSA *r)
    void RSA_free (ossl_typ.RSA *r)
    int RSA_size(const_RSA_ptr)
