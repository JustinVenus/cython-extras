cdef extern from "openssl/ossl_typ.h":
    ctypedef int ASN1_BOOLEAN
    ctypedef int ASN1_NULL
    #pointer types
    ctypedef struct ASN1_INTEGER:
        pass
    ctypedef struct ASN1_ENUMERATED:
        pass
    ctypedef struct ASN1_BIT_STRING:
        pass
    ctypedef struct ASN1_OCTET_STRING:
        pass
    ctypedef struct ASN1_PRINTABLESTRING:
        pass
    ctypedef struct ASN1_T61STRING:
        pass
    ctypedef struct ASN1_IA5STRING:
        pass
    ctypedef struct ASN1_GENERALSTRING:
        pass
    ctypedef struct ASN1_UNIVERSALSTRING:
        pass
    ctypedef struct ASN1_BMPSTRING:
        pass
    ctypedef struct ASN1_UTCTIME:
        pass
    ctypedef struct ASN1_TIME:
        pass
    ctypedef struct ASN1_GENERALIZEDTIME:
        pass
    ctypedef struct ASN1_VISIBLESTRING:
        pass
    ctypedef struct ASN1_UTF8STRING:
        pass
    ctypedef struct ASN1_PCTX:
        pass
    ctypedef struct BIGNUM:
        pass
    ctypedef struct BN_CTX:
        pass
    ctypedef struct BN_BLINDING:
        pass
    ctypedef struct BN_MONT_CTX:
        pass
    ctypedef struct BN_RECP_CTX:
        pass
    ctypedef struct BN_GENCB:
        pass
    ctypedef struct BUF_MEM:
        pass
    ctypedef struct EVP_CIPHER:
        pass
    ctypedef struct EVP_CIPHER_CTX:
        pass
    ctypedef struct EVP_MD:
        pass
    ctypedef struct EVP_MD_CTX:
        pass
    ctypedef struct EVP_PKEY:
        pass
    ctypedef struct EVP_PKEY_ASN1_METHOD:
        pass
    ctypedef struct EVP_PKEY_METHOD:
        pass
    ctypedef struct EVP_PKEY_CTX:
        pass
    ctypedef struct DH:
        pass
    ctypedef struct DH_METHOD:
        pass
    ctypedef struct DSA:
        pass
    ctypedef struct DSA_METHOD:
        pass
    ctypedef struct RSA:
        pass
    ctypedef struct RSA_METHOD:
        pass
    ctypedef struct RAND_METHOD:
        pass
    ctypedef struct ECDH_METHOD:
        pass
    ctypedef struct ECDSA_METHOD:
        pass
    ctypedef struct X509:
        pass
    ctypedef struct X509_ALGOR:
        pass
    ctypedef struct X509_CRL:
        pass
    ctypedef struct X509_CRL_METHOD:
        pass
    ctypedef struct X509_REVOKED:
        pass
    ctypedef struct X509_NAME:
        pass
    ctypedef struct X509_PUBKEY:
        pass
    ctypedef struct X509_STORE:
        pass
    ctypedef struct X509_STORE_CTX:
        pass
    ctypedef struct PKCS8_PRIV_KEY_INFO:
        pass
    ctypedef struct X509V3_CTX:
        pass
    ctypedef struct CONF:
        pass
    ctypedef struct STORE:
        pass
    ctypedef struct STORE_METHOD:
        pass
    ctypedef struct UI:
        pass
    ctypedef struct UI_METHOD:
        pass
    ctypedef struct ERR_FNS:
        pass
    ctypedef struct ENGINE:
        pass
    ctypedef struct SSL:
        pass
    ctypedef struct SSL_CTX:
        pass
    ctypedef struct X509_POLICY_NODE:
        pass
    ctypedef struct X509_POLICY_LEVEL:
        pass
    ctypedef struct X509_POLICY_TREE:
        pass
    ctypedef struct X509_POLICY_CACHE:
        pass
    ctypedef struct AUTHORITY_KEYID:
        pass
    ctypedef struct DIST_POINT:
        pass
    ctypedef struct ISSUING_DIST_POINT:
        pass
    ctypedef struct NAME_CONSTRAINTS:
        pass
    ctypedef struct CRYPTO_EX_DATA:
        pass
    ctypedef struct OCSP_REQ_CTX:
        pass
    ctypedef struct OCSP_RESPONSE:
        pass
    ctypedef struct OCSP_RESPID:
        pass

    #Callback types for crypto.h
    ctypedef int CRYPTO_EX_new(
        void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp
    )
    ctypedef void CRYPTO_EX_free(
        void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp
    )
    ctypedef int CRYPTO_EX_dup(
        CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *frm, void *from_d,
        int idx, long argl, void *argp
    )
