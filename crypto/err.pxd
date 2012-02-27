cdef extern from "openssl/err.h":
    unsigned long ERR_peek_error()
    void ERR_clear_error()
