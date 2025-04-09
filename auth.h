#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

int sign_data(const char* priv_key_path, const unsigned char* data, size_t data_len, unsigned char** sig_out, size_t* sig_len);

int verify_signature(const char* pub_key_path, const unsigned char* data, size_t data_len, const unsigned char* sig, size_t sig_len);

#endif 