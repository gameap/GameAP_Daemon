#ifndef CRYPT_H
#define CRYPT_H

// ---------------------------------------------------------------------

std::string aes_encrypt(const std::string& str_in, const std::string& key);

// ---------------------------------------------------------------------

std::string aes_decrypt(const std::string& str_in, const std::string& key);

// ---------------------------------------------------------------------

std::string base64_encode(std::string string);

// ---------------------------------------------------------------------

std::string base64_decode(std::string encoded);

#endif
