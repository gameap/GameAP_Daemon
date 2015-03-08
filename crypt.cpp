#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>

#include "crypt.h"

// ---------------------------------------------------------------------

std::string aes_encrypt(const std::string& str_in, const std::string& key)
{
    std::string str_out;
    
	CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption e;
	e.SetKey((byte*)key.c_str(), key.length());

    CryptoPP::StringSource encryptor(str_in, true, 
        new CryptoPP::StreamTransformationFilter(e, 
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(str_out),
                false // do not append a newline
            )
        )
    );
    return str_out;
}

// ---------------------------------------------------------------------

std::string aes_decrypt(const std::string& str_in, const std::string& key)
{
    std::string str_out;

	CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption d;
	d.SetKey((byte*)key.c_str(), key.length());

    CryptoPP::StringSource decryptor(str_in, true, 
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(d, 
                new CryptoPP::StringSink(str_out)
            )
        )
    );
    return str_out;
} 

// ---------------------------------------------------------------------

std::string base64_encode(std::string string)
{
	std::string encoded;
	   
	CryptoPP::StringSource ss(string, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		)
	);
	
	return encoded;
}

// ---------------------------------------------------------------------

std::string base64_decode(std::string encoded)
{
	std::string decoded;
	   
	CryptoPP::StringSource ss(encoded, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		)
	);
	
	return decoded;
}
