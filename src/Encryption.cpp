#include "Encryption.hpp"

#include "pef_debug.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

const char* aesKeyFile = "/etc/snmp/AESKey";
const char* aesIVFile = "/etc/snmp/AESIV";

char* base64_encode(const unsigned char* input, int length)
{
    PEF_ENC_DBG("base64_encode length=" << length);
    BIO *bio, *b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char* output = static_cast<char*>(std::malloc(bufferPtr->length + 1));
    std::memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return output;
}

unsigned char* base64_decode(const char* input, int* out_length)
{
    PEF_ENC_DBG("base64_decode input_len=" << std::strlen(input));
    BIO *bio, *b64;
    int decodeLen = static_cast<int>(std::strlen(input));
    unsigned char* buffer =
        static_cast<unsigned char*>(std::malloc(decodeLen + 1));

    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    *out_length = BIO_read(bio, buffer, decodeLen);
    BIO_free_all(bio);

    if (*out_length <= 0)
    {
        PEF_ENC_DBG("base64_decode failed out_length=" << *out_length);
        std::free(buffer);
        return nullptr;
    }
    return buffer;
}

bool AES_GenerateAndSaveKeys(const char* keyFile, const char* ivFile)
{
    PEF_ENC_DBG(
        "AES_GenerateAndSaveKeys keyFile=" << keyFile << " ivFile=" << ivFile);
    unsigned char key[AES_MAX_KEY_LENGTH];
    unsigned char iv[AES_MAX_IV_LENGTH];

    if (RAND_bytes(key, AES_MAX_KEY_LENGTH) != 1 ||
        RAND_bytes(iv, AES_MAX_IV_LENGTH) != 1)
    {
        PEF_ENC_DBG("AES_GenerateAndSaveKeys RAND_bytes failed");
        return false;
    }

    char* encodedKey = base64_encode(key, AES_MAX_KEY_LENGTH);
    char* encodedIV = base64_encode(iv, AES_MAX_IV_LENGTH);

    FILE* fkey = std::fopen(keyFile, "wb");
    FILE* fiv = std::fopen(ivFile, "wb");
    if (!fkey || !fiv)
    {
        PEF_ENC_DBG("AES_GenerateAndSaveKeys file open failed");
        std::free(encodedKey);
        std::free(encodedIV);
        if (fkey)
        {
            std::fclose(fkey);
        }
        if (fiv)
        {
            std::fclose(fiv);
        }
        return false;
    }

    std::fwrite(encodedKey, 1, std::strlen(encodedKey), fkey);
    std::fwrite(encodedIV, 1, std::strlen(encodedIV), fiv);

    std::fclose(fkey);
    std::fclose(fiv);
    std::free(encodedKey);
    std::free(encodedIV);

    return true;
}

int AES_GetKeyFromFile(const char* filename, unsigned char* buffer,
                       int buffer_size)
{
    PEF_ENC_DBG("AES_GetKeyFromFile file="
                << filename << " expectedSize=" << buffer_size);
    FILE* file = std::fopen(filename, "rb");
    if (!file)
    {
        PEF_ENC_DBG("AES_GetKeyFromFile open failed file=" << filename);
        return -1;
    }

    std::fseek(file, 0, SEEK_END);
    long file_size = std::ftell(file);
    if (file_size == -1)
    {
        PEF_ENC_DBG("AES_GetKeyFromFile ftell failed file=" << filename);
        std::fclose(file);
        return -1;
    }
    std::fseek(file, 0, SEEK_SET);

    char* encoded = static_cast<char*>(std::malloc(file_size + 1));
    if (!encoded)
    {
        PEF_ENC_DBG("AES_GetKeyFromFile alloc failed file=" << filename);
        std::fclose(file);
        return -1;
    }

    size_t nread = std::fread(encoded, 1, file_size, file);
    if (nread != static_cast<size_t>(file_size))
    {
        PEF_ENC_DBG("AES_GetKeyFromFile fread mismatch file="
                    << filename << " read=" << nread
                    << " expected=" << file_size);
        std::fclose(file);
        std::free(encoded);
        return -1;
    }
    encoded[file_size] = '\0';
    std::fclose(file);

    int out_len = 0;
    unsigned char* decoded = base64_decode(encoded, &out_len);
    std::free(encoded);

    if (!decoded || out_len != buffer_size)
    {
        PEF_ENC_DBG("AES_GetKeyFromFile decode size mismatch file="
                    << filename << " out_len=" << out_len
                    << " expected=" << buffer_size);
        if (decoded)
        {
            std::free(decoded);
        }
        return -1;
    }

    std::memcpy(buffer, decoded, buffer_size);
    std::free(decoded);
    return 0;
}

std::string encryptString(const std::string& plaintext)
{
    PEF_ENC_DBG("encryptString plaintextLen=" << plaintext.size());
    FILE* keyFile = std::fopen(aesKeyFile, "rb");
    FILE* ivFile = std::fopen(aesIVFile, "rb");
    if (!keyFile || !ivFile)
    {
        if (keyFile)
        {
            std::fclose(keyFile);
        }
        if (ivFile)
        {
            std::fclose(ivFile);
        }
        if (!AES_GenerateAndSaveKeys(aesKeyFile, aesIVFile))
        {
            std::cerr << "Failed to generate AES key/IV files" << std::endl;
            PEF_ENC_DBG("encryptString failed key generation");
            return "";
        }
    }
    else
    {
        std::fclose(keyFile);
        std::fclose(ivFile);
    }

    unsigned char key[AES_MAX_KEY_LENGTH];
    unsigned char iv[AES_MAX_IV_LENGTH];

    if (AES_GetKeyFromFile(aesKeyFile, key, AES_MAX_KEY_LENGTH) < 0)
    {
        std::cerr << "Failed to read AES key" << std::endl;
        return "";
    }
    if (AES_GetKeyFromFile(aesIVFile, iv, AES_MAX_IV_LENGTH) < 0)
    {
        std::cerr << "Failed to read AES IV" << std::endl;
        return "";
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP context" << std::endl;
        return "";
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv))
    {
        std::cerr << "Failed to initialize encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len = 0;
    int ciphertext_len = 0;
    std::vector<unsigned char> ciphertext(
        plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptUpdate(
                 ctx, ciphertext.data(), &len,
                 reinterpret_cast<const unsigned char*>(plaintext.data()),
                 static_cast<int>(plaintext.size())))
    {
        std::cerr << "Encryption update failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        std::cerr << "Encryption finalization failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    char* b64 = base64_encode(ciphertext.data(), ciphertext_len);
    if (!b64)
    {
        std::cerr << "Base64 encoding failed" << std::endl;
        return "";
    }
    std::string encoded(b64);
    std::free(b64);

    return encoded;
}

std::string decryptString(const std::string& b64Ciphertext,
                          int* out_plaintext_len)
{
    PEF_ENC_DBG("decryptString ciphertextLen=" << b64Ciphertext.size());
    if (b64Ciphertext.empty())
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        return {};
    }

    FILE* keyFile = std::fopen(aesKeyFile, "rb");
    if (keyFile)
    {
        std::fclose(keyFile);
    }
    else
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "AES key file not found" << std::endl;
        PEF_ENC_DBG("decryptString missing key file");
        return "";
    }

    FILE* ivFile = std::fopen(aesIVFile, "rb");
    if (ivFile)
    {
        std::fclose(ivFile);
    }
    else
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "AES IV file not found" << std::endl;
        PEF_ENC_DBG("decryptString missing iv file");
        return "";
    }

    std::array<unsigned char, AES_MAX_KEY_LENGTH> key{};
    std::array<unsigned char, AES_MAX_IV_LENGTH> iv{};

    if (AES_GetKeyFromFile(aesKeyFile, key.data(),
                           static_cast<int>(key.size())) < 0)
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Failed to read AES key" << std::endl;
        return "";
    }
    if (AES_GetKeyFromFile(aesIVFile, iv.data(), static_cast<int>(iv.size())) <
        0)
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Failed to read AES IV" << std::endl;
        return "";
    }

    int ciphertext_len = 0;
    unsigned char* ciphertext_raw =
        base64_decode(b64Ciphertext.c_str(), &ciphertext_len);
    if (!ciphertext_raw || ciphertext_len <= 0)
    {
        if (ciphertext_raw)
        {
            std::free(ciphertext_raw);
        }
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Base64 decoding failed" << std::endl;
        PEF_ENC_DBG("decryptString base64 decode failed");
        return "";
    }
    std::vector<unsigned char> ciphertext(ciphertext_raw,
                                          ciphertext_raw + ciphertext_len);
    std::free(ciphertext_raw);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Failed to create EVP context" << std::endl;
        PEF_ENC_DBG("decryptString failed to create EVP context");
        return "";
    }

    std::vector<unsigned char> plaintext(
        ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                                iv.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Failed to initialize decryption" << std::endl;
        PEF_ENC_DBG("decryptString EVP_DecryptInit_ex failed");
        return "";
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                               ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Decryption update failed" << std::endl;
        PEF_ENC_DBG("decryptString EVP_DecryptUpdate failed");
        return "";
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        if (out_plaintext_len)
        {
            *out_plaintext_len = 0;
        }
        std::cerr << "Decryption finalization failed" << std::endl;
        PEF_ENC_DBG("decryptString EVP_DecryptFinal_ex failed");
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result(reinterpret_cast<char*>(plaintext.data()),
                       static_cast<size_t>(plaintext_len));
    if (out_plaintext_len)
    {
        *out_plaintext_len = plaintext_len;
    }
    PEF_ENC_DBG("decryptString success plaintextLen=" << plaintext_len);
    return result;
}
