// Tests for src/Encryption.cpp:
//   base64_encode, base64_decode, AES_GenerateAndSaveKeys,
//   AES_GetKeyFromFile, encryptString, decryptString
//
// Include order: project header under test → undef conflicting macros → GTest

#include "Encryption.hpp"

#undef FAIL
#undef ERROR
#undef DEBUG

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include <gtest/gtest.h>

namespace
{

// ---------------------------------------------------------------------------
// Base64 encode / decode
// ---------------------------------------------------------------------------

TEST(Base64EncodeTest, KnownInput_MatchesRfc4648)
{
    const std::string plain = "Hello";
    char* encoded =
        base64_encode(reinterpret_cast<const unsigned char*>(plain.data()),
                      static_cast<int>(plain.size()));

    ASSERT_NE(encoded, nullptr);
    EXPECT_EQ(std::string(encoded), "SGVsbG8=");
    std::free(encoded);
}

TEST(Base64EncodeTest, EmptyInput_ReturnsEmptyString)
{
    char* encoded =
        base64_encode(reinterpret_cast<const unsigned char*>(""), 0);

    ASSERT_NE(encoded, nullptr);
    EXPECT_EQ(std::strlen(encoded), 0u);
    std::free(encoded);
}

TEST(Base64EncodeTest, BinaryPayload_RoundTripsCleanly)
{
    const unsigned char payload[16] = {0x00, 0x01, 0x02, 0x03, 0x10, 0x11,
                                       0x7f, 0x80, 0x9a, 0xab, 0xcd, 0xef,
                                       0xfe, 0xdc, 0xba, 0x99};
    char* encoded = base64_encode(payload, 16);
    ASSERT_NE(encoded, nullptr);

    int decodedLen = 0;
    unsigned char* decoded = base64_decode(encoded, &decodedLen);
    std::free(encoded);

    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decodedLen, 16);
    EXPECT_EQ(std::memcmp(decoded, payload, 16), 0);
    std::free(decoded);
}

TEST(Base64DecodeTest, ValidInput_RestoresOriginal)
{
    const std::string plain = "OpenBMC PEF unit test";
    char* encoded =
        base64_encode(reinterpret_cast<const unsigned char*>(plain.data()),
                      static_cast<int>(plain.size()));
    ASSERT_NE(encoded, nullptr);

    int outLen = 0;
    unsigned char* decoded = base64_decode(encoded, &outLen);
    std::free(encoded);

    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(outLen, static_cast<int>(plain.size()));
    EXPECT_EQ(std::string(reinterpret_cast<char*>(decoded), outLen), plain);
    std::free(decoded);
}

TEST(Base64DecodeTest, EmptyString_ReturnsNullOrZeroLength)
{
    int outLen = 42;
    unsigned char* decoded = base64_decode("", &outLen);
    if (decoded != nullptr)
    {
        std::free(decoded);
    }
    EXPECT_LE(outLen, 0);
}

// ---------------------------------------------------------------------------
// AES key generation and file I/O
// ---------------------------------------------------------------------------

class AesKeyFileFixture : public ::testing::Test
{
  protected:
    std::filesystem::path keyPath;
    std::filesystem::path ivPath;

    void SetUp() override
    {
        keyPath = std::filesystem::temp_directory_path() /
                  "pef_test_aes_key_XXXXXX.key";
        ivPath = std::filesystem::temp_directory_path() /
                 "pef_test_aes_iv_XXXXXX.iv";
        std::filesystem::remove(keyPath);
        std::filesystem::remove(ivPath);
    }

    void TearDown() override
    {
        std::filesystem::remove(keyPath);
        std::filesystem::remove(ivPath);
    }
};

TEST_F(AesKeyFileFixture, GenerateAndSave_ValidPaths_ReturnsTrueAndFilesExist)
{
    EXPECT_TRUE(AES_GenerateAndSaveKeys(keyPath.c_str(), ivPath.c_str()));
    EXPECT_TRUE(std::filesystem::exists(keyPath));
    EXPECT_TRUE(std::filesystem::exists(ivPath));
}

TEST(AesKeyFileTest, GenerateAndSave_InvalidDirectory_ReturnsFalse)
{
    EXPECT_FALSE(AES_GenerateAndSaveKeys("/nonexistent_dir_pef/key.bin",
                                         "/nonexistent_dir_pef/iv.bin"));
}

TEST_F(AesKeyFileFixture, GetKeyFromFile_AfterGenerate_ReturnsZeroForKey)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(keyPath.c_str(), ivPath.c_str()));

    unsigned char keyBuf[AES_MAX_KEY_LENGTH] = {};
    EXPECT_EQ(AES_GetKeyFromFile(keyPath.c_str(), keyBuf, AES_MAX_KEY_LENGTH),
              0);
}

TEST_F(AesKeyFileFixture, GetKeyFromFile_AfterGenerate_ReturnsZeroForIV)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(keyPath.c_str(), ivPath.c_str()));

    unsigned char ivBuf[AES_MAX_IV_LENGTH] = {};
    EXPECT_EQ(AES_GetKeyFromFile(ivPath.c_str(), ivBuf, AES_MAX_IV_LENGTH), 0);
}

TEST(AesKeyFileTest, GetKeyFromFile_NonExistentFile_ReturnsNegative)
{
    unsigned char buf[AES_MAX_KEY_LENGTH] = {};
    EXPECT_LT(
        AES_GetKeyFromFile("/nonexistent_pef_aes.key", buf, AES_MAX_KEY_LENGTH),
        0);
}

TEST_F(AesKeyFileFixture, GetKeyFromFile_WrongExpectedSize_ReturnsNegative)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(keyPath.c_str(), ivPath.c_str()));

    unsigned char buf[AES_MAX_KEY_LENGTH] = {};
    EXPECT_LT(AES_GetKeyFromFile(keyPath.c_str(), buf, AES_MAX_IV_LENGTH), 0);
}

// ---------------------------------------------------------------------------
// encryptString / decryptString round-trip (uses temp key files)
// ---------------------------------------------------------------------------

class EncryptionRoundTripFixture : public ::testing::Test
{
  protected:
    const char* savedKeyFile = nullptr;
    const char* savedIvFile = nullptr;
    std::filesystem::path keyPath;
    std::filesystem::path ivPath;

    void SetUp() override
    {
        keyPath = std::filesystem::temp_directory_path() /
                  "pef_enc_rt_test.key";
        ivPath = std::filesystem::temp_directory_path() / "pef_enc_rt_test.iv";
        std::filesystem::remove(keyPath);
        std::filesystem::remove(ivPath);

        savedKeyFile = aesKeyFile;
        savedIvFile = aesIVFile;
        aesKeyFile = keyPath.c_str();
        aesIVFile = ivPath.c_str();
    }

    void TearDown() override
    {
        aesKeyFile = savedKeyFile;
        aesIVFile = savedIvFile;
        std::filesystem::remove(keyPath);
        std::filesystem::remove(ivPath);
    }
};

TEST_F(EncryptionRoundTripFixture,
       EncryptString_KeysAlreadyExist_UsesExistingKeys)
{
    // Generate keys first
    ASSERT_TRUE(AES_GenerateAndSaveKeys(keyPath.c_str(), ivPath.c_str()));
    std::string ct = encryptString("pre-existing keys test");
    EXPECT_FALSE(ct.empty());
}

TEST_F(EncryptionRoundTripFixture, EncryptDecrypt_CalledTwice_BothSucceed)
{
    std::string ct1 = encryptString("first");
    std::string ct2 = encryptString("second");
    EXPECT_FALSE(ct1.empty());
    EXPECT_FALSE(ct2.empty());
}

TEST_F(EncryptionRoundTripFixture, EncryptDecrypt_PlainText_RestoresOriginal)
{
    const std::string plaintext = "OpenBMC PEF secret community";
    std::string ciphertext = encryptString(plaintext);

    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);

    EXPECT_EQ(decrypted, plaintext);
    EXPECT_EQ(outLen, static_cast<int>(plaintext.size()));
}

TEST_F(EncryptionRoundTripFixture, Encrypt_EmptyPlaintext_ReturnsNonEmpty)
{
    std::string ciphertext = encryptString("");
    EXPECT_FALSE(ciphertext.empty());
}

TEST_F(EncryptionRoundTripFixture, Decrypt_EmptyCiphertext_ReturnsEmptyString)
{
    int outLen = 99;
    std::string result = decryptString("", &outLen);

    EXPECT_TRUE(result.empty());
    EXPECT_EQ(outLen, 0);
}

TEST_F(EncryptionRoundTripFixture, Decrypt_NullOutLen_DoesNotCrash)
{
    std::string ciphertext = encryptString("safe call test");
    ASSERT_FALSE(ciphertext.empty());

    std::string result = decryptString(ciphertext, nullptr);
    EXPECT_EQ(result, "safe call test");
}

TEST_F(EncryptionRoundTripFixture, EncryptDecrypt_LongPlaintext_RoundTrips)
{
    const std::string plaintext(512, 'X');
    std::string ciphertext = encryptString(plaintext);
    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);
    EXPECT_EQ(decrypted, plaintext);
    EXPECT_EQ(outLen, 512);
}

TEST_F(EncryptionRoundTripFixture,
       EncryptDecrypt_KeysAlreadyExist_UsesElseBranch)
{
    // First call: key files absent → auto-generate (if branch)
    std::string ct1 = encryptString("first");
    ASSERT_FALSE(ct1.empty());

    // Second call: key files now exist → fclose path (else branch)
    const std::string plain2 = "second call with pre-existing keys";
    std::string ct2 = encryptString(plain2);
    ASSERT_FALSE(ct2.empty());

    int outLen = 0;
    EXPECT_EQ(decryptString(ct2, &outLen), plain2);
}

TEST_F(EncryptionRoundTripFixture, EncryptDecrypt_SpecialChars_RoundTrips)
{
    const std::string plaintext = "p@$$w0rd!#%^&*()-=+[]{}|;':\",./<>?`~\n\t";
    std::string ciphertext = encryptString(plaintext);
    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);
    EXPECT_EQ(decrypted, plaintext);
}

TEST(DecryptStringTest, MissingKeyFile_ReturnsEmptyString)
{
    const char* orig = aesKeyFile;
    aesKeyFile = "/nonexistent_dir_pef/missing.key";

    int outLen = 0;
    std::string result = decryptString("U29tZUNpcGhlcg==", &outLen);

    aesKeyFile = orig;
    EXPECT_TRUE(result.empty());
}

} // namespace
