#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <iostream>

// Generate a random salt
std::string generateSalt(size_t length = 16) {
    unsigned char salt[length];
    RAND_bytes(salt, length);

    std::stringstream ss;
    for (size_t i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return ss.str();
}

// Hash the password with salt using SHA-256
std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string saltedPassword = salt + password;  // Combine salt + password
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)saltedPassword.c_str(), saltedPassword.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return salt + ":" + ss.str();  // Store salt and hash together
}
