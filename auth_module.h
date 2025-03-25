std::string generateSalt(size_t length = 16);
std::string hashPassword(const std::string& password, const std::string& salt);
