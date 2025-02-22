#ifndef TORRENTHelper_H
#define TORRENTHelper_H

#include <string>
#include <jsoncpp/json/json.h>

// Structure to hold configuration settings
struct Config {
    std::string ftps_server;
    std::string ftps_username;
    std::string ftps_password;
    std::string tv_remote_path;
    std::string movie_remote_path;
    std::string unsorted_remote_path;
    int max_transfers;
    std::string ftps_fingerprint;
};

// Function declarations with default arguments (specified here only)
bool loadConfig(Config& config, const std::string& configFile = "config.json");
void saveFingerprintToConfig(const std::string& fingerprint, const std::string& configFile = "config.json");

#endif // TORRENTHelper_H
