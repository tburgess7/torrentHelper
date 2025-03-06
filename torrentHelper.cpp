#include "torrentHelper.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <vector>
#include <curl/curl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <cstdio>      // For fopen, fseek, etc.
#include <chrono>
#include <ctime>
#include <cstdlib>     // For system()

namespace fs = std::filesystem;

// Global log file path (will be set in main based on executable location)
std::string g_logFilePath = "thelper.log";

// ---------------- Logging Functions ----------------

void logMessage(const std::string &level, const std::string &msg) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::string timeStr = std::ctime(&now_time);
    if (!timeStr.empty() && timeStr.back() == '\n')
        timeStr.pop_back();
    std::ofstream logFile(g_logFilePath, std::ios::app);
    logFile << "[" << timeStr << "] [" << level << "] " << msg << std::endl;
}

void logDebug(const std::string &msg) {
    logMessage("DEBUG", msg);
}

void logInfo(const std::string &msg) {
    logMessage("INFO", msg);
}

void logError(const std::string &msg) {
    logMessage("ERROR", msg);
}

// ---------------- Helper Functions ----------------

// Converts binary data to a hexadecimal string.
std::string toHexString(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Retrieves the SSL fingerprint from a given CURL connection.
std::string getSSLFingerprint(CURL* curl) {
    curl_certinfo* certinfo;
    std::string fingerprint;
    if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo) == CURLE_OK && certinfo->num_of_certs > 0) {
        struct curl_slist* slist = certinfo->certinfo[certinfo->num_of_certs - 1];
        while (slist) {
            if (strstr(slist->data, "Cert:")) {
                std::string cert_data = slist->data;
                size_t begin = cert_data.find("-----BEGIN CERTIFICATE-----");
                size_t end = cert_data.find("-----END CERTIFICATE-----") + 25;
                if (begin != std::string::npos && end != std::string::npos) {
                    std::string pem_cert = cert_data.substr(begin, end - begin);
                    BIO* bio = BIO_new_mem_buf(pem_cert.c_str(), -1);
                    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                    if (cert) {
                        unsigned char hash[SHA256_DIGEST_LENGTH];
                        X509_digest(cert, EVP_sha256(), hash, NULL);
                        fingerprint = toHexString(hash, SHA256_DIGEST_LENGTH);
                        X509_free(cert);
                    }
                    BIO_free(bio);
                    break;
                }
            }
            slist = slist->next;
        }
    }
    if (fingerprint.empty()) {
        logError("SSL Fingerprint extraction failed.");
    }
    return fingerprint;
}

// Loads configuration from a JSON file (default file is specified in the header)
bool loadConfig(Config& config, const std::string& configFile) {
    std::ifstream file(configFile);
    if (!file) {
        logError("Cannot open configuration file: " + configFile);
        return false;
    }
    Json::Value root;
    file >> root;
    config.ftps_server          = root["ftps_server"].asString();
    config.ftps_username        = root["ftps_username"].asString();
    config.ftps_password        = root["ftps_password"].asString();
    config.tv_remote_path       = root["tv_remote_path"].asString();
    config.movie_remote_path    = root["movie_remote_path"].asString();
    config.unsorted_remote_path = root["unsorted_remote_path"].asString();
    config.max_transfers        = root.get("max_transfers", 2).asInt();
    config.ftps_fingerprint     = root.get("ftps_fingerprint", "").asString();
    logInfo("Configuration loaded from " + configFile);
    return true;
}

// Saves the FTPS fingerprint to the configuration file.
void saveFingerprintToConfig(const std::string& fingerprint, const std::string& configFile) {
    std::ifstream file(configFile);
    Json::Value root;
    file >> root;
    root["ftps_fingerprint"] = fingerprint;
    std::ofstream outFile(configFile);
    outFile << root;
    logInfo("Saved FTPS fingerprint to " + configFile);
}

// ---------------- URL Encoding Helper ----------------

// A simple URL encoding function.
std::string urlEncode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << std::uppercase << int((unsigned char)c);
        }
    }
    return escaped.str();
}

// ---------------- File Type Helpers ----------------

// Returns a lowercase version of a string.
std::string toLower(const std::string &str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lowerStr;
}

// Determines if a file is a media file based on its extension.
bool isMediaFile(const fs::path &p) {
    std::string ext = toLower(p.extension().string());
    std::vector<std::string> mediaExts = {".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv"};
    return std::find(mediaExts.begin(), mediaExts.end(), ext) != mediaExts.end();
}

// Determines if a file is an archive (zip or rar).
bool isArchiveFile(const fs::path &p) {
    std::string ext = toLower(p.extension().string());
    return (ext == ".zip" || ext == ".rar");
}

// Extracts an archive file into the specified output directory using system calls.
// Returns true if extraction is successful.
bool extractArchive(const fs::path &archivePath, const fs::path &outputDir) {
    std::string archiveStr = archivePath.string();
    std::string outputStr = outputDir.string();
    int ret = -1;
    logInfo("Starting extraction of archive: " + archiveStr + " to " + outputStr);
    if (toLower(archivePath.extension().string()) == ".zip") {
        std::string cmd = "unzip -o \"" + archiveStr + "\" -d \"" + outputStr + "\"";
        ret = system(cmd.c_str());
    } else if (toLower(archivePath.extension().string()) == ".rar") {
        std::string cmd = "unrar x -o+ \"" + archiveStr + "\" \"" + outputStr + "\"";
        ret = system(cmd.c_str());
    }
    if(ret == 0)
        logInfo("Archive extracted successfully: " + archiveStr);
    else
        logError("Archive extraction failed: " + archiveStr);
    return (ret == 0);
}

// Forward declaration for testFTPSFileUpload.
bool testFTPSFileUpload(Config& config, const std::string& file_path, std::string &resultMsg);

// Recursively processes a directory. For each file:
//  - If it's an archive, extract it and process the extracted files.
//  - If it's a media file, transfer it.
//  - Otherwise, skip the file.
bool processDirectory(Config &config, const fs::path &dirPath, std::string &resultMsg) {
    bool overallSuccess = true;
    for (const auto &entry : fs::recursive_directory_iterator(dirPath)) {
        if (!entry.is_regular_file())
            continue;
        fs::path filePath = entry.path();
        if (isArchiveFile(filePath)) {
            fs::path tempDir = fs::temp_directory_path() / ("extracted_" + filePath.stem().string());
            fs::create_directory(tempDir);
            logInfo("Extracting archive file: " + filePath.string() + " into temporary directory: " + tempDir.string());
            if (extractArchive(filePath, tempDir)) {
                overallSuccess &= processDirectory(config, tempDir, resultMsg);
                fs::remove_all(tempDir);
                logInfo("Temporary extraction directory removed: " + tempDir.string());
            } else {
                logError("Failed to extract archive: " + filePath.string());
                overallSuccess = false;
            }
        } else if (isMediaFile(filePath)) {
            std::string uploadMsg;
            logInfo("Found media file: " + filePath.string());
            bool success = testFTPSFileUpload(config, filePath.string(), uploadMsg);
            logInfo("Upload result: " + uploadMsg);
            resultMsg += uploadMsg + "\n";
            overallSuccess &= success;
        } else {
            logDebug("Skipping non-media file: " + filePath.string());
        }
    }
    return overallSuccess;
}

// ---------------- FTPS Transfer Functions ----------------

// Tests file upload using a C-style file pointer.
// On success, resultMsg includes the filename and full destination URL.
// On failure, resultMsg includes the reason for failure.
bool testFTPSFileUpload(Config& config, const std::string& file_path, std::string &resultMsg) {
    logInfo("Attempting to upload file: " + file_path);
    CURL* curl = curl_easy_init();
    if (!curl) {
        resultMsg = "FAIL: Failed to initialize CURL.";
        logError(resultMsg);
        return false;
    }
    logDebug("Opening file for upload: " + file_path);
    FILE* file = fopen(file_path.c_str(), "rb");
    if (!file) {
        resultMsg = "FAIL: Could not open file: " + file_path;
        logError(resultMsg);
        curl_easy_cleanup(curl);
        return false;
    }
    logInfo("File opened successfully: " + file_path);
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);
    std::string fileName = fs::path(file_path).filename().string();
    std::string encodedFileName = urlEncode(fileName);
    std::string remote_file = config.tv_remote_path + "/" + encodedFileName;
    std::string ftp_url = "ftp://" + config.ftps_server + remote_file;
    logInfo("Constructed FTP URL: " + ftp_url);
    logInfo("Connecting to FTP server...");
    
    curl_easy_setopt(curl, CURLOPT_URL, ftp_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERPWD, (config.ftps_username + ":" + config.ftps_password).c_str());
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_FTP_SSL, CURLFTPSSL_ALL);
    curl_easy_setopt(curl, CURLOPT_FTP_SSL_CCC, CURLFTPSSL_CCC_NONE);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_READDATA, file);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);
    
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        resultMsg = "SUCCESS: " + fileName + " transferred to " + ftp_url;
        logInfo("File upload successful: " + file_path);
    } else {
        resultMsg = "FAIL: " + std::string(curl_easy_strerror(res));
        logError("File upload failed for " + file_path + ": " + std::string(curl_easy_strerror(res)));
    }
    curl_easy_cleanup(curl);
    fclose(file);
    logInfo("FTP connection closed for file: " + file_path);
    return (res == CURLE_OK);
}

// Tests the FTPS connection and verifies the SSL fingerprint.
// Logs connection and disconnection events.
// If the fingerprint doesn't match, a prompt is shown and the connection is aborted.
bool testFTPSConnection(Config& config) {
    logInfo("Establishing connection to FTP server: " + config.ftps_server);
    CURL* curl = curl_easy_init();
    if (!curl) {
        logError("Failed to initialize CURL for connection test.");
        return false;
    }
    std::string ftp_url = "ftp://" + config.ftps_server;
    curl_easy_setopt(curl, CURLOPT_URL, ftp_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERPWD, (config.ftps_username + ":" + config.ftps_password).c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_FTP_SSL, CURLFTPSSL_ALL);
    curl_easy_setopt(curl, CURLOPT_FTP_SSL_CCC, CURLFTPSSL_CCC_NONE);
    curl_easy_setopt(curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        logInfo("FTP connection established successfully.");
        std::string new_fingerprint = getSSLFingerprint(curl);
        if (new_fingerprint.empty()) {
            logError("Failed to retrieve SSL fingerprint during connection test.");
            curl_easy_cleanup(curl);
            return false;
        }
        if (!config.ftps_fingerprint.empty() && config.ftps_fingerprint != new_fingerprint) {
            std::cout << "WARNING: SSL fingerprint mismatch!" << std::endl;
            std::cout << "Expected: " << config.ftps_fingerprint << std::endl;
            std::cout << "Received: " << new_fingerprint << std::endl;
            std::cout << "For security reasons, the connection will not be established." << std::endl;
            std::cout << "Do you want to override and continue? (y/n): ";
            char answer;
            std::cin >> answer;
            logError("User prompted due to SSL fingerprint mismatch. Aborting connection.");
            curl_easy_cleanup(curl);
            return false;
        } else if (config.ftps_fingerprint.empty()) {
            logInfo("First-time connection, storing fingerprint: " + new_fingerprint);
            saveFingerprintToConfig(new_fingerprint, "config.json");
        } else {
            logInfo("FTPS credentials are valid and fingerprint matched.");
        }
    } else {
        logError("FTP connection test failed: " + std::string(curl_easy_strerror(res)));
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_cleanup(curl);
    logInfo("FTP connection closed after connection test.");
    return true;
}

// ---------------- Main Function ----------------

int main(int argc, char* argv[]) {
    // Set the log file path to be in the same directory as the executable.
    fs::path exePath = fs::canonical(argv[0]);
    fs::path logPath = exePath.parent_path() / "thelper.log";
    g_logFilePath = logPath.string();

    std::string resultMsg;
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    logDebug("Program started at: " + std::string(std::ctime(&now_time)));
    
    std::ostringstream argsStream;
    for (int i = 0; i < argc; ++i) {
         argsStream << argv[i] << " ";
    }
    logDebug("Command-line arguments: " + argsStream.str());

    // Parse command-line options for -category and -path.
    std::string category;
    std::string pathArg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-category" && i + 1 < argc) {
            category = argv[++i];
        } else if (arg == "-path" && i + 1 < argc) {
            pathArg = argv[++i];
        }
    }

    // Check if either -category or -path is empty.
    if (category.empty() || pathArg.empty()) {
        logError("Invalid usage: -category and -path must be provided and non-empty.");
        std::cout << "FAIL: -category and -path must be provided and non-empty." << std::endl;
        std::cout << "Usage: " << argv[0] << " -category tv|movies|unsorted -path path/to/file_or_directory" << std::endl;
        return 1;
    }

    // Further validate the category value.
    if (category != "tv" && category != "movies" && category != "unsorted") {
        logError("Invalid category provided: " + category);
        std::cout << "FAIL: Invalid category. Valid options are tv, movies, or unsorted." << std::endl;
        return 1;
    }

    logInfo("Category: " + category);
    logInfo("Path: " + pathArg);

    Config config;
    // Determine config.json path based on executable directory.
    fs::path exeDir = exePath.parent_path();
    fs::path configPath = exeDir / "config.json";
    if (!loadConfig(config, configPath.string())) {
        logError("Failed to load configuration. Exiting.");
        std::cout << "FAIL: Failed to load configuration." << std::endl;
        return 1;
    }

    // Choose the correct remote path based on category.
    if(category == "movies") {
        config.tv_remote_path = config.movie_remote_path;
        logInfo("Remote folder set to movies folder: " + config.movie_remote_path);
    } else if(category == "unsorted") {
        config.tv_remote_path = config.unsorted_remote_path;
        logInfo("Remote folder set to unsorted folder: " + config.unsorted_remote_path);
    } else if(category == "tv") {
        // Leave as is.
        logInfo("Remote folder set to tv folder: " + config.tv_remote_path);
    }

    fs::path inputPath(pathArg);
    bool overallSuccess = true;
    if (fs::is_directory(inputPath)) {
        logInfo("Processing directory: " + inputPath.string());
        overallSuccess = processDirectory(config, inputPath, resultMsg);
    } else if (fs::is_regular_file(inputPath)) {
        overallSuccess = testFTPSFileUpload(config, inputPath.string(), resultMsg);
    } else {
        logError("Invalid path provided: " + inputPath.string());
        std::cout << "FAIL: Provided path is not a valid file or directory." << std::endl;
        return 1;
    }

    std::cout << resultMsg << std::endl;
    return overallSuccess ? 0 : 1;
}

