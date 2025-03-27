// g++ -std=c++11 -pthread casa.cpp -lssl -lcrypto -o casa
// WARNING: This code is a concoction of mixed libraries and bluffs; use at your own risk!
// The author is not responsible for any damages, losses, or other negative outcomes that may arise from the use of this code.
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <random>
#include <unordered_set>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <csignal>
#include <stdexcept>
#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <iomanip>

// OpenSSL headers
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

using namespace std;
using namespace std::chrono;

//------------------------------------------------------------------------------
// Global configuration and state
//------------------------------------------------------------------------------
const long long LOG_INTERVAL = 1000000000LL; // checkpoint every 1e9 keys
atomic<long long> keyCounter(0);
atomic<long long> matchCounter(0);
atomic<long long> validKeyCounter(0);    // Added: Counter for valid keys
atomic<long long> invalidKeyCounter(0);  // Added: Counter for invalid keys
mutex fileMutex;

int miniKeyLength = 22;      // Allowed mini key lengths: 22, 23, 26, 30
int printInterval = 0;       // seconds between performance prints
int numThreads = 1;          // default number of worker threads
bool sequenceMode = false;   // resume mode enabled
bool loggingMode = false;    // logging checkpoint mode enabled
bool multiMode = false;      // multi mini key lengths mode enabled
string targetFile = "";      // optional file of target RIPEMD160 hashes
unordered_set<string> targetHashes; // Changed to unordered_set for O(1) lookup

// For resume mode using a base key
string baseMiniKey = "";
atomic<long long> globalIndex(0);

ofstream savedFile;          // log of all generated keys (saved.txt)
ofstream foundFile;          // log of matching keys (casascius_found.txt)
ofstream sequenceLogFile;    // log for saving the last key (for resume)

steady_clock::time_point startTime;
atomic<bool> shutdownFlag(false);  // used to signal graceful termination

// -------------------- Bloom Filter Implementation ----------------------
const size_t BLOOM_SIZE = 1000000000;  // e.g., 1e9 bits (~125MB)
const size_t BLOOM_HASHES = 7;         // Number of hash functions

class BloomFilter {
    vector<uint32_t> bit_array;
    size_t m; // total number of bits
    size_t k; // number of hash functions

    inline void set_bit(size_t pos) {
        bit_array[pos >> 5] |= (1u << (pos & 31));
    }

    inline bool test_bit(size_t pos) const {
        return bit_array[pos >> 5] & (1u << (pos & 31));
    }

public:
    BloomFilter(size_t m_bits, size_t num_hashes)
        : bit_array((m_bits + 31) / 32, 0), m(m_bits), k(num_hashes) {}

    void add(const string& item) {
        size_t hash1 = hash<string>{}(item);
        size_t hash2 = hash<string>{}("salt" + item);
        for (size_t i = 0; i < k; ++i) {
            size_t combined = hash1 + i * hash2;
            size_t idx = combined % m;
            set_bit(idx);
        }
    }

    bool possibly_contains(const string& item) const {
        size_t hash1 = hash<string>{}(item);
        size_t hash2 = hash<string>{}("salt" + item);
        for (size_t i = 0; i < k; ++i) {
            size_t combined = hash1 + i * hash2;
            size_t idx = combined % m;
            if (!test_bit(idx))
                return false;
        }
        return true;
    }
};

BloomFilter* targetBloom = nullptr; // Global pointer for the Bloom filter

// -------------------- Function Prototypes ----------------------
string derivePrivateKey(const string &miniKey);
vector<unsigned char> derivePublicKey(EC_KEY* ecKey, const string &privateKeyHex, bool compressed);
string computeRipemdFromPubKey(const vector<unsigned char> &pubKey);
string randomMiniKey(int length, mt19937& gen);
string generateSequentialMiniKey();
void loadTargetHashes(const string &filename);
void printHelp();
bool isValidMiniKey(const string &miniKey);
string generateBTCAddress(const vector<unsigned char>& pubKey);
string Base58Encode(const vector<unsigned char>& input);
int randomAllowedLength(mt19937& gen);
long long extractIndexFromKey(const string &key);
void processDerive(const string &casakey);
void generationThread();
string readLastNonEmptyLine(const string &filename);
void signalHandler(int signum);

// -------------------- Function Definitions ----------------------

// **printHelp**: Display usage instructions.
void printHelp() {
    cout << "[X]Usage: ./casa [options]\n\n";
    cout << "-h / -help      : Display this help guide.\n  Shows each argument with exactly two lines of explanation.\n";
    cout << "-p / -print N   : Set print interval to N seconds.\n  Determines how frequently performance is printed to the console.\n";
    cout << "-S / -seq [key] : Enable sequence (resume) mode.\n  If a mini key is provided after -S, its numeric part is extracted and generation resumes sequentially. Otherwise, the last key from sequence_log.txt is used.\n";
    cout << "-t / -core N    : Set number of worker threads to N.\n  Specifies the number of CPU cores for parallel key generation.\n";
    cout << "-b / -bit N     : Set mini key length to N (allowed: 22, 23, 26, 30).\n  Customizes the mini key length; invalid values trigger this guide.\n";
    cout << "-f / -file F    : Use target file F of RIPEMD160 hashes for matching.\n  Generated key hashes are compared against those in F; matches are logged in casascius_found.txt.\n";
    cout << "-log            : Enable logging mode; save the last key every 1e9 keys into sequence_log.txt.\n  Facilitates resuming key generation from the last checkpoint.\n";
    cout << "--derive <casakey> : Provide a reality check for the given key.\n  Displays the short key, raw private key, checksum verification, and derived BTC address.\n";
    cout << "--multi        : Generate mini keys with random lengths among allowed values (22, 23, 26, 30).\n  Ensures diverse key generation across allowed mini key lengths.\n";
}

// **isValidMiniKey**: Verify the mini key using Casascius rules.
bool isValidMiniKey(const string &miniKey) {
    string checkStr = miniKey + "?";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(checkStr.c_str()), checkStr.size(), hash);
    return (hash[0] == 0x00);
}

// **Base58Encode**: Encode a byte vector into a Base58 string.
string Base58Encode(const vector<unsigned char>& input) {
    const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    int zeros = 0;
    for (size_t i = 0; i < input.size(); i++) {
        if (input[i] == 0)
            zeros++;
        else
            break;
    }
    BIGNUM* bn = BN_new();
    if (!bn) return "";
    BN_bin2bn(input.data(), input.size(), bn);
    BIGNUM* bn58 = BN_new();
    if (!bn58) { BN_free(bn); return ""; }
    BN_set_word(bn58, 58);
    BIGNUM* bn0 = BN_new();
    if (!bn0) { BN_free(bn); BN_free(bn58); return ""; }
    BN_zero(bn0);
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { BN_free(bn); BN_free(bn58); BN_free(bn0); return ""; }
    string result;
    while (BN_cmp(bn, bn0) > 0) {
        BIGNUM* dv = BN_new();
        BIGNUM* rem = BN_new();
        if (!dv || !rem) { break; }
        if (BN_div(dv, rem, bn, bn58, ctx) == 0) { BN_free(dv); BN_free(rem); break; }
        int rem_int = BN_get_word(rem);
        result.insert(result.begin(), pszBase58[rem_int]);
        BN_copy(bn, dv);
        BN_free(dv);
        BN_free(rem);
    }
    for (int i = 0; i < zeros; i++) {
        result.insert(result.begin(), '1');
    }
    BN_free(bn);
    BN_free(bn58);
    BN_free(bn0);
    BN_CTX_free(ctx);
    return result;
}

// **generateBTCAddress**: Create a Bitcoin address from a compressed public key.
string generateBTCAddress(const vector<unsigned char>& pubKey) {
    unsigned char shaHash[SHA256_DIGEST_LENGTH];
    SHA256(pubKey.data(), pubKey.size(), shaHash);
    unsigned char ripemdHash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(shaHash, SHA256_DIGEST_LENGTH, ripemdHash);
    vector<unsigned char> payload;
    payload.push_back(0x00);
    payload.insert(payload.end(), ripemdHash, ripemdHash + RIPEMD160_DIGEST_LENGTH);
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(payload.data(), payload.size(), hash1);
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    vector<unsigned char> addressBytes = payload;
    addressBytes.insert(addressBytes.end(), hash2, hash2 + 4);
    return Base58Encode(addressBytes);
}

// **randomAllowedLength**: Return a random allowed mini key length using a provided generator.
int randomAllowedLength(mt19937& gen) {
    vector<int> allowed = {22, 23, 26, 30};
    uniform_int_distribution<> dis(0, allowed.size() - 1);
    return allowed[dis(gen)];
}

// **randomMiniKey**: Generate a random alphanumeric mini key of the given length using a provided generator.
string randomMiniKey(int length, mt19937& gen) {
    static const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    uniform_int_distribution<> dis(0, chars.size() - 1);
    string key;
    key.push_back('S');
    for (int i = 1; i < length; i++) {
        key.push_back(chars[dis(gen)]);
    }
    return key;
}

// **generateSequentialMiniKey**: Generate a sequential mini key.
string generateSequentialMiniKey() {
    long long index = globalIndex.fetch_add(1);
    ostringstream oss;
    oss << setw(miniKeyLength - 1) << setfill('0') << index;
    return "S" + oss.str();
}

// **extractIndexFromKey**: Extract the numeric portion from a mini key.
long long extractIndexFromKey(const string &key) {
    string numStr;
    for (size_t i = 1; i < key.size(); i++) {
        if (isdigit(key[i]))
            numStr.push_back(key[i]);
    }
    if (numStr.empty())
        return 0;
    try {
        return stoll(numStr);
    } catch (...) {
        return 0;
    }
}

// **derivePrivateKey**: Derive a full 256-bit private key from the mini key using SHA-256.
string derivePrivateKey(const string &miniKey) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(miniKey.c_str()), miniKey.size(), hash);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}

// **derivePublicKey**: Generate the public key from the private key using a reusable EC_KEY.
vector<unsigned char> derivePublicKey(EC_KEY* ecKey, const string &privateKeyHex, bool compressed) {
    vector<unsigned char> keyBytes;
    BIGNUM *bn = BN_new();
    if (!bn) return keyBytes;
    if (BN_hex2bn(&bn, privateKeyHex.c_str()) == 0) {
        BN_free(bn);
        return keyBytes;
    }
    if (EC_KEY_set_private_key(ecKey, bn) == 0) {
        BN_free(bn);
        return keyBytes;
    }
    const EC_GROUP *group = EC_KEY_get0_group(ecKey);
    if (!group) {
        BN_free(bn);
        return keyBytes;
    }
    EC_POINT *pubKey = EC_POINT_new(group);
    if (!pubKey) {
        BN_free(bn);
        return keyBytes;
    }
    if (EC_POINT_mul(group, pubKey, bn, NULL, NULL, NULL) == 0) {
        EC_POINT_free(pubKey);
        BN_free(bn);
        return keyBytes;
    }
    if (EC_KEY_set_public_key(ecKey, pubKey) == 0) {
        EC_POINT_free(pubKey);
        BN_free(bn);
        return keyBytes;
    }
    if (compressed) {
        int compLen = EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
        if (compLen > 0) {
            keyBytes.resize(compLen);
            EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_COMPRESSED, keyBytes.data(), compLen, NULL);
        }
    } else {
        int uncompLen = EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (uncompLen > 0) {
            keyBytes.resize(uncompLen);
            EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_UNCOMPRESSED, keyBytes.data(), uncompLen, NULL);
        }
    }
    EC_POINT_free(pubKey);
    BN_free(bn);
    return keyBytes;
}

// **computeRipemdFromPubKey**: Compute the RIPEMD-160 hash of a public key.
string computeRipemdFromPubKey(const vector<unsigned char> &pubKey) {
    unsigned char shaHash[SHA256_DIGEST_LENGTH];
    SHA256(pubKey.data(), pubKey.size(), shaHash);
    unsigned char ripemdHash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(shaHash, SHA256_DIGEST_LENGTH, ripemdHash);
    stringstream ss;
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << static_cast<int>(ripemdHash[i]);
    return ss.str();
}

// **loadTargetHashes**: Load target RIPEMD160 hashes from file with validation.
void loadTargetHashes(const string &filename) {
    ifstream infile(filename);
    if (!infile) {
        cerr << "[X]Error opening target file: " << filename << "\n";
        return;
    }
    string line;
    while (getline(infile, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) {
            // Basic validation: ensure it's a 40-char hex string (RIPEMD160 length in hex)
            if (line.length() == 40 && all_of(line.begin(), line.end(), ::isxdigit)) {
                targetHashes.insert(line);
                if (targetBloom)
                    targetBloom->add(line);
            }
        }
    }
    infile.close();
}

// **hexToBytes**: Convert hex string to byte vector
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// **bytesToHex**: Convert byte vector to hex string
string bytesToHex(const vector<unsigned char>& bytes) {
    stringstream ss;
    for (unsigned char byte : bytes) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

// **generateWIF**: Generate WIF private key
string generateWIF(const string& privKeyHex, bool compressed) {
    vector<unsigned char> privKeyBytes = hexToBytes(privKeyHex);
    vector<unsigned char> payload;
    payload.push_back(0x80); // Mainnet private key version byte
    payload.insert(payload.end(), privKeyBytes.begin(), privKeyBytes.end());
    if (compressed) {
        payload.push_back(0x01); // Compression flag
    }
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(payload.data(), payload.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    payload.insert(payload.end(), hash2, hash2 + 4);
    return Base58Encode(payload);
}

// **processDerive**: Derive and display key details
void processDerive(const string& casakey) {
    cout << "Short key: " << casakey << "\n\n";
    cout << string(20, '-') << "\n";

    string checkStr = casakey + "?";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(checkStr.c_str()), checkStr.size(), hash);
    stringstream ss;
    for (int i = 0; i < 4; i++) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    cout << "Checksum verification:\n";
    cout << "  SHA-256(\"" << checkStr << "\"): " << ss.str() << "...\n";
    bool valid = (hash[0] == 0x00);
    cout << "  First byte: ";
    if (valid) {
        cout << "00";
    } else {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(hash[0]);
    }
    cout << " (" << (valid ? "valid" : "invalid") << ")\n";
    cout << "  Checksum is " << (valid ? "valid" : "invalid") << ".\n";

    string privKeyHex = derivePrivateKey(casakey);
    cout << "Private key (hex): " << privKeyHex << "\n";

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) {
        cout << "Error: Failed to create EC_KEY\n";
        return;
    }
    
    cout << string(60, '-') << "\n";
    vector<unsigned char> pubKeyCompressed = derivePublicKey(ecKey, privKeyHex, true);
    vector<unsigned char> pubKeyUncompressed = derivePublicKey(ecKey, privKeyHex, false);
    string pubKeyCompHex = bytesToHex(pubKeyCompressed);
    string pubKeyUncompHex = bytesToHex(pubKeyUncompressed);
    cout << string(60, '-') << "\n";
    cout << "Public key (compressed): " << pubKeyCompHex << "\n";
    cout << "Public key (uncompressed): " << pubKeyUncompHex << "\n";

    string ripemdCompressed = computeRipemdFromPubKey(pubKeyCompressed);
    string ripemdUncompressed = computeRipemdFromPubKey(pubKeyUncompressed);
    cout << string(60, '-') << "\n";
    cout << "Hash160 (compressed): " << ripemdCompressed << "\n";
    cout << "Hash160 (uncompressed): " << ripemdUncompressed << "\n";

    string btcAddressCompressed = generateBTCAddress(pubKeyCompressed);
    string btcAddressUncompressed = generateBTCAddress(pubKeyUncompressed);
    cout << string(60, '-') << "\n";
    cout << "Bitcoin address (compressed): " << btcAddressCompressed << "\n";
    cout << "Bitcoin address (uncompressed): " << btcAddressUncompressed << "\n";

    string wifCompressed = generateWIF(privKeyHex, true);
    string wifUncompressed = generateWIF(privKeyHex, false);
    cout << string(60, '-') << "\n";
    cout << "WIF private key (for compressed pubkey): " << wifCompressed << "\n";
    cout << "WIF private key (for uncompressed pubkey): " << wifUncompressed << "\n";
    cout << string(60, '-') << "\n";

    EC_KEY_free(ecKey);
}

// **readLastNonEmptyLine**: Retrieve the last non-empty line from a file.
string readLastNonEmptyLine(const string &filename) {
    ifstream infile(filename);
    if (!infile) return "";
    string lastLine, line;
    while (getline(infile, line)) {
        if (!line.empty())
            lastLine = line;
    }
    infile.close();
    return lastLine;
}

// **generationThread**: Worker thread for generating and validating mini keys.
void generationThread() {
    try {
        mt19937 gen(random_device{}());
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ecKey) {
            cerr << "[X]Failed to create EC_KEY in thread\n";
            return;
        }
        thread_local vector<string> localBuffer;
        while (!shutdownFlag.load()) {
            string miniKey;
            if (sequenceMode) {
                miniKey = generateSequentialMiniKey();
            } else {
                int currentLength = multiMode ? randomAllowedLength(gen) : miniKeyLength;
                miniKey = randomMiniKey(currentLength, gen);
            }
            
            keyCounter++;
            if (!isValidMiniKey(miniKey)) {
                invalidKeyCounter++; // Added: Increment invalid counter
                continue;
            }
            validKeyCounter++; // Added: Increment valid counter
            
            string privKeyHex = derivePrivateKey(miniKey);
            vector<unsigned char> pubKeyCompressed = derivePublicKey(ecKey, privKeyHex, true);
            vector<unsigned char> pubKeyUncompressed = derivePublicKey(ecKey, privKeyHex, false);
            string ripemdCompressed = computeRipemdFromPubKey(pubKeyCompressed);
            string ripemdUncompressed = computeRipemdFromPubKey(pubKeyUncompressed);
            
            string outBlock = miniKey + " " + privKeyHex + " " + ripemdCompressed + " " + ripemdUncompressed + "\n";
            localBuffer.push_back(outBlock);
            
            if (localBuffer.size() >= 1000) {
                lock_guard<mutex> lock(fileMutex);
                for (const auto& str : localBuffer) {
                    savedFile << str;
                    if (!savedFile.good()) {
                        cerr << "[X]Error writing to savedFile\n";
                    }
                }
                localBuffer.clear();
            }
            
            if (!targetHashes.empty() && 
                (targetBloom->possibly_contains(ripemdCompressed) || targetBloom->possibly_contains(ripemdUncompressed))) {
                if (targetHashes.count(ripemdCompressed) || targetHashes.count(ripemdUncompressed)) {
                    lock_guard<mutex> lock(fileMutex);
                    foundFile << outBlock;
                    foundFile.flush();
                    if (!foundFile.good()) {
                        cerr << "[X]Error writing to foundFile\n";
                    }
                    matchCounter++;
                    cout << string(40, '-') << "\n";
                    auto now = steady_clock::now();
                    double elapsed = duration_cast<seconds>(now - startTime).count();
                    double keysPerSec = (elapsed > 0) ? keyCounter.load() / elapsed : 0;
                    cout << "[+]Match found: " << miniKey << "\n";
                    cout << string(40, '-') << "\n";
                    cout << "[-]Keys per second: " << keysPerSec << "\n";
                }
            }
            
            if (loggingMode && (keyCounter.load() % LOG_INTERVAL == 0)) {
                lock_guard<mutex> lock(fileMutex);
                sequenceLogFile << miniKey << "\n";
                sequenceLogFile.flush();
                if (!sequenceLogFile.good()) {
                    cerr << "[X]Error writing to sequenceLogFile\n";
                }
            }
        }
        if (!localBuffer.empty()) {
            lock_guard<mutex> lock(fileMutex);
            for (const auto& str : localBuffer) {
                savedFile << str;
                if (!savedFile.good()) {
                    cerr << "[X]Error writing to savedFile\n";
                }
            }
            localBuffer.clear();
        }
        EC_KEY_free(ecKey);
    } catch (const exception &ex) {
        cerr << "Exception in generationThread: " << ex.what() << "\n";
    }
}

// **signalHandler**: Handle SIGINT for graceful termination.
void signalHandler(int signum) {
    shutdownFlag.store(true);
    cout << "\nInterrupt signal (" << signum << ") received. Shutting down threads...\n";
}

// **main**: Parse command-line arguments and launch worker threads.
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    
    if (argc == 1) {
        printHelp();
        return 0;
    }
    
    startTime = steady_clock::now();
    
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        try {
            if (arg == "-h" || arg == "-help") {
                printHelp();
                return 0;
            } else if (arg == "-p" || arg == "-print") {
                if (i + 1 < argc)
                    printInterval = stoi(argv[++i]);
                else {
                    cerr << "[X]Error: -print option requires a numeric argument.\n";
                    return 1;
                }
            } else if (arg == "-S" || arg == "-seq") {
                sequenceMode = true;
                if (i + 1 < argc) {
                    string possibleKey = argv[i+1];
                    if (!possibleKey.empty() && possibleKey[0] != '-') {
                        baseMiniKey = possibleKey;
                        globalIndex = extractIndexFromKey(baseMiniKey) + 1;
                        cout << "[=]Resuming from provided key: " << baseMiniKey << "\n";
                        i++;
                    } else {
                        string lastKey = readLastNonEmptyLine("sequence_log.txt");
                        if (!lastKey.empty()) {
                            baseMiniKey = lastKey;
                            globalIndex = extractIndexFromKey(baseMiniKey) + 1;
                            cout << "[=]Resuming from last logged key in file: " << lastKey << "\n";
                        }
                    }
                } else {
                    string lastKey = readLastNonEmptyLine("sequence_log.txt");
                    if (!lastKey.empty()) {
                        baseMiniKey = lastKey;
                        globalIndex = extractIndexFromKey(baseMiniKey) + 1;
                        cout << "[=]Resuming from last logged key in file: " << lastKey << "\n";
                    }
                }
            } else if (arg == "-t" || arg == "-core") {
                if (i + 1 < argc)
                    numThreads = stoi(argv[++i]);
                else {
                    cerr << "[X]Error: -core option requires a numeric argument.\n";
                    return 1;
                }
            } else if (arg == "-b" || arg == "-bit") {
                if (i + 1 < argc) {
                    int len = stoi(argv[++i]);
                    if (len == 22 || len == 23 || len == 26 || len == 30)
                        miniKeyLength = len;
                    else {
                        cerr << "[X]Invalid mini key length. Allowed values: 22, 23, 26, 30.\n";
                        printHelp();
                        return 1;
                    }
                } else {
                    cerr << "[X]Error: -bit option requires a numeric argument.\n";
                    return 1;
                }
            } else if (arg == "-f" || arg == "-file") {
                if (i + 1 < argc)
                    targetFile = argv[++i];
                else {
                    cerr << "[X]Error: -file option requires a filename argument.\n";
                    return 1;
                }
            } else if (arg == "-log") {
                loggingMode = true;
            } else if (arg == "--derive") {
                if (i + 1 < argc) {
                    string caKey = argv[++i];
                    processDerive(caKey);
                    return 0;
                } else {
                    cerr << "[X]Error: --derive option requires a mini key argument.\n";
                    return 1;
                }
            } else if (arg == "--multi") {
                multiMode = true;
            }
        } catch (const invalid_argument &e) {
            cerr << "Invalid argument for option " << arg << ". " << e.what() << "\n";
            return 1;
        } catch (const exception &e) {
            cerr << "[X]Exception while parsing arguments: " << e.what() << "\n";
            return 1;
        }
    }
    
    if (!targetFile.empty()) {
        targetBloom = new BloomFilter(BLOOM_SIZE, BLOOM_HASHES);
        loadTargetHashes(targetFile);
    }
    
    savedFile.open("saved.txt", ios::app);
    if (!savedFile) {
        cerr << "[X]Error opening saved.txt for writing.\n";
        return 1;
    }
    foundFile.open("casascius_found.txt", ios::app);
    if (!foundFile) {
        cerr << "[X]Error opening casascius_found.txt for writing.\n";
        savedFile.close();
        return 1;
    }
    sequenceLogFile.open("sequence_log.txt", ios::app);
    if (!sequenceLogFile) {
        cerr << "[X]Error opening sequence_log.txt for writing.\n";
        savedFile.close();
        foundFile.close();
        return 1;
    }
    
    vector<thread> threads;
    for (int i = 0; i < numThreads; i++)
        threads.emplace_back(generationThread);
    
    thread performanceThread;
    if (printInterval > 0) {
        performanceThread = thread([&]() {
            static steady_clock::time_point lastPrintTime = startTime; // Added: Track last print time
            static long long prevKeyCounter = 0;                       // Added: Previous total keys
            static long long prevValidKeyCounter = 0;                  // Added: Previous valid keys
            static long long prevInvalidKeyCounter = 0;                // Added: Previous invalid keys
            while (!shutdownFlag.load()) {
                this_thread::sleep_for(seconds(printInterval));
                auto now = steady_clock::now();
                double intervalElapsed = duration_cast<duration<double>>(now - lastPrintTime).count();
                long long currentKeyCounter = keyCounter.load();
                long long currentValidKeyCounter = validKeyCounter.load();
                long long currentInvalidKeyCounter = invalidKeyCounter.load();
                long long deltaKeys = currentKeyCounter - prevKeyCounter;
                long long deltaValid = currentValidKeyCounter - prevValidKeyCounter;
                long long deltaInvalid = currentInvalidKeyCounter - prevInvalidKeyCounter;
                double keysPerSec = (intervalElapsed > 0) ? deltaKeys / intervalElapsed : 0;
                cout << string(60, '-') << "\n";
                cout << "[-]Total Keys per second: " << fixed << setprecision(2) << keysPerSec
                     << ", Valid keys: " << deltaValid
                     << ", Invalid keys: " << deltaInvalid << "\n\n";
                cout << string(60, '-') << "\n";
                cout << "[!]Total keys: " << currentKeyCounter
                     << ", Total valid ever generated: " << currentValidKeyCounter << "\n\n";
                prevKeyCounter = currentKeyCounter;
                prevValidKeyCounter = currentValidKeyCounter;
                prevInvalidKeyCounter = currentInvalidKeyCounter;
                lastPrintTime = now;
            }
        });
    }
    
    for (auto &t : threads) {
        if (t.joinable())
            t.join();
    }
    if (performanceThread.joinable())
        performanceThread.join();
    
    cout << "[X]Shutting down gracefully.\n";
    
    if (targetBloom) {
        delete targetBloom;
        targetBloom = nullptr;
    }
    
    savedFile.close();
    foundFile.close();
    sequenceLogFile.close();
    
    return 0;
}


