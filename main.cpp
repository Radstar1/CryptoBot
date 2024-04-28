#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <curl/curl.h> // Include libcurl for making HTTP requests
#include <rapidjson/document.h> // Include RapidJSON for JSON parsing
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <iomanip> // Include <iomanip> for setfill and setw
#include <vector>


// Example API endpoint for getting Bitcoin price from CoinGecko
const std::string COINGECKO_API_ENDPOINT = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd";
const std::string BINANCE_API_ENDPOINT = "https://api.binance.us/api/v3/ticker/price?symbol=BTCUSD";
const std::string KRAKEN_API_ENDPOINT = "https://api.kraken.com/0/public/Assets";
const std::string KRAKEN_API_BALANCE_ENDPOINT = "https://api.kraken.com/0/private/Balance";

void initializeOpenSSL() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

// Callback function to write response data from HTTP request
static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* buffer) {
    size_t totalSize = size * nmemb;
    buffer->append((char*)contents, totalSize);
    return totalSize;
}



static std::string generateNonce() {
    // Get the current time in milliseconds since the epoch
    auto currentTime = std::chrono::system_clock::now();
    auto duration = currentTime.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    // Convert milliseconds to a string
    std::stringstream ss;
    ss << millis;

    return ss.str();
}

static std::vector<unsigned char> b64_decode(const std::string& data) {
    // Create a BIO for base64 decoding
    BIO* b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        throw std::runtime_error("failed to create base64 BIO");
    }

    // Disable newline characters in base64 encoding
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Create a memory BIO to read from the input data
    BIO* bmem = BIO_new_mem_buf(data.c_str(), data.length());
    if (bmem == nullptr) {
        BIO_free(b64);
        throw std::runtime_error("failed to create memory BIO");
    }

    // Push the base64 BIO onto the memory BIO
    bmem = BIO_push(b64, bmem);

    // Allocate a buffer for the decoded output
    std::vector<unsigned char> output(data.length());

    // Read from the BIO chain into the output buffer
    int decoded_size = BIO_read(bmem, output.data(), output.size());

    // Free the BIOs
    BIO_free_all(bmem);

    // Check for errors during decoding
    if (decoded_size < 0) {
        throw std::runtime_error("failed while decoding base64");
    }

    // Resize the output buffer to the actual decoded size
    output.resize(decoded_size);

    return output;
}

static std::string b64_encode(const std::vector<unsigned char>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    // Create a base64 filter/sink
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Create a memory BIO to store the encoded data
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Write data to the bio
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    // Get a pointer to the memory BIO's data
    BIO_get_mem_ptr(bio, &bufferPtr);

    // Create a std::string from the data in the memory BIO
    std::string encodedData(bufferPtr->data, bufferPtr->length);

    // Clean up
    BIO_free_all(bio);

    return encodedData;
}

static std::vector<unsigned char> sha256(const std::string& data) {
    const EVP_MD* sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (sha256 == nullptr) {
        // Handle error: unable to fetch SHA256 implementation
        return {};
    }

    // Initialize SHA256 context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        // Handle error: unable to create EVP_MD_CTX
        EVP_MD_free((EVP_MD*)sha256); // Free the SHA256 implementation object
        return {};
    }

    // Initialize SHA256
    if (EVP_DigestInit_ex(mdctx, sha256, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD*)sha256); // Free the SHA256 implementation object
        // Handle error: initialization failed
        return {};
    }

    // Update SHA256 context with data
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD*)sha256); // Free the SHA256 implementation object
        // Handle error: update failed
        return {};
    }

    // Finalize SHA256 hash
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    if (EVP_DigestFinal_ex(mdctx, digest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free((EVP_MD*)sha256); // Free the SHA256 implementation object
        // Handle error: finalization failed
        return {};
    }

    EVP_MD_CTX_free(mdctx);
    EVP_MD_free((EVP_MD*)sha256); // Free the SHA256 implementation object


    return digest;
}


static std::vector<unsigned char> hmac_sha512(const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key) {
    unsigned char* result;
    unsigned int result_len;
    result = HMAC(EVP_sha512(), key.data(), key.size(), data.data(), data.size(), NULL, &result_len);
    std::vector<unsigned char> hmac(result, result + result_len);
    return hmac;
}


static std::string GetKrakenSignature(const std::string& endpoint,
    const std::string& nonce,
    const std::string& postData, const std::string& secret_)
{
    //Step 1: Base64-decode your api_secret
    std::vector<unsigned char> b64_decode_secret_ = b64_decode(secret_);
  
    std::string concatenate = nonce + postData;
    std::vector<unsigned char> api_sha256 = sha256(concatenate);


    //Step 2: Create a new unsigned vector with the path (unsigned meaning positive ranging from 0-255)
    //This is so I can concatenate it with the api_sha256 hash later
    std::string path = "/0/private/" + endpoint;
    std::vector<unsigned char> path_sha256(path.begin(), path.end());

  
   //Step 3:Concatenate it
    path_sha256.reserve(api_sha256.size() + path_sha256.size());
    for (int num : api_sha256) {
        path_sha256.push_back(num);
    }

    //Step 4: Use the result of step 3 to hash the result of the step 2 with the HMAC-SHA-512 algorithm
    std::vector<unsigned char> hmacResult = hmac_sha512(path_sha256, b64_decode_secret_);

    //Step 5: Base64-encode the result of step 4
    std::string signature = b64_encode(hmacResult);

    return signature;
}

std::string getKrakenBalances(const std::string& apiKey, const std::string& apiSecret) {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string responseBuffer;

        // Construct POST data
        std::string nonce = generateNonce();
        std::string url = "https://api.kraken.com/0/private/Balance";
        std::string endpoint = "Balance";
        std::string postData = "nonce=" + nonce; // Include nonce in the POST data

        std::cout << nonce;

        // Generate signature
        std::string signature = GetKrakenSignature(endpoint, nonce, postData, apiSecret);

        // Set up CURL options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

        // Add API key and signature to request header
       

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("API-Key: " + apiKey).c_str());
        headers = curl_slist_append(headers, ("API-Sign: " + signature).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded; charset=utf-8");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
       
        // Perform the request
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to fetch Kraken account balance: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }

        // Clean up and return the response
        curl_easy_cleanup(curl);

        curl_slist_free_all(headers);

        return responseBuffer;
    }
    else {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return "";
    }
}

// Function to fetch Bitcoin price from CoinGecko API
double getBitcoinPriceFromCoinGecko() {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string responseBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, COINGECKO_API_ENDPOINT.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to fetch Bitcoin price from CoinGecko API: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return 0.0;  // Return 0 if there's an error
        }

        // Parse JSON response to extract Bitcoin price
        rapidjson::Document document;
        document.Parse(responseBuffer.c_str());
        if (!document.IsObject() || !document.HasMember("bitcoin") || !document["bitcoin"].IsObject() || !document["bitcoin"].HasMember("usd") || !document["bitcoin"]["usd"].IsNumber()) {
            std::cerr << "Failed to parse JSON response from CoinGecko API" << std::endl;
            curl_easy_cleanup(curl);
            return 0.0;  // Return 0 if there's an error
        }

        double bitcoinPrice = document["bitcoin"]["usd"].GetDouble();
        curl_easy_cleanup(curl);
        return bitcoinPrice;
    }
    else {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return 0.0;  // Return 0 if there's an error
    }
}

double getBitcoinPriceFromKraken() {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string responseBuffer;
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.kraken.com/0/public/Ticker?pair=XXBTZUSD");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to fetch Bitcoin price from Kraken API: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return 0.0;  // Return 0 if there's an error
        }

        // Parse JSON response to extract Bitcoin price
        rapidjson::Document document;
        document.Parse(responseBuffer.c_str());
        if (!document.IsObject() || !document.HasMember("result") || !document["result"].IsObject() || !document["result"].HasMember("XXBTZUSD") || !document["result"]["XXBTZUSD"].IsObject() || !document["result"]["XXBTZUSD"].HasMember("c") || !document["result"]["XXBTZUSD"]["c"].IsArray() || document["result"]["XXBTZUSD"]["c"].Empty()) {
            std::cerr << "Failed to parse JSON response from Kraken API or missing 'c' array in result object" << std::endl;
            curl_easy_cleanup(curl);
            return 0.0;  // Return 0 if there's an error
        }

        double bitcoinPrice = std::stod(document["result"]["XXBTZUSD"]["c"][0].GetString());
        curl_easy_cleanup(curl);
        return bitcoinPrice;
    }
    else {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return 0.0;  // Return 0 if there's an error
    }
}





int main() {

    std::cout << 'woah';
    double bitcoinPrice_Gecko = getBitcoinPriceFromCoinGecko();
    double bitcoinPrice_Kraken = getBitcoinPriceFromKraken();

    char* apiKeyValue;
    size_t bufferSize;
    errno_t err = _dupenv_s(&apiKeyValue, &bufferSize, "API_KEY_KRAKEN"); //Set your Kraken Key in your Windows Environment

    // Check if the environment variable exists and was successfully retrieved
    if (err != 0) {
        std::cerr << "Failed to retrieve API key environment variable." << std::endl;
        return 1;
    }
    // Check if the retrieved value is not empty
    if (apiKeyValue == nullptr) {
        std::cerr << "API key environment variable not set." << std::endl;
        return 1;
    }
    std::string API_KEY_KRAKEN(apiKeyValue);

    err = _dupenv_s(&apiKeyValue, &bufferSize, "API_SECRET_KRAKEN");
    // Check if the environment variable exists and was successfully retrieved
    if (err != 0) {
        std::cerr << "Failed to retrieve API_SECRET environment variable" << std::endl;
        return 1;
    }
    // Check if the retrieved value is not empty
    if (apiKeyValue == nullptr) {
        std::cerr << "API_SECRET environment variable not set." << std::endl;
        return 1;
    }
    std::string API_SECRET_KRAKEN(apiKeyValue);
    // Free the memory allocated for the environment variable value
    free(apiKeyValue);  



    if (bitcoinPrice_Gecko > 0.0) {
        std::cout << "Bitcoin price (from CoinGecko): $" << bitcoinPrice_Gecko << std::endl;

        double amountToInvest = 5; // Initial investment amount
        double amountOwned = 0.0; // Amount of Bitcoin owned
        double buyThreshold = 0.05; // Example: buy if price decreases by 5%
        double sellThreshold = 0.05; // Example: sell if price increases by 5%
    }
    else {
        std::cerr << "Failed to fetch Bitcoin price from CoinGecko API" << std::endl;
    }

    if (bitcoinPrice_Kraken > 0.0) {
        std::cout << "Bitcoin price from Kraken: $" << bitcoinPrice_Kraken << std::endl;
    }
    else {
        std::cerr << "Failed to get Bitcoin price from Kraken" << std::endl;
    }



    std::string balancesResponse_KRAKEN = getKrakenBalances(API_KEY_KRAKEN, API_SECRET_KRAKEN);
    if (!balancesResponse_KRAKEN.empty()) {
        // Parse the JSON response to extract account balances
        // Implement your parsing logic here based on the response format
        std::cout << "Account Balances:\n" << balancesResponse_KRAKEN << std::endl;
    }
    else {
        std::cerr << "Failed to fetch Kraken account balance" << std::endl;
    }


    return 0;
}