#include <iostream>
#include <sstream>
#include <string>
#include <curl/curl.h> // Include libcurl for making HTTP requests
#include <rapidjson/document.h> // Include RapidJSON for JSON parsing
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iomanip> // Include <iomanip> for setfill and setw
using namespace std;

// Example API endpoint for getting Bitcoin price from CoinGecko
const std::string COINGECKO_API_ENDPOINT = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd";
const std::string KRAKEN_API_ENDPOINT = "https://api.kraken.com/0/private/Balance";



// Callback function to write response data from HTTP request
size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* buffer) {
    size_t totalSize = size * nmemb;
    buffer->append((char*)contents, totalSize);
    return totalSize;
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

std::string generateKrakenSignature(const std::string& postData, const std::string& apiSecret) {
    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int hmacLength = 0;
    HMAC(EVP_sha512(), apiSecret.c_str(), apiSecret.length(),
        reinterpret_cast<const unsigned char*>(postData.c_str()), postData.length(),
        hmacResult, &hmacLength);

    // Convert HMAC result to hexadecimal string
    std::stringstream ss{}; // Initialize stringstream using braces
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hmacLength; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(hmacResult[i]);
    }
    return ss.str();
}

std::string getKrakenBalances(const std::string& apiKey, const std::string& apiSecret) {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string responseBuffer;
        std::string postData = "nonce=" + std::to_string(time(NULL)); // Use current timestamp as nonce
        std::string signature = generateKrakenSignature(postData, apiSecret);
        curl_easy_setopt(curl, CURLOPT_URL, KRAKEN_API_ENDPOINT.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

        // Add API key and signature to request header
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("API-Key: " + apiKey).c_str());
        headers = curl_slist_append(headers, ("API-Sign: " + signature).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to fetch Kraken account balance: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }
        curl_easy_cleanup(curl);
        return responseBuffer;
    }
    else {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return "";
    }
}


int main() {
    // Test the getBitcoinPriceFromCoinGecko() function
    char* apiKeyValue;
    size_t bufferSize;
    errno_t err = _dupenv_s(&apiKeyValue, &bufferSize, "API_KEY");
    double bitcoinPrice = getBitcoinPriceFromCoinGecko();

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
    std::string API_KEY(apiKeyValue);

    err = _dupenv_s(&apiKeyValue, &bufferSize, "API_SECRET");
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
    std::string API_SECRET(apiKeyValue);

    // Free the memory allocated for the environment variable value
    free(apiKeyValue);

    if (bitcoinPrice > 0.0) {
        std::cout << "Bitcoin price (from CoinGecko): $" << bitcoinPrice << std::endl;

        double amountToInvest = 5; // Initial investment amount
        double amountOwned = 0.0; // Amount of Bitcoin owned
        double buyThreshold = 0.05; // Example: buy if price decreases by 5%
        double sellThreshold = 0.05; // Example: sell if price increases by 5%
    }
    else {
        std::cerr << "Failed to fetch Bitcoin price from CoinGecko API" << std::endl;
    }

    // Output the API key value
    //std::cout << "API Key: " << API_KEY << std::endl;
    //std::cout << "API SECRET: " << API_SECRET << std::endl;

    // Call getKrakenBalances() function to retrieve account balances
    std::string balancesResponse = getKrakenBalances(API_KEY, API_SECRET);
    if (!balancesResponse.empty()) {
        // Parse the JSON response to extract account balances
        // Implement your parsing logic here based on the response format
        std::cout << "Account Balances:\n" << balancesResponse << std::endl;
    }
    else {
        std::cerr << "Failed to fetch Kraken account balance" << std::endl;
    }


    return 0;
}