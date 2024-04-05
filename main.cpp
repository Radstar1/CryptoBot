#include <iostream>
#include <string>
#include <curl/curl.h> // Include libcurl for making HTTP requests
#include <rapidjson/document.h> // Include RapidJSON for JSON parsing

// Example API endpoint for getting Bitcoin price from CoinGecko
const std::string COINGECKO_API_ENDPOINT = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd";

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

int main() {
    // Test the getBitcoinPriceFromCoinGecko() function
    double bitcoinPrice = getBitcoinPriceFromCoinGecko();
    if (bitcoinPrice > 0.0) {
        std::cout << "Bitcoin price (from CoinGecko): $" << bitcoinPrice << std::endl;
    }
    else {
        std::cerr << "Failed to fetch Bitcoin price from CoinGecko API" << std::endl;
    }
    return 0;
}