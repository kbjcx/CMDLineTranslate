#include <iomanip>
#include <iostream>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <sstream>

#include <stdio.h>

#include <string>
#include <strstream>

#include <time.h>

#include "curl/curl.h"
#include "nlohmann/json.hpp"

using namespace std;
using namespace nlohmann;

string get_data(int64_t& timestamp) {
    string utcDate;
    char buff[20] = {0};
    struct tm sttime;
    sttime = *gmtime(&timestamp);
    strftime(buff, sizeof(buff), "%Y-%m-%d", &sttime);
    utcDate = string(buff);
    return utcDate;
}

string int2str(int64_t n) {
    std::stringstream ss;
    ss << n;
    return ss.str();
}

string sha256Hex(const string& str) {
    char buf[3];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::string NewString = "";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        NewString = NewString + buf;
    }
    return NewString;
}

string HmacSha256(const string& key, const string& input) {
    unsigned char hash[32];

    HMAC_CTX* h;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    h = &hmac;
#else
    h = HMAC_CTX_new();
#endif

    HMAC_Init_ex(h, &key[0], key.length(), EVP_sha256(), NULL);
    HMAC_Update(h, (unsigned char*)&input[0], input.length());
    unsigned int len = 32;
    HMAC_Final(h, hash, &len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(h);
#else
    HMAC_CTX_free(h);
#endif

    std::stringstream ss;
    ss << std::setfill('0');
    for (int i = 0; i < len; i++) {
        ss << hash[i];
    }

    return (ss.str());
}

string HexEncode(const string& input) {
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();

    string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

int debug_callback(
    CURL* handle, curl_infotype type, char* data, size_t size, void* userdata) {
    if (type == CURLINFO_HEADER_OUT || type == CURLINFO_DATA_OUT) {
        std::cout.write(data, size);
    }
    return 0;
}

struct WriteData {
    std::string response;
};

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t totalSize = size * nmemb;
    WriteData* data = static_cast<WriteData*>(userdata);
    data->response.append(ptr, totalSize);
    return totalSize;
}

int main(int argc, char* argv[]) {
    string lang = "en";
    string source = "";
    for (int i = 1; i < argc; ++i) {
        // 检查当前参数是否为"-en"
        if (std::string(argv[i]) == "-z") {
            lang = "zh";
        } else {
            source = argv[i];
        }
    }

    string SECRET_ID = "";
    string SECRET_KEY = "";
    string TOKEN = "";

    string service = "tmt";
    string host = "tmt.tencentcloudapi.com";
    string region = "ap-chengdu";
    string action = "TextTranslate";
    string version = "2018-03-21";

    int64_t timestamp = time(NULL);
    string date = get_data(timestamp);

    // ************* 步骤 1：拼接规范请求串 *************
    string httpRequestMethod = "POST";
    string canonicalUri = "/";
    string canonicalQueryString = "";
    string canonicalHeaders =
        "content-type:application/json; charset=utf-8\nhost:" + host + "\n";
    string signedHeaders = "content-type;host";

    nlohmann::json request;
    request["SourceText"] = source;
    request["Source"] = "auto";
    request["Target"] = lang;
    request["ProjectId"] = 0;
    request["UntranslatedText"] = "";
    string payload = request.dump();

    string hashedRequestPayload = sha256Hex(payload);
    string canonicalRequest = httpRequestMethod + "\n" + canonicalUri + "\n" +
                              canonicalQueryString + "\n" + canonicalHeaders + "\n" +
                              signedHeaders + "\n" + hashedRequestPayload;

    // ************* 步骤 2：拼接待签名字符串 *************
    string algorithm = "TC3-HMAC-SHA256";
    string RequestTimestamp = int2str(timestamp);
    string credentialScope = date + "/" + service + "/" + "tc3_request";
    string hashedCanonicalRequest = sha256Hex(canonicalRequest);
    string stringToSign = algorithm + "\n" + RequestTimestamp + "\n" + credentialScope +
                          "\n" + hashedCanonicalRequest;

    // ************* 步骤 3：计算签名 *************
    string kKey = "TC3" + SECRET_KEY;
    string kDate = HmacSha256(kKey, date);
    string kService = HmacSha256(kDate, service);
    string kSigning = HmacSha256(kService, "tc3_request");
    string signature = HexEncode(HmacSha256(kSigning, stringToSign));
    // ************* 步骤 4：拼接 Authorization *************
    string authorization = algorithm + " " + "Credential=" + SECRET_ID + "/" +
                           credentialScope + ", " + "SignedHeaders=" + signedHeaders +
                           ", " + "Signature=" + signature;

    string url = "https://" + host;
    string authorizationHeader = "Authorization: " + authorization;
    string hostHeader = "Host: " + host;
    string actionHeader = "X-TC-Action: " + action;
    string timestampHeader = "X-TC-Timestamp: " + RequestTimestamp;
    string versionHeader = "X-TC-Version: " + version;
    string regionHeader = "X-TC-Region: " + region;
    string tokenHeader = "X-TC-Token: " + TOKEN;

    WriteData resData;

    // ************* 步骤 5：构造并发起请求 *************
    CURL* curl;
    CURLcode res;
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url.data());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
        // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_callback);
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, authorizationHeader.data());
        headers =
            curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");
        headers = curl_slist_append(headers, hostHeader.data());
        headers = curl_slist_append(headers, actionHeader.data());
        headers = curl_slist_append(headers, timestampHeader.data());
        headers = curl_slist_append(headers, versionHeader.data());
        headers = curl_slist_append(headers, regionHeader.data());
        headers = curl_slist_append(headers, tokenHeader.data());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        const char* data = payload.data();
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resData);
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            nlohmann::json response = nlohmann::json::parse(resData.response);
            std::cout << response["Response"]["TargetText"] << std::endl;
        } else {
            std::cout << "Request failed. Error code: " << res << std::endl;
        }
    }
    curl_easy_cleanup(curl);
    return 0;
}
