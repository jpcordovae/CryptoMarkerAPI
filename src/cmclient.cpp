#include "cmclient.hpp"

#include <vector>

#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>

namespace cryptomarket{

  static std::vector<unsigned char> sha384(const std::string &data)
  {
    std::vector<unsigned char> digest(SHA384_DIGEST_LENGTH);
    SHA512_CTX ctx;
    SHA384_Init(&ctx);
    SHA384_Update(&ctx,data.c_str(),data.length());
    SHA384_Final(digest.data(),&ctx);
    return digest;
  }

  //------------------------------------------------------------------------------
  // helper function to hash with HMAC algorithm:
  static std::vector<unsigned char>
  hmac_sha512(const std::vector<unsigned char>& data,
	      const std::vector<unsigned char>& key)
  {
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> digest(len);

    HMAC_CTX *ctx;
    //HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_init(ctx);

    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha384(), NULL);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, digest.data(), &len);

    //HMAC_CTX_free(ctx);
    HMAC_CTX_cleanup(ctx);

    return digest;
  }

  static std::string build_query(const CMInput &input){
    std::ostringstream oss;
    CMInput::const_iterator it = input.begin();
    for(;it!=input.end();++it){
      oss << it->first << "=" << it->second;
    }
    return oss.str();
  }

  CryptoMarketClient::CryptoMarketClient(const std::string &key, const std::string &secret
					 const std::string &url, const std::string &version)
  {
    key_ = key;
    secret_ = secret;
    url_ = url;
    version_ = version;
    init();
  }

  CryptoMarketClient::CryptoMarketClient(const std::string &key, const std::string &secret)
  {
    key_ = key;
    secret_ = secret;
    //TODO: ADD DEFAULT URL
    init();
  }

  CryptoMarketClient::CryptoMarketClient()
  {
    init();
  }

  CryptoMarketclient::init(){
    curl_ = curl_eady_init();
    if(curl_){
      //curl_easy_setopt(curl_,CURLOPT_VERBOSE, CURL_VERBOSE);
      curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYHOST, 2L);
      curl_easy_setopt(curl_,CURLOPT_USERAGENT,"CritpoMarket C++ API Client");
      curl_easy_setopt(curl_,CURLOPT_POST, 1L);
      //set callback function
      curl_easy_setopt(curl_,CURLOPT_WRITEFUNCTION,CryptoMarketClient::write_cb);
    }else{
      std::cerr << "CURL init error !!" << std::endl;
    }
  }

  CryptoMarketClient::~CryptoMarketClient()
  {
    curl_easy_cleanup(curl_);
  }

  CryptoMarketClient::signature() const
  {
    
  }

  CryptoMarketClient::write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
  {
    std::string response = reinterpret_cast<std::string*>(userdata);
    size_t real_size = size * nmemb;
    response->append(ptr,real_size);
    return real_size;
  }

  std::string CryptoMarketClient::puclib_pethod(const std::string &method, const CMInput &input)
  {
    std::string path = "/" + version_ + "/public/" + method;
  }

  std::string CryptoMarketClient::private_method(const std::string &method, const CMInput &input)
  {
    
  }

  
  
};//namespace cryptomarket
