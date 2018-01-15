#ifndef MKCLIENT_HPP_
#define MKCLIENT_HPP_

#include <string>
#include <map>
#include <curl/curl.h>
#include <stdlib.h>

#include <chrono>

namespace cryptomarket{

  //------------------------------------------------------------------------
  // request structure
  typedef std::map<std::string,std::string> CMInput;
  //  typedef shared_ptr<CMInput> CMInputPtr; // shared pointer of CMInput
  //-------------------------------------------------------------------------
  
  class CryptoMarketClient
  {
  public:
    CryptoMarketClient(const std::string &key, const std::string &secret, const std::string &url, const std::string &version);

    CryptoMarketClient(const std::string &key, const std::string &secret);

    CryptoMarketClient();

    ~CryptoMarketClient();

    std::string public_method(const std::string &method, const CMInput &input);

    std::string private_method(const std::string &method, const CMInput &input);

    void update_server_timestamp();
    
  private:
    void init();
    
    // signature for private methods
    std::string signature(const std::string &timestamp, const std::string &path_url, const std::string &postdata);
    // CURL write callback
    static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

    std::string key_;
    std::string secret_;
    std::string url_;
    std::string version_;
    CURL *curl_;
    
  };//class CryptoMarketClient
  
};//namespace cryptomarket

void initialize();
void terminate();

#endif
