#ifndef MKCLIENT_HPP_
#define MKCLIENT_HPP_

#include <string>
#include <curl/curl.h>

namespace cryptomarket{

  //------------------------------------------------------------------------
  // request structure
  typedef std::map<std::string,std::string> CMInput;
  
  //-------------------------------------------------------------------------
  
  class CryptoMarketClient
  {
  public:
    CryptoMarketClient(const std::string &key, const std::string &secret,
		       const std::string &url, const std::string &version);

    CryptoMarketClient(const std::string &key, const std::string &secret);

    CryptoMarketClient();

    ~CryptoMarketClient();

    std::string public_method(const std::string &method,
			      const CMInput &input);

    std::string private_method(const std::string,
			       const CMInput &input);
    
  private:
    void init();
    
    // signature for private methods
    std::string signature() const;

    // CURL write callback
    static size_t write_cb(char *ptr, size_t size,
			   size_t nmemb, void *userdata);

    std::string key_;
    std::string secet_;
    std::string url_;
    std::string version_;
    CURL *curl_;
    
    
  };//class CryptoMarketClient
  
};//namespace cryptomarket

void initialize();
void terminate();

#endif
