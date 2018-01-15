#include "cmclient.hpp"

#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <chrono>

#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>

#include <json-c/json.h>

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
  hmac_sha384(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key)
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

  static std::string b64_encode(const std::vector<unsigned char> &data){
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64,bmem);

    BIO_write(b64, data.data(),data.size());
    BIO_flush(b64);

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(b64, &bptr);

    std::string output(bptr->data,bptr->length);
    BIO_free(b64);
    return output;
  }

  static std::vector<unsigned char> b64_decode(const std::string &data){
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO *bmem = BIO_new_mem_buf((void*)data.c_str(),data.length());
    bmem = BIO_push(b64,bmem);

    std::vector<unsigned char> output(data.length());
    int decoded_size = BIO_read(bmem,output.data(),output.size());
    BIO_free_all(bmem);

    if(decoded_size < 0){
      std::cerr << "failed while decoding base64. ";
    }

    return output;
  }
  
  static std::string build_query(const CMInput &input)
  {
    std::ostringstream oss;
    CMInput::const_iterator it = input.begin();
    for(;it!=input.end();++it){
      if(it!=input.begin()) oss << "&";
      oss << it->first << "=" << it->second;
    }
    return oss.str();
  }


  static std::string build_post(const CMInput &input)
  {
    std::ostringstream oss;
    CMInput::const_iterator it;
    json_object *jobj = json_object_new_object();
    for(it=input.begin();it!=input.end();++it){
      json_object *jstring = json_object_new_string(it->second.c_str());
      json_object_object_add(jobj,it->first.c_str(),jstring);
    }
    return std::string(json_object_to_json_string(jobj));
  }
  
  CryptoMarketClient::CryptoMarketClient(const std::string &key, const std::string &secret, const std::string &url, const std::string &version)
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
    url_ = "https://api.cryptomkt.com";
    version_ = "v1";
    init();
  }

  CryptoMarketClient::CryptoMarketClient()
  {
    url_ = "https://api.cryptomkt.com";
    version_ = "v1";
    init();
  }

  void  CryptoMarketClient::init(){
    curl_ = curl_easy_init();
    if(curl_){
      //curl_easy_setopt(curl_,CURLOPT_VERBOSE, CURL_VERBOSE);
      curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYHOST, 2L);
      curl_easy_setopt(curl_,CURLOPT_USERAGENT,"CritpoMarket C++ API Client");
      //curl_easy_setopt(curl_,CURLOPT_POST, 1L);
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

  std::string CryptoMarketClient::signature(const std::string &timestamp,const std::string &path_url,const std::string &postdata)
  {
    std::vector<unsigned char> data(timestamp.begin(),timestamp.end());

    data.insert(data.end(),path_url.begin(),path_url.end());
    data.insert(data.end(),postdata.begin(),postdata.end());
    
    return b64_encode(hmac_sha384(data,b64_decode(secret_)));
  }

  size_t CryptoMarketClient::write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
  {
    std::string *response = reinterpret_cast<std::string*>(userdata);
    size_t real_size = size * nmemb;
    response->append(ptr,real_size);
    return real_size;
  }

  std::string CryptoMarketClient::public_method(const std::string &method, const CMInput &input)
  {
    std::string path = "/" + version_ + "/" + method;
    std::string method_url = url_ + path;

    if(!input.empty()){
      method_url.append("?");
      method_url.append(build_query(input));
    }

    //std::cout << method_url << std::endl;
    
    curl_easy_setopt(curl_,CURLOPT_URL,method_url.c_str());
    curl_easy_setopt(curl_,CURLOPT_POST, 0L); //disable POST
    curl_easy_setopt(curl_,CURLOPT_HTTPGET,1L);//enable GET
    
    //reset header
    curl_easy_setopt(curl_,CURLOPT_HTTPHEADER,NULL);

    //set callback
    std::string response;
    curl_easy_setopt(curl_,CURLOPT_WRITEDATA,static_cast<void*>(&response));

    //perform CURL request
    CURLcode result =curl_easy_perform(curl_);
    if(result != CURLE_OK){
      std::ostringstream oss;
      oss << "curl_easy_perform() failed at " << __LINE__ << "in function " << __FUNCTION__ << " : " << curl_easy_strerror(result);
    }
    return response;
  }

  void CryptoMarketClient::update_server_timestamp()
  {
    //TODO:
    //std::string sTmp = public_method();
  }
  
  std::string CryptoMarketClient::private_method(const std::string &method, const CMInput &input)
  {
    std::string path = "/" + version_ + "/" + method;
    std::string method_url = url_ + path;
    std::string post_data = build_post(input);
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time( std::localtime( &t ), "%FT%T%Z" );
    std::string timestamp = ss.str();
    
    // CURL options setup
    curl_easy_setopt(curl_,CURLOPT_URL,method_url.c_str());
    curl_easy_setopt(curl_,CURLOPT_HTTPGET,0L);//disable get
    curl_easy_setopt(curl_,CURLOPT_POST,1L);// enable post

    //set post field
    if(!post_data.empty())
    curl_easy_setopt(curl_,CURLOPT_POSTFIELDS, post_data.c_str());

    // signature
    std::string signed_data = signature(timestamp,method_url,post_data);
    
    //set header
    curl_easy_setopt(curl_,CURLOPT_HTTPHEADER,NULL);
    curl_slist *chunk = NULL;
    std::string key_header = "X-MKT-APIKEY:" + key_;
    std::string signature_header = "X-MKT-SIGNATURE:" + signed_data;
    std::string timestamp_header = "X-MKT-TIMESTAMP:" + timestamp;
    chunk = curl_slist_append(chunk,key_header.c_str());
    chunk = curl_slist_append(chunk,signature_header.c_str());
    chunk = curl_slist_append(chunk,timestamp_header.c_str());
    
    //set callback
    std::string response;
    curl_easy_setopt(curl_,CURLOPT_WRITEDATA,static_cast<void*>(&response));

    //perform CURL request
    CURLcode result = curl_easy_perform(curl_);

    if(result != CURLE_OK){
      std::ostringstream oss;
      oss << "curl_easy_perform() failed at" << __LINE__ << " in function " << __FUNCTION__ << " : " << curl_easy_strerror(result);
    }
    
    return response;
  }  
  
  
};//namespace cryptomarket
