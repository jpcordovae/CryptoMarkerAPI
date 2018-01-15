#include "src/cmclient.hpp"
#include<iostream>

using namespace cryptomarket;
using namespace std;

int main()
{

  CMInput in;
  CryptoMarketClient client;

  // testin market
  cout << client.public_method("market",in) << endl;;

  // testing ticker
  cout << client.public_method("ticker",in) << endl;;

  //testing ticker with one input
  in["market"] = "ETHCLP";
  cout << client.public_method("ticker",in) << endl;

  // test order book
  in.clear();
  in["market"] = "ETHCLP";
  in["type"]="buy";
  in["page"]="0";

  cout << client.public_method("book",in) << endl;

  in["page"] = "1";
  in["limit"] = "100";
  cout << client.public_method("book",in) << endl;

  in.clear();

  cout << "PRIVATE" << endl;
    
  return EXIT_SUCCESS;

}
