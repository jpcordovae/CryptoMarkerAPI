
test_public:
	g++ -g -Wall test_public.cpp src/cmclient.cpp -o test_public -Isrc/ -lcurl -lssl -lcrypto -ljson-c -std=c++11 



