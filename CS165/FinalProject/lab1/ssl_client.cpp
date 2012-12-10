//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
#include <fstream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>       // Random number generator

#include "utils.h"

#define BUFFER_LENGTH 16

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//---------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
	//2a. Generate random number
	unsigned char challenge[BUFFER_LENGTH];
	//fix
	if(!RAND_bytes(challenge, BUFFER_LENGTH-1))
	{
	  cerr << "Unable to generate random number for step 2." << endl;
	  exit(1);
	}
	/* verify that buf is being transmitted correctly
	for(int i = 0; i < 15; ++i)
	{
	  challenge[i] = 'a';
	} */
	
	
	//2b. Encrypt challenege with server's public key
	
	//get public key
	
	cout << endl << "Reading in public key... " << endl;
	
	BIO* pubin = BIO_new_file("rsapublickey.pem","r");
	RSA* pubkey = PEM_read_bio_RSA_PUBKEY(pubin, NULL,NULL, NULL);
	int pubkey_size = RSA_size(pubkey);
	
	//(?)
	unsigned char echallenge[pubkey_size];
	cout << "Encrypting... " << endl;
	
	int enc_size = RSA_public_encrypt(BUFFER_LENGTH, challenge, echallenge, 
	                  pubkey, RSA_PKCS1_PADDING);
	cout << "Size of encrypted thing: " << enc_size << endl;
	cout <<  endl << "Writing... " << endl;
	
	
	SSL_write(ssl, echallenge, BUFFER_LENGTH);
    string echallenge_str = 
		buff2hex((const unsigned char*)echallenge, BUFFER_LENGTH);
	string challenge_str = 
		buff2hex((const unsigned char*)challenge, BUFFER_LENGTH);
	printf("SUCCESS.\n");
	
	cout << "    (Challenge: \"" <<  challenge_str << "\"\n";
	cout << "    (Encrypted Challenge: \"" << echallenge_str << "\"\n";
	
    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");


	char* buff="FIXME";
	int len=5;
	//SSL_read;

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n",
	       buff2hex((const unsigned char*)buff,len).c_str(), len);
	       
	       
	 //hash the unencrypted challenge using SHA1
	unsigned char sha1_buff[BUFFER_LENGTH];
	memset(sha1_buff,0,sizeof(sha1_buff));
	SHA1(challenge, BUFFER_LENGTH, sha1_buff);
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", 
	       buff2hex(sha1_buff,BUFFER_LENGTH).c_str(), BUFFER_LENGTH);
    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	
	string generated_key = "";
    string decrypted_key = "";
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");
	
	SSL_write(ssl, filename + NULL, sizeof(filename)+1);
	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	SSL_shutdown(ssl);
	BIO_reset(client);
	BIO_free(client);
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
