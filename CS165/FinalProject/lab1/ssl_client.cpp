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

#define CHALLENGE_LENGTH 16
#define SHA1_LENGTH 21 //extra 1 for null termination
#define MAX_READ 128
#define F_READ 256
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
	unsigned char challenge[CHALLENGE_LENGTH];
	//fix
	if(!RAND_bytes(challenge, CHALLENGE_LENGTH-1))
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
	
	
	unsigned char echallenge[pubkey_size];
	cout << "Encrypting... " << endl;
	
	int enc_size = RSA_public_encrypt(CHALLENGE_LENGTH, challenge, echallenge, 
	                  pubkey, RSA_PKCS1_PADDING);
	cout << "Size of encrypted thing: " << enc_size << endl;
	cout <<  endl << "Writing... " << endl;
	
	
	SSL_write(ssl, echallenge, pubkey_size);
    string echallenge_str = 
		buff2hex((const unsigned char*)echallenge, pubkey_size);
	string challenge_str = 
		buff2hex((const unsigned char*)challenge, CHALLENGE_LENGTH);
	printf("SUCCESS.\n");
	
	BIO_free(pubin);
	
	cout << "    (Challenge: \"" <<  challenge_str << "\")\n";
	cout << "    (Encrypted Challenge: \"" << echallenge_str << "\")\n";
	
    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");


	unsigned char buff[MAX_READ];
	int len = SSL_read(ssl,buff,MAX_READ);
	

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n",
	       buff2hex((const unsigned char*)buff,len).c_str(), len);
	       
	       
	 //hash the unencrypted challenge using SHA1
	unsigned char sha1_buff[SHA1_LENGTH];
	memset(sha1_buff,0,SHA1_LENGTH);
	SHA1(challenge, CHALLENGE_LENGTH, sha1_buff);
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", 
	       buff2hex(sha1_buff,SHA1_LENGTH).c_str(), SHA1_LENGTH);
	/*       
	//hash the encrypted challenge just to check
	unsigned char sha1_buff2[SHA1_LENGTH];
	memset(sha1_buff2,0,SHA1_LENGTH);
	SHA1(echallenge, CHALLENGE_LENGTH, sha1_buff2);
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", 
	       buff2hex(sha1_buff2,SHA1_LENGTH).c_str(), SHA1_LENGTH);*/
    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
	BIO* keyin = BIO_new_file("rsapublickey.pem", "r");
	RSA* key = PEM_read_bio_RSA_PUBKEY(keyin, NULL, NULL, NULL);
	int key_size = RSA_size(key);
	
	unsigned char dec_hash[MAX_READ];
	
	int dec_hash_size = RSA_public_decrypt(len, buff, dec_hash, key,
		RSA_PKCS1_PADDING);
		
	if( dec_hash_size != SHA1_LENGTH)
	{
		cout << endl << "Authentication failed." << endl;
		exit(EXIT_FAILURE);
	}
	
	for(unsigned int i = 0; i < SHA1_LENGTH; ++i)
	{
		if(dec_hash[i] != sha1_buff[i])
		{
			cout << endl << "Authentication failed." << endl;
			exit(EXIT_FAILURE);
		}	
	}
	
	BIO_free(keyin);
    
	printf("AUTHENTICATED\n");
	printf("    (Generated hash: %s)\n",
		   buff2hex(sha1_buff,SHA1_LENGTH).c_str(), SHA1_LENGTH);
	printf("    (Decrypted hash: %s)\n",
		   buff2hex(dec_hash,SHA1_LENGTH).c_str(), SHA1_LENGTH);

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");
	
	SSL_write(ssl, filename + NULL, sizeof(filename)+1);
	PAUSE(2);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

    BIO* fout = BIO_new_file("transmitted_file.txt", "w");
    if(!fout)
	{
		cerr << endl << "Cannot create file to save contents." << endl;
		exit(EXIT_FAILURE);
	}
    
    cout << endl;
    int actualRead=0;
    while(1)
    {
		char read[F_READ];
		memset(read,0,F_READ);
		actualRead = SSL_read(ssl,(unsigned char*)read,F_READ-1);
		if(actualRead <= 0)
			break;
		
		cout << read;
		int bytesWritten = BIO_write(fout, read, F_READ-1);
		if(bytesWritten <= 0)
		{
			cerr << endl << "File is not being written to" << endl;
		}
	}
    
	//BIO_free(fout);
	printf("FILE RECEIVED AND DISPLAYED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	SSL_shutdown(ssl);
	//BIO_reset(client);
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	
	BIO_free_all(client);
	return EXIT_SUCCESS;
	
}
