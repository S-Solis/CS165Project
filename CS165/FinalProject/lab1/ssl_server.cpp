//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

#define READ_LENGTH 256
#define SHA1_LENGTH 21 //extra 1 for null termination
#define MAX_CHALLENGE 1025
#define F_READ 1024

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
    
	setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    
	//set up BIO
	BIO* privin = BIO_new_file("rsaprivatekey.pem", "r");
	RSA* privkey = PEM_read_bio_RSAPrivateKey(privin, NULL, NULL, NULL);
	int privkey_size = RSA_size(privkey);
	
	//get encrypted challenge
	unsigned char challenge[MAX_CHALLENGE];
	memset(challenge, 0, MAX_CHALLENGE);
	int challenge_leng = SSL_read(ssl, challenge, MAX_CHALLENGE);
	if(SSL_get_shutdown(ssl))
	{
		cout << endl << "Connection shut down while reading challenge."
			 << endl;
		exit(EXIT_FAILURE);
	}
	if(challenge_leng <= 0)
	{
		cout << endl << "No challenge could be read. " << endl;
		exit(EXIT_FAILURE);
	}
    
	
	string challenge_str = buff2hex((const unsigned char*)challenge,
		challenge_leng);
	
	BIO_free(privin);
	
	//decrypt challenge
	unsigned char dchallenge[MAX_CHALLENGE];
	memset(dchallenge, 0, MAX_CHALLENGE);
	
	int dec_size = RSA_private_decrypt(challenge_leng, challenge,
			dchallenge, privkey, RSA_PKCS1_PADDING);
			
	if(dec_size < 0)
	{
		cout << endl << "Error decrypting the challenge." << endl;
		exit(EXIT_FAILURE);
	}
	string dchallenge_str = buff2hex((const unsigned char*)dchallenge, 
		dec_size);
		
	printf("DONE.\n");
	cout << "    (Challenge: \"" <<  challenge_str << "\")\n";
	cout << "    (Decrypted Challenge: \"" << dchallenge_str << "\")\n";
	
    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
	
	unsigned char sha1_buff[SHA1_LENGTH];
	memset(sha1_buff,0,SHA1_LENGTH);
	SHA1(dchallenge, dec_size, sha1_buff);


	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", 
	       buff2hex(sha1_buff,SHA1_LENGTH).c_str(), SHA1_LENGTH);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");
	
	//read in private key
	BIO* keyin = BIO_new_file("rsaprivatekey.pem", "r");
	RSA* key = PEM_read_bio_RSAPrivateKey(keyin, NULL, NULL, NULL);
	int key_size = RSA_size(key);
	
	//encrypt hased string with private key
	unsigned char signature[MAX_CHALLENGE];
	memset(signature, 0, MAX_CHALLENGE);
	
	int siglen = RSA_private_encrypt(SHA1_LENGTH, sha1_buff,
			signature, key, RSA_PKCS1_PADDING);
	
	if(siglen < 0)
	{
		cout << endl << "Error encrypting the hash." << endl;
		exit(EXIT_FAILURE);
	}
	
	BIO_free(keyin);
    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n",
	   buff2hex((const unsigned char*)signature,
		    siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
	SSL_write(ssl, signature, siglen);

	printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

    //SSL_read
    char filename_arr[READ_LENGTH]; //max filename typically 255
    memset(filename_arr,0,READ_LENGTH);
    
    
    int filenamelen = 0;
	filenamelen = SSL_read(ssl, filename_arr, READ_LENGTH);
	if(filenamelen <= 0)
	{
		cout << endl << "File name was not properly read." << endl;
		exit(EXIT_FAILURE);
	}
	
	string filename;
	for(unsigned int i = 0; i < filenamelen; ++i)
	{
		filename += filename_arr[i];
	}

    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\")\n", filename.c_str());

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	BIO_flush(server);
	BIO* fin = BIO_new_file(filename.c_str(), "r");
	
	if(!fin)
	{
		cout << endl << "Error reading the file: " << filename << endl;
		exit(EXIT_FAILURE);
	}
	

    int bytesSent=0;
	int actualRead = 1;
	while(1)
	{
		unsigned char read[F_READ];
		memset(read,0,F_READ);
		actualRead = BIO_read(fin,read,F_READ);
		if(actualRead <= 0)
			break;
		bytesSent += actualRead;
		SSL_write(ssl, read, F_READ);
	}
		
		
	
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);
	
	
    BIO_free(fin);
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	SSL_shutdown(ssl);
    BIO_reset(server);
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
