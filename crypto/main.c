#include "aes_algo.h" 
#include <stdio.h>	
#include <string.h>  
#include<iostream>
//#include <openssl/evp.h>	

using namespace std;

int main(int arc, char *argv[])  
{  
  /* Set up the key and iv. Do I need to say to not hard code these in a 
   * real application? :-) 
   */  
  
  /* A 128 bit key */  
  //unsigned char *key = "0123456789012111";	
	 //128bits key.
	unsigned char   key[KEY_BYTE_NUMBERS]; 
	//Init vector.
	unsigned char   iv[KEY_BYTE_NUMBERS];
		  
  /* A 128 bit IV */  
  //unsigned char *iv = "01234567890123456";	
  memcpy(key, KEY, KEY_BYTE_NUMBERS);
  memcpy(iv, INITIAL_VECTOR, KEY_BYTE_NUMBERS);

  
  /* Message to be encrypted */  
   char *plaintext =  
	"The quick brown fox jumps over the lazy dog la men hehe  you a lala ";	
  
  /* Buffer for ciphertext. Ensure the buffer is long enough for the 
   * ciphertext which may be longer than the plaintext, dependant on the 
   * algorithm and mode 
   */  
  //unsigned char ciphertext[64];  
  
  /* Buffer for the decrypted text */  
  //unsigned char decryptedtext[64];
	unsigned char *plaintextbuf=NULL;
	unsigned char *ciphertextbuf=NULL;
	unsigned char *decryptplaintextbuf=NULL;
	plaintextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));
	ciphertextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));
	decryptplaintextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));

	int decryptedtext_len, ciphertext_len;  

	/* Initialise the library */	
	/*	ERR_load_crypto_strings(); 
	OpenSSL_add_all_algorithms(); 
	OPENSSL_config(NULL);*/  

	printf("Plaintext is:\n%s~\n", plaintext);  
	//memset(plaintextbuf, 5, MAX_TEXT_SIZE);
	memset(ciphertextbuf, 0, MAX_TEXT_SIZE);
	memset(decryptplaintextbuf, 0, MAX_TEXT_SIZE);

	strcpy((char *)plaintextbuf,(const char*)plaintext);
	/* Encrypt the plaintext */ 

	try
	{
		ciphertext_len = encrypt(plaintextbuf, strlen((char *)plaintextbuf), key, iv,  
								ciphertextbuf);  
	}
	catch(std::runtime_error& e)
	{
		printf("runtime error of encrypt\n");
	}
	catch(...)
	{
		printf(" error of encrypt\n");
	}
  
  /* Do something useful with the ciphertext here */  
  printf("Ciphertext is %d bytes long:\n", ciphertext_len);  
  //BIO_dump_fp(stdout, ciphertextbuf, ciphertext_len);	
  
  /* Decrypt the ciphertext */	
  /*
	try
	{
		decryptedtext_len = decrypt(ciphertextbuf, ciphertext_len, key, iv,	
			decryptplaintextbuf);  

	}
	catch(std::runtime_error&e)
	{
		printf("runtime error of decrypt\n");
	}
	catch(...)
	{
		printf(" error of decrypt\n");
	}
	
  hexdump(stdout, "== decryptplaintextbuf ==",
				  decryptplaintextbuf,
				  decryptedtext_len);
  printf("\n");

  */
  //Add a NULL terminator. We are expecting printable text 
  //decryptplaintextbuf[decryptedtext_len] = '\0';	

  /* Show the decrypted text */  
  printf("Decrypted text is:\n");  
  printf("%s~\n", decryptplaintextbuf);  
  
  /* Clean up */  
  EVP_cleanup();  
  ERR_free_strings();  
  
  return 0;  
}  

