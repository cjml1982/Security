#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <malloc.h>

#define MAX_TEXT_SIZE 1048576

static unsigned char KEY[] = {
    0x68, 0xde, 0xca, 0xe8, 0x86, 0x06, 0xb2, 0x6b,
    0x9b, 0xb9, 0x46, 0x88, 0x54, 0xed, 0x7f, 0x31
};

static unsigned char INITIAL_VECTOR[] = {
0xcd, 0x3c, 0x13, 0x69, 0xa3, 0x93, 0x0a, 0x9e, 0x50, 0xde, 0xb1, 0xfe, 0x2e, 0x8e, 0xa6, 0xe4,
0xd4, 0x72, 0x53, 0xab, 0xe8, 0x54, 0xcb, 0x81, 0x38, 0x27, 0xc7, 0x15, 0xe0, 0xd9, 0xad, 0xe1,
0x8c, 0x71, 0x14, 0x8b, 0x1c, 0x96, 0x71, 0x8a, 0xa3, 0xed, 0x4c, 0xcd, 0xcd, 0xde, 0x79, 0x2a,
0x41, 0x89, 0x85, 0xa1, 0x58, 0x60, 0xe3, 0x1b, 0x59, 0x92, 0xf8, 0xe3, 0xba, 0x92, 0xee, 0x93
};

static void hexdump(
                FILE *f,
                const char *title,
                const unsigned char *s,
                int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0) {
                fprintf(f, "\n%04x", n);
        }
        fprintf(f, " %02x", s[n]);
    }

    fprintf(f, "\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *rkey,  int rkeybit_len,
  unsigned char *iv_org, unsigned char *ciphertext)
{
        //Internal key.
        AES_KEY key;

        //int nr_of_bits = 0;
        int cipher_len =0;

        //copy the iv_org to iv, because iv would be changed after the AES encryption
        unsigned char   iv[AES_BLOCK_SIZE * 4];       
        memcpy(iv, iv_org, AES_BLOCK_SIZE * 4);

        if (MAX_TEXT_SIZE<plaintext_len)
        {
            return 0;
        }
        
        //plaintextbuf=malloc(MAX_TEXT_SIZE*sizeof(char));//malloc 10240 byte 
        //ciphertextbuf=(unsigned char *)malloc(MAX_TEXT_SIZE*sizeof(char));
        /*
        if (NULL==ciphertextbuf)
        {
            return 0;
        }
        */
        //Zeror buffer.
        //memset(plaintextbuf, 0, MAX_TEXT_SIZE);
        //memset(ciphertextbuf, 0, MAX_TEXT_SIZE);
        
        AES_set_encrypt_key(rkey, rkeybit_len, &key);

        //strcpy((char *)plaintextbuf,(const char*)plaintext);

        hexdump(stdout, "== plaintext ==",
                        plaintext,
                        plaintext_len);
        printf("\n");


        AES_cbc_encrypt(plaintext,
                        ciphertext,
                        plaintext_len,
                        &key,
                        iv,
                        AES_ENCRYPT);
        
        //strcpy((char *)ciphertext,(const char*)ciphertextbuf);

        cipher_len = strlen((const char*)ciphertext);
        
        //free(ciphertextbuf);
        hexdump(stdout, "== encrypted ciphertext ==",
                        ciphertext,
                        cipher_len);
                        
        printf("\n");

        
        return cipher_len;
       
}
  
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *rkey,  int rKeybit_len,
  unsigned char *iv_org, unsigned char *plaintext)
{
        //Internal key.
        AES_KEY key;
        
        //int nr_of_bits = 0;
        //int nr_of_bytes = 0;
        int plaintext_len=0;
        /*
        printf("plaintext=[%p]\n",plaintext); 
        printf("plaintext add=[%p]\n",&plaintext); 
        */
        //unsigned char *ciphertext=NULL;
        //unsigned char *plaintextbuf=NULL;
        
        if (MAX_TEXT_SIZE<ciphertext_len)
        {
            return 0;
        }

        //copy the iv_org to iv, because iv would be changed after the AES encryption
        unsigned char   iv[AES_BLOCK_SIZE * 4];        
        memcpy(iv, iv_org, AES_BLOCK_SIZE * 4);

        
        //ciphertext=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));//malloc 10240 byte 
        //plaintextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));
        /*
        if (NULL==plaintextbuf)
        {
            return 0;
        }
        */
        //Zeror buffer.
        //memset(plaintextbuf, 0, MAX_TEXT_SIZE);
        
        //nr_of_bits = 8 * sizeof(rkey);
        AES_set_encrypt_key(rkey, rKeybit_len, &key);

        AES_cbc_encrypt(ciphertext,
                plaintext,
                ciphertext_len,
                &key, iv,
                AES_DECRYPT);

        //strcpy((char *)plaintext,(const char*)plaintextbuf);

        plaintext_len = strlen((const char*)plaintext);

        //free(plaintextbuf);

        return plaintext_len;
        
}


int main(int argc, char **argv)
{
        //128bits key.
        unsigned char   rkey[16];
        
        unsigned char plaintext[] = "I am a dog!! wang wang 00000000 hahahahahahahahahahahahahahahahahahaha";
       
        unsigned char *plaintextbuf=NULL;
        unsigned char *ciphertextbuf=NULL;
        unsigned char *decryptplaintextbuf=NULL;
        plaintextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));
        ciphertextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));
        decryptplaintextbuf=(unsigned char*)malloc(MAX_TEXT_SIZE*sizeof(char));

        //Init vector.
        unsigned char   iv[AES_BLOCK_SIZE * 4];
        //Save vector.
        unsigned char   saved_iv[AES_BLOCK_SIZE * 4];

        //Zeror buffer.
        memset(plaintextbuf, 0, MAX_TEXT_SIZE);
        memset(ciphertextbuf, 0, MAX_TEXT_SIZE);
        memset(decryptplaintextbuf, 0, MAX_TEXT_SIZE);
        
        //Generate random
        //RAND_pseudo_bytes(rkey, sizeof rkey);
        //RAND_pseudo_bytes(saved_iv, sizeof saved_iv);
        memcpy(rkey, KEY, sizeof(rkey));
        memcpy(saved_iv, INITIAL_VECTOR, sizeof(iv));

        hexdump(stdout, "== rkey ==",
                        rkey,
                        sizeof(rkey));
        hexdump(stdout, "== iv ==",
                        saved_iv,
                        sizeof(saved_iv));
        printf("\n");
        
        //Entrypt       
        //strcpy((char *)plaintext,(const char*)text);
        
        memcpy(iv, saved_iv, sizeof(iv));
        
        //nr_of_bits = 8 * sizeof(rkey);
        //AES_set_encrypt_key(rkey, nr_of_bits, &key);

        strcpy((char *)plaintextbuf,(const char*)plaintext);
        int plaintext_len =strlen((const char*)plaintextbuf);

        hexdump(stdout, "== plaintextbuf ==",
                plaintextbuf,
                plaintext_len);
        printf("\n");


        //encrypt
        
        int nr_of_bits = 8 * sizeof(rkey);

        //Internal key.
        AES_KEY key;
        AES_set_encrypt_key(rkey, nr_of_bits, &key);
        
        AES_cbc_encrypt(plaintextbuf,
                        ciphertextbuf,
                        plaintext_len,
                        &key,
                        iv,
                        AES_ENCRYPT);

        hexdump(stdout, "== ciphertextbuf ==",
                        ciphertextbuf,
                        strlen((const char*)ciphertextbuf));
                        
        printf("\n");

        int ciphertext_len=  strlen((const char*)ciphertextbuf);
        printf ("ciphertext_len=[%d]\n",ciphertext_len);
       // int ciphertext_len=encrypt(plaintextbuf, plaintext_len, rkey, nr_of_bits, iv, ciphertextbuf);
 
        
        // [yasi] iv is changed in encryption
        
        hexdump(stdout, "== iv changed ==",
                        iv,
                        sizeof(iv));
        printf("\n");

        //Decrypt
        memcpy(iv, saved_iv, sizeof(saved_iv)); 
        //AES_set_encrypt_key(rkey, nr_of_bits, &key);
        nr_of_bits = 8 * sizeof(rkey);
        AES_set_decrypt_key(rkey, nr_of_bits, &key);
        //int ciphertext_len = strlen((const char*)ciphertext);
        
        //plaintext_len =  decrypt(ciphertextbuf, ciphertext_len, rkey,nr_of_bits, iv, decryptplaintextbuf);
        
        AES_cbc_encrypt(ciphertextbuf,
                decryptplaintextbuf,
                ciphertext_len,
                &key,
                iv,
                AES_DECRYPT); 
        /*
        hexdump(stdout, "== checktext ==",
                        checktext,
                        sizeof(checktext));
        printf("\n");
        */
        
        hexdump(stdout, "== decryptplaintextbuf ==",
                        decryptplaintextbuf,
                        strlen((const char *)decryptplaintextbuf));
        printf("\n");
        
        return 0;
}


#if 0
int main(int argc, char **argv)
{
        //128bits key.
        unsigned char   rkey[16];
        //Internal key.
        AES_KEY         key;

        //Testdata.
        // [yasi] Make static content instead of random text
        /*
        unsigned char   plaintext[AES_BLOCK_SIZE * 8] =
        {
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
                '0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
                '0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
                '0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',
                '0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7'
        };
        */
        unsigned char text[] = "I am a dog!! wang wang 00000000 hahahahahahahahahahahahahahahahahahaha";
        //unsigned char   ciphertext[AES_BLOCK_SIZE * 8];
        //unsigned char   checktext[AES_BLOCK_SIZE * 8];
        
        unsigned char *plaintext=NULL;
        unsigned char *ciphertext=NULL;
        unsigned char *decryptplaintext=NULL;
        plaintext=(unsigned char*)malloc(1024000*sizeof(char));//malloc 10240 byte 
        ciphertext=(unsigned char*)malloc(1024000*sizeof(char));//malloc 10240 byte 
        decryptplaintext=(unsigned char*)malloc(1024000*sizeof(char));//malloc 10240 byte 

        //Init vector.
        unsigned char   iv[AES_BLOCK_SIZE * 4];
        //Save vector.
        unsigned char   saved_iv[AES_BLOCK_SIZE * 4];

        int nr_of_bits = 0;
        int nr_of_bytes = 0;

        //Zeror buffer.
        /*
        memset(ciphertext, 0, sizeof ciphertext);
        memset(checktext, 0, sizeof checktext);
        */

        //memset(plaintext, 9, len);
        memset(ciphertext, 0, 1024000);
        memset(decryptplaintext, 0, 1024000);
        
        //Generate random
        //RAND_pseudo_bytes(rkey, sizeof rkey);
        //RAND_pseudo_bytes(saved_iv, sizeof saved_iv);
        memcpy(rkey, KEY, sizeof(rkey));
        memcpy(saved_iv, INITIAL_VECTOR, sizeof(iv));

        hexdump(stdout, "== rkey ==",
                        rkey,
                        sizeof(rkey));
        hexdump(stdout, "== iv ==",
                        saved_iv,
                        sizeof(saved_iv));
        printf("\n");
        
        /*
        hexdump(stdout, "== text ==",
                        text,
                        len);
        printf("\n");
        */
        //Entrypt
        
        strcpy((char *)plaintext,(const char*)text);
        
        hexdump(stdout, "== plaintext ==",
                        plaintext,
                        strlen((const char*)plaintext));
        printf("\n");
        
        memcpy(iv, saved_iv, sizeof(iv));
        nr_of_bits = 8 * sizeof(rkey);
        AES_set_encrypt_key(rkey, nr_of_bits, &key);
        nr_of_bytes =strlen((const char*)plaintext);// sizeof(plaintext);
        AES_cbc_encrypt(plaintext,
                        ciphertext,
                        nr_of_bytes,
                        &key,
                        iv,
                        AES_ENCRYPT);

        hexdump(stdout, "== ciphertext ==",
                        ciphertext,
                        strlen((const char*)ciphertext));
                        
        printf("\n");
        
        // [yasi] iv is changed in encryption
        hexdump(stdout, "== iv changed ==",
                        iv,
                        sizeof(iv));
        printf("\n");

        //Decrypt
        memcpy(iv, saved_iv, sizeof(iv));       // [yasi] without this line, decrypt will fail because iv is changed in encryption
        nr_of_bits = 8 * sizeof(rkey);
        AES_set_decrypt_key(rkey, nr_of_bits, &key);
        nr_of_bytes = strlen((const char*)ciphertext);

        /*
        AES_cbc_encrypt(ciphertext,
                        checktext,
                        nr_of_bytes,
                        &key, iv,
                        AES_DECRYPT);
        */
        AES_cbc_encrypt(ciphertext,
                decryptplaintext,
                nr_of_bytes,
                &key, iv,
                AES_DECRYPT);
        /*
        hexdump(stdout, "== checktext ==",
                        checktext,
                        sizeof(checktext));
        printf("\n");
        */
        
        hexdump(stdout, "== decryptplaintext ==",
                        decryptplaintext,
                        strlen((const char *)decryptplaintext));
        printf("\n");
        
        return 0;
}

#endif

