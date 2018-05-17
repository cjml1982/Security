/**
 * Copyright (C) 2016-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/aes.t.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */
#include "stdio.h"


#include "gtest/gtest.h"
#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
#include <ndn-cpp/util/logging.hpp>
#include <ndn-cpp/c/encrypt/crypto_hardware.h>
#include "../../src/c/encrypt/algo/aes-algorithm.h"

#include <stdexcept>
#include <ndn-cpp/lite/util/crypto-lite.hpp>
#include <ndn-cpp/lite/encrypt/algo/aes-algorithm-lite.hpp>
#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
/*
#ifndef MARTY
#define MARTY  0  //Control the printf
#endif
*/
using namespace std;
using namespace pki;

static uint8_t KEY[] = {
  0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
  0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
};

// plaintext: AES-Encrypt-Test
static uint8_t PLAINTEXT[] = {
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
};

static uint8_t CIPHERTEXT_ECB[] = {
  0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
  0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
  0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
  0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
};

static uint8_t INITIAL_VECTOR[] = {
  0x6f, 0x53, 0x7a, 0x65, 0x58, 0x6c, 0x65, 0x75,
  0x44, 0x4c, 0x77, 0x35, 0x58, 0x63, 0x78, 0x6e
};

static uint8_t CIPHERTEXT_CBC_IV[] = {
  0xb7, 0x19, 0x5a, 0xbb, 0x23, 0xbf, 0x92, 0xb0,
  0x95, 0xae, 0x74, 0xe9, 0xad, 0x72, 0x7c, 0x28,
  0x6e, 0xc6, 0x73, 0xb5, 0x0b, 0x1a, 0x9e, 0xb9,
  0x4d, 0xc5, 0xbd, 0x8b, 0x47, 0x1f, 0x43, 0x00
};

class TestAesAlgorithm : public ::testing::Test {
};

TEST_F(TestAesAlgorithm, EncryptionDecryption_CPU)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesEcb, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));
  _LOG_DEBUG(plainBlob.size());

  // Encrypt data in AES_ECB.
  Blob cipherBlob = AesAlgorithm::encrypt
    (encryptKey.getKeyBits(), plainBlob, encryptParams);
  ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));

  // Decrypt data in AES_ECB.
  Blob receivedBlob = AesAlgorithm::decrypt
    (decryptKey.getKeyBits(), cipherBlob, encryptParams);
  ASSERT_TRUE(receivedBlob.equals(plainBlob));

  // Encrypt/decrypt data in AES_CBC with auto-generated IV.
  encryptParams.setAlgorithmType(ndn_EncryptAlgorithmType_AesCbc);
  cipherBlob = AesAlgorithm::encrypt
    (encryptKey.getKeyBits(), plainBlob, encryptParams);
  receivedBlob = AesAlgorithm::decrypt
    (decryptKey.getKeyBits(), cipherBlob, encryptParams);
  ASSERT_TRUE(receivedBlob.equals(plainBlob));

  // Encrypt data in AES_CBC with specified IV.
  Blob initialVector(INITIAL_VECTOR, sizeof(INITIAL_VECTOR));
  encryptParams.setInitialVector(initialVector);
  cipherBlob = AesAlgorithm::encrypt
    (encryptKey.getKeyBits(), plainBlob, encryptParams);
  ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_CBC_IV, sizeof(CIPHERTEXT_CBC_IV))));

  // Decrypt data in AES_CBC with specified IV.
  receivedBlob = AesAlgorithm::decrypt
    (decryptKey.getKeyBits(), cipherBlob, encryptParams);
  ASSERT_TRUE(receivedBlob.equals(plainBlob));
}

#ifdef MARTY
TEST_F(TestAesAlgorithm, AES_ECB_hardware)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesEcb, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_ECB.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");

#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());
 #endif
 
  error= ndn_AesAlgorithm_encrypt128Ecb_hardware
  (encryptKey.getKeyBits().buf(), 16, plainBlob.buf(),
   16, encryptedData, &encryptedDataLength);
  
  //encryptedData->resize(encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);

#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Ecb_hardware error=%d\n",error);

  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif
  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Ecb_hardware
	(encryptKey.getKeyBits().buf(), 16, encryptedData,
	 16, plainData, &plainDataLength);

#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

#endif
  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}

TEST_F(TestAesAlgorithm, AES_CBC_hardware)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesCbc, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_CBC.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());
#endif
  
  error=ndn_AesAlgorithm_encrypt128Cbc_hardware
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), plainBlob.buf(),
	 16, encryptedData,  &encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);

#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Ecb_hardware error=%d\n",error);

  
  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif

  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Cbc_hardware
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), encryptedData,
	 encryptedDataLength, plainData, &plainDataLength);
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

#endif
  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}

TEST_F(TestAesAlgorithm, AES_ECB_CPU_ENC_hardware_DEC)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesEcb, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_ECB.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");

#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());
#endif
  
  error= ndn_AesAlgorithm_encrypt128Ecb
  (encryptKey.getKeyBits().buf(), 16, plainBlob.buf(),
   16, encryptedData, &encryptedDataLength);
  
  //encryptedData->resize(encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);

#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Ecb_hardware error=%d\n",error);

  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif

  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Ecb_hardware
	(encryptKey.getKeyBits().buf(), 16, encryptedData,
	 16, plainData, &plainDataLength);
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
#endif
  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}

TEST_F(TestAesAlgorithm, AES_ECB_hardware_ENC_CPU_DEC)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesEcb, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_ECB.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");

#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());

  #endif
  error= ndn_AesAlgorithm_encrypt128Ecb_hardware
  (encryptKey.getKeyBits().buf(), 16, plainBlob.buf(),
   16, encryptedData, &encryptedDataLength);
  
  //encryptedData->resize(encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);
#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Ecb_hardware error=%d\n",error);

  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif
  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Ecb
	(encryptKey.getKeyBits().buf(), 16, encryptedData,
	 encryptedDataLength, plainData, &plainDataLength);
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
#endif
  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}

TEST_F(TestAesAlgorithm, AES_CBC_CPU_ENC_hardware_DEC)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesCbc, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_CBC.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());

 #endif 
  error=ndn_AesAlgorithm_encrypt128Cbc
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), plainBlob.buf(),
	 16, encryptedData,  &encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);

#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Ecb_hardware error=%d\n",error);

  
  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif

  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Cbc_hardware
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), encryptedData,
	 encryptedDataLength, plainData, &plainDataLength);
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
#endif

  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}



TEST_F(TestAesAlgorithm, AES_CBC_hardware_ENC_CPU_DEC)
{
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesCbc, 16);

  Blob key(KEY, sizeof(KEY));
  DecryptKey decryptKey(key);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  // Check key loading and key derivation.
  ASSERT_TRUE(encryptKey.getKeyBits().equals(key));
  ASSERT_TRUE(decryptKey.getKeyBits().equals(key));

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt data in AES_CBC.
  int error;
  size_t BLOCK_SIZE;
  /*
   ptr_lib::shared_ptr<vector<uint8_t> > encryptedData
    (new vector<uint8_t>(plainBlob.size() + BLOCK_SIZE));
*/

  uint8_t encryptedData[32];

  size_t encryptedDataLength;
  SM_open_cryptodev("/dev/sdb");

#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("key\n");
  	}
      printf("0x%x,",encryptKey.getKeyBits().buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }

  printf("encryptKey.getKeyBits().size()=%d\n",encryptKey.getKeyBits().size());

  
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plaintext\n");
  	}
      printf("0x%x,",plainBlob.buf()[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
  
  printf("plainBlob.size()=%d\n",plainBlob.size());
#endif
  
  error=ndn_AesAlgorithm_encrypt128Cbc_hardware
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), plainBlob.buf(),
	 16, encryptedData,  &encryptedDataLength);

  Blob cipherBlob(encryptedData, encryptedDataLength);

#ifdef MARTY
  printf("encryptedDataLength=%d\n",encryptedDataLength);
  
  printf("ndn_AesAlgorithm_encrypt128Cbc_hardware error=%d\n",error);

  
  for(int i =0;i<encryptedDataLength;i++)
  {
      if (0==i)
  	{
  	    printf("encryptData\n");
  	}
      printf("0x%x,",encryptedData[i]);	  
      if (encryptedDataLength/2-1==i||encryptedDataLength-1==i)
	  	printf("\n");
  }
#endif

  uint8_t plainData[16];
  size_t plainDataLength;

  error=ndn_AesAlgorithm_decrypt128Cbc
	(encryptKey.getKeyBits().buf(), 16, INITIAL_VECTOR,
	 sizeof(INITIAL_VECTOR), encryptedData,
	 encryptedDataLength, plainData, &plainDataLength);
#ifdef MARTY
  for(int i =0;i<16;i++)
  {
      if (0==i)
  	{
  	    printf("plainData after dec\n");
  	}
      printf("0x%x,",plainData[i]);	  
      if (7==i||15==i)
	  	printf("\n");
  }
#endif
  Blob plainBlobAfterDec(plainData, plainDataLength);
         
  //Blob cipherBlob = AesAlgorithm::encrypt
   //(encryptKey.getKeyBits(), plainBlob, encryptParams);
         
  //ASSERT_TRUE(cipherBlob.equals(Blob(CIPHERTEXT_ECB, sizeof(CIPHERTEXT_ECB))));
  ASSERT_TRUE(plainBlobAfterDec.equals(Blob(PLAINTEXT, sizeof(PLAINTEXT))));

  //SM_close_cryptodev();

}

#endif

TEST_F(TestAesAlgorithm, KeyGeneration)
{
  AesKeyParams keyParams(128);
  DecryptKey decryptKey = AesAlgorithm::generateKey(keyParams);
  EncryptKey encryptKey = AesAlgorithm::deriveEncryptKey(decryptKey.getKeyBits());

  Blob plainBlob(PLAINTEXT, sizeof(PLAINTEXT));

  // Encrypt/decrypt data in AES_CBC with auto-generated IV.
  EncryptParams encryptParams(ndn_EncryptAlgorithmType_AesCbc, 16);
  Blob cipherBlob = AesAlgorithm::encrypt
    (encryptKey.getKeyBits(), plainBlob, encryptParams);
  Blob receivedBlob = AesAlgorithm::decrypt
    (decryptKey.getKeyBits(), cipherBlob, encryptParams);
  ASSERT_TRUE(receivedBlob.equals(plainBlob));
}

int
main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

