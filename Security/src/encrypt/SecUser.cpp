/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2016-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/consumer https://github.com/named-data/ndn-group-encrypt
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

#include <stdexcept>
#include <ndn-cpp/util/logging.hpp>
#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>
#include <ndn-cpp/encrypt/consumer.hpp>
#include <ndn-cpp/encrypt/schedule.hpp>
#include "../encoding/base64.hpp"
#include <ndn-cpp/interest.hpp>
#include <ndn-cpp/security/key-chain.hpp>

#include <ndn-cpp/hmac-with-sha256-signature.hpp>
#include <ndn-cpp/security/identity/memory-identity-storage.hpp>
#include <ndn-cpp/security/identity/memory-private-key-storage.hpp>
#include <ndn-cpp/security/policy/no-verify-policy-manager.hpp>
#include <ndn-cpp/encrypt/sqlite3-consumer-db.hpp>

#include <ndn-cpp/encrypt/schedule.hpp>
#include <ndn-cpp/util/logging.hpp>

#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>

#include <ndn-cpp/encrypt/SecUser.hpp>

/*
#modify by Marty, May 16th ,2017
#consumerAdapter.cpp for the  data content security
#modify history: 
#combine consumerAdapter.cpp to consumer.cpp, Marty, 2017/06/29
#modify the file name from consumer.cpp to SecUser.cpp, Marty, 2017/07/03
*/

using namespace std;
using namespace pki::func_lib;

INIT_LOGGER("ndn.Consumer");

namespace pki {

static MillisecondsSince1970
fromIsoString(const string& dateString)
{
  return Schedule::fromIsoString(dateString);
}

void
onConsumeComplete
  (const ptr_lib::shared_ptr<Data>& contentData, const Blob& result,
   int* finalCount)
{
  (*finalCount) = 1;
  cout<< "consumeComplete"<<endl;
  //Blob plainContent = contentData->getContent();
    for (int i =0 ;i < result.size();i++)
    {
        if (0==i)
        {
        printf("plainContent\n");
        }
        printf("0x%x,",result.buf()[i]);	  
        if (i%8==7)
        printf("\n");
    }
  
}

void
onError(EncryptError::ErrorCode errorCode, const string& message)
{
    cout << "onError code " << errorCode << " " << message<<endl;
    cout<< "Data process error"<<endl;
    
}

void
SecUser::Init(const Name& groupName,
 const Name& consumerName)
{

    Name keyName("/Prefix/SAMPLE/Content/HMACwithSha256");
    
    // Set up the keyChain.
    ptr_lib::shared_ptr<MemoryIdentityStorage> identityStorage
    (new MemoryIdentityStorage());
    ptr_lib::shared_ptr<MemoryPrivateKeyStorage> privateKeyStorage
    (new MemoryPrivateKeyStorage());

    identityStorage->addKey
    (keyName, KEY_TYPE_RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER,
    sizeof(DEFAULT_RSA_PUBLIC_KEY_DER)));

    privateKeyStorage->setKeyPairForKeyName
    (keyName, KEY_TYPE_RSA, DEFAULT_RSA_PUBLIC_KEY_DER,
    sizeof(DEFAULT_RSA_PUBLIC_KEY_DER), DEFAULT_RSA_PRIVATE_KEY_DER,
    sizeof(DEFAULT_RSA_PRIVATE_KEY_DER));

    KeyChain *keyChain_=new KeyChain(ptr_lib::make_shared<IdentityManager>(identityStorage, privateKeyStorage),
    ptr_lib::make_shared<NoVerifyPolicyManager>());
    Face *face_= new Face();

    Name certificateName = keyName.getSubName(0, keyName.size() - 1).append
    ("KEY").append(keyName.get(-1)).append("ID-CERT").append("0");
   

    face_->setCommandSigningInfo(*keyChain_, certificateName);
    
    impl_ = new Impl (face_, keyChain_, groupName, consumerName,getNO_LINK(), getNO_LINK());

    registered_=false;
    beReadytoConsume_=false;
    
}
SecUser::SecUser()
{
}
SecUser::~SecUser()
{

}

/*
Consumer *
Consumer::getInstance()
{
    if (NULL==uniqueInstance_)
    {
        uniqueInstance_ = new Consumer();
    }
    
    return uniqueInstance_;
}
*/

void
SecUser::onRegistedData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
{
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    for (size_t i = 0; i < data->getContent().size(); ++i)
        cout << (*data->getContent())[i];
    
    cout << endl;

    setRegisted();
}

void 
SecUser::onRegistedTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
{
    cout << "Time out for interest " << interest->getName().toUri() << endl;     
    registerFace_.expressInterest(*interest, bind(&SecUser::onRegistedData, this,_1,_2 ), bind(&SecUser::onRegistedTimeout, this, _1));
}


void 
SecUser::registerConsumer(Interest & registerInterest )
{
    //sign the interest
    // keyChain.sign(freshInterest,certificateName);
    

    const uint8_t keyBytes[] = {
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    };
    
    Blob key(keyBytes, sizeof(keyBytes));
    
 registerInterest.setMustBeFresh(false);

    Name keyName("/Prefix/SAMPLE/Content/HMACwithSha256");

    KeyChain::signWithHmacWithSha256(registerInterest, key, keyName);

    cout << "Signing register interest " << registerInterest.getName().toUri() << endl;
    //Face registerFace;
    
    // Use bind to pass the counter object to the callbacks.

    registerFace_.expressInterest(registerInterest, bind(&SecUser::onRegistedData, this,_1,_2 ), bind(&SecUser::onRegistedTimeout, this, _1));

    while(!registered_)
    {
        registerFace_.processEvents();
        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        //usleep(1000);
    }

}

void
SecUser::onReadyData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
{
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    for (size_t i = 0; i < data->getContent().size(); ++i)
        cout << (*data->getContent())[i];
    
    cout << endl;
    
    beReadytoConsume_ = true;

    //setRegisted();
}

void 
SecUser::onReadyTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
{
    cout << "Time out for interest " << interest->getName().toUri() << endl;     
    registerFace_.expressInterest(*interest, bind(&SecUser::onReadyData, this,_1,_2 ), bind(&SecUser::onReadyTimeout, this, _1));
}

void 
SecUser::requestConsumeReady(Name &requestConsume)
{
    Interest requestConsumeInterest(requestConsume);
    requestConsumeInterest.setMustBeFresh(true);
    registerFace_.expressInterest(requestConsumeInterest, bind(&SecUser::onReadyData, this,_1,_2 ), bind(&SecUser::onReadyTimeout, this, _1));

    while(!beReadytoConsume_)
    {
        registerFace_.processEvents();
    }
}

void 
SecUser::addFixedContentKey(Name& cKeyName)
{

    MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");

// add the C-KEY.
    Blob contentKeyBits = Blob(AES_KEY, sizeof(AES_KEY));
    cKeyName.append("20150101T100000");

    //Blob CKeyBlob;
    this->addDecryptionKey(cKeyName, contentKeyBits);
}

void
SecUser::addDecryptionKeyofCkey(Name& dKeyName)
{
    MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");

    // add the D-KEY.
    //Blob decryptKeyBits = Blob(DEFAULT_RSA_PRIVATE_KEY_DER, sizeof(DEFAULT_RSA_PRIVATE_KEY_DER));
    //dKeyName.append("20150101T100000");
    // Use the internal fromBase64.
    ptr_lib::shared_ptr<vector<uint8_t> > privateKeyBuffer(new vector<uint8_t>());
    fromBase64(PRIVATE_KEY, *privateKeyBuffer);
    Blob privateKeyBlob(privateKeyBuffer, false);


    //Blob CKeyBlob;
    this->addDecryptionKeyofCkey(dKeyName, privateKeyBuffer);
}

void
SecUser::setRegisted()
{
    registered_ = true;
}

void 
SecUser::consumeSecureContent(Name& contentName)
{
    int finalCount = 0;

    this->consume
        (contentName,
        bind(&onConsumeComplete, _1, _2, &finalCount),
        bind(&onError, _1, _2));
    cout<< "consumeSecureContent face address:" << impl_->face_ << std::endl;

    while (1) {
    impl_->face_->processEvents();
        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        //usleep(1000);
    }

    cout<<"consumer.consume excuted!"<<contentName<<endl;

}


SecUser::Impl::Impl
  (Face* face, KeyChain* keyChain, const Name& groupName,
   const Name& consumerName, const ptr_lib::shared_ptr<ConsumerDb>& database,
   const Link& cKeyLink, const Link& dKeyLink)
: face_(face),
  keyChain_(keyChain),
  groupName_(groupName),
  consumerName_(consumerName),
  database_(database),
  cKeyLink_(new Link(cKeyLink)),
  dKeyLink_(new Link(dKeyLink))
{
}

SecUser::Impl::Impl
  (Face* face, KeyChain* keyChain, const Name& groupName,
   const Name& consumerName,const Link& cKeyLink, const Link& dKeyLink)
: face_(face),
  keyChain_(keyChain),
  groupName_(groupName),
  consumerName_(consumerName),
    cKeyLink_(new Link(cKeyLink)),
    dKeyLink_(new Link(dKeyLink))
{
}


void
SecUser::Impl::consume
  (const Name& contentName, const OnConsumeComplete& onConsumeComplete,
   const EncryptError::OnError& onError, const Link& link)
{
  ptr_lib::shared_ptr<const Interest> interest(new Interest(contentName));

  // Prepare the callbacks. We make a shared_ptr object since it needs to
  // exist after we call expressInterest and return.
  class Callbacks : public ptr_lib::enable_shared_from_this<Callbacks> {
  public:
    Callbacks
      (SecUser::Impl* parent, const OnConsumeComplete& onConsumeComplete,
       const EncryptError::OnError& onError)
    : parent_(parent), onConsumeComplete_(onConsumeComplete), onError_(onError)
    {}

    void
    onContentVerified(const ptr_lib::shared_ptr<Data>& validData)
    {
      // Save this for calling onConsumeComplete.
        contentData_ = validData;
      
        cout<<"Consumer::Impl::consume onContentVerified "<<contentData_->getName().toUri()<<endl;

      parent_->decryptContent
        (*validData,
         bind(&Callbacks::onContentPlainText, shared_from_this(), _1),
         onError_);

    }

    void
    onContentPlainText(const Blob& plainText)
    {
      try {
        onConsumeComplete_(contentData_, plainText);
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onConsumeComplete: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onConsumeComplete.");
      }
	  cout<<"Consumer::Impl::consume onContentPlainText"<<endl;
    }

    SecUser::Impl* parent_;
    OnConsumeComplete onConsumeComplete_;
    EncryptError::OnError onError_;
    ptr_lib::shared_ptr<Data> contentData_;
  };

  ptr_lib::shared_ptr<Callbacks> callbacks(new Callbacks
    (this, onConsumeComplete, onError));
  // Copy the Link object since the passed link may become invalid.
  sendInterest
    (interest, 0, ptr_lib::make_shared<Link>(link),
     bind(&Callbacks::onContentVerified, callbacks, _1), onError);
}

void
SecUser::Impl::addDecryptionKey(const Name& keyName, const Blob& keyBlob)
{
  if (!(consumerName_.match(keyName)))
    throw runtime_error
      ("addDecryptionKey: The consumer name must be a prefix of the key name");
    
    if (cKeyMap_.find(keyName) == cKeyMap_.end())
    {
        cKeyMap_[keyName] = keyBlob;
        cout<<"addDecryptionKey cKey has in the cKeyMap="<<keyName<<endl;
    }

    if (true == database_->hasKey(keyName))
    {
        cout<<"addDecryptionKey cKey has in the cKeyMap="<<keyName<<endl;
        return;
    }

    database_->addKey(keyName, keyBlob); 
    cout<<"Consumer::Impl::consume addDecryptionKey in database"<<endl;
    
}

void
SecUser::Impl::addContentKey(const Name& keyName, const Blob& keyBlob)
{
  if (!(consumerName_.match(keyName)))
    throw runtime_error
      ("addDecryptionKey: The consumer name must be a prefix of the key name");
    
    if (cKeyMap_.find(keyName) == cKeyMap_.end())
    {
        cKeyMap_[keyName] = keyBlob;
        cout<<"addDecryptionKey cKey has in the cKeyMap="<<keyName<<endl;
    }
    
    /*
    if (true == database_->hasKey(keyName))
    {
        cout<<"addDecryptionKey cKey has in the cKeyMap="<<keyName<<endl;
        return;
    }

    database_->addKey(keyName, keyBlob); 
    cout<<"Consumer::Impl::consume addDecryptionKey in database"<<endl;
    */
}


void
SecUser::Impl::addDecryptionKeyofCkey(const Name& keyName, const Blob& keyBlob)
{
  if (!(consumerName_.match(keyName)))
    throw runtime_error
      ("addDecryptionKey: The consumer name must be a prefix of the key name");
    
    if (dKeyMap_.find(keyName) == dKeyMap_.end())
    {
        dKeyMap_[keyName] = keyBlob;
        cout<<"addDecryptionKeyofCkey  has in the dKeyMap="<<keyName<<endl;
    }
/*
    if (true == database_->hasKey(keyName))
    {
        cout<<"addDecryptionKey cKey has in the cKeyMap="<<keyName<<endl;
        return;
    }

    database_->addKey(keyName, keyBlob); 
    cout<<"Consumer::Impl::consume addDecryptionKey in database"<<endl;
   */ 
}


void
SecUser::Impl::decrypt
  (const Blob& encryptedBlob, const Blob& keyBits,
   const OnPlainText& onPlainText, const EncryptError::OnError& onError)
{
  EncryptedContent encryptedContent;
  try {
    encryptedContent.wireDecode(encryptedBlob);
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
	cout<<"Consumer::Impl::consume decrypt"<<endl;
  }

  decryptEncryptedContent(encryptedContent, keyBits, onPlainText, onError);
}

void
SecUser::Impl::decryptEncryptedContent
  (const EncryptedContent& encryptedContent, const Blob& keyBits,
   const OnPlainText& onPlainText, const EncryptError::OnError& onError)
{
  Blob payload = encryptedContent.getPayload();
  
    for(int i =0;i<keyBits.size();i++)
  {
      if (0==i)
    {
        printf("Consumer::Impl:: decryptEncryptedContent Decryption key\n");
    }
      printf("0x%x,",keyBits.buf()[i]);  
      if (i%8==7)
        printf("\n");
  }
  
  printf("Decryption key.size()=%d\n",keyBits.size());  
  

	  for(int i =0;i<payload.size();i++)
	{
		if (0==i)
	  {
		  printf("Consumer::Impl:: decryptEncryptedContent ciphered payload\n");
	  }
		printf("0x%x,",payload.buf()[i]); 	
		if (i%8==7)
		  printf("\n");
	}
	
	printf("encryptedPayload.size()=%d\n",payload.size());  

  if (encryptedContent.getAlgorithmType() == ndn_EncryptAlgorithmType_AesCbc) {
    // Prepare the parameters.
    EncryptParams decryptParams(ndn_EncryptAlgorithmType_AesCbc);
    decryptParams.setInitialVector(encryptedContent.getInitialVector());

    // Decrypt the content.
    Blob content;
    try {
      content = AesAlgorithm::decrypt(keyBits, payload, decryptParams);
    } catch (const std::exception& ex) {
      try {
        onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onError: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onError.");
      }
      return;
    }

	  for(int i =0;i<content.size();i++)
	{
		if (0==i)
	  {
		  printf("Consumer::Impl:: AesAlgorithm::decrypt\n");
	  }
		printf("0x%x,",content.buf()[i]); 	
		if (i%8==7)
		  printf("\n");
	}
	
	printf("plaintextcontent.size()=%d\n",content.size());  


    try {
      onPlainText(content);
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onPlainText: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onPlainText.");
    }
	
  }
  else if (encryptedContent.getAlgorithmType() == ndn_EncryptAlgorithmType_RsaOaep) {
    // Prepare the parameters.
    EncryptParams decryptParams(ndn_EncryptAlgorithmType_RsaOaep);

    // Decrypt the content.
    Blob content;
    try {
      content = RsaAlgorithm::decrypt(keyBits, payload, decryptParams);

      	  for(int i =0;i<content.size();i++)
	{
		if (0==i)
	  {
		  printf("Consumer::Impl:: AesAlgorithm::decrypt\n");
	  }
		printf("0x%x,",content.buf()[i]); 	
		if (i%8==7)
		  printf("\n");
	}
	
	printf("plaintextcontent.size()=%d\n",content.size());  
    } catch (const std::exception& ex) {
      try {
        onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onError: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onError.");
      }
      return;
    }

    
    try {
      onPlainText(content);
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onPlainText: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onPlainText.");
    }
  }
  else {
    try {
      onError
        (EncryptError::ErrorCode::UnsupportedEncryptionScheme,
         "UnsupportedEncryptionScheme");
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
  }
}

void
SecUser::Impl::decryptContent
  (const Data& data, const OnPlainText& onPlainText,
   const EncryptError::OnError& onError)
{
  // Get the encrypted content.
  // Make this a shared_ptr so we can pass it in callbacks.
  ptr_lib::shared_ptr<EncryptedContent> dataEncryptedContent
    (new EncryptedContent());
  try {
    dataEncryptedContent->wireDecode(data.getContent());
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }
  const Name& cKeyName = dataEncryptedContent->getKeyLocator().getKeyName();

  cout<<"Consumer::Impl::consume decryptContent getKeyLocator"<<cKeyName<<endl;

  // Check if the content key is already in the store.
  if (cKeyMap_.find(cKeyName) != cKeyMap_.end())
  {	
    decryptEncryptedContent
      (*dataEncryptedContent, cKeyMap_[cKeyName], onPlainText, onError);
	cout<<"find the decrypt content key!"<<endl;
  }
  else {
    // Retrieve the C-KEY Data from the network.
    Name interestName(cKeyName);
    interestName.append(Encryptor::getNAME_COMPONENT_FOR()).append(groupName_);
    ptr_lib::shared_ptr<const Interest> interest(new Interest(interestName));


    // Prepare the callbacks. We make a shared_ptr object since it needs to
    // exist after we call expressInterest and return.
    class Callbacks : public ptr_lib::enable_shared_from_this<Callbacks> {
    public:
      Callbacks
        (SecUser::Impl* parent,
         const ptr_lib::shared_ptr<EncryptedContent>& dataEncryptedContent,
         const Name& cKeyName, const OnPlainText& onPlainText,
         const EncryptError::OnError& onError)
      : parent_(parent), dataEncryptedContent_(dataEncryptedContent),
        cKeyName_(cKeyName), onPlainText_(onPlainText), onError_(onError)
      {}

      void
      onCKeyVerified(const ptr_lib::shared_ptr<Data>& validCKeyData)
      {
        cout<<"decryptContent ->onCKeyVerified"<<endl;
        parent_->decryptCKey
          (*validCKeyData,
           bind(&Callbacks::onCKeyPlainText, shared_from_this(), _1),
           onError_);
      }

      void
      onCKeyPlainText(const Blob& cKeyBits)
      {
        cout <<"cKeyBits" <<endl;
        	  for(int i =0;i<cKeyBits.size();i++)
	{
		if (0==i)
	  {
		  printf("onCKeyPlainText\n");
	  }
		printf("0x%x,",cKeyBits.buf()[i]); 	
		if (i%8==7)
		  printf("\n");
	}
	
	printf("onCKeyPlainText.size()=%d\n",cKeyBits.size());  
        
        parent_->cKeyMap_[cKeyName_] = cKeyBits;
        parent_->decryptEncryptedContent
          (*dataEncryptedContent_, cKeyBits, onPlainText_, onError_);
      }

      SecUser::Impl* parent_;
      ptr_lib::shared_ptr<EncryptedContent> dataEncryptedContent_;
      Name cKeyName_;
      OnPlainText onPlainText_;
      EncryptError::OnError onError_;
    };

    ptr_lib::shared_ptr<Callbacks> callbacks(new Callbacks
      (this, dataEncryptedContent, cKeyName, onPlainText, onError));
    sendInterest
      (interest, 0, cKeyLink_, bind(&Callbacks::onCKeyVerified, callbacks, _1),
       onError);
    
  }
}

void
SecUser::Impl::decryptCKey
  (const Data& cKeyData, const OnPlainText& onPlainText, 
   const EncryptError::OnError& onError)
{
  // Get the encrypted content.
  Blob cKeyContent = cKeyData.getContent();

  cout<<"Consumer::Impl::consume decryptCKey"<<endl;
  // Make this a shared_ptr so we can pass it in callbacks.
  ptr_lib::shared_ptr<EncryptedContent> cKeyEncryptedContent
    (new EncryptedContent());
  try {
    cKeyEncryptedContent->wireDecode(cKeyContent);
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }
  const Name& eKeyName = cKeyEncryptedContent->getKeyLocator().getKeyName();
  Name dKeyName = eKeyName.getPrefix(-3);
  dKeyName.append(Encryptor::getNAME_COMPONENT_D_KEY())
    .append(eKeyName.getSubName(-2));

  cout << "Consumer::Impl::decryptCKey dKeyName:" <<dKeyName<<endl;
  // Check if the decryption key is already in the store.
  if (dKeyMap_.find(dKeyName) != dKeyMap_.end())
    decryptEncryptedContent
      (*cKeyEncryptedContent, dKeyMap_[dKeyName], onPlainText, onError);
  else {
      //no need to get DKey
    #if 0  
    // Get the D-Key Data. not need to get D-key
    Name interestName(dKeyName);
    interestName.append(Encryptor::getNAME_COMPONENT_FOR()).append(consumerName_);
    ptr_lib::shared_ptr<const Interest> interest(new Interest(interestName));

    // Prepare the callbacks. We make a shared_ptr object since it needs to
    // exist after we call expressInterest and return.
    class Callbacks : public ptr_lib::enable_shared_from_this<Callbacks> {
    public:
      Callbacks
        (Consumer::Impl* parent, 
         const ptr_lib::shared_ptr<EncryptedContent>& cKeyEncryptedContent,
         const Name& dKeyName, const OnPlainText& onPlainText,
         const EncryptError::OnError& onError)
      : parent_(parent), cKeyEncryptedContent_(cKeyEncryptedContent),
        dKeyName_(dKeyName), onPlainText_(onPlainText), onError_(onError)
      {}

      void
      onDKeyVerified(const ptr_lib::shared_ptr<Data>& validDKeyData)
      {
        parent_->decryptDKey
          (*validDKeyData,
           bind(&Callbacks::onDKeyPlainText, shared_from_this(), _1),
           onError_);
      }

      void
      onDKeyPlainText(const Blob& dKeyBits)
      {
        parent_->dKeyMap_[dKeyName_] = dKeyBits;
        parent_->decryptEncryptedContent
          (*cKeyEncryptedContent_, dKeyBits, onPlainText_, onError_);
      }

      Consumer::Impl* parent_;
      ptr_lib::shared_ptr<EncryptedContent> cKeyEncryptedContent_;
      Name dKeyName_;
      OnPlainText onPlainText_;
      EncryptError::OnError onError_;
    };

    ptr_lib::shared_ptr<Callbacks> callbacks(new Callbacks
      (this, cKeyEncryptedContent, dKeyName, onPlainText, onError));

    sendInterest
      (interest, 1, dKeyLink_, bind(&Callbacks::onDKeyVerified, callbacks, _1),
       onError);
    #endif 
     
  }
}

void
SecUser::Impl::decryptDKey
  (const Data& dKeyData, const OnPlainText& onPlainText,
   const EncryptError::OnError& onError)
{
  // Get the encrypted content.
  Blob dataContent = dKeyData.getContent();

  cout<<"Consumer::Impl::consume decryptDKey"<<endl;

  // Process the nonce.
  // dataContent is a sequence of the two EncryptedContent.
  EncryptedContent encryptedNonce;
  try {
    encryptedNonce.wireDecode(dataContent);
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::InvalidEncryptedFormat, ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }
  Name consumerKeyName = encryptedNonce.getKeyLocator().getKeyName();

  // Get consumer decryption key.
  Blob consumerKeyBlob;
  try {
    consumerKeyBlob = getDecryptionKey(consumerKeyName);
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::NoDecryptKey, ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }
  if (consumerKeyBlob.size() == 0) {
    try {
      onError(EncryptError::ErrorCode::NoDecryptKey,
        "The desired consumer decryption key in not in the database");
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }

  // Process the D-KEY.
  // Use the size of encryptedNonce to find the start of encryptedPayload.
  size_t encryptedNonceSize = encryptedNonce.wireEncode().size();
  EncryptedContent encryptedPayload;
  Blob encryptedPayloadBlob
    (dataContent.buf() + encryptedNonceSize,
     dataContent.size() - encryptedNonceSize);
  if (encryptedPayloadBlob.size() == 0) {
    try {
      onError(EncryptError::ErrorCode::InvalidEncryptedFormat,
        "The data packet does not satisfy the D-KEY packet format");
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }

  // Decrypt the Encrypted Content.
  decryptEncryptedContent
    (encryptedNonce, consumerKeyBlob,
     bind(&SecUser::Impl::decrypt, encryptedPayloadBlob, _1, onPlainText, onError),
     onError);
}

void
SecUser::Impl::sendInterest
  (const ptr_lib::shared_ptr<const Interest>& interest, int nRetrials,
   const ptr_lib::shared_ptr<Link>& link, const OnVerified& onVerified,
   const EncryptError::OnError& onError)
{
  // Prepare the callbacks. We make a shared_ptr object since it needs to
  // exist after we call expressInterest and return.

  cout<<"Consumer::Impl::consume sendInterest -->"<<interest->getName().toUri()<<endl;
  
  class Callbacks : public ptr_lib::enable_shared_from_this<Callbacks> {
  public:
    Callbacks
      (SecUser::Impl* parent, int nRetrials,
       const ptr_lib::shared_ptr<Link>& link, const OnVerified& onVerified,
       const EncryptError::OnError& onError)
    : parent_(parent), nRetrials_(nRetrials), link_(link),
      onVerified_(onVerified), onError_(onError)
    {}

    void
    onData
      (const ptr_lib::shared_ptr<const Interest>& contentInterest,
       const ptr_lib::shared_ptr<Data>& contentData)
    {
      // The Interest has no selectors, so assume the library correctly
      // matched with the Data name before calling onData.
	  cout<<"Consumer::Impl::consume sendInterest-> onData->"<<contentInterest->getName()<<endl;

      try {
        parent_->keyChain_->verifyData
          (contentData, onVerified_,
           // Cast to disambiguate from the deprecated OnVerifyFailed.
           (const OnDataValidationFailed)bind
             (&Impl::onValidationFailed, _1, _2, onError_));
      } catch (const std::exception& ex) {
        try {
          onError_(EncryptError::ErrorCode::General,
                  string("verifyData error: ") + ex.what());
        } catch (const std::exception& ex) {
          _LOG_ERROR("Error in onError: " << ex.what());
        } catch (...) {
          _LOG_ERROR("Error in onError.");
        }
      }
    }

    void
    onNetworkNack
      (const ptr_lib::shared_ptr<const Interest>& interest,
       const ptr_lib::shared_ptr<NetworkNack>& networkNack)
    {
      // We have run out of options. Report a retrieval failure.
      try {
        onError_(EncryptError::ErrorCode::DataRetrievalFailure,
                 interest->getName().toUri());
      } catch (const std::exception& ex) {
        _LOG_ERROR("Error in onError: " << ex.what());
      } catch (...) {
        _LOG_ERROR("Error in onError.");
      }
         cout<<"Consumer::Impl::consume sendInterest onNetworkNack:"<< interest->getName() << endl;
    }

    void
    onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
      if (nRetrials_ > 0)
        parent_->sendInterest
          (interest, nRetrials_ - 1, link_, onVerified_, onError_);
      else
        onNetworkNack(interest, ptr_lib::make_shared<NetworkNack>());

	  cout<<"Consumer::Impl::consume sendInterest onTimeout:"<< interest->getName()<<endl;
    }

    SecUser::Impl* parent_;
    int nRetrials_;
    const ptr_lib::shared_ptr<Link> link_;
    const OnVerified onVerified_;
    EncryptError::OnError onError_;
  };

  ptr_lib::shared_ptr<Interest> interestWithLink;
  const Interest* request;
  if (link->getDelegations().size() == 0)
    // We can use the supplied interest without copying.
    request = interest.get();
  else {
    // Copy the supplied interest and add the Link.
    interestWithLink.reset(new Interest(*interest));
    // This will use a cached encoding if available.
    interestWithLink->setLinkWireEncoding(link->wireEncode());

    request = interestWithLink.get();
  }

  ptr_lib::shared_ptr<Callbacks> callbacks(new Callbacks
    (this, nRetrials, link, onVerified, onError));
  try {

    face_->expressInterest
      (*request, bind(&Callbacks::onData, callbacks, _1, _2),
       bind(&Callbacks::onTimeout, callbacks, _1),
       bind(&Callbacks::onNetworkNack, callbacks, _1, _2));
  } catch (const std::exception& ex) {
    try {
      onError(EncryptError::ErrorCode::General,
              string("expressInterest error: ") + ex.what());
    } catch (const std::exception& ex) {
      _LOG_ERROR("Error in onError: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Error in onError.");
    }
    return;
  }
}

void
SecUser::Impl::onValidationFailed
  (const ptr_lib::shared_ptr<Data>& data, const string& reason,
   const EncryptError::OnError& onError)
{
  try {
    onError
      (EncryptError::ErrorCode::Validation,
       "verifyData failed. Reason: " + reason);
  } catch (const std::exception& ex) {
    _LOG_ERROR("Error in onError: " << ex.what());
  } catch (...) {
    _LOG_ERROR("Error in onError.");
  }
  cout<<"Consumer::Impl::consume onValidationFailed"<<endl;
}

Link* SecUser::noLink_ = 0;

}
