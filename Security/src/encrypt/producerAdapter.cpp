/**
 * Copyright (C) 2013-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

/*
#created by Marty, May 16th ,2017
#producerAdapter.cpp for the  data content security
#modify history: 
*/


#include <cstdlib>
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/util/logging.hpp>

#include "stdio.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <ndn-cpp/security/identity/memory-identity-storage.hpp>
#include <ndn-cpp/security/identity/memory-private-key-storage.hpp>
#include <ndn-cpp/security/policy/no-verify-policy-manager.hpp>

#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>
#include <ndn-cpp/encrypt/encrypted-content.hpp>
#include <ndn-cpp/encrypt/schedule.hpp>
#include <ndn-cpp/encrypt/sqlite3-producer-db.hpp>
#include <ndn-cpp/encrypt/producer.hpp>
#include <ndn-cpp/encrypt/producerAdapter.hpp>

#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/hmac-with-sha256-signature.hpp>

// Use the internal fromBase64.
#include "../encoding/base64.hpp"

INIT_LOGGER("ndn.ProducerAdapter");


using namespace std;
using namespace pki::func_lib;

void hexdump(
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


namespace pki {


void
checkEncryptionKeys
(const vector<ptr_lib::shared_ptr<Data> >& result, 
MillisecondsSince1970 testTime, const Name::Component roundedTime,
int expectedExpressInterestCallCount, const int* expressInterestCallCount,
Blob* contentKey, Name cKeyName, ptr_lib::shared_ptr<ProducerDb> testDb)
{
     cout<<"checkEncryptionKeys"<<endl;
}

static MillisecondsSince1970
fromIsoString(const string& dateString)
{
    return Schedule::fromIsoString(dateString);
}

void
onCkeyError(EncryptError::ErrorCode errorCode, const string& message)
{
    cout << "onError code " << errorCode << " " << message<<endl;
    cout<< "Content Key Data process error"<<endl;
}

/*
void
createEncryptionKey(Name eKeyName, const Name& timeMarker)
{
  RsaKeyParams params;
  eKeyName = Name(eKeyName);
  eKeyName.append(timeMarker);

  //Blob dKeyBlob = RsaAlgorithm::generateKey(params).getKeyBits();
  //Blob eKeyBlob = RsaAlgorithm::deriveEncryptKey(dKeyBlob).getKeyBits();


  decryptionKeys[eKeyName] = dKeyBlob;

  ptr_lib::shared_ptr<Data> keyData(new Data(eKeyName));
  keyData->setContent(eKeyBlob);
  keyChain->sign(*keyData, certificateName);
  encryptionKeys[eKeyName] = keyData;
}
*/


    ProducerAdapter::ProducerAdapter(const Name& prefix, const Name& suffix,ptr_lib::shared_ptr<ProducerDb> database,string databaseFilePath)
        :prefix_(prefix),suffix_(suffix),database_(database),databaseFilePath_(databaseFilePath)
    {
        cout<< "ProducerAdapter initial!" << std::endl;
    
        // Use the system default key chain and certificate name to sign commands.
        keyChain_ = new KeyChain();   
        
        // The default Face will connect using a Unix socket, or to "localhost".
        mainFace_ = new Face();
        cout<< "ProducerAdapter face address:" << mainFace_ << endl;

        mainFace_->setCommandSigningInfo(*keyChain_, keyChain_->getDefaultCertificateName());
        getEkeyFace_.setCommandSigningInfo(*keyChain_, keyChain_->getDefaultCertificateName());
        //ptr_lib::shared_ptr<ProducerDb> testDb(new Sqlite3ProducerDb(databaseFilePath_)); 

        //int repeatAttempts = 3;
        registerCount_=0;
        contentCount_=0;
        eKeyGeted_=false;
        producer_ = new Producer(prefix, suffix, mainFace_,keyChain_, database_);
        cout<< "ProducerAdapter producer_ address:" << producer_ << endl;
    }

    ProducerAdapter::~ProducerAdapter()
    {
        delete producer_;
        delete mainFace_;
        delete keyChain_;
    }

    Name 
    ProducerAdapter::addFixedContentKey(Name &contentKeyName)
    {
        MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");
        contentKeyName.append("20150101T100000");
	// Load the fixed C-KEY.
        Blob contentKeyBits = Blob(AES_KEY, sizeof(AES_KEY));
        // Check if we have created the content key before.
        if (database_->hasContentKey(timeSlot))
        // We have created the content key. Return its name directly.
        {
            cout<<"addFixedContentKey already has the content key!!"<<endl;
            return contentKeyName;
        }
        
        database_->addContentKey(timeSlot, contentKeyBits);
        cout<<"ProducerAdapter addFixedContentKey "<<contentKeyName<<endl;
        
        return contentKeyName;
    }



/*
    void 
    ProducerAdapter:: onRegitsterInterest(const ptr_lib::shared_ptr<const Name>& prefix,
                const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
                uint64_t interestFilterId,
                const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
            const uint8_t keyBytes[] = {
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
            };

            Blob key(keyBytes, sizeof(keyBytes));

            Interest newInterest(interest->getName());

            if (echoKeyChain_->verifyInterestWithHmacWithSha256(newInterest, key))
            //if (keyChain_.verifyInterest(newInterest, NULL,NULL,0))
            cout << "Freshly-signed interest signature verification: VERIFIED" << endl;
            else
            cout << "Freshly-signed interest signature verification: FAILED" << endl;

            // Make and sign a Data packet.
            Data data(newInterest.getName());
            string content(data.getName().toUri());

            data.setContent((const uint8_t *)&content[0], content.size());
            echoKeyChain_->sign(data, certificateName_);

            cout << "Sent content " << content << endl;
            echoFace_->putData(data);       
    }
   */ 

    // on register Interest.
    void 
    ProducerAdapter::onRegisterInterest(const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
       registerCount_++;
       const uint8_t keyBytes[] = {
       0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
       };

       Blob key(keyBytes, sizeof(keyBytes));

       Interest newInterest(interest->getName());

       if (keyChain_->verifyInterestWithHmacWithSha256(newInterest, key))
       //if (keyChain_.verifyInterest(newInterest, NULL,NULL,0))
       cout << "Freshly-signed interest signature verification: VERIFIED" << endl;
       else
       cout << "Freshly-signed interest signature verification: FAILED" << endl;

       // Make and sign a Data packet.
       Data data(newInterest.getName());
       string content(data.getName().toUri());

       data.setContent((const uint8_t *)&content[0], content.size());
       keyChain_->sign(data, keyChain_->getDefaultCertificateName());

       cout << "Sent content " << content << endl;
       face.putData(data);
    }

    // onRegisterFailed.
    void 
    ProducerAdapter::onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       ++registerCount_;
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }

    // on content Interest.
    void 
    ProducerAdapter::onContentInterest
    (const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
        contentCount_++;

        // Make and sign a Data packet.
        Data testData;
        MillisecondsSince1970 testTime= fromIsoString("20150101T100000");
        cout<<" ProducerAdapter::onContentInterest->produce"<<endl;
        producer_->produce(testData, testTime, Blob(DATA_CONTENT, sizeof(DATA_CONTENT)));
        string content(testData.getName().toUri());

        cout << "Sent content " << content << endl;

        face.putData(testData);

    }
    // onContentFailed.
    void 
    ProducerAdapter::onContentFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       ++contentCount_;
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }
    

    void
    ProducerAdapter::onCkeyRequestInterest(const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face, 
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
      //cout << "<< I: " << interest << std::endl;
      
      MillisecondsSince1970 beginTimeSlot;
      MillisecondsSince1970 endTimeSlot;
     cout<<"onCkeyRequestInterest"<<endl;
      // Create new name, based on Interest's name
      Name dataName(interest->getName());
      dataName
        .append("20150101T100000/20150101T120000"); // add "testApp" component to Interest name
        //.appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)
    
      //static const std::string content = "HELLO KITTY";
    
        //cout<<"dataName"<<dataName<<endl;
        
    MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");
      // Create Data packet
      Data testData;
      //data->setName(dataName);
      //data->setFreshnessPeriod(time::seconds(10));
      //data->setContent(reinterpret_cast<const uint8_t*>(DEFAULT_RSA_PUBLIC_KEY_DER), sizeof(DEFAULT_RSA_PUBLIC_KEY_DER));
    Name eKeyName("/Prefix/SAMPLE/Content/E-KEY/20150101T100000/20150101T120000");
//      Blob encryptionKey(reinterpret_cast<const uint8_t*>(DEFAULT_RSA_PUBLIC_KEY_DER), sizeof(DEFAULT_RSA_PUBLIC_KEY_DER));
      
      ptr_lib::shared_ptr<vector<uint8_t> > publicKeyBuffer(new vector<uint8_t>());
      fromBase64(PUBLIC_KEY, *publicKeyBuffer);
      Blob publicKeyBlob(publicKeyBuffer, false);

      
      encryptContentKey
        (testData,publicKeyBlob, eKeyName,
        timeSlot, bind(&onCkeyError,_1,_2)) ;  
      // Sign Data packet with default identity
      keyChain_->sign(testData);

      string content(testData.getName().toUri());

        cout << "Sent contentkey " << content << endl;
      mainFace_->putData(testData);
    }

    // onCkeyRequestFailed.
    void 
    ProducerAdapter::onCkeyRequestFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       ++contentCount_;
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }
    
    bool
    ProducerAdapter::encryptContentKey
      (Data& data,const Blob& encryptionKey, const Name& eKeyName,
       MillisecondsSince1970 timeSlot, 
       const EncryptError::OnError& onError)
    {
      MillisecondsSince1970 timeCount = ::round(timeSlot);
      //ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];
    
      //Name keyName(namespace_);
     // keyName.append(Encryptor::getNAME_COMPONENT_C_KEY());
      //keyName.append(Schedule::toIsoString(getRoundedTimeSlot(timeSlot)));
    Name keyName("/Prefix/SAMPLE/Content/C-KEY/20150101T100000/FOR/Prefix/READ");
      //keyName .append("20150101T100000");
    
      Blob contentKey = database_->getContentKey(timeSlot);
      
      cout<<"ProducerAdapter::encryptContentKey"<<endl;
    
      //ptr_lib::shared_ptr<Data> cKeyData(new Data());
      
      data.setName(keyName);
      
      cout<<"encryptContentKey ckeyname"<<keyName<<endl;
      cout<<"encryptContentKey eKeyName"<<eKeyName<<endl;
      
      EncryptParams params(ndn_EncryptAlgorithmType_RsaOaep);
      try {
        Encryptor::encryptData
          (data, contentKey, eKeyName, encryptionKey, params);
      } catch (const std::exception& ex) {
        try {
          onError(EncryptError::ErrorCode::EncryptionFailure, ex.what());
        } catch (const std::exception& ex) {
          _LOG_ERROR("Error in onError: " << ex.what());
        } catch (...) {
          _LOG_ERROR("Error in onError.");
        }
        return false;
      }
    
      //keyChain_->sign(*cKeyData);
      //keyRequest->encryptedKeys.push_back(cKeyData);
      //updateKeyRequest(keyRequest, timeCount, onEncryptedKeys);
      return true;
    }


    void 
    ProducerAdapter::onEkeyData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
    {
       
        cout << "Got ekey data packet with name " << data->getName().toUri() << endl;
        /*
        for (size_t i = 0; i < data->getContent().size(); ++i)
            cout << (*data->getContent())[i];
            */
            hexdump(stdout, "== public key ==",
                            data->getContent().buf(),
                            data->getContent().size());
                            
            printf("\n");
        
       // cout <<endl<< "onData"<<endl;
    
        eKeyGeted_=true;
    }
    
    void 
    ProducerAdapter::onEkeyTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
        //++callbackCount_;
        // Use bind to pass the counter object to the callbacks.
        getEkeyFace_.expressInterest(*interest, bind(&ProducerAdapter::onEkeyData, this,_1, _2), bind(&ProducerAdapter::onEkeyTimeout, this, _1));

        cout << "Time out for interest " << interest->getName().toUri() << endl;
    }

    void 
    ProducerAdapter::getEkey(Name keyName)
    {

        Interest keyRequestInterest(keyName);

        keyRequestInterest.setMustBeFresh(true);
        keyRequestInterest.setInterestLifetimeMilliseconds(10000);

        // Use bind to pass the counter object to the callbacks.
        getEkeyFace_.expressInterest(keyRequestInterest, bind(&ProducerAdapter::onEkeyData, this, _1, _2), bind(&ProducerAdapter::onEkeyTimeout,this,  _1));
        cout <<"face.expressInterest keyRequestInterest"<<endl;
        
        while(!eKeyGeted_)
        {
            getEkeyFace_.processEvents();
            //usleep(1000);
        }
        //getEkeyFace_.shutdown();

    }

    void
    ProducerAdapter::registerConsumer(Name  prefix)
    {
     	
        Name groupName = Name("/Prefix/READ");
        Name contentName = Name("/Prefix/SAMPLE/Content");

        Face registerFace;
        KeyChain registerKeyChain;
        registerFace.setCommandSigningInfo(registerKeyChain, registerKeyChain.getDefaultCertificateName());

        // Also use the default certificate name to sign data packets.
        //Echo echo(keyChain_, face_,keyChain_->getDefaultCertificateName());
        cout << "Register prefix  " << prefix.toUri() << endl;
        // TODO: After we remove the registerPrefix with the deprecated OnInterest,
        // we can remove the explicit cast to OnInterestCallback (needed for boost).
        registerFace.registerPrefix(prefix, bind(&ProducerAdapter::onRegisterInterest,this,_1,_2,_3,_4,_5), bind(&ProducerAdapter::onRegisterFailed,this,_1));    

        while ( registerCount_< 10) {
            registerFace.processEvents();
            // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            usleep(1000);
        }
        
    }

    // on content Interest.
    void 
    ProducerAdapter::onReadyInterest
    (const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
        contentCount_++;

        // Make and sign a Data packet.

        Data data(interest->getName());
        string content(data.getName().toUri());
        
        data.setContent((const uint8_t *)&content[0], content.size());
        keyChain_->sign(data, keyChain_->getDefaultCertificateName());

        cout << "Sent content " << content << endl;

        face.putData(data);

    }
    // onContentFailed.
    void 
    ProducerAdapter::onReadyFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       ++contentCount_;
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }

    void
    ProducerAdapter::readyForConsume(Name  prefix)
    {
     	
        Name groupName = Name("/Prefix/READ");
        Name contentName = Name("/Prefix/SAMPLE/Content");

        Face registerFace;
        KeyChain registerKeyChain;
        registerFace.setCommandSigningInfo(registerKeyChain, registerKeyChain.getDefaultCertificateName());

        // Also use the default certificate name to sign data packets.
        //Echo echo(keyChain_, face_,keyChain_->getDefaultCertificateName());
        cout << "Register prefix  " << prefix.toUri() << endl;
        // TODO: After we remove the registerPrefix with the deprecated OnInterest,
        // we can remove the explicit cast to OnInterestCallback (needed for boost).
        registerFace.registerPrefix(prefix, bind(&ProducerAdapter::onReadyInterest,this,_1,_2,_3,_4,_5), bind(&ProducerAdapter::onReadyFailed,this,_1));    

        while ( registerCount_< 10) {
            registerFace.processEvents();
            // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            //usleep(1000);
        }
    }

    void 
    ProducerAdapter::produceSecureContent(Name &contentPrefix)
    {
        Blob contentKey;
        Name cKeyName;
        MillisecondsSince1970 testTime= fromIsoString("20150101T100000");
        Name timeMarker("20150101T100000/20150101T120000");

        Name::Component testTimeRounded1("20150101T100000");
        int expressInterestCallCount = 0;    
        
        cout << "produceSecureContent Register contentPrefix  " << contentPrefix.toUri() << endl;
        
        // TODO: After we remove the registerPrefix with the deprecated OnInterest,
        // we can remove the explicit cast to OnInterestCallback (needed for boost).
        cout<< "produceSecureContent mainFace_ address:" << mainFace_ << std::endl;

        mainFace_->registerPrefix(contentPrefix, bind(&ProducerAdapter::onContentInterest,this,_1,_2,_3,_4,_5),bind(&ProducerAdapter::onContentFailed,this,_1));

        Name ckeyName("/Prefix/SAMPLE/Content/C-KEY/20150101T100000/FOR/Prefix/READ");
     
        mainFace_->setInterestFilter(
            ckeyName,
            bind(&ProducerAdapter::onCkeyRequestInterest,this,  _1, _2,_3,_4,_5)
            );

        // The main event loop.
        // Wait forever to receive one interest for the prefix.
        while (contentCount_< 10) {
          mainFace_->processEvents();
          // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
          usleep(1000);
        }
    }
    

}
