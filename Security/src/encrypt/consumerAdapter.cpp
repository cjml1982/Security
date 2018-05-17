/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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
#consumerAdapter.cpp for the  data content security
#modify history: 
*/

#include <time.h>
#include <ndn-cpp/interest.hpp>
#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/hmac-with-sha256-signature.hpp>
#include <ndn-cpp/security/identity/memory-identity-storage.hpp>
#include <ndn-cpp/security/identity/memory-private-key-storage.hpp>
#include <ndn-cpp/security/policy/no-verify-policy-manager.hpp>
#include <ndn-cpp/encrypt/sqlite3-consumer-db.hpp>
#include <ndn-cpp/encrypt/consumer.hpp>
#include <ndn-cpp/encrypt/schedule.hpp>
#include <ndn-cpp/util/logging.hpp>

#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>

#include <ndn-cpp/encrypt/consumerAdapter.hpp>

#include "../encoding/base64.hpp"

using namespace std;
using namespace pki::func_lib;

INIT_LOGGER("ndn.ConsumerAdapter");
/*
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
*/

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


    ConsumerAdapter::ConsumerAdapter(const Name& groupName,
     const Name& consumerName, const ptr_lib::shared_ptr<ConsumerDb>& database)
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

        keyChain_=new KeyChain(ptr_lib::make_shared<IdentityManager>(identityStorage, privateKeyStorage),
        ptr_lib::make_shared<NoVerifyPolicyManager>());
        face_= new Face();

        Name certificateName = keyName.getSubName(0, keyName.size() - 1).append
        ("KEY").append(keyName.get(-1)).append("ID-CERT").append("0");
        

        face_->setCommandSigningInfo(*keyChain_, certificateName);

        // Create the consumer.
        consumer_  =  new Consumer(face_, keyChain_, groupName, consumerName,
            database);

        registered_=false;
        beReadytoConsume_=false;
        
    }

    ConsumerAdapter::~ConsumerAdapter()
    {
        delete consumer_;
        delete keyChain_;
        delete face_;
    }

    void
    ConsumerAdapter::onRegistedData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
    {
        cout << "Got data packet with name " << data->getName().toUri() << endl;
        for (size_t i = 0; i < data->getContent().size(); ++i)
            cout << (*data->getContent())[i];
        
        cout << endl;

        setRegisted();
    }

    void 
    ConsumerAdapter::onRegistedTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
        cout << "Time out for interest " << interest->getName().toUri() << endl;     
        registerFace_.expressInterest(*interest, bind(&ConsumerAdapter::onRegistedData, this,_1,_2 ), bind(&ConsumerAdapter::onRegistedTimeout, this, _1));
    }


    void 
    ConsumerAdapter::registerConsumer(Interest & registerInterest )
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

        registerFace_.expressInterest(registerInterest, bind(&ConsumerAdapter::onRegistedData, this,_1,_2 ), bind(&ConsumerAdapter::onRegistedTimeout, this, _1));

        while(!registered_)
        {
            registerFace_.processEvents();
            // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            usleep(1000);
        }

    }

    void
    ConsumerAdapter::onReadyData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
    {
        cout << "Got data packet with name " << data->getName().toUri() << endl;
        for (size_t i = 0; i < data->getContent().size(); ++i)
            cout << (*data->getContent())[i];
        
        cout << endl;
        
        beReadytoConsume_ = true;

        //setRegisted();
    }

    void 
    ConsumerAdapter::onReadyTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
        cout << "Time out for interest " << interest->getName().toUri() << endl;     
        registerFace_.expressInterest(*interest, bind(&ConsumerAdapter::onReadyData, this,_1,_2 ), bind(&ConsumerAdapter::onReadyTimeout, this, _1));
    }

    void 
    ConsumerAdapter::requestConsumeReady(Name &requestConsume)
    {
        Interest requestConsumeInterest(requestConsume);
        requestConsumeInterest.setMustBeFresh(true);
        registerFace_.expressInterest(requestConsumeInterest, bind(&ConsumerAdapter::onReadyData, this,_1,_2 ), bind(&ConsumerAdapter::onReadyTimeout, this, _1));

        while(!beReadytoConsume_)
        {
            registerFace_.processEvents();
        }
    }

    void 
    ConsumerAdapter::addFixedContentKey(Name& cKeyName)
    {

        MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");

	// add the C-KEY.
        Blob contentKeyBits = Blob(AES_KEY, sizeof(AES_KEY));
        cKeyName.append("20150101T100000");

        //Blob CKeyBlob;
        consumer_->addDecryptionKey(cKeyName, contentKeyBits);
    }
    
    void
    ConsumerAdapter::addDecryptionKeyofCkey(Name& dKeyName)
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
        consumer_->addDecryptionKeyofCkey(dKeyName, privateKeyBuffer);
    }

    void
    ConsumerAdapter::setRegisted()
    {
        registered_ = true;
    }

    void 
    ConsumerAdapter::consumeSecureContent(Name& contentName)
    {
        int finalCount = 0;

        consumer_->consume
            (contentName,
            bind(&onConsumeComplete, _1, _2, &finalCount),
            bind(&onError, _1, _2));
        cout<< "consumeSecureContent face address:" << face_ << std::endl;
    
        while (1) {
        face_->processEvents();
            // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            //usleep(1000);
        }

        cout<<"consumer.consume excuted!"<<contentName<<endl;

    }
    
}

}
*/
