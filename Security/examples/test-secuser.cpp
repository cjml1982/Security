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

#include <cstdlib>
//#include <fstream>
//#include <iostream>
#include <thread>
#include <time.h>

#include <unistd.h>

#include <ndn-cpp/face.hpp>
#include <ndn-cpp/name.hpp>
#include <ndn-cpp/interest.hpp>
#include <ndn-cpp/security/key-chain.hpp>
//#include <ndn-cpp/hmac-with-sha256-signature.hpp>
//#include <ndn-cpp/security/identity/memory-identity-storage.hpp>
//#include <ndn-cpp/security/identity/memory-private-key-storage.hpp>
//#include <ndn-cpp/security/policy/no-verify-policy-manager.hpp>
#include <ndn-cpp/encrypt/sqlite3-consumer-db.hpp>
#include <ndn-cpp/encrypt/SecUser.hpp>
//#include <ndn-cpp/encrypt/schedule.hpp>

//#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
//#include <ndn-cpp/encrypt/algo/encryptor.hpp>
//#include <ndn-cpp/encrypt/consumerAdapter.hpp>



using namespace std;
using namespace pki;
using namespace pki::func_lib;


static  KeyChain keyChain;

static int count =0 ;

void
onInterest(const ptr_lib::shared_ptr<const Name>& prefix,
   const ptr_lib::shared_ptr<const Interest>& interest, Face& face, 
   uint64_t interestFilterId,
   const ptr_lib::shared_ptr<const InterestFilter>& filter)
{
  //cout << "<< I: " << interest << std::endl;
  count++;
  
  MillisecondsSince1970 beginTimeSlot;
  MillisecondsSince1970 endTimeSlot;

  // Create new name, based on Interest's name
  Name dataName(interest->getName());
  dataName
    .append("20150101T100000").append("20150101T120000"); // add "testApp" component to Interest name
    //.appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

  //static const std::string content = "HELLO KITTY";

    cout<<"send publickey to producer the "<<count<<" times"<<endl;

  // Create Data packet
  shared_ptr<Data> data = make_shared<Data>();
  data->setName(dataName);
  //data->setFreshnessPeriod(time::seconds(10));
  //data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());
  data->setContent(reinterpret_cast<const uint8_t*>(DEFAULT_RSA_PUBLIC_KEY_DER), sizeof(DEFAULT_RSA_PUBLIC_KEY_DER));

  // Sign Data packet with default identity
  keyChain.sign(*data);
  // m_keyChain.sign(data, <identityName>);
  // m_keyChain.sign(data, <certificate>);

  // Return Data packet to the requester
  //cout << ">> D: " << *data << std::endl;
  face.putData(*data);
}

/*
void
onRegisterFailed(const Name& prefix, const std::string& reason)
{
  std::cerr << "ERROR: Failed to register prefix \""
            << prefix << "\" in local hub's daemon (" << reason << ")"
            << std::endl;
  //m_face.shutdown();
}
*/
void
onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
{
    count++;

  std::cerr << "ERROR: Failed to register prefix \""
            << prefix 
            << std::endl;
  //m_face.shutdown();
}

void replyPublicKey()
{
    Face face;
    //const ndn::RegisteredPrefixId * m_listenId;
    Name keyName(" /Prefix/READ/Content/E-KEY");
    
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());

    cout<<"default Certificate Name is "<<keyChain.getDefaultCertificateName()<<endl;
    
    face.registerPrefix(keyName, 
        bind(&onInterest,  _1, _2,_3,_4,_5),
        bind(&onRegisterFailed,  _1));

    /*
    face.setInterestFilter(
        keyName,
        bind(&onInterest,  _1, _2,_3,_4,_5)
        );
        */
    
    while(count <10)
    {
        face.processEvents();
    }
    //face.shutdown();

}


int main(int argc, char** argv)
{	
    Name groupName = Name("/Prefix/READ");
    Name contentName = Name("/Prefix/SAMPLE/Content");
    Name dKeyName = Name("/Prefix/SAMPLE/Content/D-KEY/20150101T100000/20150101T120000");
    Name consumerName = Name("/Prefix/SAMPLE/Content");
    
    //string databaseFilePath="./consumer.db";

    string word;
    //cout << "Enter a word to echo:" << endl;
    //cin >> word;

    Name registerName("/REGISTER/content");
    //registerName.append(word);
    
    //ptr_lib::shared_ptr<ConsumerDb> testDb(new Sqlite3ConsumerDb(databaseFilePath));

    //initial the consumerAdapter
    SecUser *consumer= new SecUser();
    consumer->Init(groupName,consumerName);

    std::thread regThread(&replyPublicKey);
    regThread.detach();

    Interest registerInterest(registerName);

    //register consumer,will expreess register interest to the producer
    consumer->registerConsumer(registerInterest);

    //consumerAdapter.addFixedContentKey(cKeyName);
    consumer->addDecryptionKeyofCkey(dKeyName);

    Name requestConsume("/READY/Content/");
    consumer->requestConsumeReady(requestConsume);
    //will expreess secure content interest to the producer 
    consumer->consumeSecureContent(contentName);

    cout<<"consumer.consume excuted!"<<contentName<<endl;

    return 0;

}

