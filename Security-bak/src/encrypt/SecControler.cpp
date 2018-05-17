/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2016-2017 Regents of the University of California.
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
#modify by Marty, May 16th ,2017
#producerAdapter.hpp for the  data content security
#modify history: 
#combine consumerAdapter.hpp to consumer.hpp, Marty, 2017/06/29
#move parameters to SecCommon.hpp, marty , 2017/07/11
*/

#include <math.h>
#include <thread>

#include <ndn-cpp/util/logging.hpp>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>
#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
#include <ndn-cpp/encrypt/schedule.hpp>
//#include <ndn-cpp/encrypt/producer.hpp>
#include <ndn-cpp/encrypt/SecControler.hpp>

// Use the internal fromBase64.
#include "../encoding/base64.hpp"

using namespace std;
using namespace pki::func_lib;

INIT_LOGGER("ndn.SecControler");

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


void
SecControler::defaultOnError(EncryptError::ErrorCode errorCode, const string& message)
{
  // Do nothing.
}
    SecControler::SecControler(Name &remotePrefix,Name &remoteSuffix, Name &selfPrefix, Name &selfSuffix)
    {
        cout<< "SecControler::SecControler!" << std::endl;
    /*
        // Use the system default key chain and certificate name to sign commands.
        keyChain_ = new KeyChain();   
        
        // The default Face will connect using a Unix socket, or to "localhost".
        mainFace_ = new Face();
        cout<< "ProducerAdapter face address:" << mainFace_ << endl;
*/
        mainFace_.setCommandSigningInfo(keyChain_, keyChain_.getDefaultCertificateName());
        getEkeyFace_.setCommandSigningInfo(keyChain_, keyChain_.getDefaultCertificateName());
        //ptr_lib::shared_ptr<ProducerDb> testDb(new Sqlite3ProducerDb(databaseFilePath_)); 

        int repeatAttempts = 3;
        eKeyGeted_=false;
        
        impl_ = new Impl(remotePrefix, remoteSuffix, selfPrefix, selfSuffix,&mainFace_, &keyChain_,  repeatAttempts, getNO_LINK());

    }

    SecControler::~SecControler()
    {

    }

    void 
    SecControler::onEkeyData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
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
    
        eKeyGeted_=true;
    }
    
    void 
    SecControler::onEkeyTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
    {
        // Use bind to pass the counter object to the callbacks.
        getEkeyFace_.expressInterest(*interest, bind(&SecControler::onEkeyData, this,_1, _2), bind(&SecControler::onEkeyTimeout, this, _1));

        cout << "Time out for interest " << interest->getName().toUri() << endl;
    }

    void 
    SecControler::getEkeyFromSecUser(Name remotePrefix,Name remoteSuffix)
    {
        //Name keyName("/Prefix/READ/Content/E-KEY");
        Name keyName(remotePrefix);
        keyName.append(Encryptor::getNAME_COMPONENT_READ()).append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_E_KEY());
        
        Interest keyRequestInterest(keyName);

        keyRequestInterest.setMustBeFresh(true);
        keyRequestInterest.setInterestLifetimeMilliseconds(10000);

        // Use bind to pass the counter object to the callbacks.
        getEkeyFace_.expressInterest(keyRequestInterest, bind(&SecControler::onEkeyData, this, _1, _2), bind(&SecControler::onEkeyTimeout,this,  _1));
        cout <<"getEkeyFromSecUser getEkeyFace_.expressInterest keyRequestInterest:"<<keyRequestInterest.getName()<<endl;
        
        while(!eKeyGeted_)
        {
            getEkeyFace_.processEvents();
            //usleep(1000);
        }
        //getEkeyFace_.shutdown();

    }

    void
    SecControler::processSecUserEventGetContentKey(Name &remotePrefix,Name &remoteSuffix, Name &selfPrefix, Name &selfSuffix)
    {
        cout<<"processSecUserEventGetContentKey remoteSuffix"<<remoteSuffix<<endl;
        //get the EKEY
        std::thread getEkeyThread(&SecControler::getEkeyFromSecUser,this,remotePrefix,remoteSuffix);
        getEkeyThread.join();
        
        //Process ready for secUser to request ContentKey
        std::thread readyThread(&SecControler::processReadyRequest, this, remotePrefix,remoteSuffix,selfPrefix, selfSuffix);
        readyThread.detach();

        //Name secUserName("/Prefix/SAMPLE/Content");
        this->processGetContentKey(remotePrefix,remoteSuffix,selfPrefix, selfSuffix);
    }

    // on content Interest.
    void 
    SecControler::onReadyInterest
    (const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {

        // Make and sign a Data packet.

        Data data(interest->getName());
        string content(data.getName().toUri());
        
        data.setContent((const uint8_t *)&content[0], content.size());
        keyChain_.sign(data, keyChain_.getDefaultCertificateName());

        cout << "Sent content " << content << endl;

        face.putData(data);

    }
    // onContentFailed.
    void 
    SecControler::onReadyFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }

    void
    SecControler::processReadyRequest(Name remotePrefix,Name remoteSuffix,Name selfPrefix, Name selfSuffix)
    { 	
        //Name readyForConsume("Prefix/READY/SecControler/TO/Prefix/SAMPLE/SecUser");
        Name readyForContentKey(selfPrefix);
        readyForContentKey.append(Encryptor::getNAME_COMPONENT_READY()).append(selfSuffix).append(Encryptor::getNAME_COMPONENT_TO());
        readyForContentKey.append(remotePrefix).append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(remoteSuffix);

        cout<<"SecControler::processReadyReques:"<<readyForContentKey<<endl;       
        readyFace_.setCommandSigningInfo(keyChain_, keyChain_.getDefaultCertificateName());

        // we can remove the explicit cast to OnInterestCallback (needed for boost).
        readyFace_.registerPrefix(readyForContentKey, bind(&SecControler::onReadyInterest,this,_1,_2,_3,_4,_5), bind(&SecControler::onReadyFailed,this,_1));    

        while ( 1) {
            readyFace_.processEvents();
            // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            //usleep(1000);
        }
    }

    // on content Interest.
    void 
    SecControler::onContentInterest
    (const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {

        // Make and sign a Data packet.
        Data testData;
        MillisecondsSince1970 testTime= fromIsoString("20150101T100000");

        this->produce(testData, testTime, Blob(DATA_CONTENT, sizeof(DATA_CONTENT)));
        
        string content(testData.getName().toUri());

        cout << "Sent content " << content << endl;

        face.putData(testData);

    }
    // onContentFailed.
    void 
    SecControler::onContentFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }
    

    void
    SecControler::onCkeyRequestInterest(const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face, 
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {      
        MillisecondsSince1970 beginTimeSlot;
        MillisecondsSince1970 endTimeSlot;
        cout<<"SecControler::onCkeyRequestInterest"<<endl;
   
        MillisecondsSince1970 timeSlot= fromIsoString("20150101T100000");

        //keyName.get(END_TIME_STAMP_INDEX).getValue().toRawStr()

        // Create Data packet
        Data cKeyData;
        
        // Create new name, based on Interest's name
        //Name eKeyName("/Prefix/SAMPLE/SeControler/TO/Prefix/SAMPE/SecUer/E-KEY/20150101T100000/20150101T120000");
        //Name cKeyInterestName("/Prefix/SAMPLE/SecControler/TO/Prefix/SAMPLE/SecUser1/C-KEY/20150101T100000/FOR/Prefix/READ ");
        Name cKeyInterestName(interest->getName()); 

        Name eKeyName = cKeyInterestName.getPrefix(-5);
        eKeyName.append(Encryptor::getNAME_COMPONENT_E_KEY()).append("20150101T100000").append("20150101T120000");

        
        ptr_lib::shared_ptr<vector<uint8_t> > publicKeyBuffer(new vector<uint8_t>());
        fromBase64(PUBLIC_KEY, *publicKeyBuffer);
        Blob publicKeyBlob(publicKeyBuffer, false);

        encryptContentKey
            (cKeyData,publicKeyBlob, eKeyName,
            timeSlot, bind(&onCkeyError,_1,_2)) ;
        
        // Sign Data packet with default identity
        keyChain_.sign(cKeyData);

        string content(cKeyData.getName().toUri());

        cout << "Sent contentkey " << content << endl;
        mainFace_.putData(cKeyData);
    }

    // onCkeyRequestFailed.
    void 
    SecControler::onCkeyRequestFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       cout << "onCkeyRequestFailed: " << prefix->toUri() << endl;
    }

    
    bool
    SecControler::encryptContentKey
      (Data& data,const Blob& encryptionKey, const Name& eKeyName,
       MillisecondsSince1970 timeSlot, 
       const EncryptError::OnError& onError)
    {
        MillisecondsSince1970 timeCount = ::round(timeSlot);
        //ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

        //Name eKeyName("/Prefix/SAMPLE/SeControler/TO/Prefix/SAMPE/SecUer/E-KEY/20150101T100000/20150101T120000");
    
        //Name ckeyName("/Prefix/SAMPLE/SecControler/Prefix/SAMPLE/SecUser/C-KEY/20150101T100000");
        Name ckeyName=eKeyName.getPrefix(-3);
        ckeyName.append(Encryptor::getNAME_COMPONENT_C_KEY()).append("20150101T100000");
        
        //Name keyName("/Prefix/SAMPLE/SecControler/Prefix/SAMPLE/SecUser/C-KEY/20150101T100000/FOR/Prefix/READ");
        Name keyName(ckeyName);
        keyName.append(Encryptor::getNAME_COMPONENT_FOR()).append("Prefix").append(Encryptor::getNAME_COMPONENT_READ());
            
        cout<<"SecControler::encryptContentKey"<<endl;

        cout<<"SecControler::encryptContentKey ckeyname "<<ckeyName<<endl;
        cout<<"SecControler::encryptContentKey eKeyName "<<eKeyName<<endl;
        cout<<"SecControler::encryptContentKey keyname "<<keyName<<endl;
        
        //Blob contentKey = database_->getContentKey(timeSlot);
        Blob contentKey;

        if (hasContentKey(ckeyName))
        {
            getContentKey(ckeyName,&contentKey);
            for(int i =0;i<contentKey.size();i++)
            {
            if (0==i)
            {
            printf("encryptContentKey\n");
            }
            printf("0x%x,",contentKey.buf()[i]);	  
            if (i%8==7)
            printf("\n");
            }

            printf("contentKey.size()=%d\n",contentKey.size());     
        }
        else
        {
            cout<<"encryptContentKey: there is not content key!"<<endl;
            return false;
        }   
      
        data.setName(keyName);
       
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
    SecControler::processGetContentKey(Name &remotePrefix,Name &remoteSuffix, Name &selfPrefix, Name &selfSuffix)
    {
        //MillisecondsSince1970 testTime= fromIsoString("20150101T100000");
        //Name timeMarker("20150101T100000/20150101T120000");

        //Name contentInterestName("/Prefix/SAMPLE/SecControler/TO/Prefix/SAMPLE/SecUser"); 
        Name contentInterestName(selfPrefix);
        contentInterestName.append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(selfSuffix);
        contentInterestName.append(Encryptor::getNAME_COMPONENT_TO()).append(remotePrefix).append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(remoteSuffix); 
        
        mainFace_.registerPrefix(contentInterestName, bind(&SecControler::onContentInterest,this,_1,_2,_3,_4,_5),bind(&SecControler::onContentFailed,this,_1));

        //Name ckeyName("/Prefix/SAMPLE/SecControler/TO/Prefix/SAMPLE/SecUser/C-KEY/20150101T100000/FOR/Prefix/READ");
        Name ckeyName(selfPrefix);
        ckeyName.append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(selfSuffix).append(Encryptor::getNAME_COMPONENT_TO());
        ckeyName.append(remotePrefix).append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());
        ckeyName.append("20150101T100000").append(Encryptor::getNAME_COMPONENT_FOR()).append(selfPrefix).append(Encryptor::getNAME_COMPONENT_READ());

        Face ckeyFace;
        ckeyFace.setCommandSigningInfo(keyChain_, keyChain_.getDefaultCertificateName());
        ckeyFace.registerPrefix(ckeyName, bind(&SecControler::onCkeyRequestInterest,this,_1,_2,_3,_4,_5),bind(&SecControler::onContentFailed,this,_1));

        cout<<"processGetContentKey registerPrefix contentInterestName:"<<contentInterestName<<endl;
        cout<<"processGetContentKey registerPrefix ckeyName:"<<ckeyName<<endl;

        /*
        mainFace_->setInterestFilter(
            ckeyName,
            bind(&SecControler::onCkeyRequestInterest,this,  _1, _2,_3,_4,_5)
            );
        */
        // The main event loop.
        // Wait forever to receive one interest for the prefix.
        while (1) {
          mainFace_.processEvents();
          ckeyFace.processEvents();
          // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
          //usleep(1000);
        }
    }


SecControler::Impl::Impl
  (const Name& remotePrefix, const Name& remoteSuffix, const Name& selfPrefix, const Name& selfSuffix, Face* face, KeyChain* keyChain,
  int repeatAttempts,
   const Link& keyRetrievalLink)
  : face_(face),
    keyChain_(keyChain),
    maxRepeatAttempts_(repeatAttempts),
    keyRetrievalLink_(keyRetrievalLink),
    secControlerRemotePrefix_(remotePrefix),
    secControlerRemoteSuffix_(remoteSuffix),
    secControlerSelfPrefix_(selfPrefix),
    secControlerSelfSuffix_(selfSuffix)
{
//Initial E-KEY
/*
  Name fixedPrefix(remotePrefix);
  Name fixedDataType(remoteSuffix);

  // Fill ekeyInfo_ with all permutations of dataType, including the 'E-KEY'
  // component of the name. This will be used in createContentKey to send
  // interests without reconstructing names every time.
  fixedPrefix.append(Encryptor::getNAME_COMPONENT_READ());
  while (fixedDataType.size() > 0) {
    Name nodeName(fixedPrefix);
    nodeName.append(fixedDataType);
    nodeName.append(Encryptor::getNAME_COMPONENT_E_KEY());

    eKeyInfo_[nodeName] = ptr_lib::make_shared<KeyInfo>();
    fixedDataType = fixedDataType.getPrefix(-1);
  }

  
  fixedPrefix.append(remoteSuffix);
  */
  namespace_ = Name(remotePrefix);
  namespace_.append(Encryptor::getNAME_COMPONENT_SAMPLE());
  namespace_.append(remoteSuffix);
}

Name
SecControler::Impl::createContentKeySaveInMap
  (MillisecondsSince1970 timeSlot, 
   const EncryptError::OnError& onError)
{
    MillisecondsSince1970 hourSlot = getRoundedTimeSlot(timeSlot);

    cout<<"SecControler::Impl createContentKeySaveInMap"<<endl;

    //Name contentKeyName("/Prefix/SAMPLE/SecControler/TO/Prefix/SAMPLE/SecUser");
    Name contentKeyName(secControlerSelfPrefix_);
    contentKeyName.append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(secControlerSelfSuffix_);
    contentKeyName.append(Encryptor::getNAME_COMPONENT_TO()).append(secControlerRemotePrefix_);
    contentKeyName.append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(secControlerRemoteSuffix_);
    contentKeyName.append(Encryptor::getNAME_COMPONENT_C_KEY());
    contentKeyName.append(Schedule::toIsoString(hourSlot));

    cout<<"SecControler::Impl createContentKey contentKeyName="<<contentKeyName<<endl;

    Blob contentKeyBits;

    // We haven't created the content key. Create one and add it into the database.
    AesKeyParams aesParams(128);
    contentKeyBits = AesAlgorithm::generateKey(aesParams).getKeyBits();

    cKeySecControlerMap_[contentKeyName]= contentKeyBits;
    //database_->addContentKey(timeSlot, contentKeyBits);

#if 0
  // Now we need to retrieve the E-KEYs for content key encryption.
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  keyRequests_[timeCount] = ptr_lib::make_shared<KeyRequest>(eKeyInfo_.size());
  ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

  // Check if the current E-KEYs can cover the content key.
  Exclude timeRange;
  excludeAfter(timeRange, Name::Component(Schedule::toIsoString(timeSlot)));
  for (map<Name, ptr_lib::shared_ptr<KeyInfo> >::iterator i = eKeyInfo_.begin();
       i != eKeyInfo_.end(); ++i) {
    // For each current E-KEY.
    const KeyInfo& keyInfo = *i->second;
    if (timeSlot < keyInfo.beginTimeSlot || timeSlot >= keyInfo.endTimeSlot) {
      // The current E-KEY cannot cover the content key, so retrieve one.
      keyRequest->repeatAttempts[i->first] = 0;
      cout<<"producer createContentKey sendKeyinterest "<<i->first<<endl;
      sendKeyInterest
        (Interest(i->first).setExclude(timeRange).setChildSelector(1),
         timeSlot, onEncryptedKeys, onError);
    }
    else {
      // The current E-KEY can cover the content key.
      // Encrypt the content key directly.
      Name eKeyName(i->first);
      eKeyName.append(Schedule::toIsoString(keyInfo.beginTimeSlot));
      eKeyName.append(Schedule::toIsoString(keyInfo.endTimeSlot));
      encryptContentKey
        (keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys, onError);
    }
  }
#endif 

  return contentKeyName;
}


Name
SecControler::Impl::createContentKeySaveInDb
  (MillisecondsSince1970 timeSlot, 
   const EncryptError::OnError& onError)
{
  MillisecondsSince1970 hourSlot = getRoundedTimeSlot(timeSlot);

  cout<<"SecControler::Impl createContentKey"<<endl;

  // Create the content key name.
  Name contentKeyName(namespace_);
  cout<<"SecControler::Impl createContentKey namespace_="<<namespace_<<endl;
  contentKeyName.append(Encryptor::getNAME_COMPONENT_C_KEY());
  contentKeyName.append(Schedule::toIsoString(hourSlot));

  cout<<"SecControler::Impl createContentKey contentKeyName="<<contentKeyName<<endl;

  Blob contentKeyBits;

  // Check if we have created the content key before.
  if (database_->hasContentKey(timeSlot))
    // We have created the content key. Return its name directly.
  {
      cout<<"already has the content key!!"<<endl;
      return contentKeyName;
  }

  // We haven't created the content key. Create one and add it into the database.
  AesKeyParams aesParams(128);
  contentKeyBits = AesAlgorithm::generateKey(aesParams).getKeyBits();
  database_->addContentKey(timeSlot, contentKeyBits);

#if 0
  // Now we need to retrieve the E-KEYs for content key encryption.
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  keyRequests_[timeCount] = ptr_lib::make_shared<KeyRequest>(eKeyInfo_.size());
  ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

  // Check if the current E-KEYs can cover the content key.
  Exclude timeRange;
  excludeAfter(timeRange, Name::Component(Schedule::toIsoString(timeSlot)));
  for (map<Name, ptr_lib::shared_ptr<KeyInfo> >::iterator i = eKeyInfo_.begin();
       i != eKeyInfo_.end(); ++i) {
    // For each current E-KEY.
    const KeyInfo& keyInfo = *i->second;
    if (timeSlot < keyInfo.beginTimeSlot || timeSlot >= keyInfo.endTimeSlot) {
      // The current E-KEY cannot cover the content key, so retrieve one.
      keyRequest->repeatAttempts[i->first] = 0;
      cout<<"producer createContentKey sendKeyinterest "<<i->first<<endl;
      sendKeyInterest
        (Interest(i->first).setExclude(timeRange).setChildSelector(1),
         timeSlot, onEncryptedKeys, onError);
    }
    else {
      // The current E-KEY can cover the content key.
      // Encrypt the content key directly.
      Name eKeyName(i->first);
      eKeyName.append(Schedule::toIsoString(keyInfo.beginTimeSlot));
      eKeyName.append(Schedule::toIsoString(keyInfo.endTimeSlot));
      encryptContentKey
        (keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys, onError);
    }
  }
#endif 

  return contentKeyName;
}


void
SecControler::Impl::produce
  (Data& data, MillisecondsSince1970 timeSlot, const Blob& content,
   const EncryptError::OnError& onError)
{
  // Get a content key.

/*
  Name contentKeyName = createContentKeySaveInDb(timeSlot, onError);
  Blob contentKey = database_->getContentKey(timeSlot);
*/

  Name contentKeyName = createContentKeySaveInMap(timeSlot, onError);

  cout <<"SecControler::Impl::produce: contentKeyName " <<contentKeyName<<endl;
  
  Blob contentKey = cKeySecControlerMap_[contentKeyName];

  for(int i =0;i<contentKey.size();i++)
  {
      if (0==i)
  	{
  	    printf("ContentKey\n");
  	}
      printf("0x%x,",contentKey.buf()[i]);	  
      if (i%8==7)
	  	printf("\n");
    }

  cout<<"SecControler::Impl cKeySecControlerMap_"<<endl;

  // Produce data.
  Name dataName(secControlerSelfPrefix_);
  dataName.append(Encryptor::getNAME_COMPONENT_SAMPLE()).append(secControlerSelfSuffix_).append(Encryptor::getNAME_COMPONENT_TO());
  dataName.append(namespace_);
  dataName.append(Schedule::toIsoString(timeSlot));

  data.setName(dataName);
  EncryptParams params(ndn_EncryptAlgorithmType_AesCbc, 16);
  Encryptor::encryptData(data, content, contentKeyName, contentKey, params);
  keyChain_->sign(data);
}

MillisecondsSince1970
SecControler::Impl::getRoundedTimeSlot(MillisecondsSince1970 timeSlot)
{
  return ::round(::floor(::round(timeSlot) / 3600000.0) * 3600000.0);
}

void
SecControler::Impl::sendKeyInterest
  (const Interest& interest, MillisecondsSince1970 timeSlot,
   const OnEncryptedKeys& onEncryptedKeys,
   const EncryptError::OnError& onError)
{
  ptr_lib::shared_ptr<Interest> interestWithLink;
  const Interest* request;
  
  cout<<"SecControler::Impl sendKeyInterest "<<interest.getName()<<endl;
  
  if (keyRetrievalLink_.getDelegations().size() == 0)
    // We can use the supplied interest without copying.
    request = &interest;
  else {
    // Copy the supplied interest and add the Link.
    interestWithLink.reset(new Interest(interest));
    // This will use a cached encoding if available.
    interestWithLink->setLinkWireEncoding(keyRetrievalLink_.wireEncode());

    request = interestWithLink.get();
  }

  //request->setMustBeFresh(true);
  //request->setInterestLifetimeMilliseconds(10000);

  face_->expressInterest
    (*request,
     bind(&SecControler::Impl::handleCoveringKey, shared_from_this(), _1, _2,
          timeSlot, onEncryptedKeys, onError),
     bind(&SecControler::Impl::handleTimeout, shared_from_this(), _1, timeSlot,
          onEncryptedKeys, onError),
     bind(&SecControler::Impl::handleNetworkNack, shared_from_this(), _1, _2,
          timeSlot, onEncryptedKeys, onError));
}

void
SecControler::Impl::handleTimeout
  (const ptr_lib::shared_ptr<const Interest>& interest,
   MillisecondsSince1970 timeSlot, const OnEncryptedKeys& onEncryptedKeys,
   const EncryptError::OnError& onError)
{
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

  cout<<"SecControler::Impl handleTimeout"<<endl;

  const Name& interestName = interest->getName();
  if (keyRequest->repeatAttempts[interestName] < maxRepeatAttempts_) {
    // Increase the retrial count.
    ++keyRequest->repeatAttempts[interestName];
    sendKeyInterest(*interest, timeSlot, onEncryptedKeys, onError);
  }
  else
    // Treat an eventual timeout as a network Nack.
    handleNetworkNack
      (interest, ptr_lib::make_shared<NetworkNack>(), timeSlot, onEncryptedKeys,
       onError);
}

void
SecControler::Impl::handleNetworkNack
  (const ptr_lib::shared_ptr<const Interest>& interest,
   const ptr_lib::shared_ptr<NetworkNack>& networkNack,
   MillisecondsSince1970 timeSlot,
   const OnEncryptedKeys& onEncryptedKeys,
   const EncryptError::OnError& onError)
{
  // We have run out of options....
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  updateKeyRequest(keyRequests_[timeCount], timeCount, onEncryptedKeys);

  cout<<"SecControler::Impl handleNetworkNack"<<endl;
}

void
SecControler::Impl::updateKeyRequest
  (const ptr_lib::shared_ptr<KeyRequest>& keyRequest,
   MillisecondsSince1970 timeCount, const OnEncryptedKeys& onEncryptedKeys)
{
  --keyRequest->interestCount;

  cout<<"SecControler::Impl updateKeyRequest"<<endl;
  
  if (keyRequest->interestCount == 0 && onEncryptedKeys) {
    try {
      onEncryptedKeys(keyRequest->encryptedKeys);
    } catch (const std::exception& ex) {
      _LOG_ERROR("Producer::Impl::updateKeyRequest: Error in onEncryptedKeys: " << ex.what());
    } catch (...) {
      _LOG_ERROR("Producer::Impl::updateKeyRequest: Error in onEncryptedKeys.");
    }
    keyRequests_.erase(timeCount);
  }
}

void
SecControler::Impl::handleCoveringKey
  (const ptr_lib::shared_ptr<const Interest>& interest,
   const ptr_lib::shared_ptr<Data>& data, MillisecondsSince1970 timeSlot,
   const OnEncryptedKeys& onEncryptedKeys,
   const EncryptError::OnError& onError)
{
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

  cout<<"SecControler::Impl handleCoveringKey"<<endl;

  const Name& interestName = interest->getName();
  const Name& keyName = data->getName();

  MillisecondsSince1970 begin = Schedule::fromIsoString
    (keyName.get(START_TIME_STAMP_INDEX).getValue().toRawStr());
  MillisecondsSince1970 end = Schedule::fromIsoString
    (keyName.get(END_TIME_STAMP_INDEX).getValue().toRawStr());

  if (timeSlot >= end) {
    // If the received E-KEY covers some earlier period, try to retrieve an
    // E-KEY covering a later one.
    Exclude timeRange(interest->getExclude());
    excludeBefore(timeRange, keyName.get(START_TIME_STAMP_INDEX));
    keyRequest->repeatAttempts[interestName] = 0;

    sendKeyInterest
      (Interest(interestName).setExclude(timeRange).setChildSelector(1),
       timeSlot, onEncryptedKeys, onError);
  }
  else {
    // If the received E-KEY covers the content key, encrypt the content.
    const Blob& encryptionKey = data->getContent();
    // If everything is correct, save the E-KEY as the current key.
    if (encryptContentKey
        (encryptionKey, keyName, timeSlot, onEncryptedKeys, onError)) {
      ptr_lib::shared_ptr<KeyInfo> keyInfo = eKeyInfo_[interestName];
      keyInfo->beginTimeSlot = begin;
      keyInfo->endTimeSlot = end;
      keyInfo->keyBits = encryptionKey;
    }
  }
}

bool
SecControler::Impl::encryptContentKey
  (const Blob& encryptionKey, const Name& eKeyName,
   MillisecondsSince1970 timeSlot, const OnEncryptedKeys& onEncryptedKeys,
   const EncryptError::OnError& onError)
{
  MillisecondsSince1970 timeCount = ::round(timeSlot);
  ptr_lib::shared_ptr<KeyRequest> keyRequest = keyRequests_[timeCount];

  Name keyName(namespace_);
  keyName.append(Encryptor::getNAME_COMPONENT_C_KEY());
  keyName.append(Schedule::toIsoString(getRoundedTimeSlot(timeSlot)));
  
  //Blob contentKey = database_->getContentKey(timeSlot);
  Blob contentKey =cKeySecControlerMap_[keyName];
  
  cout<<"SecControler::Impl encryptContentKey"<<endl;

  ptr_lib::shared_ptr<Data> cKeyData(new Data());
  cKeyData->setName(keyName);
  EncryptParams params(ndn_EncryptAlgorithmType_RsaOaep);
  try {
    Encryptor::encryptData
      (*cKeyData, contentKey, eKeyName, encryptionKey, params);
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

  keyChain_->sign(*cKeyData);
  keyRequest->encryptedKeys.push_back(cKeyData);
  updateKeyRequest(keyRequest, timeCount, onEncryptedKeys);
  return true;
}

void
SecControler::Impl::getExcludeEntries
  (const Exclude& exclude, vector<ExcludeEntry>& entries)
{
  entries.clear();

  cout<<"SecControler::Impl getExcludeEntries"<<endl;

  for (size_t i = 0; i < exclude.size(); ++i) {
    if (exclude[i].getType() == ndn_Exclude_ANY) {
      if (entries.size() == 0)
        // Add a "beginning ANY".
        entries.push_back(ExcludeEntry(Name::Component(), true));
      else
        // Set anyFollowsComponent of the final component.
        entries[entries.size() - 1].anyFollowsComponent_ = true;
    }
    else
      entries.push_back(ExcludeEntry(exclude[i].getComponent(), false));
  }
}

void
SecControler::Impl::setExcludeEntries
  (Exclude& exclude, const vector<ExcludeEntry>& entries)
{
  exclude.clear();

  cout<<"SecControler::Impl setExcludeEntries"<<endl;

  for (size_t i = 0; i < entries.size(); ++i) {
    const ExcludeEntry& entry = entries[i];

    if (i == 0 && entry.component_.getValue().size() == 0 &&
        entry.anyFollowsComponent_)
      // This is a "beginning ANY".
      exclude.appendAny();
    else {
      exclude.appendComponent(entry.component_);
      if (entry.anyFollowsComponent_)
        exclude.appendAny();
    }
  }
}

int
SecControler::Impl::findEntryBeforeOrAt
  (const vector<ExcludeEntry>& entries, const Name::Component& component)
{
  int i = entries.size() - 1;
  while (i >= 0) {
    if (entries[i].component_.compare(component) <= 0)
      break;
    --i;
  }

  cout<<"SecControler::Impl findEntryBeforeOrAt"<<endl;

  return i;
}

void
SecControler::Impl::excludeAfter(Exclude& exclude, const Name::Component& from)
{
  vector<ExcludeEntry> entries;
  getExcludeEntries(exclude, entries);

  int iNewFrom;
  int iFoundFrom = findEntryBeforeOrAt(entries, from);

  cout<<"SecControler::Impl excludeAfter"<<endl;
  
  if (iFoundFrom < 0) {
    // There is no entry before "from" so insert at the beginning.
    entries.insert(entries.begin(), ExcludeEntry(from, true));
    iNewFrom = 0;
  }
  else {
    ExcludeEntry& foundFrom = entries[iFoundFrom];

    if (!foundFrom.anyFollowsComponent_) {
      if (foundFrom.component_.equals(from)) {
        // There is already an entry with "from", so just set the "ANY" flag.
        foundFrom.anyFollowsComponent_ = true;
        iNewFrom = iFoundFrom;
      }
      else {
        // Insert following the entry before "from".
        entries.insert(entries.begin() + iFoundFrom + 1, ExcludeEntry(from, true));
        iNewFrom = iFoundFrom + 1;
      }
    }
    else
      // The entry before "from" already has an "ANY" flag, so do nothing.
      iNewFrom = iFoundFrom;
  }

  // Remove entries after the new "from".
  int iRemoveBegin = iNewFrom + 1;
  int nRemoveNeeded = entries.size() - iRemoveBegin;
  for (int i = 0; i < nRemoveNeeded; ++i)
    entries.erase(entries.begin() + iRemoveBegin);

  setExcludeEntries(exclude, entries);
}

void
SecControler::Impl::excludeRange
  (Exclude& exclude, const Name::Component& from, const Name::Component& to)
{
  if (from.compare(to) >= 0) {
    if (from.compare(to) == 0)
      throw runtime_error
        ("excludeRange: from == to. To exclude a single component, sue excludeOne.");
    else
      throw runtime_error
        ("excludeRange: from must be less than to. Invalid range: [" +
         from.toEscapedString() + ", " + to.toEscapedString() + "]");
  }

  cout<<"SecControler::Impl excludeRange"<<endl;

  vector<ExcludeEntry> entries;
  getExcludeEntries(exclude, entries);

  int iNewFrom;
  int iFoundFrom = findEntryBeforeOrAt(entries, from);
  if (iFoundFrom < 0) {
    // There is no entry before "from" so insert at the beginning.
    entries.insert(entries.begin(), ExcludeEntry(from, true));
    iNewFrom = 0;
  }
  else {
    ExcludeEntry& foundFrom = entries[iFoundFrom];

    if (!foundFrom.anyFollowsComponent_) {
      if (foundFrom.component_.equals(from)) {
        // There is already an entry with "from", so just set the "ANY" flag.
        foundFrom.anyFollowsComponent_ = true;
        iNewFrom = iFoundFrom;
      }
      else {
        // Insert following the entry before "from".
        entries.insert(entries.begin() + iFoundFrom + 1, ExcludeEntry(from, true));
        iNewFrom = iFoundFrom + 1;
      }
    }
    else
      // The entry before "from" already has an "ANY" flag, so do nothing.
      iNewFrom = iFoundFrom;
  }

  // We have at least one "from" before "to", so we know this will find an entry.
  int iFoundTo = findEntryBeforeOrAt(entries, to);
  ExcludeEntry& foundTo = entries[iFoundTo];
  if (iFoundTo == iNewFrom)
    // Insert the "to" immediately after the "from".
    entries.insert(entries.begin() + iNewFrom + 1, ExcludeEntry(to, false));
  else {
    int iRemoveEnd;
    if (!foundTo.anyFollowsComponent_) {
      if (foundTo.component_.equals(to))
        // The "to" entry already exists. Remove up to it.
        iRemoveEnd = iFoundTo;
      else {
        // Insert following the previous entry, which will be removed.
        entries.insert(entries.begin() + iFoundTo + 1, ExcludeEntry(to, false));
        iRemoveEnd = iFoundTo + 1;
      }
    }
    else
      // "to" follows a component which is already followed by "ANY", meaning
      // the new range now encompasses it, so remove the component.
      iRemoveEnd = iFoundTo + 1;

    // Remove intermediate entries since they are inside the range.
    int iRemoveBegin = iNewFrom + 1;
    int nRemoveNeeded = iRemoveEnd - iRemoveBegin;
    for (int i = 0; i < nRemoveNeeded; ++i)
      entries.erase(entries.begin() + iRemoveBegin);
  }

  setExcludeEntries(exclude, entries);
}

Link* SecControler::noLink_ = 0;

}
