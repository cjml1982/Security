/*
* create by Marty, manage the SecUser 2017/07/04
*
*
*
*
*
*/

#include <stdexcept>
#include <thread>

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

#include <ndn-cpp/encrypt/SecUserMag.hpp>

using namespace std;
using namespace pki;
using namespace pki::func_lib;

namespace pki {

    SecUserMag::SecUserMag()
    {
    }
    SecUserMag::~SecUserMag()
    {
    }

    SecUserMag *
    SecUserMag::getInstance()
    {
        if (NULL==uniqueInstance_)
            { 
                uniqueInstance_ = new SecUserMag();
            }
        return uniqueInstance_;
    }

    void
    SecUserMag::Init(Name &selfPrefix, Name &selfSuffix)
    {  
        std::thread regThread(&SecUserMag::processReplyPublicKey,this,selfPrefix,selfSuffix);
        regThread.detach();
    }
    
    void
    SecUserMag::onPublicKeyInterest(const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face, 
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
      //cout << "<< I: " << interest << std::endl;
      
      MillisecondsSince1970 beginTimeSlot;
      MillisecondsSince1970 endTimeSlot;
    
      // Create new name, based on Interest's name
      Name dataName(interest->getName());
      dataName
        .append("20150101T100000").append("20150101T120000"); // add "testApp" component to Interest name
        //.appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)
    
      // Create Data packet
      shared_ptr<Data> data = make_shared<Data>();
      data->setName(dataName);
      //data->setFreshnessPeriod(time::seconds(10));
      //data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());
      data->setContent(reinterpret_cast<const uint8_t*>(DEFAULT_RSA_PUBLIC_KEY_DER), sizeof(DEFAULT_RSA_PUBLIC_KEY_DER));
    
      // Sign Data packet with default identity
      keyChain_.sign(*data);
    
      face.putData(*data);
    }
    
    void
    SecUserMag::onPublicKeyFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {   
      std::cerr << "ERROR: Failed get the PublicKey\""
                << prefix 
                << std::endl;

    }

    void 
    SecUserMag::processReplyPublicKey(Name selfPrefix, Name selfSuffix)
    {
        Face face;

        //the publicKey name /Prefix/READ/Suffix/E-KEY
        //Name keyName(" /Prefix/READ/Content/E-KEY");
        
        Name keyName(selfPrefix);
        keyName.append(Encryptor::getNAME_COMPONENT_READ()).append(selfSuffix).append(Encryptor::getNAME_COMPONENT_E_KEY());
        
        face.setCommandSigningInfo(keyChain_, keyChain_.getDefaultCertificateName());

        cout<<"default Certificate Name is "<<keyChain_.getDefaultCertificateName()<<endl;
        
        face.registerPrefix(keyName, 
            bind(&SecUserMag::onPublicKeyInterest, this, _1, _2,_3,_4,_5),
            bind(&SecUserMag::onPublicKeyFailed, this, _1));

        /*
        face.setInterestFilter(
            keyName,
            bind(&onInterest,  _1, _2,_3,_4,_5)
            );
            */
        
        while(1)
        {
            face.processEvents();
        }
        //face.shutdown();

    }

    void
    SecUserMag::negotiateContentKey(Name remotePrefix,Name remoteSuffix, Name selfPrefix, Name selfSuffix)
    {        
        //string databaseFilePath="./consumer.db";

        SecUser *secUser= new SecUser(remotePrefix,remoteSuffix, selfPrefix, selfSuffix);
        //secUser->Init(groupName,consumerName);
        secUser->registAndNegotiateContentKey(remotePrefix,remoteSuffix, selfPrefix, selfSuffix);

    }

    bool
    SecUserMag::hasTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());

        if (cKeySecUserMagMap_.find(cKeyName)!=cKeySecUserMagMap_.end())
        {
            return true;
        }

        return false;
    }

    void
    SecUserMag::getTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());
        *Ckey = cKeySecUserMagMap_[cKeyName];
    }


    bool
    SecUserMag::saveTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());

        if (cKeySecUserMagMap_.find(cKeyName)!=cKeySecUserMagMap_.end())
        {
            cKeySecUserMagMap_.erase(cKeyName);
        }

        cKeySecUserMagMap_[cKeyName] = *Ckey;

        if (cKeySecUserMagMap_.find(cKeyName)!=cKeySecUserMagMap_.end())
        {
            return true;
        }

        return false;

    }

    SecUserMag::CGarbo::CGarbo()
    {
    }

    SecUserMag::CGarbo::~CGarbo()
    {
        if (SecUserMag::uniqueInstance_)
        {
            delete SecUserMag::uniqueInstance_;
        }
    }


    SecUserMag * SecUserMag::uniqueInstance_ =0;
}
