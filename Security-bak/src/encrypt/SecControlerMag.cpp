/*
* create by Marty, manage the SecControler 2017/07/05
* add functions for E-KEY C-KEY save and get, marty, 2017/07/11
*
*
*
*
*/
#include <thread>
#include <ndn-cpp/encrypt/algo/encryptor.hpp>
#include <ndn-cpp/encrypt/SecControlerMag.hpp>

using namespace std;
using namespace pki;
using namespace pki::func_lib;

namespace pki {
    SecControlerMag::SecControlerMag()
    {
    }

    SecControlerMag::~SecControlerMag()
    {
    }

    SecControlerMag *
    SecControlerMag::getInstance()
    {
        if(NULL == uniqueInstance_)
        {
            uniqueInstance_ = new SecControlerMag();
        }

        return uniqueInstance_;
    }

    void
    SecControlerMag::Init(Name& selfPrefix, Name& selfSuffix)
    {
     
        // The default Face will connect using a Unix socket, or to "localhost".

        //int repeatAttempts = 3;
        
        std::thread regThread(&SecControlerMag::processRegister,this,selfPrefix,selfSuffix);
        regThread.detach();

    }

    // on register Interest.
    void 
    SecControlerMag::onRegisterInterest(const ptr_lib::shared_ptr<const Name>& prefix,
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

       if (secControlerMagKeyChain_.verifyInterestWithHmacWithSha256(newInterest, key))
       //if (keyChain_.verifyInterest(newInterest, NULL,NULL,0))
       cout << "Freshly-signed interest signature verification: VERIFIED" << endl;
       else
       cout << "Freshly-signed interest signature verification: FAILED" << endl;

       // Make and sign a Data packet.
       Data data(newInterest.getName());
       string content(data.getName().toUri());

       data.setContent((const uint8_t *)&content[0], content.size());
       cout<<"secControlerMagKeyChain_->sign"<<endl;

       KeyChain *keyChain_=face.getCommandKeyChain();
       keyChain_->sign(data, keyChain_->getDefaultCertificateName());
        //keyChain_->sign(data);
       
       cout << "Sent content " << content << endl;
       face.putData(data);
    }

    // onRegisterFailed.
    void 
    SecControlerMag::onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
       cout << "Register failed for prefix " << prefix->toUri() << endl;
    }
    void
    SecControlerMag::processRegister(Name  selfPrefix, Name selfSuffix)
    {        
        //Name prefix("Prefix/REGISTER/Content");
        Name registName(selfPrefix);
        registName.append(Encryptor::getNAME_COMPONENT_REGISTER()).append(selfSuffix);
        //Face registerFace;
        //KeyChain registerKeyChain;
        secControlerMagFace_.setCommandSigningInfo(secControlerMagKeyChain_, secControlerMagKeyChain_.getDefaultCertificateName());

        // Also use the default certificate name to sign data packets.
        cout << "Register prefix  " << registName.toUri() << endl;
        
        // TODO: After we remove the registerPrefix with the deprecated OnInterest,
        // we can remove the explicit cast to OnInterestCallback (needed for boost).
        secControlerMagFace_.registerPrefix(registName, bind(&SecControlerMag::onRegisterInterest,this,_1,_2,_3,_4,_5), bind(&SecControlerMag::onRegisterFailed,this,_1));    

        while (1) {
            secControlerMagFace_.processEvents();

        }
        
    }
    
    void
    SecControlerMag::startSecControler(Name remotePrefix,Name remoteSuffix, Name selfPrefix, Name selfSuffix)
    {
        cout<<"startSecControler remoteSuffix:"<<remoteSuffix<<endl;
        SecControler secControler(remotePrefix,remoteSuffix, selfPrefix, selfSuffix);
        
        secControler.processSecUserEventGetContentKey(remotePrefix,remoteSuffix, selfPrefix, selfSuffix);   
    }

    bool
    SecControlerMag::hasTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix)
    {
        Name eKeyName(remotePrefix);
        eKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_E_KEY());
        
        if (eKeySecControlerMagMap_.find(eKeyName)!=eKeySecControlerMagMap_.end())
        {
            return true;
        }

        return false;
        
    }

    void
    SecControlerMag::getTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ekey)
    {
        Name eKeyName(remotePrefix);
        eKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_E_KEY());
        *Ekey = eKeySecControlerMagMap_[eKeyName];
    }

    bool
    SecControlerMag::saveTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ekey)
    {
        Name eKeyName(remotePrefix);
        eKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_E_KEY());
        
        if (eKeySecControlerMagMap_.find(eKeyName)!=eKeySecControlerMagMap_.end())
        {
            eKeySecControlerMagMap_.erase(eKeyName);
        }

        eKeySecControlerMagMap_[eKeyName] = *Ekey;
        
        if (eKeySecControlerMagMap_.find(eKeyName)!=eKeySecControlerMagMap_.end())
        {
            return true;
        }

        return false;

    }

    bool
    SecControlerMag::hasTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());

        if (cKeySecControlerMagMap_.find(cKeyName)!=cKeySecControlerMagMap_.end())
        {
            return true;
        }

        return false;
    }

    void
    SecControlerMag::getTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());
        *Ckey = cKeySecControlerMagMap_[cKeyName];
    }


    bool
    SecControlerMag::saveTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey)
    {
        Name cKeyName(remotePrefix);
        cKeyName.append(remoteSuffix).append(Encryptor::getNAME_COMPONENT_C_KEY());

        if (cKeySecControlerMagMap_.find(cKeyName)!=cKeySecControlerMagMap_.end())
        {
            cKeySecControlerMagMap_.erase(cKeyName);
        }

        cKeySecControlerMagMap_[cKeyName] = *Ckey;

        if (cKeySecControlerMagMap_.find(cKeyName)!=cKeySecControlerMagMap_.end())
        {
            return true;
        }

        return false;

    }
    
    SecControlerMag::CGarbo::CGarbo()
    {
    }
    
    SecControlerMag::CGarbo::~CGarbo()
    {
        if (SecControlerMag::uniqueInstance_)
        {
            delete SecControlerMag::uniqueInstance_;
        }
    }

    SecControlerMag * SecControlerMag::uniqueInstance_=0;

}

