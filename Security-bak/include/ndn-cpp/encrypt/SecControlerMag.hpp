
/*
* create by Marty, manage the SecControler 2017/07/05
* add functions for E-KEY C-KEY save and get, marty, 2017/07/11
*
*
*
*
*/

#ifndef NDN_SECCONTROLERMAG_HPP
#define NDN_SECCONTROLERMAG_HPP

#include <stdio.h>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <unistd.h>

#include <map>
#include "../face.hpp"
#include "../security/key-chain.hpp"
#include "encrypt-error.hpp"
#include "producer-db.hpp"
#include "SecControler.hpp"

namespace pki{

class SecControlerMag {
public:
    ~SecControlerMag();
    static SecControlerMag * getInstance();

    void
    Init(Name& slefPrefix, Name& selfSuffix);

    void 
    onRegisterInterest(const ptr_lib::shared_ptr<const Name>& prefix,
    const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
    uint64_t interestFilterId,
    const ptr_lib::shared_ptr<const InterestFilter>& filter);

    void 
    onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix);

    void
    processRegister(Name  selfPrefix, Name selfSuffix); 
    
    void
    startSecControler(Name remotePrefix,Name remoteSuffix, Name selfPrefix, Name selfSuffix);

    bool
    hasTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix);

    void
    getTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ekey);

    bool
    saveTheSecUserEKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ekey);

    bool
    hasTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix);

    void
    getTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey);

    bool
    saveTheSecUserCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey);

/*    
    static void
    encryptData(Data& data, const Blob& payload, const Name& keyName, const Blob& key,
    const EncryptParams& params);

    static void
    decryptData(Data& data, const Blob& payload, const Name& keyName, const Blob& key,
    const EncryptParams& params);
*/    
    Face secControlerMagFace_;
    KeyChain secControlerMagKeyChain_;

    //class CGarbo for the destruction of the static SecUserMag instance
    class CGarbo{
        public:
        ~CGarbo();
        CGarbo();
        
    };

    static CGarbo garbo;

private:    
    SecControlerMag();
    static SecControlerMag * uniqueInstance_;
    // The map key is the C-KEY name. The value is the encoded key Blob.
    std::map<Name, Blob> cKeySecControlerMagMap_;

    // The map key is the E-KEY name. The value is the encoded key Blob.
    std::map<Name, Blob> eKeySecControlerMagMap_;   

};

}

#endif
