
/*
* create by Marty, manage the SecUser 2017/07/04
*
*
*
*
*
*/

#ifndef NDN_SECUSERMAG_HPP
#define NDN_SECUSERMAG_HPP

#include <map>

#include "../data.hpp"
#include "../face.hpp"
#include "../security/key-chain.hpp"
#include "encrypt-error.hpp"
#include "encrypted-content.hpp"
#include "consumer-db.hpp"

namespace pki {

class SecUserMag {
    
public:

    ~SecUserMag();

    static SecUserMag *
    getInstance();

    void
    Init(Name &selfPrefix, Name &selfSuffix);
    
    void
    processReplyPublicKey(Name selfPrefix, Name selfSuffix);

    void
    onPublicKeyInterest(const ptr_lib::shared_ptr<const Name>& prefix,
        const ptr_lib::shared_ptr<const Interest>& interest, Face& face, 
        uint64_t interestFilterId,
        const ptr_lib::shared_ptr<const InterestFilter>& filter);
        
    void
    onPublicKeyFailed(const ptr_lib::shared_ptr<const Name>& prefix);

    void
    negotiateContentKey(Name remotePrefix,Name remoteSuffix, Name selfPrefix, Name selfSuffix);

    bool
    hasTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix);

    void
    getTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey);

    bool
    saveTheSecControlerCKey(Name &remotePrefix,Name &remoteSuffix,Blob *Ckey);



    /*

    static void
    encryptData(Data& data, const Blob& payload, const Name& keyName, const Blob& key,
    const EncryptParams& params);

    static void
    decryptData(Data& data, const Blob& payload, const Name& keyName, const Blob& key,
    const EncryptParams& params);
*/
    //class CGarbo for the destruction of the static SecUserMag instance
    class CGarbo{
        public:
        ~CGarbo();
        CGarbo();
        
    };

    static CGarbo garbo;
    
private:
    SecUserMag();
    static SecUserMag * uniqueInstance_;
    KeyChain keyChain_;  
   
    // The map key is the C-KEY name. The value is the encoded key Blob.
    std::map<Name, Blob> cKeySecUserMagMap_;

    // The map key is the seccontroler name. The value is the encoded key Blob.
    std::map<Name, Blob> negotisationResultSecUserMagMap_;      

    
};

}
#endif
