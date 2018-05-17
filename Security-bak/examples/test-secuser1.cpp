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
#include <ndn-cpp/encrypt/SecUserMag.hpp>

//#include <ndn-cpp/encrypt/schedule.hpp>

//#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
//#include <ndn-cpp/encrypt/algo/encryptor.hpp>

using namespace std;
using namespace pki;
using namespace pki::func_lib;


int main(int argc, char** argv)
{	

    Name groupName = Name("/Prefix/READ");
    Name contentName = Name("/Prefix/SAMPLE/Content");
    //Name dKeyName = Name("/Prefix/SAMPLE/Content/D-KEY/20150101T100000/20150101T120000");
    
    //Name consumerName = Name("/Prefix/SAMPLE/Content");
    
    //string databaseFilePath="./consumer.db";
    
    //ptr_lib::shared_ptr<ConsumerDb> testDb(new Sqlite3ConsumerDb(databaseFilePath));

    SecUserMag *secUserMag = SecUserMag::getInstance();
    Name selfprefix("/Prefix");
    Name selfsuffix("SecUser1");
    
    Name remoteprefix("/Prefix");
    Name remotesuffix("SecControler");
    
    secUserMag->Init(selfprefix,selfsuffix);//invote only at the begging of the Singleton instance

    //secUserMag->negotiateContentKey(remoteprefix,remotesuffix,selfprefix,selfsuffix);
    std::thread secUser1(&SecUserMag::negotiateContentKey, secUserMag, remoteprefix, remotesuffix, selfprefix, selfsuffix);
    secUser1.detach();

    Name selfprefix1("/Prefix");
    Name selfsuffix1("SecUser1");

   Name remoteprefix1("/Prefix");
   Name remotesuffix1("SecControler1");

   std::thread secUser2(&SecUserMag::negotiateContentKey, secUserMag, remoteprefix1, remotesuffix1, selfprefix1, selfsuffix1);
   secUser2.detach();
    
    //return 0;
        while(1)
        {
        usleep(10);
        }

}

