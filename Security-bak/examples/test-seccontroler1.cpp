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

#include <cstdlib>
#include <iostream>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/key-chain.hpp>

 #include "stdio.h"

//#include <algorithm>
#include <fstream>
#include <stdexcept>
//#include <ndn-cpp/security/identity/memory-identity-storage.hpp>
//#include <ndn-cpp/security/identity/memory-private-key-storage.hpp>
//#include <ndn-cpp/security/policy/no-verify-policy-manager.hpp>

//#include <ndn-cpp/encrypt/algo/aes-algorithm.hpp>
//#include <ndn-cpp/encrypt/algo/rsa-algorithm.hpp>
//#include <ndn-cpp/encrypt/algo/encryptor.hpp>
//#include <ndn-cpp/encrypt/encrypted-content.hpp>
//#include <ndn-cpp/encrypt/schedule.hpp>
#include <ndn-cpp/encrypt/sqlite3-producer-db.hpp>
#include <ndn-cpp/encrypt/SecControler.hpp>
#include <ndn-cpp/encrypt/SecControlerMag.hpp>

#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/hmac-with-sha256-signature.hpp>

using namespace std;
using namespace pki;
using namespace pki::func_lib;

int main(int argc, char** argv)
{
    Name selfPrefix("/Prefix");
    Name selfSuffix("SecControler1");

    //string databaseFilePath="./producer.db";
    
    //ptr_lib::shared_ptr<ProducerDb> testDb(new Sqlite3ProducerDb(databaseFilePath)); 
    cout<<"SecControlerMag::getInstance"<<endl;
    SecControlerMag * secControlerMag = SecControlerMag::getInstance();

    //Register process
    secControlerMag->Init(selfPrefix,selfSuffix);
    Name remotePrefix("/Prefix") ;
    Name remoteSuffix ("SecUser");

    Name selfPrefix1("/Prefix");
    Name selfSuffix1("SecControler1");

    Name remotePrefix1("/Prefix") ;
    Name remoteSuffix1 ("SecUser1");
    
    //secControlerMag->startSecControler(remotePrefix, remoteSuffix,selfPrefix, selfSuffix);
    std::thread secControler1(&SecControlerMag::startSecControler, secControlerMag, remotePrefix, remoteSuffix, selfPrefix, selfSuffix);
    secControler1.detach();

    std::thread secControler2(&SecControlerMag::startSecControler, secControlerMag, remotePrefix1, remoteSuffix1, selfPrefix1, selfSuffix1);
    secControler2.detach();


    //return 0;
    while(1)
        {
        usleep(10);
        }
}

