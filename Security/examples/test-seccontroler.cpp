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
//#include <ndn-cpp/encrypt/producer.hpp>
#include <ndn-cpp/encrypt/SecControler.hpp>

#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/hmac-with-sha256-signature.hpp>
//#include <ndn-cpp/encrypt/producerAdapter.hpp>


using namespace std;
using namespace pki;
using namespace pki::func_lib;

static int counter=0;

void 
onData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
{
    //++callbackCount_;
    counter++;
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    /*
    for (size_t i = 0; i < data->getContent().size(); ++i)
        cout << (*data->getContent())[i];
        */
        hexdump(stdout, "== public key ==",
                        data->getContent().buf(),
                        data->getContent().size());
                        
        printf("\n");

    
    
    cout <<endl<< "onData"<<endl;

    //registered=true;
}

void 
onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
{
    //++callbackCount_;
    counter++;
    cout << "Time out for interest " << interest->getName().toUri() << endl;
}


int main(int argc, char** argv)
{
    Name Prefix("/Prefix");
    Name suffix("/Content");

    Name producerName("/REGISTER/content");
    string databaseFilePath="./producer.db";
    
    ptr_lib::shared_ptr<ProducerDb> testDb(new Sqlite3ProducerDb(databaseFilePath)); 

    //Register process
    SecControler producer(Prefix,suffix,testDb,databaseFilePath);
    std::thread regThread(&SecControler::registerConsumer,&producer,producerName);
    regThread.detach();

    //get the EKEY
    Name keyName("/Prefix/READ/Content/E-KEY");
    std::thread getEkeyThread(&SecControler::getEkey,&producer,keyName);
    getEkeyThread.join();

    //Process ready for consume
    Name readyForConsume("/READY/Content");
    std::thread readyThread(&SecControler::readyForConsume,&producer,readyForConsume);
    readyThread.detach();

    //producerAdapter.registerConsumer(producerName);
    
    //Name cKeyName = Name("/Prefix/SAMPLE/Content/C-KEY");
    //cKeyName= producerAdapter.addFixedContentKey(cKeyName);
    
    Name consumerPrefix("/Prefix/SAMPLE/Content");

    producer.produceSecureContent(consumerPrefix);

    return 0;
}

