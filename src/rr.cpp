
//#include <iostream>
//#include <sstream>
//#include <cstring>

#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>

#include "exception.h"
#include "buffer.h"
#include "rr.h"

using namespace dns;
using namespace std;

void RecordNAPTR::decode(const char* buffer, int bufferSize)
{
    Buffer buff(buffer, bufferSize);   

    mOrder = buff.get16bits();
    mPreference = buff.get16bits();
    mFlags = buff.getDnsCharacterString();
    mServices = buff.getDnsCharacterString();
    mRegExp = buff.getDnsCharacterString();
    mReplacement = buff.getDnsDomainName(); 
}

void ResourceRecord::setRData(const char * rData, uint rDataSize)
{
    if (rDataSize > 2048)    
        throw(Exception("RData have size > 2048 bytes"));

    // free memory
    if (mRData)
        delete[] mRData;

    // allocate new memory
    mRData = new char[rDataSize];

    // copy rdata
    std::memcpy(mRData, rData, rDataSize);

    // set new size
    mRDataSize = rDataSize;
}

std::string ResourceRecord::asString()
{
    ostringstream text;
    text << "<DNS RR: "  << mName << " rtype=" << mType << " rclass=" << mClass << " ttl=" << mTtl << " rdata=" <<  mRDataSize << " bytes" << endl;
    return text.str();
}




