
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

void RDataRaw::decode(Buffer &buffer)
{
    // get data from buffer
    const char *data = buffer.getBytes(mDataSize);
 
    // allocate new memory
    mData = new char[mDataSize];

    // copy rdata
    std::memcpy(mData, data, mDataSize);
}

std::string RDataRaw::asString()
{
    ostringstream text;
    text << "<<RData Raw size=" << mDataSize;
    return text.str();
}

void RDataNAPTR::decode(Buffer &buffer)
{
    mOrder = buffer.get16bits();
    mPreference = buffer.get16bits();
    mFlags = buffer.getDnsCharacterString();
    mServices = buffer.getDnsCharacterString();
    mRegExp = buffer.getDnsCharacterString();
    mReplacement = buffer.getDnsDomainName(); 
}

std::string RDataNAPTR::asString()
{
    ostringstream text;
    text << "<<NAPTR order=" << mOrder << " preference=" << mPreference << " flags=" << mFlags << " services=" << mServices << " regexp=" << mRegExp << " replacement=" << mReplacement;
    return text.str();
}

void ResourceRecord::decode(Buffer &buffer)
{
    std::string rrName = buffer.getDnsDomainName();
    mType = buffer.get16bits();
    mClass = buffer.get16bits();
    mTtl = buffer.get32bits();
    mRDataSize = buffer.get16bits();
    switch (mType) {
        case typeNAPTR:
            mRData = new RDataNAPTR();
            mRData->decode(buffer);
            break;
        default:
            mRData = new RDataRaw(mRDataSize);
            mRData->decode(buffer);
            //rr->setRData(buffer.getBytes(rrRLength), rrRLength);
    }
}

std::string ResourceRecord::asString()
{
    ostringstream text;
    text << "<DNS RR: "  << mName << " rtype=" << mType << " rclass=" << mClass << " ttl=" << mTtl << " rdata=" <<  mRDataSize << " bytes ";
    if (mRData)
        text << mRData->asString();
    text << endl;
    return text.str();
}


