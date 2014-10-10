
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

/////////// RDataRaw /////////////////

RDataRaw::~RDataRaw()
{
    delete[] mData;
    mData = NULL;
}

void RDataRaw::decode(Buffer &buffer)
{
    // get data from buffer
    const char *data = buffer.getBytes(mDataSize);
 
    // allocate new memory
    mData = new char[mDataSize];

    // copy rdata
    std::memcpy(mData, data, mDataSize);
}

void RDataRaw::encode(Buffer &buffer)
{
    buffer.putBytes(mData, mDataSize);
}

std::string RDataRaw::asString()
{
    ostringstream text;
    text << "<<RData Raw size=" << mDataSize;
    return text.str();
}

/////////// RDataNAPTR /////////////////

void RDataNAPTR::decode(Buffer &buffer)
{
    mOrder = buffer.get16bits();
    mPreference = buffer.get16bits();
    mFlags = buffer.getDnsCharacterString();
    mServices = buffer.getDnsCharacterString();
    mRegExp = buffer.getDnsCharacterString();
    mReplacement = buffer.getDnsDomainName(); 
}

void RDataNAPTR::encode(Buffer &buffer)
{
    buffer.put16bits(mOrder);
    buffer.put16bits(mPreference);
    buffer.putDnsCharacterString(mFlags);
    buffer.putDnsCharacterString(mServices);
    buffer.putDnsCharacterString(mRegExp);
    buffer.putDnsDomainName(mReplacement);
}

std::string RDataNAPTR::asString()
{
    ostringstream text;
    text << "<<NAPTR order=" << mOrder << " preference=" << mPreference << " flags=" << mFlags << " services=" << mServices << " regexp=" << mRegExp << " replacement=" << mReplacement;
    return text.str();
}

/////////// ResourceRecord ////////////

ResourceRecord::~ResourceRecord()
{
    delete(mRData);
    mRData = NULL;
}

void ResourceRecord::decode(Buffer &buffer)
{
    mName = buffer.getDnsDomainName();
    mType = buffer.get16bits();
    mClass = buffer.get16bits();
    mTtl = buffer.get32bits();
    mRDataSize = buffer.get16bits();
    if (mRDataSize > 0)
    {
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
}

void ResourceRecord::encode(Buffer &buffer)
{
    buffer.putDnsDomainName(mName);
    buffer.put16bits(mType);
    buffer.put16bits(mClass);
    buffer.put32bits(mTtl);
    // save position of buffer for later use (write length of RData part)     
    uint bufferPosRDataLength = buffer.getPos(); 
    buffer.put16bits(0); // this value could be later overwritten
    // encode RData if present
    if (mRData)
    {
        mRData->encode(buffer);
        mRDataSize = buffer.getPos() - bufferPosRDataLength - 2; // 2 because two bytes for RData length are not part of RData block
        uint bufferLastPos = buffer.getPos(); 
        buffer.setPos(bufferPosRDataLength);
        buffer.put16bits(mRDataSize); // overwritte 0 with actual size of RData
        buffer.setPos(bufferLastPos);
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


