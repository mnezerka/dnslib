/**
 * DNS Resource Record 
 *
 * Copyright (C) 2014 - Michal Nezerka <michal.nezerka@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>

#include "exception.h"
#include "buffer.h"
#include "rr.h"

using namespace dns;
using namespace std;

/////////// RDataA /////////////////

void RDataA::decode(Buffer &buffer)
{
    // get data from buffer
    const char *data = buffer.getBytes(4);
    for (uint i = 0; i < 4; i++)
        mAddr[i] = data[i]; 
}

void RDataA::encode(Buffer &buffer)
{
    for (uint i = 0; i < 4; i++)
        buffer.put8bits(mAddr[i]);
}

std::string RDataA::asString()
{
    ostringstream text;
    text << "<<RData A addr=" << static_cast<uint>(mAddr[0]) << '.' << static_cast<uint>(mAddr[1]) << '.' << static_cast<uint>(mAddr[2]) << '.' << static_cast<uint>(mAddr[3]);

    return text.str();
}


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

/////////// RDataCNAME /////////////////

void RDataCNAME::decode(Buffer &buffer)
{
    mDomainName = buffer.getDnsDomainName();
}

void RDataCNAME::encode(Buffer &buffer)
{
    buffer.putDnsDomainName(mDomainName);
}

std::string RDataCNAME::asString()
{
    ostringstream text;
    text << "<<CNAME domainName=" << mDomainName;
    return text.str();
}

/////////// RDataHINFO /////////////////

void RDataHINFO::decode(Buffer &buffer)
{
    mCpu = buffer.getDnsCharacterString();
    mOs = buffer.getDnsCharacterString();
}

void RDataHINFO::encode(Buffer &buffer)
{
    buffer.putDnsCharacterString(mCpu);
    buffer.putDnsCharacterString(mOs);
}

std::string RDataHINFO::asString()
{
    ostringstream text;
    text << "<<HINFO cpu=" << mCpu << " os=" << mOs;
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
    mClass = static_cast<eClass>(buffer.get16bits());
    mTtl = buffer.get32bits();
    mRDataSize = buffer.get16bits();
    if (mRDataSize > 0)
    {
        switch (mType) {
            case typeA:
                mRData = new RDataA();
                mRData->decode(buffer);
                break;
            case typeNAPTR:
                mRData = new RDataNAPTR();
                mRData->decode(buffer);
                break;
            case typeCNAME:
                mRData = new RDataCNAME();
                mRData->decode(buffer);
                break;
            default:
                mRData = new RDataRaw(mRDataSize);
                mRData->decode(buffer);
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


