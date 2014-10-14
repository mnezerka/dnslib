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

/////////// RDataWithName ///////////

void RDataWithName::decode(Buffer &buffer, const uint size)
{
    mName = buffer.getDnsDomainName();
}

void RDataWithName::encode(Buffer &buffer)
{
    buffer.putDnsDomainName(mName);
}

/////////// RDataCNAME /////////////////

std::string RDataCNAME::asString()
{
    ostringstream text;
    text << "<<CNAME domainName=" << getName();
    return text.str();
}
//
/////////// RDataHINFO /////////////////

void RDataHINFO::decode(Buffer &buffer, const uint size)
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

/////////// RDataMB /////////////////

std::string RDataMB::asString()
{
    ostringstream text;
    text << "<<MB madname=" << getName();
    return text.str();
}
//
/////////// RDataMD /////////////////

std::string RDataMD::asString()
{
    ostringstream text;
    text << "<<MD madname=" << getName();
    return text.str();
}
//
/////////// RDataMF /////////////////

std::string RDataMF::asString()
{
    ostringstream text;
    text << "<<MF madname=" << getName();
    return text.str();
}

/////////// RDataMG /////////////////

std::string RDataMG::asString()
{
    ostringstream text;
    text << "<<MG madname=" << getName();
    return text.str();
}

/////////// RDataMINFO /////////////////

void RDataMINFO::decode(Buffer &buffer, const uint size)
{
    // TODO
}

void RDataMINFO::encode(Buffer &buffer)
{
    // TODO
}

std::string RDataMINFO::asString()
{
    ostringstream text;
    text << "<<MINFO rmailbx=" << mRMailBx << " mailbx=" << mMailBx;
    return text.str();
}


/////////// RDataMR /////////////////

std::string RDataMR::asString()
{
    ostringstream text;
    text << "<<MR newname=" << getName();
    return text.str();
}


/////////// RDataMX /////////////////
void RDataMX::decode(Buffer &buffer, const uint size)
{
    // TODO
}

void RDataMX::encode(Buffer &buffer)
{
    // TODO
}

std::string RDataMX::asString()
{
    ostringstream text;
    text << "<<MX preference=" << mPreference << " exchange=" << mExchange;
    return text.str();
}

/////////// RDataNULL /////////////////

RDataNULL::~RDataNULL()
{
    delete[] mData;
    mData = NULL;
}

void RDataNULL::decode(Buffer &buffer, const uint size)
{
    // get data from buffer
    const char *data = buffer.getBytes(size);
 
    // allocate new memory
    mData = new char[size];

    // copy rdata
    std::memcpy(mData, data, mDataSize);

    // set new size
    mDataSize = size;
}

void RDataNULL::encode(Buffer &buffer)
{
    buffer.putBytes(mData, mDataSize);
}

std::string RDataNULL::asString()
{
    ostringstream text;
    text << "<<RData Raw size=" << mDataSize;
    return text.str();
}

/////////// RDataNS /////////////////

std::string RDataNS::asString()
{
    ostringstream text;
    text << "<<NS nsdname=" << getName();
    return text.str();
}

/////////// RDataPTR /////////////////

std::string RDataPTR::asString()
{
    ostringstream text;
    text << "<<PTR ptrdname=" << getName();
    return text.str();
}

/////////// RDataSOA /////////////////

void RDataSOA::decode(Buffer &buffer, const uint size)
{
    // TODO
}

void RDataSOA::encode(Buffer &buffer)
{
    // TODO
}

std::string RDataSOA::asString()
{
    ostringstream text;
    text << "<<SOA TODO" ;
    return text.str();
}


/////////// RDataTXT /////////////////

void RDataTXT::decode(Buffer &buffer, const uint size)
{
    // TODO
}

void RDataTXT::encode(Buffer &buffer)
{
    // TODO
}

std::string RDataTXT::asString()
{
    ostringstream text;
    text << "<<TXT TODO" ;
    return text.str();
}

/////////// RDataA /////////////////

void RDataA::decode(Buffer &buffer, const uint size)
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

/////////// RDataNAPTR /////////////////

void RDataNAPTR::decode(Buffer &buffer, const uint size)
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
    mType = static_cast<eRDataType>(buffer.get16bits());
    mClass = static_cast<eClass>(buffer.get16bits());
    mTtl = buffer.get32bits();
    mRDataSize = buffer.get16bits();
    if (mRDataSize > 0)
    {
        switch (mType) {
            case RDATA_CNAME:
                mRData = new RDataCNAME();
                break;
            case RDATA_HINFO:
                mRData = new RDataCNAME();
                break;
            case RDATA_MB:
                mRData = new RDataMB();
                break;
            case RDATA_MD:
                mRData = new RDataMD();
                break;
            case RDATA_MF:
                mRData = new RDataMF();
                break;
            case RDATA_MG:
                mRData = new RDataMG();
                break;
            case RDATA_MINFO:
                mRData = new RDataMINFO();
                break;
            case RDATA_MR:
                mRData = new RDataMR();
                break;
            case RDATA_MX:
                mRData = new RDataMX();
                break;
            case RDATA_NS:
                mRData = new RDataNS();
                break;
            case RDATA_PTR:
                mRData = new RDataPTR();
                break;
            case RDATA_SOA:
                mRData = new RDataSOA();
                break;
            case RDATA_TXT:
                mRData = new RDataTXT();
                break;
            case RDATA_A:
                mRData = new RDataA();
                break;
            case RDATA_WKS:
                mRData = new RDataA();
                break;
            case RDATA_NAPTR:
                mRData = new RDataNAPTR();
                break;
            default:
                mRData = new RDataNULL();
        }
        uint bPos = buffer.getPos();
        mRData->decode(buffer, mRDataSize);
        if (buffer.getPos() - bPos != mRDataSize)
            throw (Exception("Number of decoded bytes are different than expected size"));
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


