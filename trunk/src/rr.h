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

#ifndef _DNS_RR_H
#define	_DNS_RR_H

#include <string>
#include <vector>

#include "dns.h"
#include "buffer.h"

namespace dns {

/** Abstract class that act as base for all Resource Record RData types */
class RData {
public:
    virtual ~RData() { };
    virtual void decode(Buffer &buffer) = 0;
    virtual void encode(Buffer &buffer) = 0;
    virtual std::string asString() = 0;
};

/** Generic RData field which stores raw RData bytes.
 *
 * This class is used for cases when RData type is not known or
 * class for appropriate type is not implemented. */
class RDataRaw : public RData {

public:
    RDataRaw(uint dataSize) : mDataSize(dataSize), mData(NULL) { };
    virtual ~RDataRaw();
    virtual void decode(Buffer &buffer);
    virtual void encode(Buffer &buffer);
    virtual std::string asString();

private:
    // raw data
    uint mDataSize;
    char* mData;

};

// http://www.ietf.org/rfc/rfc2915.txt - NAPTR

class RDataNAPTR : public RData {

public:    
    RDataNAPTR() : mOrder(0), mPreference(0), mFlags(""), mServices(""), mRegExp(""), mReplacement("") { };
    virtual ~RDataNAPTR() { };

    void setOrder(uint newOrder) { mOrder = newOrder; };
    uint getOrder() { return mOrder; };
    void setPreference(uint newPreference) { mPreference = newPreference; };
    uint getPreference() { return mPreference; };
    void setFlags (std::string newFlags) { mFlags = newFlags; };
    std::string getFlags () { return mFlags; };
    void setServices (std::string newServices) { mServices = newServices; };
    std::string getServices () { return mServices; };
    void setRegExp (std::string newRegExp) { mRegExp = newRegExp; };
    std::string getRegExp () { return mRegExp; };
    void setReplacement (std::string newReplacement) { mReplacement = newReplacement; };
    std::string getReplacement () { return mReplacement; };

    virtual void decode(Buffer &buffer);
    virtual void encode(Buffer &buffer);
    virtual std::string asString();

private:
    uint mOrder;
    uint  mPreference;
    std::string mFlags;
    std::string mServices;
    std::string mRegExp;
    std::string mReplacement;
};

/** Represents DNS Resource Record
 *
 * Each resource record has the following format:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                                               /
 *     /                      NAME                     /
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     CLASS                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TTL                      |
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                   RDLENGTH                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *     /                     RDATA                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 
 * where:
 * 
 * NAME            a domain name to which this resource record pertains.
 * 
 * TYPE            two octets containing one of the RR type codes.  This
 *                 field specifies the meaning of the data in the RDATA
 *                 field.
 * 
 * CLASS           two octets which specify the class of the data in the
 *                 RDATA field.
 * 
 * TTL             a 32 bit unsigned integer that specifies the time
 *                 interval (in seconds) that the resource record may be
 *                 cached before it should be discarded.  Zero values are
 *                 interpreted to mean that the RR can only be used for the
 *                 transaction in progress, and should not be cached.
 * 
 * RDLENGTH        an unsigned 16 bit integer that specifies the length in
 *                 octets of the RDATA field.
 * 
 * RDATA           a variable length string of octets that describes the
 *                 resource.  The format of this information varies
 *                 according to the TYPE and CLASS of the resource record.
 *                 For example, the if the TYPE is A and the CLASS is IN,
 *                 the RDATA field is a 4 octet ARPA Internet address. 
 */
class ResourceRecord
{
public:
    // a host address
    static const uint typeA = 1;
    // an authoritative name server
    static const uint typeNS = 2;
    // a mail destination (Obsolete - use MX)
    static const uint typeMD = 3;
    // a mail forwarder (Obsolete - use MX)
    static const uint typeMF = 4;
    // the canonical name for an alias
    static const uint typeCNAME = 5;
    // marks the start of a zone of authority 
    static const uint typeSOA = 6;
    // a mailbox domain name (EXPERIMENTAL)
    static const uint typeMB = 7;
    // a mail group member (EXPERIMENTAL)
    static const uint typeMG = 8;
    // a mail rename domain name (EXPERIMENTAL)
    static const uint typeMR = 9;
    // a null RR (EXPERIMENTAL)
    static const uint typeNULL = 10;
    // a well known service description
    static const uint typeWKS = 11; 
    // a domain name pointer
    static const uint typePTR = 12;
    // host information
    static const uint typeHINFO = 13;
    // mailbox or mail list information 
    static const uint typeMINFO = 14;
    // mail exchange
    static const uint typeMX = 15;

    // naming authority pointer
    static const uint typeNAPTR = 35;

    // text strings
    static const uint typeTXT = 16;
    static const uint typeSRV = 0x0021;
    static const uint typeA6 = 0x0026;
    static const uint typeOPT = 0x0029;
    static const uint typeANY = 0x00ff;

    /* Typical class */
    static const uint  ClassIN = 1; 

    /* Constructor */
    ResourceRecord() : mName(""), mType (0), mClass(0), mTtl(0), mRDataSize(0), mRData(NULL) { };
    ~ResourceRecord();

    void setName(std::string newName) { mName = newName; };
    uint getName() const;

    void setType(uint type) { mType = type; };
    uint getType() const;

    void setClass(uint newClass) { mClass = newClass; };
    uint getClass() const;

    void setTtl(uint newTtl) { mTtl = newTtl; };
    uint getTtl() const;

    //void setRData(const char * rData, uint rDataSize);
    void setRData(RData *newRData) { mRData = newRData; };
    //uint getRDataSize() const;
    //const char* getRData() const;

    void decode(Buffer &buffer);

    void encode(Buffer &buffer);

    std::string asString();

private:
    /* Domain name to which this resource record pertains */
    std::string mName;

    /* Type field */
    uint mType;

    /* Class field */
    uint mClass;

    /* TTL field */
    uint mTtl;

    /* size of RData */
    uint mRDataSize;

    /* rdata */
    RData *mRData;
};

} // namespace
#endif	/* _DNS_RR_H */

