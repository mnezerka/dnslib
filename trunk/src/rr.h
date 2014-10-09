
// http://www.ietf.org/rfc/rfc2915.txt - NAPTR

#ifndef _DNS_RR_H
#define	_DNS_RR_H

#include <string>
#include <vector>

#include "dns.h"
#include "buffer.h"

namespace dns {

class RData {
public:
    virtual void decode(Buffer &buffer) = 0;
    virtual std::string asString() = 0;

};

class RDataRaw : public RData {

public:
    RDataRaw(uint dataSize) : mDataSize(dataSize), mData(NULL) { };
    ~RDataRaw()  { if (mData) delete[] mData; };

    virtual void decode(Buffer &buffer);
    virtual std::string asString();

private:
    // raw data
    uint mDataSize;
    char* mData;

};


class RDataNAPTR : public RData {

public:    

    RDataNAPTR() : mOrder(0), mPreference(0), mFlags(""), mServices(""), mRegExp(""), mReplacement("") { };
    void decode(Buffer &buffer);
    virtual std::string asString();

private:

    uint mOrder;
    uint  mPreference;
    std::string mFlags;
    std::string mServices;
    std::string mRegExp;
    std::string mReplacement;
};

class ResourceRecord
{
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

public:

    /* Constructor */
    ResourceRecord() : mName(""), mType (0), mClass(0), mTtl(0), mRDataSize(0), mRData(NULL) { };

    void setName(std::string newName) { mName = newName; };
    uint getName() const;

    void setType(uint type) { mType = type; };
    uint getType() const;

    void setClass(uint newClass) { mClass = newClass; };
    uint getClass() const;

    void setTtl(uint newTtl) { mTtl = newTtl; };
    uint getTtl() const;

    void setRData(const char * rData, uint rDataSize);
    uint getRDataSize() const;
    const char* getRData() const;

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

