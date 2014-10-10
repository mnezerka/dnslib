#include <iostream>
#include <string>
#include <iomanip>
#include <algorithm>
#include <string.h>

#include "buffer.h"
#include "exception.h"
using namespace dns;
using namespace std;

uchar Buffer::get8bits()
{
    // check if we are inside buffer
    checkAvailableSpace(1);        
    uchar value = static_cast<uchar> (mBufferPtr[0]);
    mBufferPtr += 1;

    return value;
}

void Buffer::put8bits(const uchar value)
{
    // check if we are inside buffer
    checkAvailableSpace(1);        
    *mBufferPtr = value & 0xFF;
    mBufferPtr++;
}

uint Buffer::get16bits()
{
    // check if we are inside buffer
    checkAvailableSpace(2);        
    uint value = static_cast<uchar> (mBufferPtr[0]);
    value = value << 8;
    value += static_cast<uchar> (mBufferPtr[1]);
    mBufferPtr += 2;

    return value;
}

void Buffer::put16bits(const uint value)
{
    // check if we are inside buffer
    checkAvailableSpace(2);        
    *mBufferPtr = (value & 0xFF00) >> 8;
    mBufferPtr++;
    *mBufferPtr = value & 0xFF;
    mBufferPtr++;
}

uint Buffer::get32bits()
{
    // check if we are inside buffer
    checkAvailableSpace(4);
    uint value = 0;
    value += (static_cast<uchar> (mBufferPtr[0])) << 24;
    value += (static_cast<uchar> (mBufferPtr[1])) << 16;
    value += (static_cast<uchar> (mBufferPtr[2])) << 8;
    value += static_cast<uchar> (mBufferPtr[3]);
    mBufferPtr += 4;

    return value;
}

void Buffer::put32bits(const uint value)
{
    // check if we are inside buffer
    checkAvailableSpace(4);
    *mBufferPtr = (value & 0xFF000000) >> 24;
    mBufferPtr++;
    *mBufferPtr = (value & 0x00FF0000) >> 16;
    mBufferPtr++;
    *mBufferPtr = (value & 0x0000FF00) >> 8;
    mBufferPtr++;
    *mBufferPtr = value & 0x000000FF;
    mBufferPtr++;
}

void Buffer::setPos(const uint pos)
{
    // check if we are inside buffer
    if (pos >= mBufferSize)
        throw(Exception("Try to set pos behind buffer"));
    mBufferPtr = mBuffer + pos; 
}

char* Buffer::getBytes(const uint count) 
{
    checkAvailableSpace(count);
    char *result = mBufferPtr;    
    mBufferPtr += count;

    return result;
}

void Buffer::putBytes(const char* data, const uint count) 
{
    if (count == 0)
        return;

    // check if we are inside buffer
    checkAvailableSpace(count);
    memcpy(mBufferPtr, data, sizeof(char) * count);
    mBufferPtr += count;
}

std::string Buffer::getDnsCharacterString()
{
    std::string result("");
 
    // read first octet (byte) to know length of string
    uint stringLen = get8bits();
    if (stringLen > 0)
        result.append(getBytes(stringLen), stringLen); // read label

    return result;
}

void Buffer::putDnsCharacterString(const std::string value)
{
    put8bits(value.length());
    putBytes(value.c_str(), value.length());
}

std::string Buffer::getDnsDomainName()
{
    std::string domain;

    while (true)
    {
        uchar ctrlCode = get8bits();
        if (ctrlCode == 0)
        {
            break;
        }
        else if (ctrlCode >> 6 == 3)
        {
            // read second byte
            uchar ctrlCode2 = get8bits();
            uint linkAddr = ((ctrlCode & 63) << 8) + ctrlCode2;
            // change buffer position
            uint saveBuffPos = getPos();
            setPos(linkAddr);
            std::string linkDomain = getDnsDomainName();
            setPos(saveBuffPos);
            if (domain.size() > 0)
                domain.append(".");
            domain.append(linkDomain);
            // link always terminates the domain name (no zero at the end in this case) 
            break;
        }
        else
        {
            if (domain.size() > 0)
                domain.append(".");
            domain.append(getBytes(ctrlCode), ctrlCode); // read label
        }
    }

    return domain;
}

void Buffer::putDnsDomainName(const std::string value)
{
    char domain[MAX_LABEL_LEN + 1]; // one additional byte for teminating zero byte
    uint domainLabelIndexes[MAX_LABEL_LEN + 1]; // one additional byte for teminating zero byte

    if (value.length() > MAX_DOMAIN_LEN)
        throw(Exception("domain name too long to be stored in dns message (limit is 63 characters)"));

    // write empty domain
    if (value.length() == 0)
    {
        put8bits(0);
        return;
    }

    // convert value to <domain> without links as defined in RFC
    // blue.ims.cz -> |4|b|l|u|e|3|i|m|s|2|c|z|0|
    uint labelLen = 0;
    uint labelLenPos = 0;
    uint domainPos = 1;
    uint ix = 0;
    uint domainLabelIndexesCount = 0;
    while (true) 
    {    
        if (value[ix] == '.' || ix == value.length())
        {
            domain[labelLenPos] = labelLen; 
            domainLabelIndexes[domainLabelIndexesCount++] = labelLenPos; 
            // finish at the end of the string value 
            if (ix == value.length())
            {
                // terminating zero byte
                domain[domainPos] = 0;
                domainPos++;
                break;
            }

            labelLenPos = domainPos;
            labelLen = 0;
        }
        else
        {
            labelLen++;
            domain[domainPos] = value[ix];
        }
        domainPos++;
        ix++;
    }

    // look for domain name parts in buffer and look for fragments for compression
    // loop over all domain labels 
    bool compressionTipFound = false;
    uint compressionTipPos = 0;
    for (uint i = 0; i < domainLabelIndexesCount; i++)
    {
        // position of current label in domain buffer
        uint domainLabelPos = (uint)domainLabelIndexes[i];
        // pointer to subdomain (including initial byte for first label length) 
        char* subDomain = domain + domainLabelPos;
        // length of subdomain (e.g. |3|i|m|s|2|c|z|0| for blue.ims.cz)
        uint subDomainLen = domainPos - domainLabelPos;

        // find buffer range that makes sense to search in
        uint buffLen = mBufferPtr - mBuffer;
        // if buffer is large enought for searching
        if (buffLen > subDomainLen)
        {
            // modify buffer length
            buffLen -= subDomainLen;
            // go through buffer from beginning and try to find occurence of compression tip
            for (uint buffPos = 0; buffPos < buffLen ; buffPos++)
            { 
                // compare compression tip and content at current position in buffer
                compressionTipFound = (memcmp(mBuffer + buffPos, subDomain, subDomainLen) == 0); 
                if (compressionTipFound)
                {
                    compressionTipPos = buffPos;
                    break;
                }
            }
        }
    
        if (compressionTipFound)
        {
            // link starts with value bin(1100000000000000)
            uint linkValue = 0xc000; 
            linkValue += compressionTipPos;
            put16bits(linkValue);
            break;
        }
        else
        {
            // write label
            uint labelLen = subDomain[0];
            putBytes(subDomain, labelLen + 1);
        }
    }
    // write terminating zero if no compression tip was found and all labels are writtten to buffer
    if (!compressionTipFound)
        put8bits(0);
}

void Buffer::dump()
{
    cout << "Buffer dump" << endl;
    cout << "size: " << (mBufferPtr - mBuffer) << " bytes" << endl;
    cout << "---------------------------------" << setfill('0');

    for (int i = 0; i < (mBufferPtr - mBuffer); i++) {
        if ((i % 10) == 0) {
            cout << endl << setw(2) << i << ": ";
        }
        uchar c = mBuffer[i];
        cout << hex << setw(2) << int(c) << " " << dec;
    }
    cout << endl << setfill(' ');
    cout << "---------------------------------" << endl;
}

void Buffer::checkAvailableSpace(const uint additionalSpace)
{
    // check if buffer pointer is valid 
    if (mBufferPtr < mBuffer)
        throw(Exception("Buffer pointer is invalid"));

    // get position in buffer 
    uint bufferPos = (mBufferPtr - mBuffer);

    // check if we are inside buffer
    if ((bufferPos + additionalSpace) > mBufferSize)
        throw(Exception("Try to read behind buffer"));
}


