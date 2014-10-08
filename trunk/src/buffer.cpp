
#include "buffer.h"
#include "exception.h"

using namespace dns;
using namespace std;

uchar Buffer::get8bits()
{
    // check if we are inside buffer
    if (mBufferPtr - mBuffer + 1 > mBufferSize)
        throw(Exception("Try to read behind buffer"));
        
    uchar value = static_cast<uchar> (mBufferPtr[0]);
    mBufferPtr += 1;

    return value;
}

uint Buffer::get16bits()
{
    // check if we are inside buffer
    if (mBufferPtr - mBuffer + 2 > mBufferSize)
        throw(Exception("Try to read behind buffer"));
        
    uint value = static_cast<uchar> (mBufferPtr[0]);
    value = value << 8;
    value += static_cast<uchar> (mBufferPtr[1]);
    mBufferPtr += 2;

    return value;
}

uint Buffer::get32bits()
{
    // check if we are inside buffer
    if (mBufferPtr - mBuffer + 4 > mBufferSize)
        throw(Exception("Try to read behind buffer"));

    uint value = 0;
    value += (static_cast<uchar> (mBufferPtr[0])) << 24;
    value += (static_cast<uchar> (mBufferPtr[1])) << 16;
    value += (static_cast<uchar> (mBufferPtr[2])) << 8;
    value += static_cast<uchar> (mBufferPtr[3]);
    mBufferPtr += 4;

    return value;
}

void Buffer::setPos(const uint pos)
{
    // check if we are inside buffer
    if (pos >= mBufferSize)
        throw(Exception("Try to set pos behind buffer"));
    mBufferPtr = mBuffer + pos; 
}

const char* Buffer::getBytes(uint count) 
{
    // check if we are inside buffer
    if (mBufferPtr - mBuffer + count > mBufferSize)
        throw(Exception("Try to read behind buffer"));

    const char *result = mBufferPtr;    
    mBufferPtr += count;

    return result;
}

std::string Buffer::getDnsCharacterString()
{
    std::string result("");

    // check if we are inside buffer
    if (mBufferPtr - mBuffer + 1 > mBufferSize)
        throw(Exception("Try to read behind buffer"));
 
    // read first octet (byte) to know length of string
    uint stringLen = get8bits();
    if (stringLen > 0)
    {
        // check if we are inside buffer
        if (mBufferPtr - mBuffer + stringLen > mBufferSize)
            throw(Exception("Try to read behind buffer"));
     
        result.append(getBytes(stringLen), stringLen); // read label
        mBufferPtr += stringLen;
    }
    return result;
}

std::string Buffer::getDnsDomainName()
{
}
