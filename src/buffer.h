#ifndef _DNS_BUFFER_H
#define	_DNS_BUFFER_H

#include "dns.h"

namespace dns
{

class Buffer
{
private: 

    // buffer content
    const char* mBuffer;
    // buffer content size
    const uint mBufferSize;
    // current position in buffer
    const char* mBufferPtr;

public:

    Buffer(const char* buffer, uint bufferSize) : mBuffer(buffer), mBufferSize(bufferSize), mBufferPtr(buffer) { }

    uint getPos() { return mBufferPtr - mBuffer; }
    void setPos(const uint pos);

    uint getSize() { return mBufferSize; }

    uchar get8bits();
    uint get16bits();
    uint get32bits();
    const char* getBytes(uint count);
    std::string getDnsCharacterString();
    std::string getDnsDomainName();
};

} // namespace
#endif	/* _DNS_BUFFER_H */

