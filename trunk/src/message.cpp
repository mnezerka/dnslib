/* 
 * File:   message.cpp
 * Author: tomas
 * 
 * Created on 29 de junio de 2009, 17:39
 */

#include <iostream>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>

#include "logger.h"
#include "message.h"
#include "exception.h"

using namespace dns;
using namespace std;

string Message::asString() const throw()
{
    ostringstream text;
    text << "ID: " << showbase << hex << m_id << endl << noshowbase;
    text << "\tfields: [ QR: " << m_qr << " opCode: " << m_opcode << " ]" << endl;
    text << "\tQDcount: " << mQueries.size() << endl;
    text << "\tANcount: " << mAnswers.size() << endl;
    text << "\tNScount: " << mAuthorities.size() << endl;
    text << "\tARcount: " << mAdditional.size() << endl;

    return text.str();
}

void Message::decode(const char* buffer, int bufferSize) throw()
{
    Logger& logger = Logger::instance();
    logger.trace("Message::decode()");
    log_buffer(buffer, bufferSize);

    const char* bufferOrig = buffer;
    unsigned int bufferPos = 0;

    // 1. read header
    if (bufferSize < 12)
        throw(Exception("Invalid DNS message (header)"));

    m_id = get16bits(buffer);
    uint fields = get16bits(buffer);
    m_qr = fields & QR_MASK;
    m_opcode = fields & OPCODE_MASK;
    m_aa = fields & AA_MASK;
    m_tc = fields & TC_MASK;
    m_rd = fields & RD_MASK;
    m_ra = fields & RA_MASK;
    uint qdCount = get16bits(buffer);
    uint anCount = get16bits(buffer);
    uint nsCount = get16bits(buffer);
    uint arCount = get16bits(buffer);
    bufferPos += 12;

    cout << "pos before questions:" << bufferPos << endl;

    // 2. read Question Sections
    for (int i = 0; i < qdCount; i++)
    {
        logger.trace("Message::decoding Query Section");

        
        if (bufferPos >= bufferSize)
            throw(Exception("Invalid DNS message (Question section)"));

        uint qNameSize = 0;
        std::string qName = decodeDomain(bufferOrig, bufferSize, bufferPos, qNameSize);
        buffer += qNameSize;
        bufferPos += qNameSize;

        uint qType = get16bits(buffer);
        bufferPos += 2;

        uint qClass = get16bits(buffer);
        bufferPos += 2;

        QuerySection *qs = new QuerySection(qName);
        qs->setType(qType);
        qs->setClass(qClass);
        mQueries.push_back(qs);
    }

    cout << "pos before answers:" << bufferPos << endl;

    // 3. read Answer Resource Records
    for (int i = 0; i < anCount; i++)
    {
        logger.trace("Message::decoding Answers");
        
        cout << bufferPos << ", " << bufferSize;

        if (bufferPos >= bufferSize)
            throw(Exception("Invalid DNS message (Answers section)"));

        uint qNameSize = 0;
        std::string qName = decodeDomain(bufferOrig, bufferSize, bufferPos, qNameSize);
        buffer += qNameSize;
        bufferPos += qNameSize;
        break;
    }
}

std::string Message::decodeDomain(const char* buffer, int bufferSize, uint start, uint& size) throw()
{
    std::string domain;
    const char* bufferOrig = buffer;
    buffer = buffer + start;
    bufferSize = bufferSize - start;
    size = 0;
     
    cout << "size at beginning: " << size << endl;
    cout << "buffer size at beginning: " << bufferSize << endl;

    if (bufferSize == 0)
        throw(Exception("Invalid DNS message (Domain name)"));

    while (true)
    {
        if (size + 1 >= bufferSize)
            throw(Exception("Invalid DNS message (Domain name)"));

        uchar ctrlCode = buffer[0];
        cout << "ctrlCode is: " << uint(ctrlCode) << " two bytes: " << (ctrlCode >> 6) << endl;
        if (ctrlCode == 0)
        {
            buffer += 1; // zero byte 
            size += 1; // zero byte 
            cout << "found end of domain name" << endl;
            break;
        }
        else if (ctrlCode >> 6 == 3)
        {
            if (size + 2 >= bufferSize)
                 throw(Exception("Invalid DNS message (Domain name)"));

            cout << "it is a link" << endl;
            uint linkAddr = ((buffer[0] & 63) << 8) + buffer[1];
            cout << "link addr is: " << linkAddr << endl;
            uint linkSize = 0;
            std::string linkDomain = decodeDomain(bufferOrig, bufferSize, linkAddr, linkSize);
            size += 2; // link address
            domain.append(linkDomain);
        }
        else
        {
            buffer += 1; // ctrlCode
            size += 1 + ctrlCode; // ctrlCode + label length

            if (size >= bufferSize)
                throw(Exception("Invalid DNS message (Domain name)"));

            if (domain.size() > 0)
                domain.append(".");
            domain.append(buffer, ctrlCode); // read label
            buffer += ctrlCode; // label
        }
    }

    cout << "size at end: " << size << endl;
    cout << domain << endl;
    return domain;
}

void Message::encodeHeader(char* buffer) throw ()
{
    put16bits(buffer, m_id);

    int fields = (m_qr << 15);
    fields += (m_opcode << 14);
    //...
    fields += m_rcode;
    put16bits(buffer, fields);

    put16bits(buffer, mQueries.size());
    put16bits(buffer, mAnswers.size());
    put16bits(buffer, mAuthorities.size());
    put16bits(buffer, mAdditional.size());
}

void Message::log_buffer(const char* buffer, int size) throw ()
{
    ostringstream text;

    text << "Message::log_buffer()" << endl;
    text << "size: " << size << " bytes" << endl;
    text << "---------------------------------" << setfill('0');

    for (int i = 0; i < size; i++) {
        if ((i % 10) == 0) {
            text << endl << setw(2) << i << ": ";
        }
        uchar c = buffer[i];
        text << hex << setw(2) << int(c) << " " << dec;
    }
    text << endl << setfill(' ');
    text << "---------------------------------";

    Logger& logger = Logger::instance();
    logger.trace(text);
}

int Message::get16bits(const char*& buffer) throw ()
{
    int value = static_cast<uchar> (buffer[0]);
    value = value << 8;
    value += static_cast<uchar> (buffer[1]);
    buffer += 2;

    return value;
}

void Message::put16bits(char*& buffer, uint value) throw ()
{
    buffer[0] = (value & 0xFF00) >> 8;
    buffer[1] = value & 0xFF;
    buffer += 2;
}

void Message::put32bits(char*& buffer, ulong value) throw ()
{
    buffer[0] = (value & 0xFF000000) >> 24;
    buffer[1] = (value & 0xFF0000) >> 16;
    buffer[2] = (value & 0xFF00) >> 16;
    buffer[3] = (value & 0xFF) >> 16;
    buffer += 4;
}
