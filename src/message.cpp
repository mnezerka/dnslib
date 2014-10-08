/* 
 * File:   message.cpp
 * Author: tomas
 * 
 * Created on 29 de junio de 2009, 17:39
 */

#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <netinet/in.h>

#include "logger.h"
#include "message.h"
#include "exception.h"

using namespace dns;
using namespace std;

std::string QuerySection::asString()
{
    ostringstream text;
    text << "<DNS Question: " << mQName << " qtype=" << mQType << " qclass=" << mQClass << endl;
    return text.str();
}

void Message::decode(const char* buffer, int bufferSize) throw()
{
    Logger& logger = Logger::instance();
    logger.trace("Message::decode()");
    log_buffer(buffer, bufferSize);

    Buffer buff(buffer, bufferSize);   

    // 1. read header
    m_id = buff.get16bits();
    uint fields = buff.get16bits();
    m_qr = fields & QR_MASK;
    m_opcode = fields & OPCODE_MASK;
    m_aa = fields & AA_MASK;
    m_tc = fields & TC_MASK;
    m_rd = fields & RD_MASK;
    m_ra = fields & RA_MASK;
    uint qdCount = buff.get16bits();
    uint anCount = buff.get16bits();
    uint nsCount = buff.get16bits();
    uint arCount = buff.get16bits();

    // 2. read Question Sections
    for (int i = 0; i < qdCount; i++)
    {
        logger.trace("Message::decoding Query Section");

        std::string qName = decodeDomain(buff);
        uint qType = buff.get16bits();
        uint qClass = buff.get16bits();

        QuerySection *qs = new QuerySection(qName);
        qs->setType(qType);
        qs->setClass(qClass);
        mQueries.push_back(qs);
    }

    // 3. read Answer Resource Records
    logger.trace("Message::decoding Answers");
    Message::decodeResourceRecords(buff, anCount, mAnswers);
    logger.trace("Message::decoding Authorities");
    Message::decodeResourceRecords(buff, nsCount, mAuthorities);
    logger.trace("Message::decoding Additional");
    Message::decodeResourceRecords(buff, arCount, mAdditional);
}

std::string Message::decodeDomain(Buffer &buffer) throw()
{
    std::string domain;

    while (true)
    {
        uchar ctrlCode = buffer.get8bits();
        if (ctrlCode == 0)
        {
            break;
        }
        else if (ctrlCode >> 6 == 3)
        {
            // read second byte
            uchar ctrlCode2 = buffer.get8bits();
            uint linkAddr = ((ctrlCode & 63) << 8) + ctrlCode2;
            // change buffer position
            uint saveBuffPos = buffer.getPos();
            buffer.setPos(linkAddr);
            std::string linkDomain = decodeDomain(buffer);
            buffer.setPos(saveBuffPos);
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
            domain.append(buffer.getBytes(ctrlCode), ctrlCode); // read label
        }
    }

    return domain;
}

void Message::decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list)
{
    for (int i = 0; i < count; i++)
    {
        std::string rrName = decodeDomain(buffer);
        uint rrType = buffer.get16bits();
        uint rrClass = buffer.get16bits();
        uint rrTtl = buffer.get32bits();
        uint rrRLength = buffer.get16bits();

        ResourceRecord *rr = new ResourceRecord(rrName);
        rr->setType(rrType);
        rr->setClass(rrClass);
        rr->setTtl(rrTtl);
        if (rrRLength > 0) {
            rr->setRData(buffer.getBytes(rrRLength), rrRLength);
        }
        list.push_back(rr);
    }
}

void Message::encodeHeader(char* buffer) throw ()
{
    /*
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
    */
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

string Message::asString()
{
    ostringstream text;
    text << "Header:" << endl;
    text << "ID: " << showbase << hex << m_id << endl << noshowbase;
    text << "  fields: [ QR: " << m_qr << " opCode: " << m_opcode << " ]" << endl;
    text << "  QDcount: " << mQueries.size() << endl;
    text << "  ANcount: " << mAnswers.size() << endl;
    text << "  NScount: " << mAuthorities.size() << endl;
    text << "  ARcount: " << mAdditional.size() << endl;

    if (mQueries.size() > 0)
    {
        text << "Queries:" << endl;
        for(std::vector<QuerySection*>::iterator it = mQueries.begin(); it != mQueries.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAnswers.size() > 0)
    {
        text << "Answers:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAnswers.begin(); it != mAnswers.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAuthorities.size() > 0)
    {
        text << "Authorities:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAuthorities.begin(); it != mAuthorities.end(); ++it)
            text << "  " << (*it)->asString();
    }

    if (mAdditional.size() > 0)
    {
        text << "Additional:" << endl;
        for(std::vector<ResourceRecord*>::iterator it = mAdditional.begin(); it != mAdditional.end(); ++it)
            text << "  " << (*it)->asString();
    }


    return text.str();
}


