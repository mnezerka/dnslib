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

void Message::decode(const char* buffer, int bufferSize)
{
    Logger& logger = Logger::instance();
    logger.trace("Message::decode()");
    log_buffer(buffer, bufferSize);

    Buffer buff(const_cast<char*>(buffer), bufferSize);   

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

        std::string qName = buff.getDnsDomainName();
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

void Message::decodeResourceRecords(Buffer &buffer, uint count, std::vector<ResourceRecord*> &list)
{
    for (int i = 0; i < count; i++)
    {
        ResourceRecord *rr = new ResourceRecord();
        rr->decode(buffer);
        list.push_back(rr);
    }
}

void Message::encode(char* buffer, int bufferSize)
{
    Buffer buff(buffer, bufferSize);

    // encode header 

    buff.put16bits(m_id);
    uint fields = ((m_qr & 1) << 15);
    fields += ((m_opcode & 15) << 11);
    fields += ((m_aa & 1) << 10);
    fields += ((m_tc & 1) << 9);
    fields += ((m_rd & 1) << 8);
    fields += ((m_ra & 1) << 7);
    fields += ((m_rcode & 15));
    buff.put16bits(fields);
    buff.put16bits(mQueries.size());
    buff.put16bits(mAnswers.size());
    buff.put16bits(mAuthorities.size());
    buff.put16bits(mAdditional.size());

    // encode queries
    for(std::vector<QuerySection*>::iterator it = mQueries.begin(); it != mQueries.end(); ++it)
        (*it)->encode(buff);

    for(std::vector<ResourceRecord*>::iterator it = mAnswers.begin(); it != mAnswers.end(); ++it)
        (*it)->encode(buff);

    buff.dump();
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


