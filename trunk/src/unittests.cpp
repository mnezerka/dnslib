
#include <iostream>

#include "exception.h"
#include "message.h"
#include "rr.h"
#include "buffer.h"
#include "assert.h"

using namespace std;

void testBuffer()
{
    // check decoding of character string
    char b1[] = {'\x05', 'h', 'e', 'l', 'l', 'o', '\x00', 'a', 'h', 'o', 'j' };
    dns::Buffer b(b1, sizeof(b1));

    std::string strCheck = b.getDnsCharacterString();
    assert (strCheck == "hello");

    strCheck = b.getDnsCharacterString();
    assert (strCheck == ""); 

    // check decoding of domain name
    char b2[] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
    dns::Buffer buff2(b2, sizeof(b2) - 1);
    strCheck  = buff2.getDnsDomainName();
    assert (strCheck == "www.google.com"); 

    // check encoding of domain name
    char b3[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer buff3(b3, sizeof(b3) - 1);
    buff3.putDnsDomainName("");
    assert (b3[0] == '\x00');
    assert (b3[1] == 'x');
}

void testBufferCharacterString()
{
    // check encoding of domain name
    char b1[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer buff1(b1, sizeof(b1) - 1);
    buff1.putDnsCharacterString("");
    assert (b1[0] == '\x00');
    assert (b1[1] == 'x');

    buff1.setPos(0);
    buff1.putDnsCharacterString("ah");
    assert (b1[0] == '\x02');
    assert (b1[1] == 'a');
    assert (b1[2] == 'h');
    assert (b1[3] == 'x');
}

void testCNAME_MB_MD_MF_MG_MR_NS_PTR()
{
    char wireData[] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
    dns::uint wireDataSize = sizeof(wireData) - 1;
    dns::Buffer buff(wireData, wireDataSize);

    dns::RDataCNAME rCNAME;
    rCNAME.decode(buff, wireDataSize);
    assert (rCNAME.getName() == "www.google.com"); 
    assert (rCNAME.getType() == dns::RDATA_CNAME);

    dns::RDataMB rMB;
    buff.setPos(0);
    rMB.decode(buff, wireDataSize);
    assert (rMB.getName() == "www.google.com"); 
    assert (rMB.getType() == dns::RDATA_MB);

    dns::RDataMD rMD;
    buff.setPos(0);
    rMD.decode(buff, wireDataSize);
    assert (rMD.getName() == "www.google.com"); 
    assert (rMD.getType() == dns::RDATA_MD);

    dns::RDataMF rMF;
    buff.setPos(0);
    rMF.decode(buff, wireDataSize);
    assert (rMF.getName() == "www.google.com"); 
    assert (rMF.getType() == dns::RDATA_MF);

    dns::RDataMG rMG;
    buff.setPos(0);
    rMG.decode(buff, wireDataSize);
    assert (rMG.getName() == "www.google.com"); 
    assert (rMG.getType() == dns::RDATA_MG);

    dns::RDataMR rMR;
    buff.setPos(0);
    rMR.decode(buff, wireDataSize);
    assert (rMR.getName() == "www.google.com"); 
    assert (rMR.getType() == dns::RDATA_MR);

    dns::RDataNS rNS;
    buff.setPos(0);
    rNS.decode(buff, wireDataSize);
    assert (rNS.getName() == "www.google.com"); 
    assert (rNS.getType() == dns::RDATA_NS);

    dns::RDataPTR rPTR;
    buff.setPos(0);
    rPTR.decode(buff, wireDataSize);
    assert (rPTR.getName() == "www.google.com"); 
    assert (rPTR.getType() == dns::RDATA_PTR);
}

void testHINFO()
{
    dns::RDataHINFO r;
    assert (r.getType() == dns::RDATA_HINFO);
}


void testMINFO()
{
    dns::RDataMINFO r;
    assert (r.getType() == dns::RDATA_MINFO);
}

void testMX()
{
    dns::RDataMX r;
    assert (r.getType() == dns::RDATA_MX);
}

void testNULL()
{
    dns::RDataNULL r;
    assert (r.getType() == dns::RDATA_NULL);
}

void testSOA()
{
    dns::RDataSOA r;
    assert (r.getType() == dns::RDATA_SOA);
}

void testTXT()
{
    dns::RDataTXT r;
    assert (r.getType() == dns::RDATA_TXT);

    char txtData[] = { '\x02', '\x65', '\x65', '\x00'};
    dns::Buffer b(txtData, sizeof(txtData));
    r.decode(b, sizeof(txtData));

    char txtData2[] = { '\x02', '\x65', '\x65', '\x03', '\x64', '\x64', '\x64', '\x00'};
    dns::Buffer b2(txtData2, sizeof(txtData2));
    r.decode(b2, sizeof(txtData2));
}

void testRDataA()
{
    dns::RDataA r;
    assert (r.getType() == dns::RDATA_A);

    char addr[] = { '\x01', '\x02', '\x03', '\x04' };
    dns::Buffer b(addr, sizeof(addr));
    r.decode(b, sizeof(addr));
    dns::uchar *addr2 = r.getAddress();
    assert (addr2[0] == 1);
    assert (addr2[1] == 2);
    assert (addr2[2] == 3);
    assert (addr2[3] == 4);

    b.setPos(0);
    r.encode(b);
}

void testWKS()
{
    dns::RDataWKS r;
    assert (r.getType() == dns::RDATA_WKS);

    char wksData[] = { '\x01', '\x02', '\x03', '\x04', '\xaa', '\xff', '\xef'};
    dns::Buffer b(wksData, sizeof(wksData));
    r.decode(b, sizeof(wksData));

    assert(r.getProtocol() == 0xaa);
    assert(r.getBitmapSize() == 2);

    b.setPos(0);
    r.encode(b);
}

void testRDataAAAA()
{
    dns::RDataAAAA r;
    assert (r.getType() == dns::RDATA_AAAA);

    char addr[] = { '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10' };
    dns::Buffer b(addr, sizeof(addr));
    r.decode(b, sizeof(addr));
    dns::uchar *addr2 = r.getAddress();
    for (unsigned int i = 0; i < 16; i++)
        assert (addr2[i] == i + 1);

    b.setPos(0);
    r.encode(b);
}

void testNAPTR()
{
    dns::RDataNAPTR r;

    char naptr1[] = "\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    dns::Buffer b(naptr1, sizeof(naptr1) - 1);
    r.decode(b, sizeof(naptr1) - 1);
    assert (r.getOrder() == 50);
    assert (r.getPreference() == 51);
    assert (r.getFlags() == "s");
    assert (r.getServices() == "SIP+D2T");
    assert (r.getRegExp() == "");
    assert (r.getReplacement() == "_sip._tcp.icscf.brn56.iit.ims");
}

void testPacket()
{
    // check header without any queries and records
    char packet1[] = "\xd5\xad\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
    dns::Message m1;
    m1.decode(packet1, sizeof(packet1) - 1);
    assert (m1.getId() == 0xd5ad);
    assert (m1.getOpCode() == 0);
    assert (m1.getAA() == 0);
    assert (m1.getTC() == 0);
    assert (m1.getRD() == 1);
    assert (m1.getRA() == 1);
    assert (m1.getRCode() == 0);
    assert (m1.getQdCount() == 0);
    assert (m1.getAnCount() == 0);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);

    // check raw resource records
    char packet2[] = "\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03\x77\x77\x77\x01\x6c\xc0\x10\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x68\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x63\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x67\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x93";
    m1.decode(packet2, sizeof(packet2) - 1);
    assert (m1.getQdCount() == 1);
    assert (m1.getAnCount() == 5);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);

    // check naptr resource records
    char packet3[] = "\x14\x38\x85\x80\x00\x01\x00\x03\x00\x00\x00\x00\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\x00\x23\x00\x01\xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x4a\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2f\x00\x0a\x00\x0a\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x53\x00\x04\x5f\x73\x69\x70\x05\x5f\x73\x63\x74\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x85\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x32\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x55\x00\x04\x5f\x73\x69\x70\x04\x5f\x75\x64\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    m1.decode(packet3, sizeof(packet3) - 1);
    assert (m1.getQdCount() == 1);
    assert (m1.getAnCount() == 3);
    assert (m1.getNsCount() == 0);
    assert (m1.getArCount() == 0);

    char packetSOA[] = "\x00\x00\x21\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x36\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x77\x82\x0d\xbc\x00\x01\x51\x80\x00\x00\x1c\x20\x00\x36\xee\x80\x00\x02\xa3\x00";
    m1.decode(packetSOA, sizeof(packetSOA) - 1);

    char packetHINFO[] = "\x00\x00\x29\x00\x00\x01\x00\x01\x00\x02\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\xff\x00\x00\x0e\x10\x00\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x0a\x01\x0b\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x14\x09\x54\x65\x68\x6f\x6d\x79\x6c\x6c\x79\x09\x44\x4e\x53\x2d\x53\x75\x69\x74\x65\x0b\x68\x6f\x73\x74\x31\x2d\x68\x6f\x73\x74\x32\x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x54\x3e\x33\x78\x01\x2c\x00\x10\x6f\xba\x22\x36\xf2\x25\xe2\x35\x13\x8f\x29\xbc\xa7\xb4\x89\x50\x00\x00\x00\x00\x00\x00";
    m1.decode(packetHINFO, sizeof(packetHINFO) - 1);
    // TODO - compare values
}

void testPacketInvalid()
{
    char packet1[] = "\x00\x00\x01\x00\x00\x01\x00\x01\x00\x01\x00\x02\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x01\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x21\x00\x01\x00\x00\x0e\x10\x00\x08\x49\x00\x00\x00\x00\x00\xc8\x00\x01\x41\xc0\x2e\x00\x1e\x00\x01\x00\x00\x0e\x10\x00\x06\x01\x80\x00\x00\x00\x02\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x63\x00\x01\x00\x00\x0e\x10\x00\x0e\x0d\x76\x3d\x73\x70\x66\x31\x20\x65\x78\x70\x3a\x25\x1e\x0b\x68\x6f\x73\x74\x31\x2d\x68\x6f\x73\x74\x32\x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x54\x3e\x44\xe5\x01\x2c\x00\x10\xe7\x01\x33\xed\x6a\x86\xab\x55\x30\xf3\xdd\xf1\x4f\x87\x9f\x6b\x00\x00\x00\x00\x00\x00";
    dns::Message m1;
    try
    { 

        m1.decode(packet1, sizeof(packet1) - 1);
        cout << m1.asString() << endl;
        throw ("Failed");
    }
    catch (dns::Exception e) { /* ok */ };

    char packet2[] = "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x01\x00\x01\x02\x31\x31\x01\x31\x02\x31\x30\x02\x31\x30\x07\x69\x6e\x2d\x61\x64\x64\x72\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x30\x1c\x31\x27\x29\x29\x29\x20\x41\x4e\x44\x20\x28\x28\x28\x27\x66\x6f\x6f\x27\x20\x4c\x49\x4b\x45\x20\x27\x66\x6f\x6f\xc0\x12\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x00\x29\x20\x00\x00\x00\x80\x00\x00\x00";
    try
    { 
        dns::Message m2;
        m2.decode(packet2, sizeof(packet2) - 1);
        cout << m2.asString() << endl;
        throw ("Failed");
    }
    catch (dns::Exception e) { /* ok */ };
}

void testCreatePacket()
{
    dns::Message answer;
    answer.setId(45);
    answer.setQr(dns::Message::typeResponse);

    // add NAPTR answer
    dns::ResourceRecord *rr = new dns::ResourceRecord();
    rr->setType(dns::RDATA_NAPTR);
    rr->setClass(dns::CLASS_IN);
    rr->setTtl(60);
    dns::RDataNAPTR *rdata = new dns::RDataNAPTR();
    rdata->setOrder(50);
    rdata->setPreference(51);
    rdata->setServices("SIP+D2T");
    rdata->setRegExp("");
    rdata->setReplacement("_sip._tcp.icscf.brn56.iit.ims");
    rr->setRData(rdata);

    answer.addAnswer(rr);

    dns::uint mesgSize;
    char mesg[2000];
    answer.encode(mesg, 2000, mesgSize);

    // todo check buffer
}

int main(int argc, char** argv)
{
    cout << "testBuffer" << endl;
    testBuffer();

    cout << "testBufferCharacterString" << endl;
    testBufferCharacterString();

    cout << "testCNAME_MB_MD_MF_MG_MR_NS_PTR" << endl;
    testCNAME_MB_MD_MF_MG_MR_NS_PTR();

    cout << "testHINFO" << endl;
    testHINFO();

    cout << "testMINFO" << endl;
    testMINFO();

    cout << "testMX" << endl;
    testMX();

    cout << "testNULL" << endl;
    testNULL();

    cout << "testSOA" << endl;
    testSOA();

    cout << "testTXT" << endl;
    testTXT();

    cout << "testWKS" << endl;
    testWKS();

    cout << "testRDataA" << endl;
    testRDataA();

    cout << "testRDataAAAA" << endl;
    testRDataAAAA();

    cout << "testNAPTR" << endl;
    testNAPTR();

    cout << "testPacket" << endl;
    testPacket();

    cout << "testPacketInvalid" << endl;
    testPacketInvalid();

    cout << "testCreatePacket" << endl;
    testCreatePacket();

    return 0;
}
