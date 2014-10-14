
#include <iostream>

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

    cout << "testCreatePacket" << endl;
    testCreatePacket();

    return 0;
}
