#ifndef PCAP_H
#define PCAP_H

#include <QMainWindow>
#include <pcap.h>
#include <QVector>
namespace Ui
{
class PCAP;
}

struct PcapHeader
{
    qint32 t1;
    qint32 t2;
    qint32 caplen;
    qint32 len;
};
struct Ethernet
{
    unsigned char qwe[13];
};

//struct IPV
//{
//    qint8 vers;
//    qint8 hl;
//    qint16 dsf;
//    qint32 TL;
//    qint32 identification;
//    qint32 flags;
//    qint16 TimetoLive;
//    qint16 Protocol;
//    qint32 checksum;
//    qint64 sourse;
//    qint64 dest;
//};

class PCAP : public QMainWindow
{
    Q_OBJECT

public:
    explicit PCAP(QWidget *parent = 0);
    ~PCAP();

private slots:




    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::PCAP *ui;
};


class Deny
{
public:
    PcapHeader pHeader;
    Ethernet ethernet;
    unsigned char* data;
};



struct PcapFHeader
{
    qint32 magic;
    qint16 version_major;
    qint16 version_minor;
    qint32 thiszone;     /* gmt to local correction */
    qint32 sigfigs;    /* accuracy of timestamps */
    qint32 snaplen;    /* max length saved portion of each pkt */
    qint32 linktype;   /* data link type (LINKTYPE_*) */
};





struct TCP
{

};


class PacketStream
{
public:
    PcapFHeader fHeader;
    QList <Deny> packets;
};

#endif // PCAP_H
