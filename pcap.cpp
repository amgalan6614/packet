#include "pcap.h"
#include "ui_pcap.h"
#include "QFileDialog"
#include <QFile>
#include <QDebug>
#include <iostream>
#include <QVector>
#include <sstream>


using namespace std;
PCAP::PCAP(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::PCAP)
{
    ui->setupUi(this);
    connect(ui->PCAPOPEN,SIGNAL(triggered()),this,SLOT(open()));
}


PCAP::~PCAP()
{
    delete ui;
}

PacketStream ps;
Deny ph;
QString QW;

void PCAP::on_pushButton_clicked()
{
    int avr=0;
    int max,min,i=0;
    QString Name = QFileDialog::getOpenFileName(0,"Open File","","PCAP files (*.cap)");
    qDebug() << Name;
    if ( Name == "")
        return;
    QW=Name;
    QFile file(Name);
    if (!file.open(QIODevice::ReadOnly))
    {
        qDebug() <<"error open file";
    }
        file.read((char *)&ps.fHeader, 24);
        QString dec;
        int d;
        QString s;
//        dec=              QString::       number(ps.fHeader.magic);
//        int d=dec.toInt();
//        QString s=QString::number(d,16).toUpper();
        ui->textEdit->append("Заголовок файла: ");
        ui->textEdit->append("Magic: "+QString::number(ps.fHeader.magic));
        dec=QString::number(ps.fHeader.version_major);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Version Major: "+s);
        dec=QString::number(ps.fHeader.version_minor);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Version Minor: "+s);
//        dec=QString::number(ps.fHeader.thiszone);
//        d=dec.toInt();
//        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Thiszone: "+QString::number(ps.fHeader.thiszone));
        dec=QString::number(ps.fHeader.sigfigs);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Sigfigs: "+s);
//        dec=QString::number(ps.fHeader.snaplen);
//        d=dec.toInt();
//        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Snaplen: "+QString::number(ps.fHeader.snaplen));
        dec=QString::number(ps.fHeader.linktype);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Linktype: "+s);
        min=65535;
        max=0;
        while ( file.pos() < file.size())
        {
            qDebug()<<file.pos();
            file.read((char *)&ph.pHeader,16);
            file.read((char *)&ph.data,ph.pHeader.caplen);
//            file.seek(file.pos()-ph.pHeader.caplen);
//            file.read((char *)&ph.ethernet,14);
//            file.seek(file.pos()-14+ph.pHeader.caplen);
            if (ph.pHeader.caplen>max)
                max=ph.pHeader.caplen;
            if (ph.pHeader.caplen<min)
                min=ph.pHeader.caplen;
            avr=avr+ph.pHeader.caplen;
            i++;
//            dec=QString::number(ph.ethernet.qwe);
//            d=dec.toInt();
//            s=QString::number(d,16).toUpper();
            qDebug() <<"t1" << ph.pHeader.t1 << "t2" << ph.pHeader.t2 << "caplen" << ph.pHeader.caplen <<"len" <<ph.pHeader.len<< " number - " <<i;
//            for (int j=0;j<ph.pHeader.caplen;j++)
//            {
//                qDebug()<<hex<<(ph.data[j]&0xff);
//            }
              ps.packets.append(ph);
//            ui->textEdit->append("Packet number "+QString::number(i));
//            ui->textEdit->append("t1:"+QString::number(ph.pHeader.t1)+" t2:"+QString::number(ph.pHeader.t2)+" Захваченная длина пакета:" +QString::number(ph.pHeader.caplen)+" Общая длина пакета:"+ QString::number(ph.pHeader.len));
        }

        ui->textEdit->append("Количество пакетов: "+QString::number(i));
        avr=avr / i;
        ui->lineEdit_5->setText(QString::number(avr));
        ui->lineEdit_6->setText(QString::number(max));
        ui->lineEdit_7->setText(QString::number(min));
        qDebug() << "Size = " << file.size();
        qDebug() << ps.fHeader.snaplen << "   " << ps.fHeader.linktype;
        file.close();
}

void PCAP::on_pushButton_2_clicked()
{
    int p=0;
    QString Line;
    Line = ui->lineEdit_4->text();
    int Num;
    Num = Line.toInt();
    Num = Num -1 ;
    qDebug() <<"t1" << ps.packets[Num].pHeader.t1 << "t2" << ps.packets[Num].pHeader.t2 << "caplen" << ps.packets[Num].pHeader.caplen <<"len" <<ps.packets[Num].pHeader.len;
    ui->textEdit->append("Packet number "+QString::number(Num+1));
    ui->textEdit->append("t1:"+QString::number(ps.packets[Num].pHeader.t1)+" t2:"+QString::number(ps.packets[Num].pHeader.t2)+" Захваченная длина пакета:" +QString::number(ps.packets[Num].pHeader.caplen)+" Общая длина пакета:"+ QString::number(ps.packets[Num].pHeader.len));
//    ui->textEdit->append("");
//    ui->textEdit->insertPlainText("Destination adress:");
//    for (int j = 0 ;j<6;j++)
//    {
//        QString dec=QString::number(ps.packets[Num].ethernet.qwe[j]);
//        int d=dec.toInt();
//        QString s=QString::number(d,16).toUpper();
//        if (d<16)
//            ui->textEdit->insertPlainText(" 0"+s);
//       else
//            ui->textEdit->insertPlainText(" " + s);
//    }
//    ui->textEdit->append("");
//    ui->textEdit->insertPlainText("Source adress:");
//    for (int j = 6 ;j<12;j++)
//    {
//        QString dec=QString::number(ps.packets[Num].ethernet.qwe[j]);
//        int d=dec.toInt();
//        QString s=QString::number(d,16).toUpper();
//        if (d<16)
//            ui->textEdit->insertPlainText(" 0"+s);
//       else
//            ui->textEdit->insertPlainText(" " + s);
//    }
//    ui->textEdit->append("");
//    ui->textEdit->insertPlainText("Type:");
//    for (int j = 12 ;j<14;j++)
//    {
//        QString dec=QString::number(ps.packets[Num].ethernet.qwe[j]);
//        int d=dec.toInt();
//        QString s=QString::number(d,16).toUpper();
//        if (d<16)
//            ui->textEdit->insertPlainText(" 0"+s);
//       else
//            ui->textEdit->insertPlainText(" " + s);
//    }










    ui->textEdit->append("");
    ui->textEdit->insertPlainText("Destination MAC-adress:");
    for (int j = p ; j < 6 ;j++)
    {
        QString dec;
        dec=QString::number(ps.packets[Num].data[j]);
        int d=dec.toInt();
        QString s=QString::number(d,16).toUpper();

       if (d < 16)
            ui->textEdit->insertPlainText(" 0"+s);
       else
            ui->textEdit->insertPlainText(" " + s);
    }
    p=6;
    ui->textEdit->append("");
    ui->textEdit->insertPlainText("Source MAC-adress:");
    for (int j = p ; j < 12 ;j++)
    {
        QString dec;
        dec=QString::number(ps.packets[Num].data[j]);
        int d=dec.toInt();
        QString s=QString::number(d,16).toUpper();
       if (d < 16)
            ui->textEdit->insertPlainText(" 0"+s);
       else
            ui->textEdit->insertPlainText(" " + s);
    }
    p=12;
    ui->textEdit->append("");
    ui->textEdit->insertPlainText("Type:");
    for (int j = p ; j < 14 ;j++)
    {
        QString dec;
        dec=QString::number(ps.packets[Num].data[j]);
        int d=dec.toInt();
        QString s=QString::number(d,16).toUpper();
       if (d < 16)
            ui->textEdit->insertPlainText(" 0"+s);
       else
            ui->textEdit->insertPlainText(" " + s);
    }
    p=14;
    QString dec=QString::number(ps.packets[Num].data[p]);
    int d=dec.toInt();
    QString s=QString::number(d,16).toUpper();

    ui->textEdit->append("");

    ui->textEdit->insertPlainText("Length:"+s[1]);
    int k=s.toInt();
    k=k%10;
    k=k*4;
    k=k-20;
    p=23;
    dec=QString::number(ps.packets[Num].data[p]);
    d=dec.toInt();
    s=QString::number(d,16).toUpper();
    ui->textEdit->append("");
    if (d < 16)
         ui->textEdit->insertPlainText("Protocol: 0"+ s);
    else
         ui->textEdit->insertPlainText("Protocol: " + s);

    p=26;
    ui->textEdit->append("");
    ui->textEdit->insertPlainText("Source:");
    for (int j=p;j<p+4;j++)
    {
        ui->textEdit->insertPlainText(QString::number(ps.packets[Num].data[j])+".");
    }

    p=30;
    ui->textEdit->append("");
    ui->textEdit->insertPlainText("Destination:");
    for (int j=p;j<p+4;j++)
    {
        ui->textEdit->insertPlainText(QString::number(ps.packets[Num].data[j])+".");
    }
    p=34+k;
    ui->textEdit->append("");
    s=QString::number(ps.packets[Num].data[p]);
    d=s.toInt();
    s=QString::number(d,16).toUpper();
    QString z=QString::number(ps.packets[Num].data[p+1]);
    d=z.toInt();
    z=QString::number(d,16).toUpper();
    s=s+z;
    ui->textEdit->insertPlainText("Source Port:"+s);
    ui->textEdit->append("");
    p=36+k;
    s=QString::number(ps.packets[Num].data[p]);
    d=s.toInt();
    s=QString::number(d,16).toUpper();
    z=QString::number(ps.packets[Num].data[p+1]);
    d=z.toInt();
    z=QString::number(d,16).toUpper();
    s=s+z;
    ui->textEdit->insertPlainText("Destination Port:"+s);

    for (int j=0;j<ps.packets[Num].pHeader.caplen;j++)
    {
        if (j % 16 == 0 )
            ui->textEdit->append("");
        if (j % 8 == 0 )
            ui->textEdit->insertPlainText("   ");
        QString dec;
        dec=QString::number(ps.packets[Num].data[j]);
        int d=dec.toInt();
        QString s=QString::number(d,16).toUpper();
       if (d < 16)
            ui->textEdit->insertPlainText(" 0"+s);
       else
            ui->textEdit->insertPlainText(" " + s);
    }


}
