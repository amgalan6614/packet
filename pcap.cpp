#include "pcap.h"
#include "ui_pcap.h"
#include "QFileDialog"
#include <QFile>
#include <QDebug>
#include <iostream>
#include<QVector>
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

long massive[1000000];
void PCAP::on_pushButton_clicked()
{
    int avr=0;
    int max,min,i=0;
    QString Name = QFileDialog::getOpenFileName(0,"Open File","","PCAP files (*.*)");
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
        ui->textEdit->append("Заголовок файла: ");
        ui->textEdit->append("Magic: "+QString::number(ps.fHeader.magic));
        ui->textEdit->append("Version Major: "+QString::number(ps.fHeader.version_major));
        ui->textEdit->append("Version Minor: "+QString::number(ps.fHeader.version_minor));
        ui->textEdit->append("Thiszone: "+QString::number(ps.fHeader.thiszone));
        ui->textEdit->append("Sigfigs: "+QString::number(ps.fHeader.sigfigs));
        ui->textEdit->append("Snaplen: "+QString::number(ps.fHeader.snaplen));
        ui->textEdit->append("Linktype: "+QString::number(ps.fHeader.linktype));
        min=65535;
        max=0;
        while ( file.pos() < file.size())
        {
            qDebug()<<file.pos();
            massive[i]=file.pos();
            file.read((char *)&ph.pHeader,16);            
            file.read((char *)&ph.data,ph.pHeader.caplen);
            if (ph.pHeader.caplen>max)
                max=ph.pHeader.caplen;
            if (ph.pHeader.caplen<min)
                min=ph.pHeader.caplen;
            avr=avr+ph.pHeader.caplen;
            i++;
            qDebug() <<"t1" << ph.pHeader.t1 << "t2" << ph.pHeader.t2 << "caplen" << ph.pHeader.caplen <<"len" <<ph.pHeader.len;
            for (int j=0;j<ph.pHeader.caplen;j++)
            {
                qDebug()<<hex<<(ph.data[j]&0xff);
            }
//            ui->textEdit->append("Packet number "+QString::number(i));
//            ui->textEdit->append("t1:"+QString::number(ph.pHeader.t1)+" t2:"+QString::number(ph.pHeader.t2)+" Захваченная длина пакета:" +QString::number(ph.pHeader.caplen)+" Общая длина пакета:"+ QString::number(ph.pHeader.len));
        }
        ps.packets.push_back(ph);
        ui->textEdit->append("Количество пакетов: "+QString::number(i));
        avr=avr / i;
        ui->lineEdit_5->setText(QString::number(avr));
        ui->lineEdit_6->setText(QString::number(max));
        ui->lineEdit_7->setText(QString::number(min));
        qDebug() << "Size = " << file.size();
        qDebug() << ps.fHeader.snaplen << "   " << ps.fHeader.linktype;
}

void PCAP::on_pushButton_2_clicked()
{
    QString Line;
    Line = ui->lineEdit_4->text();
    int Num;
    Num = Line.toInt();
    QFile file(QW);
    if (!file.open(QIODevice::ReadOnly))
    {
        qDebug() <<"error open file";
    }
    file.seek(massive[Num]);
    file.read((char *)&ph.pHeader,16);
    file.read((char *)&ph.data,ph.pHeader.caplen);
    qDebug() <<"t1" << ph.pHeader.t1 << "t2" << ph.pHeader.t2 << "caplen" << ph.pHeader.caplen <<"len" <<ph.pHeader.len;
    ui->textEdit->append("Packet number "+QString::number(Num));
    ui->textEdit->append("t1:"+QString::number(ph.pHeader.t1)+" t2:"+QString::number(ph.pHeader.t2)+" Захваченная длина пакета:" +QString::number(ph.pHeader.caplen)+" Общая длина пакета:"+ QString::number(ph.pHeader.len));
    ui->textEdit->append("");
    for (int j=0;j<ph.pHeader.caplen;j++)
    {
        QString dec;
        dec=QString::number(ph.data[j]);
        int d=dec.toInt();
        QString s=QString::number(d,16).toUpper();
        ui->textEdit->insertPlainText(" "+s + " ");
        qDebug()<<hex<<(ph.data[j]&0xff);
    }
}
