#include "pcap.h"
#include "ui_pcap.h"
#include "QFileDialog"
#include <QFile>
#include <QDebug>
#include <iostream>
#include <QVector>
#include <sstream>
#include "QStandardItemModel"
#include "QStandardItem"


using namespace std;
PCAP::PCAP(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::PCAP)
{
    ui->setupUi(this);
    connect(ui->PCAPOPEN,SIGNAL(triggered()),this,SLOT(open()));
    ui->tableWidget->setColumnCount(8);
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setShowGrid(true);
    ui->tableWidget->setHorizontalHeaderItem(0,new QTableWidgetItem(tr("MAC source")));
    ui->tableWidget->setHorizontalHeaderItem(1,new QTableWidgetItem(tr("MAC destination")));
    ui->tableWidget->setHorizontalHeaderItem(2,new QTableWidgetItem(tr("Type")));
    ui->tableWidget->setHorizontalHeaderItem(3,new QTableWidgetItem(tr("PROTOCOL")));
    ui->tableWidget->setHorizontalHeaderItem(4,new QTableWidgetItem(tr("IP source")));
    ui->tableWidget->setHorizontalHeaderItem(5,new QTableWidgetItem(tr("IP destination")));
    ui->tableWidget->setHorizontalHeaderItem(6,new QTableWidgetItem(tr("Ports source")));
    ui->tableWidget->setHorizontalHeaderItem(7,new QTableWidgetItem(tr("Ports destination")));
}


PCAP::~PCAP()
{
    delete ui;
}

PacketStream ps;
Deny ph;
QString QW;
QTableWidgetItem *item;

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
        ui->textEdit->append("Thiszone: "+QString::number(ps.fHeader.thiszone));
        dec=QString::number(ps.fHeader.sigfigs);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Sigfigs: "+s);
        ui->textEdit->append("Snaplen: "+QString::number(ps.fHeader.snaplen));
        dec=QString::number(ps.fHeader.linktype);
        d=dec.toInt();
        s=QString::number(d,16).toUpper();
        ui->textEdit->append("Linktype: "+s);
        min=65535;
        max=0;
        while ( file.pos() < file.size())
        {
               int p = 0;
            const int tab_ab_row = ui->tableWidget->rowCount();
               ui->tableWidget->insertRow(tab_ab_row);
            qDebug()<<file.pos();

            file.read((char *)&ph.pHeader,16);
            ph.data = new unsigned char [ph.pHeader.caplen];
            for (int c = 0 ; c<ph.pHeader.caplen;c++)
            {
                file.read((char *)&ph.data[c],1);
            }
             QString Line;
             QString dec;
             dec=QString::number(ph.data[0]);
             int d=dec.toInt();
             QString s=QString::number(d,16).toUpper();
             if (d<16)
                 s="0"+s;
             Line = s ;
            for (int j = p+1 ; j < 6 ;j++)
            {
                dec=QString::number(ph.data[j]);
                d=dec.toInt();
                s=QString::number(d,16).toUpper();
                if (d<16)
                    s="0"+s;
                Line = Line + ":" + s ;
            }
            ui->tableWidget->setItem(tab_ab_row,0,new QTableWidgetItem(Line));
            Line = "";

            dec=QString::number(ph.data[6]);
            d=dec.toInt();
            s=QString::number(d,16).toUpper();
            if (d<16)
                s="0"+s;
            Line = s ;
            p=6;
           for (int j = p+1 ; j < 12 ;j++)
           {
               dec=QString::number(ph.data[j]);
               d=dec.toInt();
               s=QString::number(d,16).toUpper();
               if (d<16)
                   s="0"+s;
               Line = Line + ":" + s ;
           }
            ui->tableWidget->setItem(tab_ab_row,1,new QTableWidgetItem(Line));

            dec=QString::number(ph.data[12]);
            d=dec.toInt();
            s=QString::number(d,16).toUpper();
            if (d<16)
                s="0"+s;
            Line = s ;
            p=13;
           for (int j = p ; j < 14 ;j++)
           {
               dec=QString::number(ph.data[j]);
               d=dec.toInt();
               s=QString::number(d,16).toUpper();
               if (d<16)
                   s="0"+s;
               Line = Line + "x" + s ;
           }
           if (Line == "08x00")
               Line = Line + " (IP)";
            ui->tableWidget->setItem(tab_ab_row,2,new QTableWidgetItem(Line));
            Line="";

            p=23;
          dec=QString::number(ph.data[p]);
          d=dec.toInt();
          s=QString::number(d,16).toUpper();
               if (d<16)
                   s="0"+s;
               Line =s ;
            if (Line == "06")
                Line = Line + " (TCP)";
            ui->tableWidget->setItem(tab_ab_row,3,new QTableWidgetItem(Line));

            p=14;
            dec=QString::number(ph.data[p]);

            d=dec.toInt();
            s=QString::number(d,16).toUpper();
            int k=s.toInt();
            k=k%10;
            k=k*4;
            k=k-20;
            Line = "";
            p=26;
            dec=QString::number(ph.data[p]);
            Line = dec;
           for (int j = p+1 ; j < p+4 ;j++)
           {
               dec=QString::number(ph.data[j]);
               Line = Line +"."+ dec ;
           }
            ui->tableWidget->setItem(tab_ab_row,4,new  QTableWidgetItem(Line));

            p=30;
            dec=QString::number(ph.data[p]);
            Line = dec;
           for (int j = p+1 ; j < p+4 ;j++)
           {
               dec=QString::number(ph.data[j]);
               Line = Line +"."+ dec ;
           }
            ui->tableWidget->setItem(tab_ab_row,5,new  QTableWidgetItem(Line));
            p=34+k;
            s=QString::number(ph.data[p]);
            d=s.toInt();
            s=QString::number(d,16).toUpper();
            QString z=QString::number(ph.data[p+1]);
            d=z.toInt();
            z=QString::number(d,16).toUpper();
            s=s+z;
            s = QString::number(s.toInt(0,16),10);
            ui->tableWidget->setItem(tab_ab_row,6,new QTableWidgetItem(s));
            p=36+k;
            s=QString::number(ph.data[p]);
            d=s.toInt();
            s=QString::number(d,16).toUpper();
            z=QString::number(ph.data[p+1]);
            d=z.toInt();
            z=QString::number(d,16).toUpper();
            s=s+z;
            s = QString::number(s.toInt(0,16),10);
            ui->tableWidget->setItem(tab_ab_row,7,new QTableWidgetItem(s));
            if (ph.pHeader.caplen>max)
                max=ph.pHeader.caplen;
            if (ph.pHeader.caplen<min)
                min=ph.pHeader.caplen;
            avr=avr+ph.pHeader.caplen;
            i++;
            qDebug() <<"t1" << ph.pHeader.t1 << "t2" << ph.pHeader.t2 << "caplen" << ph.pHeader.caplen <<"len" <<ph.pHeader.len<< " number - " <<i;
              ps.packets.append(ph);
//              item= new QTableWidgetItem;
//              item->setText(QString::number(ph.data[0],16)+" " +QString::number(ph.data[1],16)+" "+QString::number(ph.data[2],16)+" "+QString::number(ph.data[3],16)+" "+QString::number(ph.data[4],16)+" "+" "+QString::number(ph.data[5],16));
//              ui->tableWidget->setItem(i,0,item);

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

    ui->textEdit->insertPlainText("Source Port:"+QString::number(s.toInt(0,16),10));
    ui->textEdit->append("");
    p=36+k;
    s=QString::number(ps.packets[Num].data[p]);
    d=s.toInt();
    s=QString::number(d,16).toUpper();
    z=QString::number(ps.packets[Num].data[p+1]);
    d=z.toInt();
    z=QString::number(d,16).toUpper();
    s=s+z;
    ui->textEdit->insertPlainText("Destination Port:"+QString::number(s.toInt(0,16),10));
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
