import pyshark
import json
from matplotlib import pyplot

def DrawCharts(Sv , Cl):
    SvX = []
    SvY = []
    ClX = []
    ClY = []
    for item in Cl['intervals']:
        ClY.append(item['sum']['bits_per_second']/10**6)
        ClX.append(item['sum']['end'])
    for item in Sv['intervals']:
        SvY.append(item['sum']['bits_per_second']/10**6)
        SvX.append(item['sum']['end'])
    pyplot.plot(SvX, SvY, marker='o',color='g', label='Server')
    pyplot.plot(ClX, ClY, marker='o', color='r', label='Client')
    pyplot.legend(loc='upper right')
    pyplot.ylabel("ًRate(Mbps)")
    pyplot.xlabel("Time(s)")
    pyplot.show()

    
from pyshark.capture.capture import Capture
print("====== *[{ Start Capturing ...}]* ======")
capture = pyshark.LiveCapture(interface='lo' ,bpf_filter='port 4040' )
capture.sniff(timeout=30)
print("====== *[{ End Capturing ...}]* ======")

print("Count of Packet : is" , len(capture))
TransportLayer = str(capture[0])
if(TransportLayer.find("UDP") != -1):
    print("====== *[{ UDP Connection ...}]* ======")
    Sum_of_len = 0
    for index in range(0,len(capture)):
        Sum_of_len += int(capture[index].length)
    LastPacket = str(capture[len(capture)-1])
    LastTime = float(LastPacket[LastPacket.find("Time since first frame:")+24:LastPacket.find("Time since first frame:")+35])
    # print(Sum_of_len)
    # print(LastTime)
    if(LastTime):
        print("throghput count in python code : " , (Sum_of_len *8 / LastTime)/10**9 , " Gbps")
    ClFile = open('client.json')
    SvFile = open('server.json')
    ClJsonFile = ClFile.read()
    SvJsonFile = SvFile.read()
    ClDataCapture = json.loads(ClJsonFile)
    SvDataCapture = json.loads(SvJsonFile)
    ClFile.close()
    SvFile.close()
    print("throghput of Sender in Json File : " , SvDataCapture['end']['sum']['bits_per_second'] / 10**9 , " Gbps")
    print("throghput of Reciver in Json File : " , ClDataCapture['end']['sum']['bits_per_second'] / 10**9 , " Gbps")
    DrawCharts(SvDataCapture , ClDataCapture)
else:
    print("====== *[{ TCP Connection ...}]* ======")
    Sum_of_len = 0
    for index in range(0,len(capture)):
        Sum_of_len += int(capture[index].length)
    LastPacket = str(capture[len(capture)-1])
    LastTime = float(LastPacket[LastPacket.find("Time since first frame in this TCP stream:")+43:LastPacket.find("Time since first frame in this TCP stream:")+54])
    # print(Sum_of_len)
    # print(LastTime)
    if(LastTime):
        print("throghput count in python code : " , (Sum_of_len *8 / LastTime)/10**9 , " Gbps")
    ClFile = open('client.json')
    SvFile = open('server.json')
    ClJsonFile = ClFile.read()
    SvJsonFile = SvFile.read()
    ClDataCapture = json.loads(ClJsonFile)
    SvDataCapture = json.loads(SvJsonFile)
    ClFile.close()
    SvFile.close()
    print("throghput of Sender From This Stream in Json File : " , ClDataCapture['end']['sum_sent']['bits_per_second'] / 10**9 , " Gbps")
    print("throghput of Reciver From This Stream in Json File : " , ClDataCapture['end']['sum_received']['bits_per_second'] / 10**9 , " Gbps")
    Retransmision = 0
    for item in range(0 , len(capture)):
        if((str(capture[item])).find('retransmission' )!= -1):
            Retransmision += 1
    print("Count of Retransmision is" , Retransmision)
    DrawCharts(SvDataCapture , ClDataCapture)