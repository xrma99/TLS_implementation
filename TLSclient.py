
# coding: utf-8

# In[1]:


import socket
from time import ctime
import hashlib
from Crypto.Cipher import DES
import base64
from binascii import a2b_base64,b2a_base64
import random
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Random
import Crypto.Signature.PKCS1_v1_5
import Crypto.Hash


q=7
p=15
Iv=30347
Ipad=0x12345678

# DES加密
def encrypt_str(data,Key):

    remain=len(data)%8
    remainstr=(8-remain)*" "
    data=data+remainstr #加padding

    obj=DES.new(Key)
    Enres=obj.encrypt(data)
    EnresBase=b2a_base64(Enres)
    return bytes.decode(EnresBase)


# DES解密
def decrypt_str(data,Key):
    obj=DES.new(Key)
    x=a2b_base64(data)#string转特殊base64
    y=obj.decrypt(x)
    return y

# 通信正文加密
def TLSencrypt(flag,msg,srcaddr,dstaddr,key):
    #make the message
    time=ctime()
    res=str(time)+" "+str(srcaddr)+" "+str(dstaddr)+" "+str(msg)
    mac = hashlib.md5(res.encode('utf8')).hexdigest()
    totalmsg=res+" "+str(mac)#生成报文
    
    return str(flag)+" "+encrypt_str(totalmsg,key)#加密

# 通信正文解密
def TLSdecrypt(data,Key):
    msg=decrypt_str(data,Key)
    return Verifymsg(msg)

    
def Verifymsg(msg):
    msg=bytes.decode(msg)#获得str报文
    words=msg.split()
    mac=words[-1]
    realmsg=words[0:-1]
    realmsg=" ".join(realmsg)
    
    realmsgmac=hashlib.md5(realmsg.encode('utf8')).hexdigest()
    if(str(realmsgmac)==mac):
        return realmsg
    else:
        return "This message is not valid.\n"

def Clienthandshake(srcaddr,dstaddr):
    flag=0 #标志位，表示此报文是握手报文
    time=ctime() #约等于发送时间
    
    rB=random.randint(1,p-1)
    Pb=(q**rB)%p
    
    msg=str(Pb) #正文
    print("Pb:",msg)
    
    res=str(time)+" "+str(srcaddr)+" "+str(dstaddr)+" "+str(msg)
    mac = hashlib.md5(res.encode('utf8')).hexdigest()
    totalmsg=res+" "+str(mac)
    
    with open("D:\\ServerPb.pem", "rb") as x:
        b = x.read()  
        cipher_public = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(b))
        cipher_text = cipher_public.encrypt(totalmsg.encode()) # 使用公钥进行加密
        
    return ("0 ").encode()+cipher_text,rB 


if __name__ == '__main__':
    print("Session Key Exchange Algorithm: DHE-RSA\n")
    print("Session Encryption and Decryption Algorithm: DES\n")
    dstipaddr = '192.168.56.1'
    dstport=23456
    DSTADDR=(dstipaddr,dstport)
    
    hname = socket.getfqdn(socket.gethostname(  ))
    ipaddr = socket.gethostbyname(hname)
    port=34567
    MYADDR=(ipaddr,port)

    tcpsock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    tcpsock.connect(DSTADDR)

    print("Connecting to the server...\n")
    
    data,db=Clienthandshake(MYADDR,DSTADDR)#生成握手报文(bytes类型)
    tcpsock.send(data) #发送握手报文
    while True:
        msg=tcpsock.recv(2048)#接收服务器握手报文
        if(msg[0]==48):#server handshake
            break
    msg=msg[2:len(msg)]
    
    with open("D:\\ClientPv.pem", "rb") as x:
        a = x.read()
        cipher_private = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(a))
        text = cipher_private.decrypt(msg, Crypto.Random.new().read)    # 使用私钥进行解密
    
    #text=bytes.decode(text)
    msg=Verifymsg(text)
    words=msg.split()
    Pa=int(words[-1],10)
    k=(Pa**db)%p
    k=hex((k**Iv)+Ipad)
    key=k[2:10] #session key
    print(msg)
        
    while True:
        data=input("Message>>> ")
        
        if(data=="exit"):#end the connection
            data=TLSencrypt(2,data,MYADDR,DSTADDR,key)
        else:
            data=TLSencrypt(1,data,MYADDR,DSTADDR,key)
        tcpsock.send(data.encode())
    
        msg=tcpsock.recv(2048)
        if not msg:
            break
        msgtype=msg[0]
        msg=msg[2:len(msg)]
        msg=msg.decode('utf-8')        
        msg=TLSdecrypt(msg,key)
        print(msg)
        if(msgtype==50):#exit
            break

    tcpsock.close()
    print("Connection closed:",DSTADDR)

