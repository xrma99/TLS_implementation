
# coding: utf-8

# In[ ]:


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



def Serverhandshake(srcaddr,dstaddr):
    #make the message
    flag=0 #标志位，表示此报文是握手报文
    time=ctime() #约等于发送时间
    
    rA=random.randint(1,p-1) #这个函数取的是一个闭区间
    Pa=(q**rA)%p
    
    msg=str(Pa) #正文
    print("Pa:",msg)
    res=str(time)+" "+str(srcaddr)+" "+str(dstaddr)+" "+str(msg)
    mac = hashlib.md5(res.encode('utf8')).hexdigest()
    totalmsg=res+" "+str(mac)
    
    with open("D:\\ClientPb.pem", "rb") as x:
        b = x.read()  
        cipher_public = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(b))
        cipher_text = cipher_public.encrypt(totalmsg.encode()) # 使用公钥进行加密
    
    
    return ("0 ").encode()+cipher_text,rA 




if __name__ == '__main__':
    print("Session Key Exchange Algorithm: DHE-RSA\n")
    print("Session Encryption and Decryption Algorithm: DES\n")
    hname = socket.getfqdn(socket.gethostname(  ))
    ipaddr = socket.gethostbyname(hname)
    port=23456
    MYADDR=(ipaddr,port)
    print(MYADDR)
    tcpsock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)#IPv4, TCP的流式socket
    tcpsock.bind(MYADDR)
    print("This socket is ready to receive...\n")
    tcpsock.listen()#监听连接
    key="12345678"
    
    while True:
        print("Waiting for connection...\n")
        tcpclisock,caddr=tcpsock.accept()#接受TCP连接并返回
        print("...connectingfrom:",caddr)
        while True:
            msg=tcpclisock.recv(2048)
            if not msg:
                break            
            msgtype=msg[0]
            msg=msg[2:len(msg)]
            if(msgtype==48):#handshake, 48是‘0’的ASCII码
                data,da=Serverhandshake(MYADDR,caddr)#生成握手报文(bytes类型)
                tcpclisock.send(data)
                
                with open("D:\\ServerPv.pem", "rb") as x:
                    a = x.read()
                    cipher_private = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(a))
                    text = cipher_private.decrypt(msg, Crypto.Random.new().read)    # 使用私钥进行解密
                
                msg=Verifymsg(text)
                words=msg.split()
                Pb=int(words[-1],10)
                k=(Pb**da)%p
                k=hex((k**Iv)+Ipad)
                key=k[2:10] #session key
                print(msg)             

            elif(msgtype==49):#normal contact
                msg=msg.decode('utf-8')
                msg=TLSdecrypt(msg,key)
                print(msg)
                data=input("Message>>> ")
                
                if(data=="exit"):#end the connection
                    data=TLSencrypt(2,data,MYADDR,caddr,key)
                    tcpclisock.send(data.encode())
                    break #Server发送说关闭那就直接关闭
                else:
                    data=TLSencrypt(1,data,MYADDR,caddr,key)
                
                tcpclisock.send(data.encode())
            else:#close connection
                msg=msg.decode('utf-8')
                msg=TLSdecrypt(msg,key)
                print(msg)
                data=TLSencrypt(2,"exit",MYADDR,caddr,key) 
                tcpclisock.send(data.encode())
                break
                
            
        tcpclisock.close()
        print("Connection closed:",caddr)

    tcpsock.close()
    

