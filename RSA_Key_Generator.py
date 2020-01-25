
# coding: utf-8

# In[1]:


import Crypto.PublicKey.RSA
import Crypto.Random
 
x = Crypto.PublicKey.RSA.generate(2048)
a = x.exportKey("PEM")  # 生成私钥
b = x.publickey().exportKey()   # 生成公钥
with open("D:\\ServerPv.pem", "wb") as x:
    x.write(a)
with open("D:\\ServerPb.pem", "wb") as x:
    x.write(b)
    
x = Crypto.PublicKey.RSA.generate(2048)
a = x.exportKey("PEM")  # 生成私钥
b = x.publickey().exportKey()   # 生成公钥
with open("D:\\ClientPv.pem", "wb") as x:
    x.write(a)
with open("D:\\ClientPb.pem", "wb") as x:
    x.write(b)

