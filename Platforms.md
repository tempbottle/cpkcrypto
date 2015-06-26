#Install and run CPK Crypto Library in different operating systems




## OpenSolaris ##

The Solaris cryptographic framework can only load modules that signed by Sun Microsystems. So the compiled pkcs11 cpk.so can not be successful loadded. It must be signed by the tool elfsign and the corresponding certiﬁcate should be
applied from Sun and stored in the certiﬁcates directory. After that, administrator can load the module and view related information with the tool **cryptoadm**.


```
# cryptoadm list -vm 
Provider: /etc/crypto/modules/pkcs11_cpk.so 
Number of slots: 1 
Slot #1 
Description: CPK Crypto Softtoken 
Manufacturer: Guan Zhi                       
PKCS#11 Version: 2.20 
Hardware Version: 0.0 
Firmware Version: 0.0 
Token Present: True 
Slot Flags: CKF_TOKEN_PRESENT 
Token Label: CPK PKCS#11 Software token     
Manufacturer ID: Guan Zhi                       
Model: 1.0             
Serial Number:                 
Hardware Version: 0.0 
Firmware Version: 0.0 
UTC Time:                 
PIN Length: 0-0 
Flags: 

Mechanisms: 
                                                      P  
                                          S     V  K  a     U  D 
                                          i     e  e  i     n  e 
                                       S  g  V  r  y  r  W  w  r 
                              E  D  D  i  n  e  i  G  G  r  r  i 
                           H  n  e  i  g  +  r  +  e  e  a  a  v  E 
mechanism name   min  max  W  c  c  g  n  R  i  R  n  n  p  p  e  C 
--------------------------------------------------------------------- 
0x80000002       128  521  .  X  X  .  X  .  X  .  .  .  .  .  .  . 
0x80000003       128  521  .  .  .  .  X  .  X  .  .  .  .  .  .  . 
0x80000004       128  521  .  .  .  .  X  .  X  .  .  .  .  .  .  . 
0x80000005       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x80000016       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x80000006       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x80000007       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x80000017       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x80000008       128  521  .  .  .  .  X  X  X  X  .  .  .  .  .  . 
0x80000009       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x8000000a       128  521  .  X  X  .  .  .  .  .  .  .  .  .  .  . 
0x8000000b       128  521  .  X  X  .  X  X X X .  .  .  .  .  . 
0x8000000c       128  521  .  X  X  .  X  X X X .  .  .  .  .  .
```