# CPK命令行工具用户手册 1.0 #

本软件提供了CPK密钥管理功能和基于标识的密码操作功能。系统的主要功能包括：

  * 实现了椭圆曲线密码和素数域上的组合公钥（CPK）密码系统；
  * 提供了CPK基于身份的密钥管理功能；
  * 提供了CPK基于身份的加密和数字签名功能；
  * 提供了保留文件格式的文件加密和数字签名功能。

工具支持的操作系统：

  * GNU/Linux
  * OS X
  * Windows XP/Vista/7
  * Android

## 系统初始化 ##


本软件的密钥管理功能包括CPK密码系统的系统建立和用户私钥的生成。
组合公钥系统的建立
```
$ cpk -setup <domain_id>
```
其中domain\_id是安全域的标识符字符串。命令执行之后会在当目录输出系统主密钥文件master\_secret和公开系统参数文件public\_params。其中系统的主密钥文件master\_secret是以明文保存，因此系统的安全管理员应妥善保管该文件。
公开系统参数可以保存在本地，也可以发布到需要的URL为系统中的用户提供公开访问的方式。在系统建立之后，管理员可以通过命令行程序为ID生成并发布对应的私钥。
```
$ cpk -setup http://infosec.pku.edu.cn/cpk/authority
```


导出公开系统参数
```
cpk -export-params [-out  file]
```
打印公开系统参数
```
cpk -print-params
```
生成用户私钥
```
cpk -genkey identity -pass password -out file
```

## 用户端密钥管理功能 ##
导入公开系统参数
```
cpk -import-param -in paramfile
```

设置用户身份标识
```
cpk -set-identity identity
```
导入用户签名私钥
```
cpk -import-sign-key -in keyfile -pass password
```
改变签名私钥口令
```
cpk -change-sign-password -pass oldpassword -newpass newpassword
```

导入用户解密私钥
```
cpk -import-decrypt-key -in keyfile -pass password
```
改变用户解密私钥保护口令
```
cpk -change-decrypt-password -pass oldpassword -newpass newpassword
```

## 加密与签名功能 ##
文本签名
```
echo “message to be signed” | cpk -sign
Enter Password:
MDQCGDCeaudRNSA/TX3poVAEF49llXGeHcU4fQIYWUEPsLT1U5faZYjA7QyimOZgypd0etCv
```
文本验证
```
echo “message to be signed” | cpk -verify -signature MDQCGDCeaudRNSA/TX3poVAEF49llXGeHcU4fQIYWUEPsLT1U5faZYjA7QyimOZgypd0etCv -signer guan@pku.edu.cn
```

```
$ cpk -genkey user_id
```
其中user\_id是用户的公开标识，cpkgenkey会读取～/.cpk/master\_secret文件并生成对应的私钥文件。