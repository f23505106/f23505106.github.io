---
layout: post
title: "tls与密码学基础"
categories: [crypto,ssl,tls]
mathjax: true
---
# tls与密码学基础

## 总览

## 非对称加密和数字签名
这部分的定义位于[rfc3279](https://tools.ietf.org/html/rfc3279)
* Rivest-Shamir-Adelman (RSA)
* Digital Signature Algorithm (DSA)
* Elliptic Curve Digital Signature Algorithm (ECDSA)

非对称加密用于密钥交换和签名，在[tls其使用如下](https://en.wikipedia.org/wiki/Transport_Layer_Security#Algorithm)
![](https://markdown-1251303493.cos.ap-beijing.myqcloud.com/keyExTls.png)

DSA(即表中的DSS)在tls 1.3已经废弃，只支持rsa和ecdsa

签名一般是非对称加密配合hash算法使用
### RSA

[rsa规范](https://tools.ietf.org/html/rfc8017),详细的文档建议仔细读。

#### RSA的数学原理

rsa的数学模型如下

$$m^{e \times d} \pmod n \equiv m \label{eq:1} \tag{1}$$

加密过程

$$m^e \pmod n = c \tag{2}$$

解秘过程

$$c^d \pmod n = m \tag{3}$$

其中
* **m**待加密的消息
* **c**加密后的密文
* **n和e**公钥
* **n和d**私钥

密钥的生成也就是找到**n e d**三个值。

为了找到满足$\eqref{eq:1}$的数。这里直接说结论，不进行数学的论证，找到了[欧拉定理](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation)及证明，[中文证明](https://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)

当m和n互质时有下面公式成立
$$m^{\phi(n)} \equiv 1\pmod n \tag{4}$$

其中`φ(n)`为欧拉函数，如果n是质数`φ(n)=n-1`，如果n可以分解为质数p q的乘积，`φ(pq)=(p-1)(q-1)`

选择质数 p q 令 `n = pq` `φ(n)=(p-1)(q-1)` 可以被加密的数需要小于n，n即为密码的长度，常见(1024 2048)

任意选择一个质数 e， e需要和`φ(n)`互质(实际常使用3或者65537方便计算)。

$$ed \pmod {\phi(n)}  = 1$$

$$d = \frac{k \phi(n)+1}{e}$$

k为正整数 可以计算出d

* **n和e**公钥
* **n和d**私钥

#### RSA加解密基本操作(Cryptographic Primitives)
这里称基本操作是因为只设计加解密的数学计算，加解密模式会在基本操作基础上增加安全检查之类的过程。

#####  RSA加密操作(RSAEP-RSA Encryption Primitives)
RSAEP ((n, e), m)
输入:

* (n, e) RSA 公钥
* m 待加密的明文, 一个整数大小在 [0, n - 1]之间

输出:

* c 加密后的密文，一个整数大小在 [0, n - 1]之间

错误:

* 如果m不在[0, n - 1]之间，"message representative out of range"

默认前提:

* RSA 公钥(n, e)是有效的

步骤:

1. 如果m不在[0, n - 1]之间，输出"message representative out of range"结束
2. 计算$$c = m^e \pmod n
3. 输出 c

密钥的存储使用[asn1格式](http://luca.ntop.org/Teaching/Appunti/asn1.html) [解析](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)，主要有两种格式，二进制（DER），二进制base64编码(PEM)

综合以上 在一个rsa的私钥里会存储如下信息，[rfc定义](https://tools.ietf.org/html/rfc3447#appendix-A.1.1)

```
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n  Modulus (𝑛=𝑝𝑞)
    publicExponent    INTEGER,  -- e  Public exponent (𝑒)
    privateExponent   INTEGER,  -- d  Private exponent (𝑑=𝑒−1(mod𝜙(𝑛)))
    prime1            INTEGER,  -- p  First prime (𝑝)
    prime2            INTEGER,  -- q  Second prime (𝑞)
    exponent1         INTEGER,  --    First exponent, used for Chinese remainder theorem (𝑑𝑃=𝑑(mod𝑝−1))
    exponent2         INTEGER,  --    Second exponent, used for CRT (𝑑𝑄=𝑑(mod𝑞−1))
    coefficient       INTEGER,  --    Coefficient, used for CRT (𝑞inv=𝑞−1(mod𝑝))
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

选择如下key设置，存储为文件`my.rsa`,其他key[示例1](https://stackoverflow.com/questions/19850283/how-to-generate-rsa-keys-using-specific-input-numbers-in-openssl)
[示例2](https://thatsmaths.com/2016/08/11/a-toy-example-of-rsa-encryption/)

```
asn1=SEQUENCE:rsa_key

[rsa_key]
version=INTEGER:0
modulus=INTEGER:55
pubExp=INTEGER:7
privExp=INTEGER:23
p=INTEGER:5
q=INTEGER:11
e1=INTEGER:3
e2=INTEGER:3
coeff=INTEGER:1
```
使用`openssl asn1parse -genconf my.rsa -out my.der`转化为der格式的文件，[der文件格式解析](https://stackoverflow.com/questions/18039401/how-can-i-transform-between-the-two-styles-of-public-key-format-one-begin-rsa)
对应文件内容为

```
hexdump my.der
0000000 30 1b 02 01 00 02 01 37 02 01 07 02 01 17 02 01
0000010 05 02 01 0b 02 01 03 02 01 03 02 01 01         
000001d
```
该文件具体格式为

```
openssl rsa -in my.der -inform der -text -check
Private-Key: (6 bit)
modulus: 55 (0x37)
publicExponent: 7 (0x7)
privateExponent: 23 (0x17)
prime1: 5 (0x5)
prime2: 11 (0xb)
exponent1: 3 (0x3)
exponent2: 3 (0x3)
coefficient: 1 (0x1)
RSA key ok
writing RSA key
-----BEGIN RSA PRIVATE KEY-----
MBsCAQACATcCAQcCARcCAQUCAQsCAQMCAQMCAQE=
-----END RSA PRIVATE KEY-----
```
最下面为对应二进制文件的base64字符串即pem格式的文件的内容。

随着密码学的发展，非对称加密增加了Diffie-Hellman 和 Ellicptic Curve，为了在存储时能区分具体是哪种加密方式
引入了`oid`唯一标识符，

RSA 对应的oid为 PKCS#1: 1.2.840.113549.1.1.1

之前rsa公钥的asn1格式为

```
public struct RSAPublicKey {
   INTEGER modulus,
   INTEGER publicExponent 
}
```
添加oid之后
```
public struct SubjectPublicKeyInfo {
   AlgorithmIdentifier algorithm,
   RSAPublicKey subjectPublicKey
}

SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER, -- 1.2.840.113549.1.1.1 rsaEncryption (PKCS#1 1)
        parameters              ANY DEFINED BY algorithm OPTIONAL  },
    subjectPublicKey     BIT STRING {
        RSAPublicKey ::= SEQUENCE {
            modulus            INTEGER,    -- n
            publicExponent     INTEGER     -- e
        }
    }
}
```
SubjectPublicKeyInfo可以存储所有格式的公钥









