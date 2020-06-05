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

**输入:**
* (n, e) RSA 公钥
* m 待加密的明文, 一个整数大小在 [0, n - 1]之间

**输出:**
* c 加密后的密文，一个整数大小在 [0, n - 1]之间

**错误:**
* 如果m不在[0, n - 1]之间，"message representative out of range"

**默认前提:**
* RSA 公钥(n, e)是有效的

**步骤:**
1. 如果m不在[0, n - 1]之间，输出"message representative out of range"结束
2. 计算$$c = m^e \pmod n$$
3. 输出 c

#####  RSA解密操作(RSADP-RSA Decryption Primitives)
RSADP (K, c)

**输入:**
* K RSA私钥这里只讨论(n, d)这种情况
* c 待解密密文，一个整数大小在 [0, n - 1]之间

**输出:**
* m 解密后的明文，一个整数大小在 [0, n - 1]之间

**错误:**
* 如果c不在[0, n - 1]之间，"ciphertext representative out of range"

**默认前提:**
* RSA 私钥(n, d)是有效的

**步骤:**
1. 如果c不在[0, n - 1]之间，输出"ciphertext representative out of range"结束
2. 计算$$m = c^d \pmod n$$
3. 输出 m

签名的过程和加密类似，只是用私钥计算签名-RSASP1，用公钥验证签名-RSAVP1。

#### RSA加解密模式(Cryptographic Schemes)
加解密模式会在加解密基本操作基础上增加安全检查之类的过程。
[举个例子](https://security.stackexchange.com/questions/183179/what-is-rsa-oaep-rsa-pss-in-simple-terms)

假设rsa对应的n为4096位，这个强度已经很高了，看起来是无法破解的，假设公钥的e为3。
现在Alice用这个公钥加密消息"No" 给Bob，对应的计算过程为

* "No" => ASCII("No") => 0x4E 0x6F => m=0x4E6F
* c = POW(0x4E6F, 3) MOD n => c = 0x75CCE07084F MOD n

n有4096位比较大，c = 0x75CCE07084F小于n，取余之后是本身。监听者Mallory会看到[506 个 0x00s] 07 5C CE 07 08 4F信息传输。
"Hmm," Mallory想这个信息很可疑，前面有太多的0，Mallory打开计算器，将0x75CCE07084F转化为十进制8095174953039，因为知道公钥的
e为3，Malloy对8095174953039开三次方得到20079，将20079转化为16进制，得到0x4E6F，查询ASCII码表，可以得出这个消息就是"No"。
Malloy现在不用私钥就解出对应消息。

问题出在哪呢？首先可能会说e选的太小了，因为e是公开的这个并不是主要原因，开高次方虽然看起复杂，计算起来也很快。
从加密后的信息看里面有太多的0，这才是密文被猜出的主要原因。
为了减少密文中0的数量，需要把代表明文的整数增大，保证取余操作生效，即对明文信息进行padding。

还有一个问题就是直接加密相同的明文每次生成的密文也是相同的，大量观察下也能根据频率猜出信息的一部分内容。为了解决这个问题，
只能向明文里加入随机的内容，这样就能保证相同的明文多次加密生成的密文不同，也是一种padding模式。

首先提出解决这个问题并大规模使用的模式是RSAES-PKCS1-v1_5(RSA Encryption Schemes)

##### RSAES-PKCS1-v1_5加密模式
RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)

**输入:**
* (n, e) RSA公钥 k表示n的二进制位数除于8,即n长度有多byte
* M 待加密的明文信息 长度为mLen byte, 要求mLen <= k - 11

**输出:**
* C 加密后的密文,长度为k

**错误:**
* 如果M的长度超过k - 11,"message too long"

**步骤:**
1. 检查M的长度, 如果mLen > k - 11, 输出"message too long"结束.
2. EME-PKCS1-v1_5 编码
    1. 生成一个随机的字符串PS,长度为`k - mLen - 3` byte 每个byte都不为0x00, PS最小的长度为8.
    2. 将PS和M组合生成新的长度为k的编码后的字符串EM
        > EM = 0x00 || 0x02 || PS || 0x00 || M.
3. RSA加密
    1. 将字符串EM转化为一个整数m
    2. 使用RSAEP加密操作, 计算出代表密文的整数c
        > c = RSAEP ((n, e), m)
    3. 将整数c转化代表密文的长度为k的字符串C
4. 输出密文C






在实际的应用中，直接使用rsa会存在问题

1. 相同的明文每次加密后生成的相同的密文
2. 在明文比较小的时候，能直接通过密文猜出对应的明文




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









