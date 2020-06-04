---
layout: post
title: "tls与密码学基础"
categories: [crypto,ssl,tls]
mathjax: true
---
# tls与密码学基础

## 总览

## RSA
rsa的数学模型如下

$$m^{e \times d} \pmod n \equiv m \tag$$

加密过程

$$m^e \pmod n = c \tag$$

解秘过程

$$c^d \pmod n = m$$

其中
* **m**待加密的消息
* **c**加密后的密文
* **n和e**公钥
* **n和d**私钥

密钥的生成也就是找到**n e d**三个值。

解释（不重要，理解p和q就可以，这个会在key文件里出现）

一、互质关系

如果两个正整数，除了1以外，没有其他公因子，我们就称这两个数是互质关系。比如，17和32没有公因子，所以它们是互质关系。这说明，不是质数也可以构成互质关系。

关于互质关系，不难得到以下结论：

* 任意两个质数构成互质关系，比如13和61。
* 一个数是质数，另一个数只要不是前者的倍数，两者就构成互质关系，比如3和10。
* 如果两个数之中，较大的那个数是质数，则两者构成互质关系，比如97和57。
* 1和任意一个自然数是都是互质关系，比如1和99。
* p是大于1的整数，则p和p-1构成互质关系，比如57和56。
* p是大于1的奇数，则p和p-2构成互质关系，比如17和15。

二、欧拉函数

任意给定正整数n，请问在小于等于n的正整数之中，有多少个与n构成互质关系？（比如，在1到8之中，有多少个数与8构成互质关系？）
计算这个值的方法就叫做欧拉函数，以φ(n)表示。在1到8之中，与8形成互质关系的是1、3、5、7，所以 φ(n) = 4。
如果n是质数，则 φ(n)=n-1 。因为质数与小于它的每一个数，都构成互质关系。比如5与1、2、3、4都构成互质关系

三、欧拉定理

欧拉函数的用处，在于欧拉定理。”欧拉定理”指的是：
如果两个正整数m和n互质，则n的欧拉函数 φ(n) 可以让下面的等式成立:

$$m^{\phi(n)} \equiv 1\pmod n$$

即

$$m^{\phi(n)}\pmod n = 1$$

借助欧拉定理，可以使找到合适的**n e d**变得简单

泛化

$$m^{k \phi(n)}\pmod n = 1$$

k是任意整数

欧拉定理两面同时乘于m的到

$$m^{k \phi(n)+1} \pmod n = m$$


可以看到**k &phi;(n)+1**就是想得到的 **e x d**


为了方便计算**k &phi;(n)+1**取 质数**p q** 使**n=p x q**同时取质数**e**(常用3或65537)

**k &phi;(n)+1 = e x d -> k(p-1)(q-1)+1 = e x d** 其中p q e为已知，k d为未知，这个方程可以用"扩展欧几里得算法"求解。

**注意** e在选取时需要和 &phi;(n)互质。

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
对应公钥格式如下

```
RSAPublicKey:

RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
```
选择如下key设置，存储为文件`my.rsa`

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
使用`openssl asn1parse -genconf my.rsa -out my.der`转化为der格式的文件
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
最下面为对应二进制文件的base64字符串











