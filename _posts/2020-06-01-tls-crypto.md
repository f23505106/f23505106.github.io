---
layout: post
title: "tls与密码学基础"
categories: [crypto,ssl,tls]
mathjax: true
---
# tls与密码学基础

## 总览

## RSA
rsa的数学模型为

$$m^{e \times d} \pmod n \equiv m$$

加密过程

$$m^e \pmod n = c$$

解秘过程

$$c^d \pmod n = m$$

其中
* **m**待加密的消息
* **c**加密后的密文
* **n和e**公钥
* **n和d**私钥