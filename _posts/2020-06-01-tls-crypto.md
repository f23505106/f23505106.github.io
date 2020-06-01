---
layout: post
title: "tls与密码学基础"
categories: [crypto,ssl,tls]
mathjax: true
---
#tls与密码学基础

##总览

##RSA
rsa的数学模型为
$$m^(e \times d) \pmod n \equiv m$$

加密过程
$$m^e \pmod n = c$$

解秘过程
$$c^d \pmod n = m$$

其中
* m待加密的消息
* c加密后的密文
* 公钥n和e
* 私钥n和d