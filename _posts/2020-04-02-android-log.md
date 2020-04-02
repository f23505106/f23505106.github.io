---
layout: post
title: "android log实现分析"
tags:
  - android
  - log
---
对log系统要求:

* 快，对不能对性能影响很大
* 准，在应用crash时不能丢失log
* 稳，支持多个进程同时访问

#Android log实现分析

#xlog分析