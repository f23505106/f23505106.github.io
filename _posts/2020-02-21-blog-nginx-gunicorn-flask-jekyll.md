---
layout: post
title: "静态博客系统搭建使用nginx+gunicorn+flask+jekyll"
categories: [markdown,服务器]
header-img: "img/post-bg-os-metro.jpg"
tags:
  - markdown
  - 服务器
---

github使用jekyll作为博客系统，作为开发者只需要使用markdown写好，通过git push到github即可显示出来。
大大减轻了单独建站的难度。之前因为精力，经济原因，尝试了很多种方式，购买空间后到期未续费，作出后效果不好而放弃等。
需要一种文章和格式相分离，方便博客迁移的系统。markdown作为书写方式肯定是首选，博客系统以文章为主，静态网站即可满足。
具体结构如下

![结构图](https://markdown-1251303493.cos.ap-beijing.myqcloud.com/github_io.png)
