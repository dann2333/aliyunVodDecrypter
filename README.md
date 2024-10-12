# aliyunVodDecrypter
A tool to decrypt aliyun vod private encrypt.

阿里云Vod私有加密解密工具
使用方法：安装依赖，而后运行main.py，输入playauth与origin_url（用于referer与origin）即可自动下载合并到程序运行目录的output文件夹下
使用前请确保您安装了ffmpeg，并且其可被命令直接调用
可按需调整`config.py`预先定义origin_url或者修改程序使用的header
作者的ffmpeg版本为：
`ffmpeg version 7.1-full_build-www.gyan.dev Copyright (c) 2000-2024 the FFmpeg developers
  built with gcc 14.2.0 (Rev1, Built by MSYS2 project)
`
本程序使用了来自https://yzctzl.github.io/2021/aliplayer/#%E5%88%86%E6%9E%90%E8%B0%83%E7%94%A8%E5%A0%86%E6%A0%88
的程序代码，非常感谢这位大佬！
