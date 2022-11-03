# Ymodem文件传输方法说明

该使用说明主要描述如何使用Ymodem协议通过串口向模组传输文件，需要模组的接收端处于接收模式才可以传输，该协议传输规范符合标准Ymodem 1K的传输规范，整体代码由python实现，接收端为QuecPython模块，模块端代码由QuecPython代码编写

适用系统

- **Windows**
- **Linux**

协议传输参考Ymodem协议实现，代码实现参考 Pypi的xmodem模块，在xmodem协议的基础上实现了ymodem协议传输，新增特性支持单次连接传输多个文件，并且基于QuecPython做了众多适配，不再适用于传统的xmodem模式

## 发送端使用方法

### python代码使用方法

python代码依赖库（python版本>3.0)

- os
- time
- serial

#### 函数调用

调用方法，在代码中调用如下函数

```python
# port为要传输的串口,filepath为文件本地路径,remote_filepath为传输到模组中的路径(绝对路径)
send_file(port, [filepath, remote_filepath]...)
# 当需要传多个文件时，参数累加文件列表即可
```

如果想调整Ymodem传输模式，参照以下方法修改（推荐使用默认参数，QuecPython环境下只可使用rzsz、rbsb、pram）

> KMD/IMP 详见官方文档

YMODEM传输模式，默认使用program为rzsz，文件头长度为128字节，文件体长度为1024字节，即 mode为 ymodem1k

|Program   | Length | Date | Mode | S/N | 1k-Blk | YMODEM-g|
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
|Unix rz/sz | yes    | yes  | yes  | no  | yes    | sb only  |
|VMS rb/sb  | yes    | no   | no   | no  | yes    | no       |
|Pro-YAM    | yes    | yes  | no   | yes | yes    | yes      |
|CP/M YAM   | no     | no   | no   | no  | yes    | no       |
|KMD/IMP    | ？   | no   | no   | no  | yes    | no       |

若要修改默认program，需要在send_file函数代码中增加初始化参数

```python
sender = Modem(sender_read, sender_write，"rzsz")   # 可选参数: rzsz|rbsb|pyam|cyam|kimp
```

#### 回调函数

回调参数：

| 参数（按顺序）  | 描述               |
| --------------- | ------------------ |
| total packets   | 待发送的文件总大小 |
| success packets | 发送成功的包总大小 |

### 命令行工具使用方法

待补充

## 接收端使用方法

### 进入传输模式

模组端使用只需进入传输模式即可

```
enter_ymodem(callback=None)
```

传输模式会等待10s，10s后没有数据传入就退出传输模式

### 回调函数

回调参数：

| 参数（按顺序） | 描述             |
| -------------- | ---------------- |
| filename       | 传输完成的文件名 |
| filesize       | 传输文件的大小   |