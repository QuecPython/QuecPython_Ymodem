# Copyright (c) Quectel Wireless Solution, Co., Ltd.All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding:utf-8 -*-


import gc
import uos
import sys
import ql_fs
import osTimer
import utime as time
from queue import Queue
from machine import UART

SOH = b"\x01"
STX = b"\x02"
EOT = b"\x04"
ACK = b"\x06"
NAK = b"\x15"
CAN = b"\x18"
CRC = b"\x43"

USE_LENGTH_FIELD = 0b100000
USE_DATE_FIELD = 0b010000
USE_MODE_FIELD = 0b001000
USE_SN_FIELD = 0b000100
ALLOW_1K_BLOCK = 0b000010
ALLOW_YMODEM_G = 0b000001

DEBUG = False

_MAIN_UART_ = UART(UART.UART2, 115200, 8, 0, 1, 0) if DEBUG else None


def _print(data):
    global DEBUG, _MAIN_UART_
    if DEBUG:
        _data = data if isinstance(data, bytes) else (data.encode() if isinstance(data, str) else str(data).encode())
        _data += b"" if _data.endswith(b"\r\n") else b"\r\n"
        _MAIN_UART_.write(_data)
    else:
        print(DEBUG)


def check_file():
    def wrapper(func):
        def _wrapper(*args, **kwargs):
            new_args = list()
            new_args.append(args[0])
            trans_file = args[1]
            _files = []
            for _file in trans_file:
                source, target = _file.strip("[]").split(",")
                _print("source: %s, target: %s" % (source, target))
                if ql_fs.path_exists(source):
                    file_info = {
                        "filepath": source,
                        "name": target.strip(" "),
                        "length": ql_fs.path_getsize(source),
                        "mtime": time.mktime(time.localtime()),
                        "source": "rtos"
                    }
                    _files.append(file_info)
                else:
                    _print("File [{}] is not exists.".format(source))
            new_args.append(_files)
            return func(*tuple(new_args), **kwargs)
        return _wrapper
    return wrapper


class Serial(object):
    def __init__(self, uart, buadrate=57600, databits=8, parity=0, stopbits=1, flowctl=0):
        self._uart = UART(uart, buadrate, databits, parity, stopbits, flowctl)
        self._uart.set_callback(self._uart_cb)
        self._queue = Queue(maxsize=1)
        self._timer = osTimer()

    def _uart_cb(self, *args):
        if self._queue.size() == 0:
            self._queue.put(None)

    def _timer_cb(self, *args):
        if self._queue.size() == 0:
            self._queue.put(None)

    def write(self, data):
        return self._uart.write(data)

    def read(self, nbytes, timeout=0):
        if nbytes == 0:
            return b""
        if self._uart.any() == 0 and timeout != 0:
            timer_started = False
            if timeout > 0:  # < 0 for wait forever
                self._timer.start(timeout, 0, self._timer_cb)
                timer_started = True
            self._queue.get()
            if timer_started:
                self._timer.stop()
        r_data = self._uart.read(min(nbytes, self._uart.any()))
        if self._queue.size():
            self._queue.get()
        return r_data

    def close(self):
        self._uart.close()


class Modem(object):
    crc_table = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    ]  # TODO release mem

    def __init__(self, reader, writer, mode="ymodem1k", program="rzsz"):
        # Args check.
        assert mode == "ymodem1k", "Invalid mode specified: %s" % mode
        assert program in ("rzsz", "rbsb", "pyam", "cyam", "kimp"), "Invalid program specified: %s" % program

        self.reader = reader
        self.writer = writer
        self.mode = mode
        self.program_features = dict(
            rzsz=USE_LENGTH_FIELD | USE_DATE_FIELD | USE_MODE_FIELD | ALLOW_1K_BLOCK,
            rbsb=USE_LENGTH_FIELD | ALLOW_1K_BLOCK,
            pyam=USE_LENGTH_FIELD | USE_DATE_FIELD | USE_SN_FIELD | ALLOW_1K_BLOCK | ALLOW_YMODEM_G,
            cyam=ALLOW_1K_BLOCK,
            kimp=ALLOW_1K_BLOCK,
        )[program]
        self._recv_file_name = ""
        self._remaining_data_length = 0
        self._recv_file_mtime = 0
        self._recv_mode = 0
        self._recv_sn = 0
        self.total_size = 0

    def abort(self, count=2):
        [self.writer(CAN) for _ in range(count)]
        self._delete_failed_file(self._recv_file_name)
        # return False

    def recv(self, crc_mode=1, retry=10, timeout=1000, delay=1, callback=None):
        """
        Parse the first package of YMODEM Batch Transmission to get the target file information
        """
        try:
            stream = None
            char = self._in_transfer_mode(crc_mode, retry, delay)
            if char is not None:
                stream = self._get_file_header(char, crc_mode)
            if stream is not None:
                char = self._in_transfer_mode(crc_mode, retry, delay)
            else:
                return None
            success_count = 0
            income_size = 0
            packet_size = 128
            sequence = 1
            cancel = 0
            write_packet = b""
            while True:
                error_count = 0
                while True:
                    if char == SOH:
                        if packet_size != 128:
                            packet_size = 128
                        break
                    elif char == STX:
                        if packet_size != 1024:
                            packet_size = 1024
                        break
                    elif char == EOT:
                        if cancel:
                            self.writer(ACK)
                            stream.close()
                            if callable(callback):
                                callback(self._recv_file_name, income_size)
                            self.recv()
                            return True
                        else:
                            cancel = 1
                            self.writer(NAK)
                            char = self.reader(1, timeout)
                    elif char == CAN:
                        if cancel:
                            self._delete_failed_file(self._recv_file_name)
                            return None
                        else:
                            cancel = 1
                            char = self.reader(1, timeout)
                    else:
                        error_count += 1
                        char = self.reader(1, timeout)
                        if error_count > retry:
                            self.abort()
                            return None
                if not self._verify_complement(timeout, sequence):
                    pass
                else:
                    data = self.reader(packet_size + 1 + crc_mode)
                    if data and len(data) == (packet_size + 1 + crc_mode):
                        valid, data = self._verify_recv_checksum(crc_mode, data)
                        # Write the original data to the target file
                        if valid:
                            success_count += 1
                            valid_length = packet_size
                            if self._remaining_data_length > 0:
                                valid_length = min(valid_length, self._remaining_data_length)
                                self._remaining_data_length -= valid_length
                            gc.collect()
                            write_packet += data[:valid_length]
                            income_size += len(data)
                            if len(write_packet) not in (0, 1024, 2048, 3072):
                                stream.write(write_packet)
                                write_packet = b""
                            else:
                                if self._remaining_data_length == 0:
                                    stream.write(write_packet)
                                    write_packet = b""
                            self.writer(ACK)
                            time.sleep_ms(5)
                            sequence = (sequence + 1) % 0x100
                            char = self.reader(1, timeout)
                            continue
                        else:
                            pass
                    else:
                        pass
                while True:
                    data = self.reader(1, timeout)
                    if data is None:
                        break
                self.writer(NAK)
                char = self.reader(1, timeout)
                continue
        except Exception as e:
            sys.print_exception(e)
            return False

    def _in_transfer_mode(self, crc_mode, retry, delay, timeout=1000, cancel=0, error_count=0):
        while True:
            if error_count >= retry:
                self.abort()
                return None
            elif crc_mode and error_count < (retry // 2):
                if not self.writer(CRC):
                    time.sleep(delay)
                    error_count += 1
            else:
                crc_mode = 0
                if not self.writer(NAK):
                    time.sleep(delay)
                    error_count += 1
            char = self.reader(1, timeout)
            if not len(char):
                error_count += 1
                continue
            elif char == SOH:
                return char
            elif char == STX:
                return char
            elif char == EOT:
                return char
            elif char == CAN:
                if cancel:
                    return None
                else:
                    cancel = 1
            else:
                error_count += 1

    def _get_file_header(self, char, crc_mode, timeout=1000, retry=10, packet_size=128):
        error_count = 0
        cancel = 0
        while True:
            while True:
                if char == SOH:
                    if packet_size != 128:
                        packet_size = 128
                    break
                elif char == STX:
                    if packet_size != 1024:
                        packet_size = 1024
                    break
                elif char == CAN:
                    if cancel:
                        return None
                    else:
                        cancel = 1
                else:
                    error_count += 1
                    if error_count > retry:
                        self.abort()
                        return None
            if not self._verify_complement(timeout):
                pass
            else:
                data = self.reader(packet_size + 1 + crc_mode)
                if data and len(data) == (packet_size + 1 + crc_mode):
                    valid, data = self._verify_recv_checksum(crc_mode, data)
                    if valid:
                        data = data.lstrip(b"\x00")
                        if not len(data):
                            self.writer(ACK)
                            return None
                        gc.collect()
                        self._recv_file_name = bytes.decode(data.split(b"\x00")[0], "utf-8")
                        self._check_path(self._recv_file_name)
                        try:
                            stream = open(self._recv_file_name, "wb+")
                        except IOError:
                            return None
                        data = bytes.decode(data.split(b"\x00")[1], "utf-8")
                        if self.program_features & USE_LENGTH_FIELD:
                            space_index = data.find(" ")
                            self._remaining_data_length = int(data if space_index == -1 else data[:space_index])
                            data = data[space_index + 1:]
                        if self.program_features & USE_DATE_FIELD:
                            space_index = data.find(" ")
                            self._recv_file_mtime = int(data if space_index == -1 else data[:space_index], 8)
                            data = data[space_index + 1:]
                        if self.program_features & USE_MODE_FIELD:
                            space_index = data.find(" ")
                            self._recv_mode = int(data if space_index == -1 else data[:space_index])
                            data = data[space_index + 1:]
                        if self.program_features & USE_SN_FIELD:
                            space_index = data.find(" ")
                            self._recv_sn = int(data if space_index == -1 else data[:space_index])
                        self.writer(ACK)
                        return stream
                    else:
                        pass
                else:
                    pass
            while True:
                data = self.reader(1, timeout)
                if data is None:
                    break
            self.writer(NAK)
            char = self.reader(1, timeout)
            continue

    @staticmethod
    def _check_path(path):
        if not ql_fs.path_exists(ql_fs.path_dirname(path)):
            ql_fs.mkdirs(ql_fs.path_dirname(path))

    @staticmethod
    def _delete_failed_file(path=""):
        if path and ql_fs.path_exists(path):
            uos.remove(path)

    def _verify_complement(self, timeout=1000, sequence=0):
        seq1 = self.reader(1, timeout)
        if seq1 is None:
            seq2 = None
        else:
            seq1 = ord(seq1)
            seq2 = self.reader(1, timeout)
            if seq2 is not None:
                seq2 = 0xff - ord(seq2)
        return (seq1 == seq2 == sequence)

    def _verify_recv_checksum(self, crc_mode, data):
        if crc_mode:
            _checksum = bytearray(data[-2:])
            remote_sum = (_checksum[0] << 8) + _checksum[1]
            local_sum = self._calc_crc(data[:-2])
            valid = bool(remote_sum == local_sum)
        else:
            _checksum = bytearray([data[-1]])
            remote_sum = _checksum[0]
            local_sum = self._calc_checksum(data[:-1])
            valid = remote_sum == local_sum
        return valid, data

    @staticmethod
    def _calc_checksum(data, checksum=0):
        return (sum(data) + checksum) % 256

    def _calc_crc(self, data, crc=0):
        for char in bytearray(data):
            crc_tbl_idx = ((crc >> 8) ^ char) & 0xff
            crc = ((crc << 8) ^ self.crc_table[crc_tbl_idx]) & 0xffff
        return crc & 0xffff

    @check_file()
    def send(self, trans_file, retry=10, timeout=1000, callback=None):
        packet_size = dict(
            xmodem=128,
            xmodem1k=1024,
            ymodem=128,
            # Not all but most programs support 1k length
            ymodem1k=(128, 1024)[(self.program_features & ALLOW_1K_BLOCK) != 0],
        )[self.mode]
        self.total_size = sum([i["length"] for i in trans_file])
        success_count = 0
        for i in trans_file:
            _print("trans_file: %s" % str(i))
            _print("[Sender]: Waiting the mode request and open file...")
            stream = open(i["filepath"], "rb")
            # wait C
            crc_mode = self._wait_c(timeout=timeout, retry=retry)
            if not crc_mode:
                return False
            # send file header SOH and wait ACK
            _print("[Sender]: Preparing info block")
            if not self.serial_trans(self._make_file_header_info(128, crc_mode, i), timeout, retry):
                return False
            # Data packets
            _print("[Sender]: Waiting the mode request...")
            # wait C
            crc_mode = self._wait_c(timeout=timeout, retry=retry)
            if not crc_mode:
                return False
            # send file body and wait ACK
            sequence = 1
            while True:
                _print("[Sender]: start _make_file_body_info")
                data, length = self._make_file_body_info(stream, packet_size, crc_mode, sequence)
                _print("[Sender]: end _make_file_body_info")
                if data:
                    if not self.serial_trans(data, timeout, retry, success_count, sequence):
                        return False
                    else:
                        success_count += length
                        if callable(callback):
                            callback(self.total_size, success_count, i["name"])
                else:
                    break
                sequence = (sequence + 1) % 0x100
            # send EOT and wait NAK
            self.writer(EOT)
            _print("[Sender]: EOT sent and awaiting NAK")
            if not self._wait_nak_ack(NAK):
                return False
            # send EOT and wait ACK
            self.writer(EOT)
            _print("[Sender]: EOT sent and awaiting ACK")
            if not self._wait_nak_ack(ACK):
                return False
            # send end frame and wait ACK
            _print("[Sender]: Transmission finished (ACK)")
            stream.close()
        self._send_end_packet(128)
        _print("[Sender]: Received %r" % self.reader(1))
        time.sleep(1)
        return True

    def _wait_c(self, cancel=0, timeout=10 * 1000, retry=10):
        error_count, crc_mode = 0, 0
        while True:
            # Blocking may occur here, the reader needs to have a timeout mechanism
            char = self.reader(1, timeout)
            if char:
                if char == NAK:
                    crc_mode = 0
                    _print("[Sender]: Received checksum request (NAK)")
                    return crc_mode
                elif char == CRC:
                    crc_mode = 1
                    _print("[Sender]: Received CRC request (C/CRC)")
                    return crc_mode
                elif char == CAN:
                    if cancel:
                        _print("[Sender]: Transmission cancelled (CAN)")
                        return False
                    else:
                        cancel = 1
                        _print("[Sender]: Ready for transmission cancellation (CAN)")
                elif char == EOT:
                    _print("[Sender]: Transmission cancelled (EOT)")
                    return False
                else:
                    _print("[Sender]: Error, expected NAK, CRC, EOT or CAN but got %r" % char)
            else:
                _print("[Sender]: No valid data was read")
            error_count += 1
            if error_count > retry:
                _print("[Sender]: Error, error_count reached {}, aborting...".format(retry))
                self.abort()
                return False

    def _make_file_header_info(self, packet_size, crc_mode, info=None):
        _print("_make_file_header_info")
        # Required field: Name
        header = self._make_send_header(packet_size, 0)
        _print("1 target name %s" % info["name"])
        data = info["name"].encode("utf-8")
        _print("2 target name %s" % data)
        # Optional field: Length
        if self.program_features & USE_LENGTH_FIELD:
            data += bytes(1)
            data += str(info["length"]).encode("utf-8")
        if self.program_features & USE_DATE_FIELD:
            mtime = oct(int(info["mtime"]))
            if mtime.startswith("0o"):
                data += (" " + mtime[2:]).encode("utf-8")
            else:
                data += (" " + mtime[1:]).encode("utf-8")
        # Optional field: Mode
        if self.program_features & USE_MODE_FIELD:
            if info["source"] == "Unix":
                data += (" " + oct(0x8000)).encode("utf-8")
            else:
                data += " 0".encode("utf-8")
        # Optional field: Serial Number
        if self.program_features & USE_MODE_FIELD:
            data += " 0".encode("utf-8")
        data += (b"\x00" * ((packet_size - len(data)) if packet_size > len(data) else 0))
        checksum = self._make_send_checksum(crc_mode, data)
        return (header + data + checksum)

    @staticmethod
    def _make_send_header(packet_size, sequence):
        _print("_make_send_header")
        assert packet_size in (128, 1024), packet_size
        _bytes = []
        if packet_size == 128:
            _bytes.append(ord(SOH))
        elif packet_size == 1024:
            _bytes.append(ord(STX))
        _bytes.extend([sequence, 0xff - sequence])
        return bytearray(_bytes)

    def _make_send_checksum(self, crc_mode, data):
        _print("_make_send_checksum")
        _bytes = []
        if crc_mode:
            crc = self._calc_crc(data)
            _bytes.extend([crc >> 8, crc & 0xff])
        else:
            crc = self._calc_checksum(data)
            _bytes.append(crc)
        return bytearray(_bytes)

    def serial_trans(self, info, timeout=1000, retry=10, success_count=1, sequence=None):
        error_count = 0
        # Blocking may occur here, the writer needs to have a timeout mechanism
        _print("[Sender]: data: {}".format(info))
        self.writer(info)
        _print("[Sender]: Block {} (Seq {}) sent".format(success_count, str(sequence)))
        while True:
            char = self.reader(1, timeout)
            _print("[Sender]: reader resp char {}".format(char))
            if char == ACK:
                return True
            elif char == NAK:   # 接收端写文件异常直接中断
                return False
            else:
                _print("[Sender]: error, expected ACK but got {} for block {}".format(char, str(sequence)))
                error_count += 1
                time.sleep_ms(timeout)
                if error_count > retry:
                    _print("[Sender]: Error, NAK received {} times, aborting...".format(error_count))
                    self.abort()
                    return False

    def _make_file_body_info(self, stream, packet_size, crc_mode, sequence):
        data = stream.read(packet_size)
        if not data:
            _print("[Sender]: Reached EOF")
            return False, 0
        length = len(data)
        header = self._make_send_header(packet_size, sequence)
        data += (b"\x1a" * ((packet_size - length) if packet_size > length else 0))
        checksum = self._make_send_checksum(crc_mode, data)
        return header + data + checksum, length

    def _wait_nak_ack(self, flags, timeout=10000, retry=10):
        error_count = 0
        while True:
            char = self.reader(1, timeout)
            if char == flags:
                _print("[Sender]: Received %r" % flags)
                return True
            else:
                _print("[Sender]: Error, expected %r but got %r" % (flags, char))
                error_count += 1
                if error_count > retry:
                    _print("[Sender]: Warning, EOT was not %r, aborting transfer..." % flags)
                    self.abort()
                    return False

    def _send_end_packet(self, packet_size, crc_mode=1):
        header = self._make_send_header(packet_size, 0)
        data = packet_size * b"\x00"
        checksum = self._make_send_checksum(crc_mode, data)
        _print(header + data + checksum)
        self.writer(header + data + checksum)


def enter_ymodem(callback=None):
    serial_io = Serial(UART.REPL_UART if hasattr(UART, "REPL_UART") else UART.UART3)
    receiver = Modem(serial_io.read, serial_io.write)
    receiver.recv(callback=callback)
    serial_io.close()


def send_file(trans_file):
    serial_io = Serial(UART.REPL_UART if hasattr(UART, "REPL_UART") else UART.UART3)
    sender = Modem(serial_io.read, serial_io.write)
    try:
        sender.send(trans_file)
    except Exception as e:
        _print(str(e))
    serial_io.close()


if __name__ == "__main__":
    enter_ymodem()