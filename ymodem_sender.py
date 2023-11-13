#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project:FactoryTool
@File:ymodem.py
@Author:rivern.yuan
@Date:2022/10/11 16:31
"""

# import fire
import os
import time
import serial
import logging


log = logging.getLogger("Modem")
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.DEBUG, datefmt="%Y-%m-%d %H:%M:%S")

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


def check_file():
    def wrapper(func):
        def _wrapper(*args, **kwargs):
            new_args = list()
            new_args.append(args[0])
            file_handler = list()
            for i, value in enumerate(args[1]):
                arg_list = value.strip("[]").split(",")
                if os.path.exists(arg_list[0]):
                    file_info = {
                        "filepath": arg_list[0],
                        "name": arg_list[1].strip(" "),
                        "length": os.path.getsize(arg_list[0]),
                        "mtime": os.path.getmtime(arg_list[0]),
                        "source": "win"
                    }
                    file_handler.append(file_info)
                else:
                    log.error("{} 本地文件不存在".format(arg_list[0]))
            new_args.append(file_handler)
            return func(*tuple(new_args), **kwargs)
        return _wrapper
    return wrapper


class Modem:
    # For CRC algorithm
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
    ]

    def __init__(self, reader, writer, mode="ymodem1k", program="rzsz"):
        """
        YMODEM Header Information and Features
        _____________________________________________________________
        | Program   | Length | Date | Mode | S/N | 1k-Blk | YMODEM-g |
        |___________|________|______|______|_____|________|__________|
        |Unix rz/sz | yes    | yes  | yes  | no  | yes    | sb only  |
        |___________|________|______|______|_____|________|__________|
        |VMS rb/sb  | yes    | no   | no   | no  | yes    | no       |
        |___________|________|______|______|_____|________|__________|
        |Pro-YAM    | yes    | yes  | no   | yes | yes    | yes      |
        |___________|________|______|______|_____|________|__________|
        |CP/M YAM   | no     | no   | no   | no  | yes    | no       |
        |___________|________|______|______|_____|________|__________|
        |KMD/IMP    | ?      | no   | no   | no  | yes    | no       |
        |___________|________|______|______|_____|________|__________|

        """
        # Args check.
        assert mode == "ymodem1k", "Invalid mode specified: %s" % mode
        assert program in ("rzsz", "rbsb", "pyam", "cyam", "kimp"), "Invalid program specified: %s" % program

        self.reader = reader
        self.writer = writer
        self.mode = mode
        self.total_size = 0
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

    def abort(self, count=2, timeout=60):
        for _ in range(count):
            self.writer(CAN, timeout)

    @check_file()
    def send(self, trans_file, retry=10, timeout=1, callback=None):
        try:
            packet_size = dict(
                xmodem=128,
                xmodem1k=1024,
                ymodem=128,
                # Not all but most programs support 1k length
                ymodem1k=(128, 1024)[(self.program_features & ALLOW_1K_BLOCK) != 0],
            )[self.mode]
        except KeyError:
            raise ValueError("Invalid mode specified: {self.mode}".format(self=self))
        for i in trans_file:
            self.total_size += i["length"]
        success_count = 0
        for i in trans_file:
            log.debug("[Sender]: Waiting the mode request and open file...")
            stream = open(i["filepath"], "rb")
            # wait C
            crc_mode = self._wait_c(timeout, retry)
            if not crc_mode:
                return False
            # send file header SOH and wait ACK
            log.debug("[Sender]: Preparing info block")
            if not self.serial_trans(self._make_file_header_info(128, crc_mode, i), timeout, retry):
                return False
            # Data packets
            log.debug("[Sender]: Waiting the mode request...")
            # wait C
            crc_mode = self._wait_c(timeout, retry)
            if not crc_mode:
                return False
            # send file body and wait ACK
            sequence = 1
            while True:
                data, length = self._make_file_body_info(stream, packet_size, crc_mode, sequence)
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
            log.debug("[Sender]: EOT sent and awaiting NAK")
            if not self._wait_nak_ack(NAK):
                return False
            # send EOT and wait ACK
            self.writer(EOT)
            log.debug("[Sender]: EOT sent and awaiting ACK")
            if not self._wait_nak_ack(ACK):
                return False
            # send end frame and wait ACK
            log.info("[Sender]: Transmission finished (ACK)")
            stream.close()
        self._send_end_packet(128)
        log.debug("[Sender]: Received %r", self.reader(1))
        return True

    def _make_file_header_info(self, packet_size, crc_mode, info=None):
        # Required field: Name
        header = self._make_send_header(packet_size, 0)
        data = info["name"].encode("utf-8")
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
        data = data.ljust(packet_size, b"\x00")
        checksum = self._make_send_checksum(crc_mode, data)
        return header + data + checksum

    def _make_file_body_info(self, stream, packet_size, crc_mode, sequence):
        data = stream.read(packet_size)
        length = len(data)
        if not data:
            log.debug("[Sender]: Reached EOF")
            return False, 0
        header = self._make_send_header(packet_size, sequence)
        # fill with 1AH(^z)
        data = data.ljust(packet_size, b"\x1a")
        checksum = self._make_send_checksum(crc_mode, data)
        return header + data + checksum, length

    def _wait_c(self, cancel=0, timeout=10, retry=10):
        error_count, crc_mode = 0, 0
        while True:
            # Blocking may occur here, the reader needs to have a timeout mechanism
            char = self.reader(1, timeout)
            if char:
                if char == NAK:
                    crc_mode = 0
                    log.debug("[Sender]: Received checksum request (NAK)")
                    return crc_mode
                elif char == CRC:
                    crc_mode = 1
                    log.debug("[Sender]: Received CRC request (C/CRC)")
                    return crc_mode
                elif char == CAN:
                    if cancel:
                        log.info("[Sender]: Transmission cancelled (CAN)")
                        return False
                    else:
                        cancel = 1
                        log.debug("[Sender]: Ready for transmission cancellation (CAN)")
                elif char == EOT:
                    log.info("[Sender]: Transmission cancelled (EOT)")
                    return False
                else:
                    log.error("[Sender]: Error, expected NAK, CRC, EOT or CAN but got %r", char)
            else:
                log.debug("[Sender]: No valid data was read")
            error_count += 1
            if error_count > retry:
                log.error("[Sender]: Error, error_count reached {}, aborting...".format(retry))
                self.abort(timeout=timeout)
                return False

    def _wait_nak_ack(self, flags, timeout=10, retry=10):
        error_count = 0
        while True:
            char = self.reader(1, timeout)
            if char == flags:
                log.debug("[Sender]: Received %r", flags)
                return True
            else:
                log.error("[Sender]: Error, expected %r but got %r", flags, char)
                error_count += 1
                if error_count > retry:
                    log.warning("[Sender]: Warning, EOT was not %r, aborting transfer...", flags)
                    self.abort(timeout=timeout)
                    return False

    def serial_trans(self, info, timeout=1, retry=10, success_count=1, sequence=None):
        error_count = 0
        # Blocking may occur here, the writer needs to have a timeout mechanism
        # log.info("[Sender]: data: {}".format(info))
        self.writer(info)
        log.debug("[Sender]: Block {} (Seq {}) sent".format(success_count, str(sequence)))
        while True:
            char = self.reader(1)
            if char == ACK:
                return True
            if char == NAK:   # 接收端写文件异常直接中断
                return False
            else:
                log.error("[Sender]: error, expected ACK but got {} for block {}".format(char, str(sequence)))
                error_count += 1
                time.sleep(timeout)
                if error_count > retry:
                    log.error("[Sender]: Error, NAK received {} times, aborting...".format(error_count))
                    self.abort(timeout=timeout)
                    return False

    @staticmethod
    def _make_send_header(packet_size, sequence):
        assert packet_size in (128, 1024), packet_size
        _bytes = []
        if packet_size == 128:
            _bytes.append(ord(SOH))
        elif packet_size == 1024:
            _bytes.append(ord(STX))
        _bytes.extend([sequence, 0xff - sequence])
        return bytearray(_bytes)

    def _make_send_checksum(self, crc_mode, data):
        _bytes = []
        if crc_mode:
            crc = self._calc_crc(data)
            _bytes.extend([crc >> 8, crc & 0xff])
        else:
            crc = self._calc_checksum(data)
            _bytes.append(crc)
        return bytearray(_bytes)

    def _send_end_packet(self, packet_size, crc_mode=1):
        header = self._make_send_header(packet_size, 0)
        data = packet_size * b"\x00"
        checksum = self._make_send_checksum(crc_mode, data)
        log.info(header + data + checksum)
        self.writer(header + data + checksum)

    @staticmethod
    def _calc_checksum(data, checksum=0):
        return (sum(data) + checksum) % 256

    # CRC-16-CCITT
    def _calc_crc(self, data, crc=0):
        for char in bytearray(data):
            crc_tbl_idx = ((crc >> 8) ^ char) & 0xff
            crc = ((crc << 8) ^ self.crc_table[crc_tbl_idx]) & 0xffff
        return crc & 0xffff

    def receive(self, crc_mode=1, retry=10, timeout=1, delay=1, callback=None):
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
                        packet_size = 128 if packet_size != 128 else packet_size
                        break
                    elif char == STX:
                        packet_size = 1024 if packet_size != 1024 else packet_size
                        break
                    elif char == EOT:
                        if cancel:
                            self.writer(ACK, timeout)
                            stream.close()
                            if callable(callback):
                                callback(self._recv_file_name, income_size)
                            self.receive()
                            return True
                        else:
                            cancel = 1
                            self.writer(NAK, timeout)
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
                        # log.debug("retry read char %s" % char)
                        if error_count > retry:
                            self.abort(timeout=timeout)
                            return None
                if not self._verify_complement(timeout, sequence):
                    log.error("verify_complement failed")
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
                            write_packet += data[:valid_length]
                            income_size += len(data)
                            log.debug("self._remaining_data_length %s, income_size: %s" % (self._remaining_data_length, income_size))
                            if len(write_packet) not in (0, 1024, 2048, 3072):
                                stream.write(write_packet)
                                write_packet = b""
                            else:
                                if self._remaining_data_length == 0:
                                    stream.write(write_packet)
                                    write_packet = b""
                            time.sleep(0.05)
                            # log.debug("resp ACK start")
                            self.writer(ACK, timeout)
                            # log.debug("resp ACK over")
                            sequence = (sequence + 1) % 0x100
                            # log.debug("After ACK start")
                            char = self.reader(1, timeout)
                            # log.debug("After ACK read char %s" % char)
                            continue

                data = self.reader(1, timeout)
                while data:
                    data = self.reader(1, timeout)

                self.writer(NAK, timeout)
                char = self.reader(1, timeout)
                continue
        except Exception as e:
            log.error(str(e))
            return False

    def _in_transfer_mode(self, crc_mode, retry, delay, timeout=1, cancel=0, error_count=0):
        while True:
            if error_count >= retry:
                self.abort(timeout=timeout)
                return None
            elif crc_mode and error_count < (retry // 2):
                self.writer(CRC, timeout)
            else:
                crc_mode = 0
                self.writer(NAK, timeout)
            time.sleep(delay)
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

    def _get_file_header(self, char, crc_mode, timeout=1, retry=10, packet_size=128):
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
                        self.abort(timeout=timeout)
                        return None
            if not self._verify_complement(timeout):
                pass
            else:
                data = self.reader(packet_size + 1 + crc_mode, timeout)
                if data and len(data) == (packet_size + 1 + crc_mode):
                    valid, data = self._verify_recv_checksum(crc_mode, data)
                    if valid:
                        data = data.lstrip(b"\x00")
                        if not len(data):
                            self.writer(ACK, timeout)
                            return None
                        _recv_file = data.split(b"\x00")[0]
                        _recv_file = _recv_file.decode("utf-8")
                        self._recv_file_name = bytes.decode(data.split(b"\x00")[0], "utf-8")
                        log.debug("_recv_file_name %s" % self._recv_file_name)
                        self._check_path(self._recv_file_name)
                        try:
                            stream = open(self._recv_file_name, "wb+")
                        except IOError:
                            log.error("receive file [%s] is not exist." % self._recv_file_name)
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
                        self.writer(ACK, timeout)
                        return stream
                    else:
                        pass
                else:
                    pass
            while True:
                data = self.reader(1, timeout)
                if data is None:
                    break
            self.writer(NAK, timeout)
            char = self.reader(1, timeout)
            continue

    def _verify_complement(self, timeout=1, sequence=0):
        seq1 = self.reader(1, timeout)
        if seq1 is None:
            seq2 = None
        else:
            seq1 = ord(seq1)
            seq2 = self.reader(1, timeout)
            if seq2 is not None:
                seq2 = 0xff - ord(seq2)
        res = (seq1 == seq2 == sequence)
        # log.debug("_verify_complement res %s" % res)
        return res

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
        # log.debug("_verify_recv_checksum valid %s, data %s" % (valid, data))
        return valid, data

    @staticmethod
    def _check_path(path):
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

    @staticmethod
    def _delete_failed_file(path=""):
        if path and os.path.exists(path):
            os.remove(path)


def send_file(*args):
    serial_io = serial.Serial()
    serial_io.port = args[0]
    serial_io.baudrate = "57600"
    serial_io.parity = "N"
    serial_io.bytesize = 8
    serial_io.stopbits = 1
    serial_io.timeout = 2

    try:
        serial_io.open()
    except Exception:
        raise Exception("Failed to open serial port!")

    def sender_read(size, timeout=3):
        serial_io.timeout = timeout
        return serial_io.read(size) or None

    def sender_write(data, timeout=3):
        serial_io.writeTimeout = timeout
        return serial_io.write(data)

    def send_callback(total_size, success_count, filename):
        log.debug(total_size, success_count, filename)
        # TODO 回调需要带文件名

    sender_write(b"import example\r\n")
    sender_write(b"example.exec(\"/usr/ymodem.py\")\r\n")
    time.sleep(2)
    serial_io.read(serial_io.inWaiting())
    sender = Modem(sender_read, sender_write)
    if sender.send(args[1:], callback=None):
        log.debug("QuecPython File Download Success")
    else:
        log.debug("QuecPython File Download Failure")
    serial_io.close()


def receive_file(*args):
    """
    从设备下载文件到本地

    Args:
        args (tuple):
            args[0] (int): 交互串口号.
            args[1:] (list): 需要下载的文件信息, 可以一次传入多个文件进行下载, 即文件信息列表, 文件信息数据格式为:
                             "[{需要下载的设备文件全路径}, {下载到本地的文件全路径}]",
                             如: "[/usr/test, D:/Download/test]"

    函数调用样例:
        receive_file("COM23", "[/usr/test, D:/Download/test]", "[/usr/test.1, D:/Download/test.1]")

    *注意:
        下载到本地文件的全路径, 目录分割全部使用"/"进行分割, 不论是windows系统或者linux系统, 如: D:/Download/test,
        不可使用"\\"进行分割, 如: D:\\Download\\test
        如果使用"\\"进行分割, 需多写一个, 如: D:\\\\Download\\\\test
    """
    serial_io = serial.Serial()
    serial_io.port = args[0]
    serial_io.baudrate = 57600
    serial_io.parity = "N"
    serial_io.bytesize = 8
    serial_io.stopbits = 1
    serial_io.timeout = 2

    try:
        serial_io.open()
    except Exception:
        raise Exception("Failed to open serial port!")

    def receive_data():
        data = ""
        for i in range(20):
            data += serial_io.read(serial_io.inWaiting()).decode("utf-8", errors="ignore")
            if data.endswith(">>> "):
                break
            time.sleep(0.5)
        log.debug(data)
        return data

    def sender_read(size, timeout=3):
        serial_io.timeout = timeout
        return serial_io.read(size) or None

    def sender_write(data, timeout=3):
        serial_io.writeTimeout = timeout
        data = data if isinstance(data, bytes) else (data.encode() if isinstance(data, str) else str(data).encode())
        # data += b"" if data.endswith(b"\r\n") else b"\r\n"
        return serial_io.write(data)

    def send_callback(total_size, success_count, filename):
        log.debug(total_size, success_count, filename)
        # TODO 回调需要带文件名

    clear_data = serial_io.read(serial_io.inWaiting())
    import_ymodem = "from usr import ymodem"
    while True:
        sender_write(import_ymodem.encode() + b"\r\n")
        data = receive_data()
        data = data.split("\r\n")
        log.debug(data)
        if not (len(data) > 1 and import_ymodem in data[-2] and data[-1] == '>>> '):
            if import_ymodem != "import ymodem":
                import_ymodem = "import ymodem"
                continue
            else:
                raise SystemExit("Device import ymodem error.")
        break

    receiver = Modem(sender_read, sender_write)
    send_args = ("ymodem.send_file([%s])\r\n" % (",".join(["\'%s\'" % i for i in args[1:]]))).encode("utf-8")
    sender_write(send_args)
    time.sleep(1)
    clear_data = serial_io.read(serial_io.inWaiting())
    log.debug(clear_data)

    receiver.receive()
    log.debug("receive download file over.")
    serial_io.close()


if __name__ == "__main__":
    # fire.Fire(send_file)
    # send_file("COM23", "[D:/Download/test, /usr/test]")
    receive_file("COM23", "[/usr/test, D:/Download/test]", "[/usr/test.1, D:/Download/test.1]")
