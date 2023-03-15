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

import log
import uos
import usys
import ql_fs
import utime as time
from machine import UART
import osTimer
from queue import Queue

uart = UART(UART.UART0, 115200, 8, 0, 1, 0)
log.set_output(uart)
log.basicConfig(level=log.NOTSET)
logger = log.getLogger("Ymodem")

SOH = b'\x01'
STX = b'\x02'
EOT = b'\x04'
ACK = b'\x06'
NAK = b'\x15'
CAN = b'\x18'
CRC = b'\x43'

USE_LENGTH_FIELD = 0b100000
USE_DATE_FIELD = 0b010000
USE_MODE_FIELD = 0b001000
USE_SN_FIELD = 0b000100
ALLOW_1K_BLOCK = 0b000010
ALLOW_YMODEM_G = 0b000001


class Serial(object):
    def __init__(self,
                 uart,
                 buadrate=57600,
                 databits=8,
                 parity=0,
                 stopbits=1,
                 flowctl=0):

        self._uart = UART(uart, buadrate, databits, parity, stopbits, flowctl)
        self._queue = Queue(maxsize=1)
        self._timer = osTimer()
        self._uart.set_callback(self._uart_cb)

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
            return b''
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
    ]

    def __init__(self, reader, writer, mode='ymodem1k'):
        self.reader = reader
        self.writer = writer
        self.mode = mode
        self.program_features = USE_LENGTH_FIELD | USE_DATE_FIELD | USE_MODE_FIELD | ALLOW_1K_BLOCK
        self._recv_file_name = ""
        self._remaining_data_length = 0
        self._recv_file_mtime = 0
        self._recv_mode = 0
        self._recv_sn = 0

    def abort(self, count=2):
        for _ in range(count):
            self.writer(CAN)
        self._delete_failed_file(self._recv_file_name)
        return False

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
                    start = time.ticks_ms()
                    if char == SOH:
                        if packet_size != 128:
                            packet_size = 128
                            logger.info("[Receiver]: Set 128 bytes for packet_size")
                        break
                    elif char == STX:
                        if packet_size != 1024:
                            packet_size = 1024
                            logger.info("[Receiver]: Set 1024 bytes for packet_size")
                        break
                    elif char == EOT:
                        if cancel:
                            self.writer(ACK)
                            logger.info("[Receiver]: Transmission finished (%d bytes)", income_size)
                            stream.close()
                            if callable(callback):
                                callback(self._recv_file_name, income_size)
                            self.recv()
                            return True
                        else:
                            cancel = 1
                            self.writer(NAK)
                            logger.info(
                                "[Receiver]: Ready for transmission cancellation (EOT) at data block {} (seq {})".format(
                                    success_count, sequence))
                            char = self.reader(1, timeout)
                    elif char == CAN:
                        if cancel:
                            logger.info("[Receiver]: Transmission cancelled (CAN) at data block {} (seq {})".format(success_count, sequence))
                            self._delete_failed_file(self._recv_file_name)    # delete transfer failed file
                            return None
                        else:
                            cancel = 1
                            logger.info("[Receiver]: Ready for transmission cancellation (CAN) at data block {} (seq {})".format(success_count, sequence))
                            char = self.reader(1, timeout)
                    else:
                        logger.info("[Receiver]: Error, expected SOH/STX EOT CAN but got {0!r}".format(char))
                        error_count += 1
                        char = self.reader(1, timeout)
                        if error_count > retry:
                            logger.info("[Receiver]: Error, error_count reached {}, aborting...".format(retry))
                            self.abort()
                            return None
                if not self._verify_complement(packet_size, crc_mode, timeout, sequence):
                    pass
                else:
                    data = self.reader(packet_size + 1 + crc_mode)
                    if data and len(data) == (packet_size + 1 + crc_mode):
                        valid, data = self._verify_recv_checksum(crc_mode, data)
                        # Write the original data to the target file
                        if valid:
                            success_count += 1
                            logger.info('[Receiver]: Data block %d (seq=%d) OK', success_count, sequence)
                            valid_length = packet_size
                            if self._remaining_data_length > 0:
                                valid_length = min(valid_length, self._remaining_data_length)
                                self._remaining_data_length -= valid_length
                            write_packet += data[:valid_length]
                            income_size += len(data)
                            if len(write_packet) not in (0, 1024, 2048, 3072, 4096):     # 4k byte packet write
                                try:
                                    stream.write(write_packet)
                                except Exception as e:
                                    logger.error('[Receiver]: write error :{}'.format(e))
                                    stream.close()
                                write_packet = b""
                                logger.info('[Receiver]: write Data block OK')
                            self.writer(ACK)
                            logger.info(str(time.ticks_diff(time.ticks_ms(), start)))
                            sequence = (sequence + 1) % 0x100
                            char = self.reader(1, timeout)
                            continue
                        else:
                            pass
                    else:
                        pass
                logger.info("[Receiver]: Error, requesting retransmission (NAK)")
                while True:
                    data = self.reader(1, timeout)
                    if data is None:
                        break
                self.writer(NAK)
                char = self.reader(1, timeout)
                continue
        except Exception as e:
            logger.error('[Receiver]: Error:{}'.format(e))
            return False

    def _in_transfer_mode(self, crc_mode, retry, delay, timeout=1000, cancel=0, error_count=0):
        while True:
            if error_count >= retry:
                logger.info("[Receiver]: Error, error_count reached {}, aborting...".format(retry))
                self.abort()
                return None
            elif crc_mode and error_count < (retry // 2):
                if not self.writer(CRC):
                    logger.info("[Receiver]: Error, write failed, sleeping for {}".format(delay))
                    time.sleep(delay)
                    error_count += 1
            else:
                crc_mode = 0
                if not self.writer(NAK):
                    logger.info("[Receiver]: Error, write failed, sleeping for {}".format(delay))
                    time.sleep(delay)
                    error_count += 1
            char = self.reader(1, timeout)
            if not len(char):
                logger.info("[Receiver]: Error, read timeout in info block")
                error_count += 1
                continue
            elif char == SOH:
                logger.info("[Receiver]: Received valid header (SOH)")
                return char
            elif char == STX:
                logger.info("[Receiver]: Received valid header (STX)")
                return char
            elif char == CAN:
                if cancel:
                    logger.info("[Receiver]: TRANSMISSION Cancelled (CAN)")
                    return None
                else:
                    logger.info("[Receiver]: Ready for transmission cancellation (CAN)")
                    cancel = 1
            else:
                logger.info("[Receiver]: Error, read char: {}".format(char))
                error_count += 1

    def _get_file_header(self, char, crc_mode, timeout=1000, retry=10, packet_size=128):  # Ymodem header default packet size
        error_count = 0
        cancel = 0
        while True:
            while True:
                if char == SOH:
                    if packet_size != 128:
                        packet_size = 128
                        logger.info("[Receiver]: Set 128 bytes for packet_size")
                    break
                elif char == STX:
                    if packet_size != 1024:
                        packet_size = 1024
                        logger.info("[Receiver]: Set 1024 bytes for packet_size")
                    break
                elif char == CAN:
                    if cancel:
                        logger.info("[Receiver]: TRANSMISSION Cancelled (CAN)")
                        return None
                    else:
                        cancel = 1
                        logger.info("[Receiver]: Ready for transmission cancellation (CAN)")
                else:
                    err_msg = ("[Receiver]: Error, expected SOH, EOT but got {0}".format(char))
                    logger.info(err_msg)
                    error_count += 1
                    if error_count > retry:
                        logger.info("[Receiver]: Error, error_count reached %d, aborting...".format(retry))
                        self.abort()
                        return None
            logger.info('[Receiver]: Preparing for data packets....')
            if not self._verify_complement(packet_size, crc_mode, timeout):
                pass
            else:
                logger.info("[Receiver]: Read a packet")
                data = self.reader(packet_size + 1 + crc_mode)
                if data and len(data) == (packet_size + 1 + crc_mode):
                    valid, data = self._verify_recv_checksum(crc_mode, data)
                    if valid:
                        data = data.lstrip(b"\x00")
                        if not len(data):
                            self.writer(ACK)
                            return None
                        self._recv_file_name = bytes.decode(data.split(b"\x00")[0], "utf-8")
                        logger.info("[Receiver]: File - {}".format(self._recv_file_name))
                        self._check_path(self._recv_file_name)
                        try:
                            stream = open(self._recv_file_name, "wb+")
                        except IOError:
                            # stream.close()
                            logger.info("[Receiver]: Error, cannot open save path")
                            return None
                        data = bytes.decode(data.split(b"\x00")[1], "utf-8")
                        if self.program_features & USE_LENGTH_FIELD:
                            space_index = data.find(" ")
                            self._remaining_data_length = int(data if space_index == -1 else data[:space_index])
                            logger.info("[Receiver]: Size - {} bytes".format(self._remaining_data_length))
                            data = data[space_index + 1:]
                        if self.program_features & USE_DATE_FIELD:
                            space_index = data.find(" ")
                            self._recv_file_mtime = int(data if space_index == -1 else data[:space_index], 8)
                            logger.info("[Receiver]: Mtime - {} seconds".format(self._recv_file_mtime))
                            data = data[space_index + 1:]
                        if self.program_features & USE_MODE_FIELD:
                            space_index = data.find(" ")
                            self._recv_mode = int(data if space_index == -1 else data[:space_index])
                            logger.info("[Receiver]: Mode - {}".format(self._recv_mode))
                            data = data[space_index + 1:]
                        if self.program_features & USE_SN_FIELD:
                            space_index = data.find(" ")
                            self._recv_sn = int(data if space_index == -1 else data[:space_index])
                            logger.info("[Receiver]: SN - {}".format(self._recv_sn))
                        self.writer(ACK)
                        return stream
                    else:
                        pass
                else:
                    pass
            logger.info('[Receiver]: Warning, requesting retransmission (NAK)')
            while True:
                data = self.reader(1, timeout)
                if data is None:
                    break
            self.writer(NAK)
            char = self.reader(1, timeout)
            continue

    @staticmethod
    def _check_path(path):
        if ql_fs.path_exists(ql_fs.path_dirname(path)):
            return
        else:
            ql_fs.mkdirs(ql_fs.path_dirname(path))
            return

    @staticmethod
    def _delete_failed_file(path):
        if ql_fs.path_exists(path):
            uos.remove(path)

    def _verify_complement(self, packet_size, crc_mode, timeout=1000, sequence=0):
        seq1 = self.reader(1, timeout)
        if seq1 is None:
            seq2 = None
            logger.info("[Receiver]: Warning, read failed to get first sequence byte")
        else:
            seq1 = ord(seq1)
            seq2 = self.reader(1, timeout)
            if seq2 is None:
                logger.info("[Receiver]: Warning, read failed to get second sequence byte")
            else:
                seq2 = 0xff - ord(seq2)
        # Packet received in wrong number
        if not (seq1 == seq2 == sequence):
            logger.info("[Receiver]: Error, expected seq %d but got (seq1 %r, seq2 %r), receiving next block...", sequence, seq1, seq2)
            # skip this packet
            logger.info(self.reader(packet_size + 1 + crc_mode))
            logger.info("[Receiver]: a wrong packet dropped")
            return False
        else:
            return True

    def _verify_recv_checksum(self, crc_mode, data):
        if crc_mode:
            _checksum = bytearray(data[-2:])
            remote_sum = (_checksum[0] << 8) + _checksum[1]
            local_sum = self._calc_crc(data[:-2])
            valid = bool(remote_sum == local_sum)
            if not valid:
                logger.info("[Receiver]: Error, checksum failed (remote %04x, local %04x)", remote_sum, local_sum)
        else:
            _checksum = bytearray([data[-1]])
            remote_sum = _checksum[0]
            local_sum = self._calc_checksum(data[:-1])
            valid = remote_sum == local_sum
            if not valid:
                logger.info("[Receiver]: Error, checksum failed (remote %02x, local %02x)", remote_sum, local_sum)
        return valid, data

    @staticmethod
    def _calc_checksum(data, checksum=0):
        return (sum(data) + checksum) % 256

    def _calc_crc(self, data, crc=0):
        for char in bytearray(data):
            crc_tbl_idx = ((crc >> 8) ^ char) & 0xff
            crc = ((crc << 8) ^ self.crc_table[crc_tbl_idx]) & 0xffff
        return crc & 0xffff

    def send(self):
        pass


def enter_ymodem(callback=None):
    serial_io = Serial(UART.REPL_UART)
    receiver = Modem(serial_io.read, serial_io.write)
    receiver.recv(callback=callback)
    serial_io.close()


if __name__ == '__main__':
    enter_ymodem()
