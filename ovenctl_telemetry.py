#!/usr/bin/env python3

import sys, socket, struct, optparse, time
from enum import IntEnum

BINDER_PORT = 10001

MB_SLAVEADDR = 1

class ModbusFunctions(IntEnum):
    READN = 0x03
    READN_ALT = 0x04
    WRITE = 0x06
    WRITEN = 0x10

class ModbusErrors(IntEnum):
    UNKNOWN_ERROR = 0
    INVALID_FUNCTION = 1
    INVALID_PARAMETER_ADDRESS = 2
    PARAMETER_OUT_OF_RANGE = 3
    SLAVE_NOT_READY = 4
    WRITE_ACCESS_DENIED = 5

    #@classmethod
    #def _missing_(cls, value):
    #    return ModbusErrors.UNKNOWN_ERROR

class ModbusException(Exception):
    """Indicate that a MODBus message was in some way invalid or unexpected"""
    def __init__(self, args, msgbytes):
        """Construct a ModbusException

        Parameters:
            args: further information about the exception (eg. a text string)
            msgbytes: the full text of the message"""
        self.msgbytes=msgbytes
        self.args=args
    def __str__(self):
        return "Invalid MODBus message (%s).  Bytes: %s" % (
            self.args, self.msgbytes)

class ModbusShortMessageException(ModbusException):
    """Indicate that a MODBus message was too short

    This is used internally by the parse_*_response functions and caught by
    the OvenCtl.do_* methods.  User code should never see it."""
    def __init__(self, length, wanted, msgbytes):
        """Construct a ModbusShortMessageException

        Parameters:
            length: the length of the message we got
            wanted: the length we expected the message to have
            msgbytes: the full text of the message"""
        self.length=length
        self.wanted=wanted
        self.msgbytes=msgbytes
    def __str__(self):
        return "Wanted %s bytes, got %s" % (self.wanted, self.length)

class ModbusFunctionException(ModbusException):
    """Indicate that a MODBus message had an unexpected Function code"""
    def __init__(self, fn, expected, msgbytes):
        """Construct a ModbusFunctionException

        Parameters:
            fn: the Function code of the message
            expected: the Function code we were expecting
            msgbytes: the full text of the message"""
        self.fn=fn
        self.expected=expected
        self.msgbytes=msgbytes
    def __str__(self):
        return "Expected fn %02x, got %02x" % (self.expected, self.fn)

class ModbusCrcException(ModbusException):
    """Indicate that a MODBus message had an invalid CRC16"""
    def __init__(self, crc, checkcrc, msgbytes):
        """Construct a ModbusCrcException

        Parameters:
            crc: the CRC16 enclosed in the message
            checkcrc: the CRC16 we computed for the message
            msgbytes: the full text of the message"""
        self.crc=crc
        self.checkcrc=checkcrc
        self.msgbytes=msgbytes
    def __str__(self):
        return "Expected crc %04x, got %04x" % (self.checkcrc, self.crc)

class ModbusErrorException(ModbusException):
    """Indicate that the remote sent an error response"""
    def __init__(self, ecode, msgbytes):
        """Construct a ModbusErrorException

        Parameters:
            ecode: the error code enclosed in the message
            msgbytes: the full text of the message"""
        self.ecode=ecode
        self.ename=ModbusErrors(int(self.ecode))
        self.msgbytes=msgbytes
    def __str__(self):
        return "MODBus error code %d (%s)" % (self.ecode, self.ename)

class ModbusBadResponseException(ModbusException):
    """Indicate that response parsing failed for unknown reasons

    This is used in cases where it should be impossible, as the errors
    that could occur should already have been caught and a different
    ModbusException raised.  If you get one of these, something is
    very wrong!"""
    def __init__(self, msgbytes):
        """Construct a ModbusBadResponseException

        Parameter: msgbytes: the full text of the message"""
        self.msgbytes=msgbytes
    def __str__(self):
        return "'Impossible' MODBus error.  Bytes: %s" % self.msgbytes

class ModbusInterface(object):
    """Control a single oven"""
    def __init__(self, hostname, port=BINDER_PORT, timeout=2.5, retries=3):
        """Construct an OvenCtl instance to control an oven

        Parameters:
            hostname: the hostname or IP address of the oven
            port: the port to connect on (default 10001)
            timeout: the connect timeout in seconds (default 2.5)
            retries: the number of times to retry connection"""
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.retries = retries

    def connect_with_retry(self):
        if not self.retries: return socket.create_connection((self.hostname, self.port), self.timeout)
        delay = 0.01
        for i in range(self.retries):
            try:
                sock = socket.create_connection((self.hostname, self.port), self.timeout)
                return sock
            except socket.error as err:
                left = self.retries - i - 1
                print('%s; %d tries left' % (err, left))
                if left == 0:
                    raise err
            time.sleep(delay)
            delay *= 2

    def calc_crc16(self, msg): # string -> int
        """Calculate the CRC16 checksum according to secn 2.8 of the techspec"""
        crc = 0xffff
        for byte in bytearray(msg):
            crc ^= byte
            for bit in range(8):
                sbit = crc&1
                crc>>=1
                crc^=sbit*0xA001
        return crc

    def encode_float(self, value): # float -> [int, int]
        """Encode a float into MODBus format as in secn 2.11.1 of the techspec"""
        words=struct.unpack('>HH', struct.pack('>f', value))
        return words[1],words[0]

    def decode_float(self, value): # [int, int] -> float
        """Decode a float from MODBus format as in secn 2.11.1 of the techspec"""
        # Yes, the words _are_ supposed to be swapped over
        return struct.unpack('>f', struct.pack('>HH', value[1], value[0]))[0]

    def make_readn_request(self, addr, n_words): # (int, int) -> string
        """Build a "Read more than one word" MODBus request string

        The request is for n_words words starting from address addr

        Techspec: 2.9.1"""
        msg = struct.pack('>BBHH', MB_SLAVEADDR, ModbusFunctions.READN, addr, n_words)
        return msg + struct.pack('<H', self.calc_crc16(msg))

    def parse_readn_response(self, msgbytes): # string -> [int...]
        """Parse a "Read more than one word" MODBus response string

        Returns a list of words read

        Can raise:
            ModbusException
            ModbusShortMessageException
            ModbusFunctionException
            ModbusCrcException

        Techspec: 2.9.1"""
        if len(msgbytes) < 3:
            raise ModbusShortMessageException(len(msgbytes), None, msgbytes)
        ignore, func, n_bytes = struct.unpack('>BBB', msgbytes[:3])
        if not func in [ModbusFunctions.READN, ModbusFunctions.READN_ALT]:
            raise ModbusFunctionException(func, ModbusFunctions.READN, msgbytes)
        if n_bytes&1:
            raise ModbusException("Odd number of bytes read", msgbytes)
        if len(msgbytes) < 5+n_bytes:
            raise ModbusShortMessageException(len(msgbytes), 5+n_bytes, msgbytes)
        crc, = struct.unpack('<H', msgbytes[3+n_bytes:5+n_bytes])
        checkcrc = self.calc_crc16(msgbytes[:3+n_bytes])
        if crc != checkcrc:
            raise ModbusCrcException(crc, checkcrc, msgbytes)
        n_words = n_bytes>>1
        words = []
        for word in range(n_words):
            words.extend(struct.unpack('>H', msgbytes[3+word*2:5+word*2]))
        return words

    def make_write_request(self, addr, value): # (int, int) -> string
        """Build a "Write one word" MODBus request string

        The request is to write value to address addr

        Techspec: 2.9.2"""
        msg = struct.pack('>BBHH', MB_SLAVEADDR, ModbusFunctions.WRITE, addr, value)
        return msg + struct.pack('<H', self.calc_crc16(msg))

    def parse_write_response(self, msgbytes): # string -> (int, int)
        """Parse a "Write one word" MODBus response string

        Returns (address written to, value written)

        Can raise:
            ModbusShortMessageException
            ModbusFunctionException
            ModbusCrcException

        Techspec: 2.9.2"""
        if len(msgbytes) < 8:
            raise ModbusShortMessageException(len(msgbytes), 8, msgbytes)
        crc, = struct.unpack('<H', msgbytes[6:8])
        ignore, func, addr, value = struct.unpack('>BBHH', msgbytes[:6])
        if func != ModbusFunctions.WRITE:
            raise ModbusFunctionException(func, ModbusFunctions.WRITE, msgbytes)
        checkcrc = self.calc_crc16(msgbytes[:6])
        if crc != checkcrc:
            raise ModbusCrcException(crc, checkcrc, msgbytes)
        return addr, value

    def make_writen_request(self, addr, words): # (int, [int...]) -> string
        """Build a "Write more than one word" MODBus request string

        The request is to write words, the list of words, to address addr

        Techspec: 2.9.3"""
        n_words = len(words)
        msg = struct.pack('>BBHHB', MB_SLAVEADDR, ModbusFunctions.WRITEN, addr, n_words,
            n_words*2)
        for word in words:
            msg += struct.pack('>H', word)
        return msg + struct.pack('<H', self.calc_crc16(msg))

    def parse_writen_response(self, msgbytes): # string -> (int, int)
        """Parse a "Write more than one word" MODBus response string

        Returns (address written to, number of words written)

        Can raise:
            ModbusShortMessageException
            ModbusFunctionException
            ModbusCrcException

        Techspec: 2.9.3"""
        if len(msgbytes) < 8:
            raise ModbusShortMessageException(len(msgbytes), 8, msgbytes)
        crc, = struct.unpack('<H', msgbytes[6:8])
        ignore, func, addr, n_words = struct.unpack('>BBHH', msgbytes[:6])
        if func != ModbusFunctions.WRITEN:
            raise ModbusFunctionException(func, ModbusFunctions.WRITEN, msgbytes)
        checkcrc = self.calc_crc16(msgbytes[:6])
        if crc != checkcrc:
            raise ModbusCrcException(crc, checkcrc, msgbytes)
        return addr, n_words

    def parse_err_response(self, msgbytes): # string -> (bool, int)
        """Test a response string to see if it's a MODBus error response

        Returns (response is an error, error code)
        If response is not an error, error code returned is None

        Can raise: ModbusCrcException

        Techspec: 2.7"""
        if len(msgbytes) < 5:
            return False, None
        crc, = struct.unpack('<H', msgbytes[3:5])
        ignore, func, ecode = struct.unpack('>BBB', msgbytes[:3])
        if not func&0x80:
            return False, None
        checkcrc = self.calc_crc16(msgbytes[:3])
        if crc != checkcrc:
            # we've already established that it _is_ an err_response
            raise ModbusCrcException(crc, checkcrc, msgbytes)
        return True, ecode

    def do_readn(self, addr, n_words):
        """Read n_words words from the oven at address addr

        Returns a list of words read

        Can raise: ModbusException: trouble at t' mill"""
        read_req = self.make_readn_request(addr, n_words)
        sock = self.connect_with_retry()
        try:
            sock.send(read_req)
            # slave_addr, function, n_bytes, value(n_words)(2), crc(2)
            resp_len = 5+(n_words*2)
            good_resp = False
            resp = bytearray()
            while not good_resp:
                if len(resp) >= resp_len:
                    raise ModbusBadResponseException(resp)
                resp += sock.recv(resp_len-len(resp))
                iserr,e = self.parse_err_response(resp)
                if iserr:
                    raise ModbusErrorException(e, resp)
                try:
                    data = self.parse_readn_response(resp)
                except ModbusShortMessageException:
                    continue
                good_resp = (len(data) == n_words)
            return data
        finally:
            sock.close()

    def do_write(self, addr, data):
        """Write data, a single word, to address addr on the oven

        Can raise: ModbusException: trouble at t' mill"""
        write_req = self.make_write_request(addr, data)
        sock = self.connect_with_retry()
        try:
            sock.send(write_req)
            resp_len = 8 # slave_addr, function, addr(2), data(2), crc(2)
            good_resp = False
            resp = bytearray()
            while not good_resp:
                if len(resp) >= resp_len:
                    raise ModbusBadResponseException(resp)
                resp += sock.recv(resp_len-len(resp))
                iserr,e = self.parse_err_response(resp)
                if iserr:
                    raise ModbusErrorException(e, resp)
                try:
                    resp_addr, resp_data =self. parse_write_response(resp)
                except ModbusShortMessageException:
                    continue
                good_resp = (resp_addr==addr) and (resp_data==data)
            return
        finally:
            sock.close()

    def do_writen(self, addr, data): # data is a list of WORDS
        """Write data, a list of words, to the oven, starting at address addr

        Can raise: ModbusException: trouble at t' mill"""
        write_req = self.make_writen_request(addr, data)
        sock = self.connect_with_retry()
        try:
            sock.send(write_req)
            resp_len = 8 # slave_addr, function, addr(2), length(2), crc(2)
            good_resp = False
            resp = bytearray()
            while not good_resp:
                if len(resp) >= resp_len:
                    raise ModbusBadResponseException(resp)
                resp += sock.recv(resp_len-len(resp))
                iserr,e = self.parse_err_response(resp)
                if iserr:
                    raise ModbusErrorException(e, resp)
                try:
                    resp_addr, resp_words =self. parse_writen_response(resp)
                except ModbusShortMessageException:
                    continue
                good_resp = (resp_addr==addr) and (resp_words==len(data))
            return
        finally:
            sock.close()

    def read_float(self, addr):
        """Read a floating-point value from the oven at address addr

        Can raise: ModbusException"""
        data = self.do_readn(addr, 2)
        return self.decode_float(data)

    def write_float(self, addr, value):
        """Write a floating-point value to the oven at address addr

        Can raise: ModbusException"""
        self.do_writen(addr, self.encode_float(value))

    def read_int(self, addr):
        """Read an integer value from the oven at address addr

        Can raise: ModbusException"""
        data = self.do_readn(addr, 1)
        return data[0]

    def write_int(self, addr, value):
        """Write an integer value to the oven at address addr

        Can raise: ModbusException"""
        self.do_write(addr, value)


class BinderMB2(ModbusInterface):
    # 2.11.14 Base address table for MB2
    CURRENT_TEMPERATURE = 0x1004
    CURRENT_HUMIDITY = 0x100A
    SETPOINT_TEMPERATURE = 0x10B2
    SETPOINT_HUMIDITY = 0x10B4
    SETPOINT_FANSPEED = 0x10B6
    MANUAL_TEMPERATURE = 0x114C
    MANUAL_HUMIDITY = 0x114E
    MANUAL_FANSPEED = 0x1150
    TRACK_READ = 0x1292
    TRACK_MANUAL = 0x1158

    def __init__(self, hostname, port=BINDER_PORT, timeout=2.5, retries=3):
        ModbusInterface.__init__(self, hostname, port, timeout, retries)

    def get_temp(self):
        return self.read_float(self.CURRENT_TEMPERATURE)

    def get_humidity(self):
        return self.read_float(self.CURRENT_HUMIDITY)

    def get_setpoint_temperature(self):
        return self.read_float(self.SETPOINT_TEMPERATURE)

    def get_setpoint_humidity(self):
        return self.read_float(self.SETPOINT_HUMIDITY)

    def get_setpoint_fanspeed(self):
        return self.read_float(self.SETPOINT_FANSPEED)

    def set_manual_temperature(self, value):
        return self.write_float(self.MANUAL_TEMPERATURE, value)

    def set_manual_humidity(self, value):
        return self.write_float(self.MANUAL_HUMIDITY, value)

    def set_manual_fanspeed(self, value):
        return self.write_float(self.MANUAL_FANSPEED, value)

    def get_track(self):
        return self.read_int(self.TRACK_READ)

    def set_manual_track(self, value):
        return self.write_int(self.TRACK_MANUAL, value)

def parse_cmdline():
    parser = optparse.OptionParser()
    parser.usage = "%prog -H hostname [-p port] [options]"
    parser.add_option('-H', '--host', help='host to connect to')
    parser.add_option('-p', '--port', help='TCP port to connect to',
                      default=BINDER_PORT)
    parser.add_option('-Q', '--query', action='store_true',
                      help='Query oven config')
    parser.add_option('-I', '--idle', action='store_true',
                      help='Set oven to Idle mode')
    parser.add_option('-T', '--temp', type='float', default=None,
                      help='Set target temperature in deg C')
    parser.add_option('-W', '--wait', action='store_true',
                      help='Wait until target temp reached')
    parser.add_option('-S', '--stable', action='store_true',
                      help='Wait until temp stable at target')
    parser.add_option('-l', '--limit', type='float', default=1.0,
                      help='Tolerance (in deg C) for -W,-S')
    parser.add_option('-%', '--humidity', type='float', default=None,
                      help='Humidity (in r.h. percent)')
    parser.add_option('-a', '--acclimatise', type='int', default=5,
                      help='Time (in minutes) to wait for contents to '
                           'acclimatise (for -W,-S)')
    parser.add_option('-d', '--dry', action='store_true',
                      help='Activate bedew protection')
    parser.add_option('-f', '--force', action='store_true',
                      help='Override safety interlocks')
    options, args = parser.parse_args()

    if not options.host:
        print("ERROR: -H/--host is required")
        sys.exit(2)

    if sum(map(lambda v:bool(v is not None), [options.query, options.idle, options.temp, options.humidity])) != 1:
        print("ERROR: Please specify exactly one action")
        sys.exit(2)

    return options


if __name__ == '__main__':
    options = parse_cmdline()
    oven = BinderMB2(options.host, options.port)

    try:
        if options.temp is not None:
            oven.set_manual_temperature(options.temp)
        elif options.humidity is not None:
            oven.set_manual_humidity(options.humidity)
        elif options.query:
            try:
                print( "Temperature: {:6.2f} 'C  ({:6.2f} 'C)".format(oven.get_temp(), oven.get_setpoint_temperature()))
                print( "Humidity:    {:6.2f} %   ({:6.2f} %)".format(oven.get_humidity(), oven.get_setpoint_humidity()))
                print( "Fan Speed:             ({:6.2f})".format(oven.get_setpoint_fanspeed()))
                print( "Track:       {:b}".format(oven.get_track()))
            except ModbusException as err:
                print( "Failed to get parameter: %s" % err)
        else:
            assert 0, "No actions taken!" # Should be impossible
    except ModbusException as err:
        print("Failed to set oven setpoint: %s" % err)
        sys.exit(1)
    except socket.timeout as err:
        print( "Socket error: %s" % err)
        sys.exit(3)
