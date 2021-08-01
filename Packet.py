import struct
import array


class Packet(object):
    def __init__(self):
        self.__bytes = array.array('B', b'\0' * 20)
        self.__payload = array.array('B', )

    def __str__(self):
        tmp_str = 'TCP_Packet{\n   [ '
        if self.get_ECE():
            tmp_str += 'ece '
        if self.get_CWR():
            tmp_str += 'cwr '
        if self.get_ACK():
            tmp_str += 'ack '
        if self.get_FIN():
            tmp_str += 'fin '
        if self.get_PSH():
            tmp_str += 'psh '
        if self.get_RST():
            tmp_str += 'rst '
        if self.get_SYN():
            tmp_str += 'syn '
        if self.get_URG():
            tmp_str += 'urg '
        tmp_str += ']\n   port: %d -> %d\n' % (self.get_th_sport(), self.get_th_dport())
        tmp_str += '   seq: %d, ' % (self.get_th_seq())
        tmp_str += 'ack: %d, ' % (self.get_th_ack())
        tmp_str += 'reserved: %d\n' % (self.get_th_reserved())
        tmp_str += '   win: %d, ' % (self.get_th_win())
        tmp_str += 'sum: %d, ' % (self.get_th_sum())
        tmp_str += 'urp: %d\n' % (self.get_th_urp())
        tmp_str += 'data: %s\n}' % (self.get_PAYLOAD())

        return tmp_str

    def set_th_sport(self, aValue):
        self.__set_word(0, aValue)

    def get_th_sport(self):
        return self.__get_word(0)

    def get_th_dport(self):
        return self.__get_word(2)

    def set_th_dport(self, aValue):
        self.__set_word(2, aValue)

    def get_th_seq(self):
        return self.__get_long(4)

    def set_th_seq(self, aValue):
        self.__set_long(4, aValue)

    def get_th_ack(self):
        return self.__get_long(8)

    def set_th_ack(self, aValue):
        self.__set_long(8, aValue)

    def __get_th_flags(self):
        return self.__get_word(12) & 0x00FF

    def __set_th_flags(self, aValue):
        masked = self.__get_word(12) & (~0x00FF)
        nb = masked | (aValue & 0x00FF)
        return self.__set_word(12, nb, ">")

    def get_th_win(self):
        return self.__get_word(14)

    def set_th_win(self, aValue):
        self.__set_word(14, aValue)

    def set_th_sum(self, aValue):
        self.__set_word(16, aValue)

    def get_th_sum(self):
        return self.__get_word(16)

    def get_th_urp(self):
        return self.__get_word(18)

    def set_th_urp(self, aValue):
        return self.__set_word(18, aValue)

    def __get_flag(self, bit):
        if self.__get_th_flags() & bit:
            return 1
        else:
            return 0

    def __set_flags(self, aValue):
        tmp_value = self.__get_th_flags() | aValue
        return self.__set_th_flags(tmp_value)

    def get_PAYLOAD(self):
        return self.__payload

    def set_PAYLOAD(self, string):
        self.__payload = array.array('B', string)

    def get_th_reserved(self):
        return self.__get_byte(12) & 0x0f

    def get_th_off(self):
        return self.__get_byte(12) >> 4

    def set_th_off(self, aValue):
        mask = 0xF0
        masked = self.__get_byte(12) & (~mask)
        nb = masked | ((aValue << 4) & mask)
        return self.__set_byte(12, nb)

    def get_CWR(self):
        return self.__get_flag(128)

    def set_CWR(self):
        return self.__set_flags(128)

    # Use for
    def get_ECE(self):
        return self.__get_flag(64)

    def set_ECE(self):
        return self.__set_flags(64)

    def get_URG(self):
        return self.__get_flag(32)

    def set_URG(self):
        return self.__set_flags(32)

    def get_ACK(self):
        return self.__get_flag(16)

    def set_ACK(self) -> object:
        return self.__set_flags(16)

    def get_PSH(self):
        return self.__get_flag(8)

    def set_PSH(self):
        return self.__set_flags(8)

    def get_RST(self):
        return self.__get_flag(4)

    def set_RST(self):
        return self.__set_flags(4)

    def get_SYN(self):
        return self.__get_flag(2)

    def set_SYN(self):
        return self.__set_flags(2)

    def get_FIN(self):
        return self.__get_flag(1)

    def set_FIN(self):
        return self.__set_flags(1)

    def set_checksum(self):
        self.set_th_sum(self.cal_checksum())

    def cal_checksum(self):
        return self.compute_checksum((self.__bytes + self.__payload))

    @staticmethod
    def compute_checksum(anArray):
        nleft = len(anArray)
        sum = 0
        pos = 0
        while nleft > 1:
            sum = anArray[pos] * 256 + (anArray[pos + 1] + sum)
            pos = pos + 2
            nleft = nleft - 2
        if nleft == 1:
            sum = sum + anArray[pos] * 256
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum += (sum >> 16)
        return ~sum & 0xFFFF

    def __validate_index(self, index, size):
        orig_index = index
        if index < 0:
            index = len(self.__bytes) + index

        diff = index + size - len(self.__bytes)
        if diff > 0:
            self.__bytes.fromstring('\0' * diff)
            if orig_index < 0:
                orig_index -= diff

        return orig_index

    def get_bytes(self):
        return (self.__bytes + self.__payload).tobytes()

    def __set_bytes(self, bytes):
        self.__bytes = array.array('B', bytes.tolist())

    def __set_byte(self, index, value):
        index = self.__validate_index(index, 1)
        self.__bytes[index] = value

    def __get_byte(self, index):
        index = self.__validate_index(index, 1)
        return self.__bytes[index]

    def __set_word(self, index, value, order='!'):
        index = self.__validate_index(index, 2)
        ary = array.array("B", struct.pack(order + 'H', value))
        if -2 == index:
            self.__bytes[index:] = ary
        else:
            self.__bytes[index:index + 2] = ary

    def __get_word(self, index, order='!'):
        index = self.__validate_index(index, 2)
        if -2 == index:
            bytes = self.__bytes[index:]
        else:
            bytes = self.__bytes[index:index + 2]
        (value,) = struct.unpack(order + 'H', bytes)
        return value

    def __set_long(self, index, value, order='!'):
        index = self.__validate_index(index, 4)
        ary = array.array("B", struct.pack(order + 'L', value))
        if -4 == index:
            self.__bytes[index:] = ary
        else:
            self.__bytes[index:index + 4] = ary

    def __get_long(self, index, order='!'):
        index = self.__validate_index(index, 4)
        if -4 == index:
            bytes = self.__bytes[index:]
        else:
            bytes = self.__bytes[index:index + 4]
        (value,) = struct.unpack(order + 'L', bytes)
        return value

    def set_bytes_from_string(self, data):
        self.__bytes = array.array('B', data[:20])
        self.__payload = array.array('B', data[20:])

    def check(self):
        if len(self.__bytes) != 20:
            print('Header size is not 20')
            return False
        if self.cal_checksum() != 0:
            print('Checksum is failed')
            return False
        return True


if __name__ == '__main__':
    packet = Packet()
    packet.set_th_dport(43650)
    packet.set_th_sport(57277)
    packet.set_th_ack(76850)
    packet.set_th_seq(13240)
    packet.set_th_win(0)
    packet.set_ECE()
    message = "this is a message"
    packet.set_PAYLOAD(message.encode())
    # packet.set_PAYLOAD(array.array('B', [12, 12, 23, 213]))

    print(packet.cal_checksum())

    packet.set_checksum()
    bys = packet.get_bytes()
    packet2 = Packet()
    packet2.set_bytes_from_string(bys)
    print(packet2.check())
    print(packet2)
    # print(bys)
