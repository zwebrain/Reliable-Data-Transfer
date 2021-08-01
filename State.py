from enum import Enum, unique


@unique
class State(Enum):
    CLOSED = 0  # 初始状态
    LISTEN = 1  # 服务端监听状态，等待客户端连接
    SYN_SENT = 2  # 客户端发起连接，发送SYN报文
    SYN_RCVD = 3  # 服务端收到SYN，发送SYN-ACK
    ESTABLISHED = 4  # 确认建立连接
    FIN_WAIT_1 = 5  # 主动关闭连接，发送FIN，等待ACk
    FIN_WAIT_2 = 6  # 半关闭连接，收到ACk，等待FIN，只能接收不能发送
    TIME_WAIT = 7  # 收到FIN后等待 2*MSL
    CLOSING = 8  # 双方同时发送FIN
    CLOSE_WAIT = 9  # 已回复FIN-ACK，等待程序处理完后发FIN
    LAST_ACK = 10  # 等待主动关闭端的FIN-ACk
