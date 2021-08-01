import time
from threading import Thread

from State import State as ST
from Packet import Packet as pk

"""
以下是各种状态的转换方法
xxx_transition表示现在正在xxx状态下
"""

# 因为CLOSE WAIT->LAST_ACK是过一段时间主动发送，所以我们记录从ESTABLISH->CLOSE_WAIT的包
CLOSEWAIT_Seq = 0
CLOSEWAIT_ACK = 0


class FSM(Thread):

    def __init__(self):
        super().__init__()
        self.state = ST.CLOSED

    def CLOSED_Transition(self, option=None) -> (ST, pk):
        # ActiveOpen 不收包，发包
        if option == 'ActiveOpen':
            self.state, send_packet = self.CLOSED_2_SYN_SENT()
            return self.state, send_packet
        # PassiveOpen 不收包，不发包
        elif option == 'PassiveOpen':
            self.state = self.CLOSED_2_LISTEN()
            return self.state
        else:
            return self.state

    def LISTEN_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # ActiveOpen 不收包，发包
        if option == 'ActiveOpen':
            self.state, send_packet = self.LISTEN_2_SYN_SENT()
            return self.state, send_packet
        # 收包，发包
        else:
            self.state, send_packet = self.LISTEN_2_SYN_RCVD(recv_packet)
            return self.state, send_packet

    def SYN_SENT_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # TimeOut 不收包，不发包
        if option == 'TimeOut':
            self.state = self.SYN_SENT_2_CLOSED()
            return self.state
        # ActiveClose 不收包，不发包
        elif option == 'ActiveClose':
            self.state = self.SYN_SENT_2_CLOSED()
            return self.state
        # 进入Establish 收包，不发包
        # 进入SYN_RCVD 收包，发包
        else:
            self.state, send_packet = self.SYN_SENT_2_transition(recv_packet)
            return self.state, send_packet

    def SYN_RCVD_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # ActiveClose 收包，发包
        if option == 'ActiveClose':
            self.state, send_packet = self.SYN_RCVD_2_FIN_WAIT_1(recv_packet)
            return self.state, send_packet
        # 进入Established 收包，不发包
        else:
            self.state = self.SYN_RCVD_2_ESTABLISHED(recv_packet)
            return self.state

    def ESTABLISH_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # ActiveClose 收包，发包
        if option == 'ActiveClose':
            self.state, send_packet = self.ESTABLISHED_2_FIN_WAIT_1_transition()
            return self.state, send_packet
        # 正常传包/收到Fin关闭 收包，发包
        else:
            self.state, send_packet = self.ESTABLISHED_2_transmit(recv_packet)
            return self.state, send_packet

    def CLOSE_WAIT_Transition(self, option=None) -> (ST, pk):
        # 自动关闭，不收包，发包
        self.state, send_packet = self.CLOSE_WAIT_2_LAST_ACK()
        return self.state, send_packet

    def LAST_ACK_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # 收到ACK关闭，收包，不发包
        self.state = self.LAST_ACK_2_CLOSED(recv_packet)
        return self.state

    def FIN_WAIT_1_Transition(self, recv_packet=None) -> (ST, pk):
        # Receive ACK for FIN
        # transitions to the FIN-WAIT-2 state

        # Receive FIN, Send ACK
        # moves to the CLOSING state

        # Receive FIN and ACK, Send ACK
        # moves to the TIME_WAIT state
        self.state, send_packet = self.FIN_WAIT_1_transition(recv_packet)
        return self.state, send_packet

    def FIN_WAIT_2_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # 收包，发包
        self.state, send_packet = self.FIN_WAIT_2_2_TIME_WAIT(recv_packet)
        return self.state, send_packet

    def CLOSING_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # 收包，不发包
        self.state, send_packet = self.CLOSING_2_TIME_WAIT(recv_packet)
        return self.state

    def TIME_WAIT_Transition(self, recv_packet=None, option=None) -> (ST, pk):
        # 不收包，不发包
        self.state, send_packet = self.TIME_WAIT_2_CLOSED()
        return self.state, send_packet

    # 主动打开
    # Active Open, Send SYN
    # transitions to the SYN-SENT state
    def CLOSED_2_SYN_SENT(self) -> (ST, pk):
        assert self.state == ST.CLOSED
        self.state = ST.SYN_SENT
        send_packet = pk()
        send_packet.set_SYN()
        send_packet.set_th_seq(0)  # 初次建立从0开始
        send_packet.set_th_ack(0)
        return self.state, send_packet

    # Passive Open
    # transitions to the LISTEN state
    def CLOSED_2_LISTEN(self) -> (ST, pk):
        assert self.state == ST.CLOSED
        self.state = ST.LISTEN
        return self.state

    # 主动打开
    # Send SYN
    # transitions to the SYN_SENT state
    def LISTEN_2_SYN_SENT(self) -> (ST, pk):
        assert self.state == ST.LISTEN
        self.state = ST.SYN_SENT
        send_packet = pk()
        send_packet.set_SYN()
        send_packet.set_th_seq(0)  # 初次建立从0开始
        send_packet.set_th_ack(0)
        return self.state, send_packet

    # Receive Client SYN, Send SYN+ACK
    # moves to the SYN-RECEIVED state
    def LISTEN_2_SYN_RCVD(self, recv_packet) -> (ST, pk):
        assert self.state == ST.LISTEN
        if recv_packet.get_SYN():
            self.state = ST.SYN_RCVD
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_SYN()
            send_packet.set_th_seq(0)  # 初次建立从0开始
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_th_PAYLOAD()))
            return self.state, send_packet
        else:
            return self.state

    # Receive SYN, Send ACK
    # transitions to SYN-RECEIVED

    # Receive SYN+ACK, Send ACK
    # ESTABLISHED state
    def SYN_SENT_2_transition(self, recv_packet) -> (ST, pk):
        assert self.state == ST.SYN_SENT
        if recv_packet.get_SYN() == 1 and recv_packet.get_ACK() == 0:
            self.state = ST.SYN_RCVD
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_th_ack())
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet
        elif recv_packet.get_SYN() == 1 and recv_packet.get_ACK() == 1:
            self.state = ST.ESTABLISHED
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_th_ack())
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet
        else:
            return self.state

    # 超时或主动关闭引起的情况
    def SYN_SENT_2_CLOSED(self) -> (ST, pk):
        assert self.state == ST.SYN_SENT
        self.state = ST.CLOSED
        return self.state

    # Receive ACK
    # transitions to the ESTABLISHED state
    def SYN_RCVD_2_ESTABLISHED(self, recv_packet) -> ST:
        assert self.state == ST.SYN_RCVD
        if recv_packet.get_ACK() == 1:
            self.state = ST.ESTABLISHED
            return self.state
        else:
            return self.state

    # 超时引起的情况
    # Close, Send RST
    # def SYN_RCVD_2_CLOSED(self, recv_packet) -> (ST, pk):
    #     assert self.state == ST.SYN_RCVD
    #     self.state = ST.CLOSED
    #     send_packet = pk()
    #     send_packet.set_RST()
    #     send_packet.set_th_seq(recv_packet.get_ACK)
    #     if len(recv_packet.get_th_PAYLOAD()) == 0:
    #         send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
    #     else:
    #         send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
    #     return self.state, send_packet

    # 关闭引起的情况
    # Send FIN
    def SYN_RCVD_2_FIN_WAIT_1(self, recv_packet) -> (ST, pk):
        assert self.state == ST.SYN_RCVD
        self.state = ST.FIN_WAIT_1
        send_packet = pk()
        send_packet.set_FIN()
        send_packet.set_th_seq(recv_packet.get_ACK)
        if len(recv_packet.get_th_PAYLOAD()) == 0:
            send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
        else:
            send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
        return self.state, send_packet

    # todo 缺少了ACK和SEQ num的记录，理论上要在Establish中做记录
    # 主动关闭
    # Close, Send FIN
    # transition to the FIN-WAIT-1 state
    def ESTABLISHED_2_FIN_WAIT_1_transition(self) -> (ST, pk):
        assert self.state == ST.ESTABLISHED
        self.state = ST.FIN_WAIT_1
        send_packet = pk()
        send_packet.set_FIN()
        # todo SEQ 和 ACK num 都需要改
        send_packet.set_th_seq(1)
        send_packet.set_th_ack(1)
        return self.state, send_packet

    # Basic Transmit State

    # Receive FIN
    # transition to the CLOSE-WAIT state.
    def ESTABLISHED_2_transmit(self, recv_packet) -> (ST, pk):
        assert self.state == ST.ESTABLISHED
        if recv_packet.get_FIN():
            self.state = ST.CLOSE_WAIT
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_th_ack())
            CLOSEWAIT_Seq = recv_packet.get_th_ack() + 1
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
                CLOSEWAIT_ACK = recv_packet.get_th_seq() + 1
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
                CLOSEWAIT_ACK = recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD())
            return self.state, send_packet
        else:
            send_packet = pk()
            send_packet.set_th_seq(recv_packet.get_th_ack())
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet

    # Close, Send FIN
    # transitions to LAST-ACK.
    def CLOSE_WAIT_2_LAST_ACK(self) -> (ST, pk):
        assert self.state == ST.CLOSE_WAIT
        self.state = ST.LAST_ACK
        send_packet = pk()
        send_packet.set_FIN()
        send_packet.set_th_seq(CLOSEWAIT_Seq)
        send_packet.set_th_ack(CLOSEWAIT_ACK)
        return self.state, send_packet

    # Receive ACK
    # transitions to CLOSED
    def LAST_ACK_2_CLOSED(self, recv_packet) -> (ST, pk):
        assert self.state == ST.LAST_ACK
        if recv_packet.get_ACK():
            self.state = ST.CLOSED
            return self.state
        else:
            return self.state

    # Receive ACK for FIN
    # transitions to the FIN-WAIT-2 state

    # Receive FIN, Send ACK
    # moves to the CLOSING state

    # Receive FIN and ACK, Send ACK
    # moves to the TIME_WAIT state
    def FIN_WAIT_1_transition(self, recv_packet) -> (ST, pk):
        assert self.state == ST.FIN_WAIT_1
        if recv_packet.get_ACK() and not recv_packet.get_FIN():
            self.state = ST.FIN_WAIT_2
            return self.state, None
        elif recv_packet.get_FIN() and not recv_packet.get_ACK():
            self.state = ST.CLOSING
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_ACK)
            if len(recv_packet.get_th_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet
        elif recv_packet.get_FIN() and recv_packet.get_ACK():
            self.state = ST.TIME_WAIT
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_ACK)
            if len(recv_packet.get_th_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet
        else:
            return self.state, None

    # Receive FIN, Send ACK
    # moves to the TIME-WAIT state
    def FIN_WAIT_2_2_TIME_WAIT(self, recv_packet) -> (ST, pk):
        assert self.state == ST.FIN_WAIT_2
        if recv_packet.get_FIN():
            self.state = ST.TIME_WAIT
            send_packet = pk()
            send_packet.set_ACK()
            send_packet.set_th_seq(recv_packet.get_th_ack())
            if len(recv_packet.get_PAYLOAD()) == 0:
                send_packet.set_th_ack(recv_packet.get_th_seq() + 1)
            else:
                send_packet.set_th_ack(recv_packet.get_th_seq() + len(recv_packet.get_PAYLOAD()))
            return self.state, send_packet
        else:
            return self.state, None

    # Receive ACK for FIN
    # transitions to the TIME-WAIT stat
    def CLOSING_2_TIME_WAIT(self, recv_packet) -> (ST, pk):
        assert self.state == ST.CLOSING
        if recv_packet.get_ACK():
            self.state = ST.TIME_WAIT
            return self.state
        else:
            return self.state

    # After a designated wait period, device transitions to the CLOSED state.
    def TIME_WAIT_2_CLOSED(self, recv_packet=None) -> (ST, pk):
        assert self.state == ST.TIME_WAIT
        self.state = ST.CLOSED
        return self.state, None
