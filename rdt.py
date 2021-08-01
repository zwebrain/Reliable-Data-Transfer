from USocket import UnreliableSocket
import threading
from time import time, localtime, sleep, strftime
import random
import loguru
from FSM import FSM as fsm
from Packet import Packet as pk
from State import State as ST
from multiprocessing import SimpleQueue


class RDTSocket(UnreliableSocket):
    """
    The functions with which you are to build your RDT.
    -   recvfrom(bufsize)->bytes, addr
    -   sendto(bytes, address)
    -   bind(address)

    You can set the mode of the socket.
    -   settimeout(timeout)
    -   setblocking(flag)
    By default, a socket is created in the blocking mode.
    https://docs.python.org/3/library/socket.html#socket-timeouts

    """

    def __init__(self, rate=None, debug=True):
        super().__init__(rate=rate)
        self.server = False
        self.timers = {}
        self.FLEETING_TIME = 0.00001
        self.data_cnt = 0
        self.send_packet_buf = {}
        self.recv_packet_buf = {}
        self.time_packet_buf = {}
        self.start = 0
        self.bias = 0
        self.win_threshold = 16
        self.recv_queue = SimpleQueue()
        self.send_queue = SimpleQueue()
        self.recv_data_buffer = [b'']
        self.seq = 0
        self.ack = 0
        self.ack_cnt = 0
        self.win_size = 5
        self.data_len = 2000
        self.send_thread = None
        self.recv_thread = None
        self.proc_thread = None
        self.tcp_ports = []
        self._rate = rate
        self.src_ip = '127.0.0.1'
        self.src_port = random.randint(32168, 60999)
        self.dst_ip = None
        self.dst_port = None
        self.init_time = time()

        # 状态和状态机
        self.fsm = fsm()
        self.state = self.fsm.state

        # 用于debug

        self.debugBtn = False
        if debug:
            self.logger = loguru.logger.bind(object_name="socket.")
            self.debugBtn = True
            self.logger.debug(f"Created TCP socket {self}")

        # 用于 Flow控制
        self.S_RTT = 0
        self.DevRTT = 0
        self.RTO = 0

    @property
    def socket_id(self):
        return f"TCP/{self.src_ip}/{self.src_port}/{self.dst_ip}/{self.dst_port}"

    # 绑定套接字地址
    def bind(self, address):
        self.src_ip = address[0]
        self.src_port = address[1]
        self.tcp_ports.append(self.src_port)
        super().bind(address)
        if self.debugBtn:
            self.logger.debug(f"{self.socket_id} - Socket bound to local address")

    # 一般是服务器accept的
    def accept(self) -> ("RDTSocket", (str, int)):
        conn, addr = RDTSocket(rate=self._rate, debug=self.debugBtn), None
        tcp_port = random.randint(32168, 60999)
        while tcp_port in self.tcp_ports:
            tcp_port = random.randint(32168, 60999)
        conn.bind(('127.0.0.1', tcp_port))
        conn.server =True
        self.tcp_ports.append(tcp_port)
        self.setblocking(True)

        conn.debugBtn = self.debugBtn
        # 服务器进入LISTEN状态，开始收听
        conn.state = conn.fsm.CLOSED_Transition(option='PassiveOpen')
        if conn.debugBtn:
            conn.logger.debug(f"{conn.socket_id} - PassiveOpen, State: {conn.state}")

        # 服务器在LISTEN状态下，等待收包，如果收到，进入SYN_RCVD状态
        while conn.state == ST.LISTEN:
            recv = self.recv_from(2048)
            # 收到客户端的SYN，发送SYNACK包
            if recv:
                data, addr = recv
                syn_packet = pk()
                syn_packet.set_bytes_from_string(data)

                # 绑定好客户端的ip和端口
                conn.dst_ip, conn.dst_port = addr

                if conn.debugBtn:
                    conn.logger.debug(
                        f"{conn.socket_id} -  Socket accept connection with ip: "
                        f"{conn.dst_ip}, port {conn.dst_port}")

                conn.state, send_packet = conn.fsm.LISTEN_Transition(recv_packet=syn_packet)
                conn.send_packet_port_bind(send_packet)
                conn.seq = random.randint(0, (2 << 14) - 1)
                conn.ack = syn_packet.get_th_seq() + 1
                send_packet.set_th_seq(conn.seq)
                send_packet.set_checksum()
                self.set_timer(conn.seq, send_packet)
                conn.send_to(send_packet.get_bytes())

                if conn.debugBtn:
                    conn.logger.debug(
                        f"{conn.socket_id} -  Successfully sent SYNACK to : "
                        f"{conn.dst_ip}, port {conn.dst_port}")

        # 服务器在SYN_RCVD状态下，准备建立连接
        while conn.state == ST.SYN_RCVD:
            recv = conn.recv_from(2048)
            # 收到客户端的ACK，进入ESTABLISHED阶段
            if recv:
                data, addr = recv
                ack_packet = pk()
                ack_packet.set_bytes_from_string(data)
                conn.dst_ip, conn.dst_port = addr
                conn.state = conn.fsm.SYN_RCVD_Transition(recv_packet=ack_packet)
                conn.seq = ack_packet.get_th_ack()
                conn.ack = ack_packet.get_th_seq() + 1
                if conn.debugBtn:
                    conn.logger.debug(
                        f"{conn.socket_id} -  Successfully established with ip: "
                        f"{conn.dst_ip}, port {conn.dst_port}")

        conn.thread_start()
        return conn, addr

    # 发起connect通常是客户端
    def connect(self, address: (str, int)):
        """
        Connect to a remote socket at address.
        Corresponds to the process of establishing a connection on the client side.
        """
        init_time = time()
        # 指定发送ip和端口
        self.bind((self.src_ip, self.src_port))

        # 开始连接...
        self.dst_ip, self.dst_port = address
        if self.debugBtn:
            self.logger.debug(
                f"{self.socket_id} -  Socket attempting connection to ip: "
                f"{self.dst_ip}, port {self.dst_port}")

        # 进入SYN_SENT状态，准备发送连接包
        self.state, send_packet = self.fsm.CLOSED_Transition(option='ActiveOpen')
        # 绑定端口
        self.send_packet_port_bind(send_packet)
        # 初始化SEQ
        self.seq = random.randint(0, (2 << 14) - 1)

        send_packet.set_th_seq(self.seq)
        send_packet.set_checksum()
        self.set_timer(self.seq, send_packet)
        self.send_to(send_packet.get_bytes())

        # 客户端在SYN_SENT状态下，发送了申请，如果收到，进入ESTABLISHED状态
        while self.state == ST.SYN_SENT:
            recv = self.recv_from(2048)
            # 超时——返回CLOSE
            current_time = time()
            # 握手时长3秒后超时
            if current_time - init_time > 3:
                self.state = self.fsm.SYN_SENT_Transition(option='TimeOut')
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Connection time out to ip: "
                        f"{self.dst_ip}, port {self.dst_port}")
                break

            # 收到服务器的SYN_ACK
            elif recv:
                data, addr = recv
                recv_packet = pk()
                recv_packet.set_bytes_from_string(data)
                self.state, send_packet = self.fsm.SYN_SENT_Transition(recv_packet=recv_packet)
                self.dst_port = recv_packet.get_th_sport()
                self.send_packet_port_bind(send_packet)
                send_packet.set_checksum()
                self.set_timer(send_packet.get_th_seq, send_packet)
                self.send_to(send_packet.get_bytes())
                self.ack = send_packet.get_th_ack()
                self.seq = send_packet.get_th_seq() + 1
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Connection set up successfully with ip: "
                        f"{self.dst_ip}, port {self.dst_port}")
                self.thread_start()

    def recv_from(self, bufsize) -> (bytes, (str, int)):
        data, addr = super(RDTSocket, self).recvfrom(bufsize)
        if self.debugBtn:
            recv_packet = pk()
            recv_packet.set_bytes_from_string(data)
            self.logger.debug(f"{self.socket_id} - Receive, State: {self.state}, Packet:\n{recv_packet}")
        return data, addr

    def send_to(self, data: bytes):
        if self.debugBtn:
            self.logger.debug(
                f"{self.socket_id} -  Send data {self.send_packet_buf.keys()}")
        addr = (self.dst_ip, self.dst_port)
        if self.debugBtn:
            packet = pk()
            packet.set_bytes_from_string(data)
            self.logger.debug(
                f"{self.socket_id} -  Send {addr}, State: {self.state}, Packet:\n{packet}")
        self.sendto(data=data, addr=addr)

    def thread_start(self):
        assert self.state == ST.ESTABLISHED
        self.send_thread = threading.Thread(target=self.send_thread_method)
        self.send_thread.start()
        self.recv_thread = threading.Thread(target=self.recv_thread_method)
        self.recv_thread.start()
        self.proc_thread = threading.Thread(target=self.proc_thread_method)
        self.proc_thread.start()
        if self.debugBtn:
            self.logger.debug(
                f"{self.socket_id} -  Thread: OPEN 3 Threads!!!")

    def send_thread_method(self):
        while self.state == ST.ESTABLISHED:
            # 如果发队列为空
            if self.send_queue.empty():
                sleep(self.FLEETING_TIME)
            # 如果发队列不为空，发送队首data
            else:
                data = self.send_queue.get()
                self.send_to(data)

            sleep(self.FLEETING_TIME)
            # 如果状态关闭且队列为空，则结束线程
            if self.send_queue.empty() and self.state == ST.CLOSED:
                if self.debugBtn:
                    self.logger.debug(f"{self.socket_id} -  Thread: send_threading, CLOSED")
                break
        if self.debugBtn:
            self.logger.debug(f"{self.socket_id} -  Thread: send_threading, Have CLOSED")
        for i in self.timers:
            self.timers[i].cancel()

    def recv_thread_method(self):
        while self.state == ST.ESTABLISHED:
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} -  Debug3")
            recv = self.recv_from(2048)
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} -  Debug4")

            # 只接受来自建立tcp会话的地址
            if recv:
                recv_data, address = recv
                if address == (self.dst_ip, self.dst_port):
                    self.recv_queue.put(recv_data)

        if self.debugBtn:
            self.logger.debug(f"{self.socket_id} -  Thread: recv_threading, Have CLOSED")
        for i in self.timers:
            self.timers[i].cancel()

    def proc_thread_method(self):
        while self.state == ST.ESTABLISHED:
            while self.recv_queue.empty() and self.state != ST.CLOSED:
                sleep(self.FLEETING_TIME)

            if self.state == ST.CLOSED:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Thread: proc_threading, CLOSED1")
                for i in self.timers:
                    self.timers[i].cancel()
                break

            # 将收队列队首打包为Packet: recv_pk
            recv_pk = pk()
            recv_pk.set_bytes_from_string(self.recv_queue.get())
            # 检查recv_pk是否出现异常
            if not recv_pk.check():
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Thread: proc_threading, checksum problem {recv_pk.cal_checksum()}, \n{recv_pk}")
                # 重新索要该SEQ
                self.send_seq_wanted_packet()
                continue

            if recv_pk.get_FIN():
                if recv_pk.get_ACK():

                    pass
                # 服务器收到客户端的关闭申请，由ESTABLISHED 转入 CLOSE_WAIT 状态
                else:
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  Server received FIN from Client, start to close connection with:"
                            f"{self.dst_ip},port {self.dst_port}")

                    while self.state == ST.ESTABLISHED:
                        self.state, send_packet = self.fsm.ESTABLISH_Transition(recv_packet=recv_pk)
                        self.send_packet_port_bind(send_packet)
                        send_packet.set_checksum()
                        self.send_to(send_packet.get_bytes())
                        self.send_to(send_packet.get_bytes())

                    if self.debugBtn:
                        self.logger.debug(f"{self.socket_id} -  Thread: proc_threading, Have CLOSED")
                    self.recv_data_buffer.append(b'')
                    break

            elif recv_pk.get_ECE() and recv_pk.get_ACK():
                self.seq = recv_pk.get_th_ack()
                self.ack = recv_pk.get_th_seq()
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Thread: proc_threading, ack ece")

            elif recv_pk.get_SYN():

                pass

            elif recv_pk.get_ACK():
                # 异常情况: 收到没有存储在time_packet_buf的ACK
                # todo BUGBUGBUG?
                this_seq = recv_pk.get_th_ack()
                if self.debugBtn:
                    self.logger.debug(f"{this_seq} -  {self.seq}")
                if this_seq < self.seq:

                    continue
                while self.state == ST.ESTABLISHED and this_seq not in self.time_packet_buf:
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  Thread: proc_threading, no {recv_pk.get_th_ack()} "
                            f"in time_packet_buf: {self.time_packet_buf}")
                    sleep(self.FLEETING_TIME*10)
                    break

                else:
                    RTT = time() - self.time_packet_buf[this_seq]
                    self.update_RTO(RTT)
                    if self.debugBtn:
                        self.logger.debug(f"RTT: {RTT}, RTO: {self.RTO}")

                if recv_pk.get_th_ack() > self.seq + self.data_len:
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  move_window because of {this_seq}")
                    self.move_window(this_seq)

                elif recv_pk.get_th_ack() > self.seq:
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  move_window2 because of {this_seq}")
                    self.move_window2(this_seq)

                elif recv_pk.get_th_ack() == self.seq:
                    # 重复确认
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  duplicate ACK {this_seq}")
                    self.ack_cnt += 1
                    if self.ack_cnt == 3:
                        packet = self.send_packet_buf[self.seq]
                        self.timers[packet.get_th_seq()].cancel()
                        self.resend(packet, False)
                        self.ack_cnt = 0

            else:
                self.send_data_ack(recv_pk)

        if self.debugBtn:
            self.logger.debug(
                f"{self.socket_id} -  Thread: proc_threading, CLOSED2")
        for i in self.timers:
            self.timers[i].cancel()

    def resend(self, packet: pk, timeout=True):
        if packet.get_th_seq() < self.seq:
            return
        elif packet.get_th_seq() == self.seq:
            self.send_to(packet.get_bytes())
            self.win_threshold = self.win_size // 2
            if not timeout:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} minus: "
                        f"self.win_size = self.win_threshold {self.win_threshold}")
                self.win_size = self.win_threshold
            else:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} minus: "
                        f"self.win_size = 1")
                self.win_size = 1
                self.bias = 1

        self.set_timer(packet.get_th_seq(), packet)

    # RT0 调整
    def update_RTO(self, RTT):
        self.S_RTT = self.S_RTT + 0.125 * (RTT - self.S_RTT)
        self.DevRTT = 0.75 * self.DevRTT + 0.25 * abs(RTT - self.S_RTT)
        self.RTO = 1 * self.S_RTT + 4 * self.DevRTT

    def set_timer(self, seq, packet):
        # print("Set timeout: ", self.RTO)
        rto = max(3, self.RTO)
        if seq != -1:
            self.timers[seq] = threading.Timer(rto, self.resend, [packet, True])
            self.timers[seq].start()
        else:
            threading.Timer(rto, self.resend, [packet, True]).start()

    # 发送ACK
    def send_data_ack(self, recv_pk: pk):
        if self.debugBtn:
            self.logger.debug(
                f"{self.socket_id} - Send data ack: seq {self.seq}, ack {self.ack}, "
                f"data_cnt {self.data_cnt}, recv_packet_buf{self.recv_packet_buf}")

        if self.ack > recv_pk.get_th_seq():
            # 重复收到ack
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} - Send data ack case: self.ack > recv_pk.get_th_seq()")
            self.data_cnt += 1
            if self.data_cnt == 2:
                self.send_seq_wanted_packet()
                self.data_cnt = 0

        elif self.ack < recv_pk.get_th_seq():
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} - Send data ack case: self.ack < recv_pk.get_th_seq()")
            # 存储当前收到的SEQ
            self.recv_packet_buf[recv_pk.get_th_seq()] = recv_pk
            # 乞求正确的SEQ
            self.send_seq_wanted_packet()

        else:
            # 终于等到正确的SEQ
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} - Send data ack case: self.ack = recv_pk.get_th_seq()")
            self.data_cnt = 0
            self.recv_packet_buf[recv_pk.get_th_seq()] = recv_pk

            # 从缓冲区中获取全部先前接收的数据
            while self.ack in self.recv_packet_buf:
                packet = self.recv_packet_buf.pop(self.ack)
                self.recv_data_buffer[-1] = self.recv_data_buffer[-1] + packet.get_PAYLOAD()

                # 判断传送的一整个数据是不是最后一个了
                if packet.get_ECE():
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  All data is received1!")
                    self.ack = packet.get_th_seq() + len(packet.get_PAYLOAD())
                    self.send_seq_wanted_packet(True)
                    self.recv_data_buffer.append(b'')
                    return
                else:
                    self.ack = packet.get_th_seq() + len(packet.get_PAYLOAD())
                    self.send_seq_wanted_packet()

            if recv_pk.get_ECE() and self.ack == recv_pk.get_th_seq() + len(recv_pk.get_PAYLOAD()):
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  All data is received2!")
                self.recv_data_buffer.append(b'')

    def move_window(self, ack):
        t = ack - self.seq
        self.seq = ack

        if t % self.data_len != 0:
            self.bias = 0
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} - self.bias = 0")
        else:
            step = t // self.data_len
            self.bias -= step
            if self.win_size > self.win_threshold:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} plus: "
                        f"(1 / int(self.win_size)) * step {(1 / int(self.win_size)) * step}")
                self.win_size += (1 / int(self.win_size)) * step
            else:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} plus: "
                        f"step {step}")
                self.win_size += step

        self.start += t
        self.ack_cnt = 0

        # 更新发送缓冲区
        out = []
        out_time = []
        for e in self.send_packet_buf.keys():
            if e < self.seq:
                out.append(e)
        for e in self.time_packet_buf.keys():
            if e < self.seq + self.data_len*2:
                out_time.append(e)
        for e in out:
            self.send_packet_buf.pop(e)
        for e in out_time:
            self.time_packet_buf.pop(e)

    def move_window2(self, ack):
        t = ack - self.seq
        self.seq = ack

        if t % self.data_len != 0:
            self.bias = 0
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} - self.bias = 0")
        else:
            step = t // self.data_len
            self.bias -= step
            if self.win_size > self.win_threshold:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} plus: "
                        f"(1 / int(self.win_size)) * step {(1 / int(self.win_size)) * step}")
                self.win_size += (1 / int(self.win_size)) * step
            else:
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} - Win_size {self.win_size} plus: "
                        f"step {step}")
                self.win_size += step

        self.start += t
        self.ack_cnt = 0

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the socket.
        The return value is a bytes object representing the data received.
        The maximum amount of data to be received at once is specified by bufsize.

        Note that ONLY data send by the peer should be accepted.
        In other words, if someone else sends data to you from another address,
        it MUST NOT affect the data returned by this function.
        """

        while len(self.recv_data_buffer) < 2:
            sleep(self.FLEETING_TIME)

        data = self.recv_data_buffer[0]
        if len(self.recv_data_buffer[0]) > bufsize:
            self.recv_data_buffer[0] = data[bufsize:]
            data = data[:bufsize]
        else:
            self.recv_data_buffer.pop(0)

        sleep(self.FLEETING_TIME)
        return data

    def send(self, data: bytes):
        """
        Send data to the socket.
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        if self.debugBtn:
            self.logger.debug(f"new send")

        self.start, self.bias, final_seq = 0, 0, self.seq + len(data)
        final = False
        while self.seq < final_seq:
            while self.bias < int(self.win_size) or not final:
                u = int(self.start + self.bias * self.data_len)
                v = int(u + self.data_len)
                seq = int(self.seq + self.bias * self.data_len)
                if u > len(data):
                    break
                packet = pk()
                packet.set_th_seq(seq)
                packet.set_th_ack(self.ack)
                self.send_packet_port_bind(packet)
                packet.set_PAYLOAD(data[u:v])
                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Send data {len(data)}, u {u}, v {v}, start {self.start}, bias {self.bias}, seq {seq}:{self.seq}, final {final_seq}")
                if v >= len(data):
                    packet.set_ECE()
                    final = True
                packet.set_checksum()
                self.set_timer(seq, packet)
                self.send_packet_buf[seq] = packet
                self.time_packet_buf[seq + len(packet.get_PAYLOAD())] = time()
                self.send_queue.put(packet.get_bytes())
                self.bias += 1
            sleep(self.FLEETING_TIME)
        sleep(self.FLEETING_TIME)

    # 主动发起close通常是客户端
    # 最终主动结束的是服务器
    def close(self):
        """
        Finish the connection and release resources. For simplicity, assume that
        after a socket is closed, neither futher sends nor receives are allowed.
        """

        # 客户端在ESTABLISH状态下，发送了FIN，进入FIN_WAIT_1状态
        # 这部分写在互相传包那部分，这里默认客户端进入FIN_WAIT_1，服务器进入CLOSE_WAIT状态
        if self.server:
            sleep(2)

        while self.state == ST.ESTABLISHED:

            self.state, send_packet = self.fsm.ESTABLISH_Transition(option='ActiveClose')
            sleep(self.FLEETING_TIME)
            self.send_packet_port_bind(send_packet)
            send_packet.set_checksum()

            self.send_to(send_packet.get_bytes())
            self.send_to(send_packet.get_bytes())

            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} -  Client start to close the connection with: "
                    f"{self.dst_ip}, port {self.dst_port}")
        """
        客户端部分
        """
        # ////////////////////////////////////////////////////////////////////////
        # ////////////////////////////////////////////////////////////////////////
        # 客户端在FIN_WAIT_1状态下
        # 收到FIN 进入CLOSING状态 发送ACK
        # 收到ACK 进入FIN_WAIT_2状态 不发送
        # 收到FIN ACK 进入TIME_WAIT状态 发送SCK
        while self.state == ST.FIN_WAIT_1:
            if self.debugBtn:
                self.logger.debug(f"{self.socket_id} -  Debug1")
            recv = self.recv_from(2048)
            if self.debugBtn:
                self.logger.debug(f"{self.socket_id} -  Debug2")

            if recv:
                data, addr = recv
                recv_packet = pk()
                recv_packet.set_bytes_from_string(data)

                self.state, send_packet = self.fsm.FIN_WAIT_1_Transition(recv_packet=recv_packet)

                # 收到服务器的FIN 进入CLOSING状态 发送ACK
                if self.state == ST.CLOSING:
                    self.send_packet_port_bind(send_packet)
                    send_packet.set_checksum()
                    self.send_to(send_packet.get_bytes())

                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  Client receive FIN and closing together with server: "
                            f"{self.dst_ip}, port {self.dst_port}")

                # 收到服务器的FIN ACK 进入TIME_WAIT状态 发送ACK
                elif self.state == ST.TIME_WAIT:
                    self.send_packet_port_bind(send_packet)
                    send_packet.set_checksum()
                    self.send_to(send_packet.get_bytes())
                    self.send_to(send_packet.get_bytes())
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  Client receive FINACK from : "
                            f"{self.dst_ip}, port {self.dst_port} and begin to close...")

                # 进入FIN_WAIT_2状态，不发送
                # elif self.state == ST.FIN_WAIT_2:
                elif self.state == ST.FIN_WAIT_2:
                    if self.debugBtn:
                        self.logger.debug(
                            f"{self.socket_id} -  Client receive ACK from : "
                            f"{self.dst_ip}, port {self.dst_port} and enter to FIN_WAIT_2..")
            # 收不到超时了
            else:
                send_packet = pk()
                send_packet.set_th_seq(self.seq)
                send_packet.set_th_ack(self.ack)
                send_packet.set_FIN()
                self.send_packet_port_bind(send_packet)
                self.send(send_packet.get_bytes())

        # 客户端在FIN_WAIT_2状态下
        # 收到服务器的FIN，发送ACK
        while self.state == ST.FIN_WAIT_2:
            recv = self.recv_from(2048)

            if recv:
                data, addr = recv
                recv_packet = pk()
                recv_packet.set_bytes_from_string(data)

                self.state, send_packet = self.fsm.FIN_WAIT_2_Transition(recv_packet=recv_packet)
                if send_packet is None:
                    continue
                self.send_packet_port_bind(send_packet)
                send_packet.set_checksum()
                self.send_to(send_packet.get_bytes())
                self.send_to(send_packet.get_bytes())

                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Client receive ACK twice from : "
                        f"{self.dst_ip}, port {self.dst_port} and enter to TIME_WAIT, waiting to close")

        # 客户端在TIME_WAIT状态下
        # 回到CLOSED状态
        while self.state == ST.TIME_WAIT:
            self.state, useless = self.fsm.TIME_WAIT_Transition()
            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} -  Client close the connection completely with: "
                    f"{self.dst_ip}, port {self.dst_port} ")

            super().close()

        # ////////////////////////////////////////////////////////////////////////
        # ////////////////////////////////////////////////////////////////////////

        """
        服务器部分
        """
        # ////////////////////////////////////////////////////////////////////////
        # ////////////////////////////////////////////////////////////////////////
        while self.state == ST.CLOSE_WAIT:

            self.state, send_packet = self.fsm.CLOSE_WAIT_Transition(option='ActiveClose')
            self.send_packet_port_bind(send_packet)

            self.send_to(send_packet.get_bytes())

            if self.debugBtn:
                self.logger.debug(
                    f"{self.socket_id} -  Server append to close and send FIN to client: "
                    f"{self.dst_ip}, port {self.dst_port} ")

        # 服务器在LAST_ACK状态下
        # 收到客户端的ACK
        # 不回复直接关闭，回到CLOSED状态
        while self.state == ST.LAST_ACK:
            recv = self.recv_from(2048)

            if recv:
                data, addr = recv
                recv_packet = pk()
                recv_packet.set_bytes_from_string(data)

                self.state = self.fsm.LAST_ACK_Transition(recv_packet=recv_packet)

                if self.debugBtn:
                    self.logger.debug(
                        f"{self.socket_id} -  Server passively closed after receive last ACK from server : "
                        f"{self.dst_ip}, port {self.dst_port} ")

                super().close()

    # 每个要发送的包绑定发送端口和接收端口
    def send_packet_port_bind(self, send_packet):
        send_packet.set_th_dport(self.dst_port)
        send_packet.set_th_sport(self.src_port)

    # 只是乞求现在需要的SEQ
    def send_seq_wanted_packet(self, recv_pk=None):
        packet = pk()
        if recv_pk is None:
            packet.set_ACK()
            self.send_packet_port_bind(packet)
            packet.set_th_ack(self.ack)
            packet.set_th_seq(self.seq)
            packet.set_checksum()
            self.send_to(packet.get_bytes())
        else:
            packet.set_ACK()
            packet.set_ECE()
            self.send_packet_port_bind(packet)
            packet.set_th_ack(self.ack)
            packet.set_th_seq(self.seq)
            packet.set_checksum()
            self.send_to(packet.get_bytes())
