import logging
import socket
import struct
import fcntl
import ctypes
import array
import ffilib
import select

IOError = OSError
class CanError(IOError):
    """Indicates an error with the CAN network.

    """
    pass

log = logging.getLogger(__name__)

PF_CAN       = 29
SOCK_RAW     = 3
SOCK_DGRAM   = 2
AF_CAN       = PF_CAN
CAN_RAW      = 1
CAN_BCM      = 2
SIOCGIFINDEX =  0x8933
CANFD_MTU = 72

def create_socket():
    """Creates a raw CAN socket. The socket will
    be returned unbound to any interface.
    """
    sock = socket.socket(PF_CAN, socket.SOCK_RAW, CAN_RAW)
    log.info('Created a socket')
    return sock
    
def get_addr(sock, channel):
    """Get sockaddr for a channel."""
    if channel:
        data = struct.pack("16si", channel.encode(), 0)
        #print(data)
        res = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, data, True)
        #print(data)
        idx, = struct.unpack("i", data[16:])
        #print(idx)
    else:
        # All channels
        idx = 0
    return struct.pack("HiLL", AF_CAN, idx, 0, 0)
def Msg(canid, dlc, data):
    if (dlc>8):
        dlc=8
    if (dlc<0):
        dlc=0
    return struct.pack("is3s8s", canid|1<<31, bytes([dlc]), bytes([0,0,0]), bytes(data))
def bind_socket(sock, channel='can0'):
    """
    Binds the given socket to the given interface.

    :param socket.socket sock:
        The socket to be bound
    :raises OSError:
        If the specified interface isn't found.
    """
    log.debug('Binding socket to channel=%s', channel)
    addr = get_addr(sock, channel)
    libc = ffilib.libc()
    bind = libc.func("i", "bind", "ipi")
    res = bind(sock.fileno(), addr, len(addr))
    log.debug('Bound socket.')
    
class Message():
    @staticmethod
    def fromBytes(b):
        _id, dlc, _void, data = struct.unpack("is3s8s",b)
        extbit = ((_id>>31)&1)==1
        _id = _id&0x1fffffff
        return Message(_id,extbit,dlc[0],data)
    def __init__(self, canId, extId = True, dlc=0, data=None):
        self.canId = canId
        self.extId = extId
        self.data = data
        self.dlc = dlc
    def toBytes(self):
        eb = 0 if self.extId==False else 1
        return struct.pack("is3s8s", self.canId|eb<<31, bytes([self.dlc]), bytes([0,0,0]), bytes(self.data))
    def __str__(self):
        dt = "".join(["%02X" %i for i in self.data])
        return "%08X [%d] %s" %(self.canId, self.dlc, dt)
class SocketcanBus():
    def __init__(self, channel):
        self.socket = create_socket()
        self.channel = channel
        bind_socket(self.socket, channel)
        self.poll = select.epoll()
        self.poll.register(self.socket.fileno(), eventmask=select.EPOLLIN)
    def send(self, msg):  
        sent = self.socket.send(msg)
        return sent
    def recv(self, timeout):
        # get all sockets that are ready (can be a list with a single value
        # being self.socket or an empty list if self.socket is not ready)

        # get all sockets that are ready (can be a list with a single value
        # being self.socket or an empty list if self.socket is not ready)
        #ready_receive_sockets, _, _ = select.select([self.socket], [], [], timeout)
        ret = self.poll.poll_ms(timeout*1000)
        if len(ret)==0:
            raise CanError("Failed to receive: timeout")


        if ret: # not empty or True
            cf, addr = self.socket.recvfrom(CANFD_MTU)
            #print(cf,addr)
            #msg = capture_message(self.socket, get_channel)
            #if not msg.channel and self.channel:
            #    # Default to our own channel
            #    msg.channel = self.channel
            #return msg, self._is_filtered
            return Message.fromBytes(cf)
        else:
            # socket wasn't readable or timeout occurred
            return None, self._is_filtered


if __name__ == "__main__":            
    #can0 = SocketcanBus("can0")
    #can0.send(Msg(0x12345678, 8, "pidor".encode()))
    can1 = SocketcanBus("can1")
    can1.send(Msg(0x12345678, 8, "pidor1".encode()))

    #print(can0.recv(100))
    print(can1.recv(100))