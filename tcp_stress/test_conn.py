#!/usr/bin/env python3

from scapy.all import *

class TCPConn:

    class Error(BaseException):
        def __init__(self, s):
            self.s = s
        def __str__(self):
            return self.s
    class ConnImpossibleError(Error):
        def __init__(self):
            TCPConn.Error.__init__(self, "Connection impossible")
    class AckNotReceivedError(Error):
        def __init__(self):
            TCPConn.Error.__init__(self, "Request not acked by the remote side")

    class ConnectInterruption:
        pass
    class InterruptionAfterTheSyn(ConnectInterruption):
        pass
    class InterruptionAfterTheSynAck(ConnectInterruption):
        pass

    def __init__(self, ip, dport=80):
        self.dport = dport
        self.ip = ip
        self.sport = RandShort()._fix()

    def connect(self, timeout=10, interruption=None):
        """Perform the 3-Way Handshake (SYN, SYN-ACK, ACK)"""

        # Prepare the SYN
        syn_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="S")

        if interruption is TCPConn.InterruptionAfterTheSyn:
            # Send the SYN, without waiting the SYN-ACK
            send(syn_pck)
            return
        else:
            # Send the SYN, the server has to response with a SYN-ACK
            synack_pck = sr1(syn_pck, timeout=timeout)
            if (synack_pck is None) or (synack_pck.sprintf("%TCP.flags%") != "SA"):
                raise TCPConn.ConnImpossibleError

        # Interruption of the hanshake after the SYN-ACK reception
        if interruption is TCPConn.InterruptionAfterTheSynAck:
            return

        self.local_seq = 1
        self.remote_seq = synack_pck.seq + 1
        self.remote_window = synack_pck.window

        # Send the ACK
        ack_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")
        ack_pck.seq = self.local_seq
        ack_pck.ack = self.remote_seq
        ack_pck.window = self.remote_window
        send(ack_pck)

    class TransmitInterruption:
        pass
    class InterruptionDoNotAcknowledge(TransmitInterruption):
        pass

    def transmit(self, data, interruption=None):
        """Transmit data to the peer."""

        pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")/data
        pck.seq = self.local_seq
        pck.ack = self.remote_seq
        pck.window = self.remote_window

        ack_pck_response = sr1(pck, timeout=1)
        if (ack_pck_response is None) or not ("A" in ack_pck_response.sprintf("%TCP.flags%")):
            raise TCPConn.AckNotReceivedError

        self.local_seq += len(data)
        self.remote_seq += len(ack_pck_response.load)

        # Nothing to acknwoledge ?
        if (len(ack_pck_response.load) == 0) or (interruption is TCPConn.InterruptionDoNotAcknowledge):
            return

        ack_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")
        ack_pck.seq = self.local_seq
        ack_pck.ack = self.remote_seq
        ack_pck.window = self.remote_window
        send(ack_pck)

    def close(self):
        rst_pck = IP(dst=self.ip)/TCP(sport=self.sport,dport=self.dport, flags="R")
        rst_pck.seq = self.local_seq
        send(rst_pck)


def initiate_connections(ip, port, n, interruption=None):
    """Try to initiate n connections. Return the list of available connections."""
    cs = []
    for i in range(n):
        try:
            c = TCPConn(ip=ip, dport=port)
            c.connect(timeout=1, interruption=interruption)
        except TCPConn.ConnImpossibleError:
            pass
        else:
            cs.append(c)
    return cs


def test_interruption_after_syn_connections(ip, port, n):
    cs = initiate_connections(ip, port, n, interruption=TCPConn.InterruptionAfterTheSyn)
    return len(cs)

def test_interruption_after_syn_ack_connections(ip, port, n):
    cs = initiate_connections(ip, port, n, interruption=TCPConn.InterruptionAfterTheSynAck)
    return len(cs)

def test_connections(ip, port, n):
    cs = initiate_connections(ip, port, n)
    for c in cs:
        c.close()
    return len(cs)


def test_http_connections(ip, port, n):
    cs = initiate_connections(ip, port, n)
    for c in cs:
        c.transmit("GET /netx/Admin.html HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip), interruption=TCPConn.InterruptionDoNotAcknowledge)
    for c in cs:
        c.close()


if __name__ == "__main__":
    import argparse
    import time

    # Descriptions for the usage
    description = "Test how many connections are accepted by a TCP server."
    epilog = ("On a GNU/Linux: do not forget to block automatic RST from kernel with\n"
        "# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local interface ip address> -j DROP")

    # Parse the arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, 
        description=description, epilog=epilog)
    parser.add_argument('--verbose', dest='verbose', action='store_true', help='Verbose output', default=False)
    parser.add_argument('--http', dest='http', action='store_true', help='Send HTTP/1.1 requests', default=False)
    parser.add_argument('address', metavar='address', type=str, help='TCP server address')
    parser.add_argument('port', metavar='port', type=int, help='Port number')
    parser.add_argument('probes', metavar='probes', type=int, help='Number of connection probes')
    args = parser.parse_args()
    if not args.verbose:
        conf.verb = 0

    # Test the connection for a TCP server
    n = test_connections(args.address, args.port, args.probes)
    print("Number of connections : {}".format(n))

    time.sleep(1)

    # Test the connection (interruption after the SYN) for a TCP server
    n = test_interruption_after_syn_connections(args.address, args.port, args.probes)
    print("Number of interrupted (after the SYN) connections : {}".format(n))
    
    time.sleep(1)

    # Test the connection (interruption after the SYN-ACK) for a TCP server
    n = test_interruption_after_syn_ack_connections(args.address, args.port, args.probes)
    print("Number of interrupted (after the SYN-ACK) connections : {}".format(n))

    # Test the connection for a HTTP/1.1 server
    time.sleep(1)
    test_http_connections(args.address, args.port, args.probes)
