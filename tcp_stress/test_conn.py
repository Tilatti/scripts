#!/usr/bin/env python3

from scapy.all import *
import time

#conf.L3socket=L3RawSocket

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
        """The first SYN will just be transmitted, without any further action."""
        pass
    class InterruptionAfterTheSynAck(ConnectInterruption):
        """The SYN-ACK from the remote has been received, but will not be acknowledged."""
        pass

    def __init__(self, ip, dport=80):
        self.dport = dport
        self.ip = ip
        self.sport = RandShort()._fix()

    def connect(self, timeout=10, interruption=None):
        """Perform the 3-Way Handshake (SYN, SYN-ACK, ACK) to initiate the connection."""

        # Prepare the SYN
        syn_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="S")

        if interruption is TCPConn.InterruptionAfterTheSyn:
            # Send the SYN, without waiting the SYN-ACK
            send(syn_pck)
            return
        # Send the SYN, the server has to response with a SYN-ACK
        synack_pck = sr1(syn_pck, timeout=timeout)
        if (synack_pck is None) or (synack_pck.sprintf("%TCP.flags%") != "SA"):
            raise TCPConn.ConnImpossibleError

        # Interruption of the hanshake after the SYN-ACK reception
        if interruption is TCPConn.InterruptionAfterTheSynAck:
            return

        self.local_seq = 1
        self.remote_seq = synack_pck.seq + 1
        self.local_window = synack_pck.window
        self.full_window = synack_pck.window

        # Send the ACK
        ack_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")
        ack_pck.seq = self.local_seq
        ack_pck.ack = self.remote_seq
        ack_pck.window = self.local_window
        send(ack_pck)

    class TransmitInterruption:
        pass
    class InterruptionDoNotAcknowledge(TransmitInterruption):
        """
        If the ACK packet received from the remote peer (acknowledging the
        transmitted data) contains payload, this payload will not be acknowledged.
        """
        pass

    def transmit(self, data, interruption=None):
        """Transmit data to the peer."""

        # Prepare the request to the server    
        pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")/data
        pck.ack = self.remote_seq
        pck.seq = self.local_seq
        pck.window = self.local_window

        if interruption is TCPConn.InterruptionDoNotAcknowledge:
            # Send the data, without waiting the following ACK and response
            send(pck)
            return
        # Send the data, the server has to response with ACK and response data
        ack_pck_response = sr1(pck, timeout=1)
        if (not ack_pck_response) or not ("A" in ack_pck_response.sprintf("%TCP.flags%")):
            raise TCPConn.AckNotReceivedError
        self.local_seq += len(data)

        # Acknowledge the server while their is somehting to acknowledge
        # TODO: check that the size of our window doesn't reach zero !
        # TODO: if the server send more than two packets in order to transmit
        # the response, each packet will be repeated by the server before we
        # acknowledge it !
        while ack_pck_response and (len(ack_pck_response.load) > 0):
            self.remote_seq += len(ack_pck_response.load)
            self.local_window -= len(ack_pck_response.load)
            ack_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")
            ack_pck.seq = self.local_seq
            ack_pck.ack = self.remote_seq
            ack_pck.window = self.local_window
            ack_pck_response = sr1(ack_pck, timeout=3)
        self.local_window = self.full_window

    class CloseInterruption:
        pass
    class InterruptionDoNotAcknowledgeTheFin(CloseInterruption):
        """
        After the remote peer received and acknolwedged our FIN packet, we
        also expect that to receive a FIN packet, but we do not acknowledge it.
        """
        pass

    def close(self, timeout=1, interruption=None):
        """Perform the 4-Way handshake to close the connection."""

        # Prepare the FIN 
        fin_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="F")
        fin_pck.seq = self.local_seq
        fin_pck.ack = self.remote_seq
        fin_pck.window = self.local_window

        # Send the FIN, the server has to response with a ACK and a FIN
        answered, unanswered = sr(fin_pck, timeout=2)
        if (len(answered) == 0) or not ("A" in answered[0][1].sprintf("%TCP.flags%")):
            raise TCPConn.AckNotReceivedError

        # Interruption of the handshake without acknowledging the last FIN
        if interruption is TCPConn.InterruptionDoNotAcknowledgeTheFin:
            return

        self.local_seq += 1
        self.remote_seq += 1

        # Send the ACK
        ack_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="A")
        ack_pck.seq = self.local_seq
        ack_pck.ack = self.remote_seq
        send(ack_pck)

    def reset(self):
        """Send a RST packet to abort the connection."""
        rst_pck = IP(dst=self.ip)/TCP(sport=self.sport, dport=self.dport, flags="R")
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

def probe_connections(ip, port, probes):
    """Try to open a number of connections in //."""
    cs = initiate_connections(ip, port, probes)
    for c in cs:
        c.close()
    return len(cs)

def wait_until_is_available(ip, port, probes=1, timeout=60):
    """Wait until the server accepts one or several new connection in //."""
    iteration = 0
    while (probe_connections(ip, port, probes) < probes) and (iteration < (timeout / 10)):
        time.sleep(10)
        iteration += 1
    print("---> We were not able to initiate {} connections in // during at least {} s.".format(probes, iteration * 10))

def test(ip, port, probes, payload=None):
    max_nb_connections = probe_connections(ip, port, probes)
    if max_nb_connections == 0:
        print("The server accepted 0 connections ... unable to test somethings !")
    print("The server accepted {} connections.".format(max_nb_connections))

    # ----

    initiate_connections(ip, port, max_nb_connections, interruption=TCPConn.InterruptionAfterTheSyn)

    wait_until_is_available(ip, port, max_nb_connections, timeout=60)
    nb_connections = probe_connections(ip, port, max_nb_connections)
    print("After transmission of SYN packets without any further action, the server accepts {} connections.".format(nb_connections))

    # ----

    initiate_connections(ip, port, max_nb_connections, interruption=TCPConn.InterruptionAfterTheSynAck)

    wait_until_is_available(ip, port, max_nb_connections, timeout=60)
    nb_connections = probe_connections(ip, port, max_nb_connections)
    print("After reception of the SYN-ACK packet, without the transmission of the corresponding ACK, the server accepts {} connections."
        .format(nb_connections))

    # ----

    cs = initiate_connections(ip, port, max_nb_connections)
    for c in cs:
        c.close(interruption=TCPConn.InterruptionDoNotAcknowledgeTheFin)

    wait_until_is_available(ip, port, max_nb_connections, timeout=60*4)
    nb_connections = probe_connections(ip, port, max_nb_connections)
    print("After reception of the FIN packet, without the transmission of the corresponding ACK, the server accepts {} connections."
        .format(nb_connections))

    # ---- The following tests are only available if a "request" payload
    # ---- (triggering the transmission of a "response" in the other side).

    if payload is not None:

        # ----

        cs = initiate_connections(ip, port, 1) # TODO: More than 1 connection here, seems to confuse the close() method.
        for c in cs:
            c.transmit(payload)
        for c in cs:
            c.close()

        wait_until_is_available(ip, port, max_nb_connections, timeout=60)
        nb_connections = probe_connections(ip, port, max_nb_connections)
        print("After simple transmission of a request and the reception of a response, the server accepts {} connections.".format(nb_connections))

        # ----

        cs = initiate_connections(ip, port, max_nb_connections)
        for c in cs:
            c.transmit(payload, interruption=TCPConn.InterruptionDoNotAcknowledge)

        wait_until_is_available(ip, port, max_nb_connections, timeout=60*4*2)
        nb_connections = probe_connections(ip, port, max_nb_connections)
        print("After transmission of a request and the reception of a response, without the transmission of the corresponding ACK AND without "
              "the normal connection termination, the server accepts {} connections.".format(nb_connections))

        # ----

        cs = initiate_connections(ip, port, max_nb_connections)
        for c in cs:
            c.transmit(payload)
        for c in cs:
            c.reset()

        wait_until_is_available(ip, port, max_nb_connections, timeout=60)
        nb_connections = probe_connections(ip, port, max_nb_connections)
        print("After transmission of a request and the reception of a response, and the transmission of a RST packet, "
              "the server accepts {} connections.".format(nb_connections))

        # ----

        cs = initiate_connections(ip, port, max_nb_connections)
        for c in cs:
            c.transmit(payload, interruption=TCPConn.InterruptionDoNotAcknowledge)
        for c in cs:
            c.reset()

        wait_until_is_available(ip, port, max_nb_connections, timeout=60*4)
        nb_connections = probe_connections(ip, port, max_nb_connections)
        print("After transmission of a request and the reception of a response, without the transmission of the corresponding ACK AND with "
              "the transmission of a RST packet, the server accepts {} connections.".format(nb_connections))

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
    parser.add_argument('--payload', dest='payload_file', type=str, help='Pathname of a file with the payload to transmit', default=None)
    parser.add_argument('address', metavar='address', type=str, help='TCP server address')
    parser.add_argument('port', metavar='port', type=int, help='Port number')
    parser.add_argument('probes', metavar='probes', type=int, help='Number of connection probes')
    args = parser.parse_args()
    if not args.verbose:
        conf.verb = 0

    if args.payload_file:
        if args.payload_file == "-":
            payload = sys.stdin.read()
        else:
            with open(args.payload_file, "rb") as f:
                payload = f.read()
    else:
        payload = None

    try:
        probe_connections(args.address, args.port, 1)
    except TCPConn.Error:
        parser.error("Unable to perform non-erroneous connection's open & close" 
            "... maybe you forgot to do the following:\n{}".format(epilog))

    test(args.address, args.port, args.probes, payload)
