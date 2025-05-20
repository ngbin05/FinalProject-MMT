####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import json
import heapq
from router import Router
from packet import Packet


class LSrouter(Router):
    """Link state routing protocol implementation without external graph libs."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # port -> neighbor address
        self.neighbors = {}
        # port -> cost
        self.costs = {}
        # link states: router addr -> { neighbor_addr: cost }
        self.link_states = {addr: {}}
        # sequence numbers: router addr -> int
        self.seq_nums = {addr: 0}
        # forwarding table: dest_addr -> port
        self.forwarding_table = {}
        # initial advertisement
        initial_lsp = {
            'sender': self.addr,
            'seq_num': self.seq_nums[self.addr],
            'links': list(self.link_states[self.addr].items())
        }
        # flood initial LSP (no neighbors yet)
        self._flood(initial_lsp)

    def handle_packet(self, port, packet):
        """Process incoming packet (data or LSP)."""
        if packet.is_traceroute:
            dst = packet.dst_addr
            if dst in self.forwarding_table:
                self.send(self.forwarding_table[dst], packet)
        else:
            lsp = json.loads(packet.content)
            sender = lsp['sender']
            seq = lsp['seq_num']
            links = lsp['links']  # list of (neighbor, cost)
            # accept newer
            if seq > self.seq_nums.get(sender, -1):
                self.seq_nums[sender] = seq
                self.link_states[sender] = {nbr: cost for nbr, cost in links}
                # recompute routes
                self._compute_forwarding()
                # flood to others
                self._flood(lsp, exclude_port=port)

    def handle_new_link(self, port, endpoint, cost):
        """Link up: register neighbor and advertise."""
        self.neighbors[port] = endpoint
        self.costs[port] = cost
        self.link_states[self.addr][endpoint] = cost
        self.seq_nums[self.addr] += 1
        self._compute_forwarding()
        lsp = {
            'sender': self.addr,
            'seq_num': self.seq_nums[self.addr],
            'links': list(self.link_states[self.addr].items())
        }
        self._flood(lsp)

    def handle_remove_link(self, port):
        """Link down: remove neighbor and advertise."""
        if port in self.neighbors:
            nbr = self.neighbors.pop(port)
            self.costs.pop(port, None)
            self.link_states[self.addr].pop(nbr, None)
            self.seq_nums[self.addr] += 1
            self._compute_forwarding()
            lsp = {
                'sender': self.addr,
                'seq_num': self.seq_nums[self.addr],
                'links': list(self.link_states[self.addr].items())
            }
            self._flood(lsp)

    def handle_time(self, time_ms):
        """Periodic heartbeat."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.seq_nums[self.addr] += 1
            lsp = {
                'sender': self.addr,
                'seq_num': self.seq_nums[self.addr],
                'links': list(self.link_states[self.addr].items())
            }
            self._flood(lsp)

    def _compute_forwarding(self):
        """Use Dijkstra to recompute forwarding table."""
        # build adjacency
        adj = {r: nbrs.copy() for r, nbrs in self.link_states.items()}
        # dijkstra
        dist = {self.addr: 0}
        prev = {}
        heap = [(0, self.addr)]
        while heap:
            d, u = heapq.heappop(heap)
            if d > dist.get(u, float('inf')):
                continue
            for v, w in adj.get(u, {}).items():
                nd = d + w
                if nd < dist.get(v, float('inf')):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(heap, (nd, v))
        # build forwarding table
        self.forwarding_table.clear()
        for dest in dist:
            if dest == self.addr:
                continue
            # backtrack to find next hop
            node = dest
            while prev.get(node) and prev[node] != self.addr:
                node = prev[node]
            if prev.get(node) == self.addr:
                # find port to node
                for p, nbr in self.neighbors.items():
                    if nbr == node:
                        self.forwarding_table[dest] = p
                        break

    def _flood(self, lsp, exclude_port=None):
        """Send LSP to neighbors except exclude_port."""
        pkt = Packet(Packet.ROUTING, self.addr, None, json.dumps(lsp))
        for p in self.neighbors:
            if p != exclude_port:
                self.send(p, pkt)

    def __repr__(self):
        return f"LSrouter(addr={self.addr}, seq={self.seq_nums.get(self.addr)})"
