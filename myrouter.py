#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # 存储接口信息
        self.interfaces = self.net.interfaces()
        # 创建接口IP到MAC地址的映射
        self.ip_mac_map = {}
        for intf in self.interfaces:
            self.ip_mac_map[intf.ipaddr] = intf.ethaddr
            
        # 创建ARP缓存表，格式为：{ip: (mac, timestamp)}
        self.arp_table = {}
        # ARP表项超时时间（秒）
        self.arp_timeout = 100
        # ARP请求重试次数
        self.arp_retry_count = 5
        # ARP请求超时时间（秒）
        self.arp_request_timeout = 1.0
        
        # 读取转发表
        self.forwarding_table = []
        self.load_forwarding_table()

    def load_forwarding_table(self):
        """从forwarding_table.txt加载转发表"""
        with open('forwarding_table.txt', 'r') as f:
            for line in f:
                network, netmask, nexthop, interface = line.strip().split()
                entry = {
                    'network': IPv4Address(network),
                    'netmask': IPv4Address(netmask),
                    'nexthop': IPv4Address(nexthop) if nexthop != '-' else None,
                    'interface': interface
                }
                self.forwarding_table.append(entry)

    def lookup_forwarding_table(self, ip_addr):
        """在转发表中查找最长前缀匹配项"""
        longest_match = None
        longest_prefix_len = -1

        for entry in self.forwarding_table:
            # 计算网络前缀长度
            network_bits = IPv4Address(int(entry['netmask']))._ip
            prefix_len = bin(network_bits).count('1')
            
            # 检查IP是否匹配当前表项
            if int(ip_addr) & int(entry['netmask']) == int(entry['network']):
                # 如果找到更长的前缀匹配，更新结果
                if prefix_len > longest_prefix_len:
                    longest_prefix_len = prefix_len
                    longest_match = entry

        return longest_match

    def update_arp_table(self):
        """更新ARP表，删除超时的表项"""
        current_time = time.time()
        # 创建需要删除的IP列表
        to_delete = []
        for ip, (mac, timestamp) in self.arp_table.items():
            if current_time - timestamp > self.arp_timeout:
                to_delete.append(ip)
        # 删除超时的表项
        for ip in to_delete:
            del self.arp_table[ip]

    def send_arp_request(self, target_ip, interface):
        """发送ARP请求"""
        arp_request = create_ip_arp_request(
            self.ip_mac_map[interface.ipaddr],
            interface.ipaddr,
            target_ip
        )
        self.net.send_packet(interface.name, arp_request)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        
        # 检查是否是ARP包
        if packet.has_header(Arp):
            # 获取ARP头部
            arp = packet.get_header(Arp)
            
            # 更新ARP缓存表
            self.arp_table[arp.senderprotoaddr] = (arp.senderhwaddr, time.time())
            
            # 检查目标IP是否在路由器的接口中
            if arp.targetprotoaddr in self.ip_mac_map:
                # 如果是ARP请求，则需要回应
                if arp.operation == ArpOperation.Request:
                    # 创建ARP响应包
                    arp_reply = create_ip_arp_reply(
                        self.ip_mac_map[arp.targetprotoaddr],  # 源MAC（路由器接口的MAC）
                        arp.senderhwaddr,                      # 目标MAC（请求方的MAC）
                        arp.targetprotoaddr,                   # 源IP（路由器接口的IP）
                        arp.senderprotoaddr                    # 目标IP（请求方的IP）
                    )
                    # 发送ARP响应
                    self.net.send_packet(ifaceName, arp_reply)
            
            # 定期更新ARP表
            self.update_arp_table()
            return
        
        # 如果是IP包，进行转发处理
        elif packet.has_header(IPv4):
            ip_header = packet.get_header(IPv4)
            
            # 检查是否是发往路由器本身的包
            if ip_header.dst in self.ip_mac_map:
                return
            
            # 减少TTL
            ip_header.ttl -= 1
            if ip_header.ttl <= 0:
                return
            
            # 在转发表中查找匹配项
            match = self.lookup_forwarding_table(ip_header.dst)
            if match is None:
                return
                
            # 确定下一跳IP
            next_hop = match['nexthop'] if match['nexthop'] else ip_header.dst
            out_interface = None
            for intf in self.interfaces:
                if intf.name == match['interface']:
                    out_interface = intf
                    break
                    
            if not out_interface:
                return
                
            # 检查ARP缓存表中是否有下一跳的MAC地址
            if next_hop in self.arp_table:
                next_hop_mac = self.arp_table[next_hop][0]
                # 创建新的以太网头部
                eth_header = packet.get_header(Ethernet)
                eth_header.src = self.ip_mac_map[out_interface.ipaddr]
                eth_header.dst = next_hop_mac
                # 发送数据包
                self.net.send_packet(out_interface.name, packet)
            else:
                # 发送ARP请求获取下一跳的MAC地址
                retry_count = 0
                while retry_count < self.arp_retry_count:
                    self.send_arp_request(next_hop, out_interface)
                    # 等待ARP响应
                    try:
                        response = self.net.recv_packet(timeout=self.arp_request_timeout)
                        _, _, arp_reply = response
                        if arp_reply.has_header(Arp):
                            arp_header = arp_reply.get_header(Arp)
                            if (arp_header.operation == ArpOperation.Reply and 
                                arp_header.senderprotoaddr == next_hop):
                                # 更新ARP缓存表
                                self.arp_table[next_hop] = (arp_header.senderhwaddr, time.time())
                                # 转发数据包
                                eth_header = packet.get_header(Ethernet)
                                eth_header.src = self.ip_mac_map[out_interface.ipaddr]
                                eth_header.dst = arp_header.senderhwaddr
                                self.net.send_packet(out_interface.name, packet)
                                break
                    except NoPackets:
                        retry_count += 1
                        continue

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()