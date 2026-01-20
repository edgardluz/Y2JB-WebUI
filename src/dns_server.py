import socket
import threading
import os
import json
import struct

class DNSServer:
    def __init__(self, config_file, host_ip, forwarder=('1.1.1.1', 53)):
        self.config_file = config_file
        self.host_ip = host_ip
        self.forwarder = forwarder
        self.rules = []
        self.running = False
        self.lock = threading.Lock() 
        self.load_rules()

    def load_rules(self):
        with self.lock:
            self.rules.clear()
            if not os.path.exists(self.config_file):
                return

            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.rules = data
                print(f"[DNS] Rules hot-reloaded. Total: {len(self.rules)}")
            except Exception as e:
                print(f"[DNS] Error reloading rules: {e}")

    def find_target(self, query_domain):
        query_domain = query_domain.lower().rstrip('.')
        
        with self.lock:
            for rule in self.rules:
                domain = rule.get('domain', '').lower().rstrip('.')
                target = rule.get('target', '0.0.0.0')
                
                if query_domain == domain or query_domain.endswith('.' + domain):
                    return target if target != 'SELF' else self.host_ip
        return None

    def parse_domain(self, data):
        try:
            state = 0
            expected_length = 0
            domain_parts = []
            x = 0
            y = 0
            payload = data[12:]
            for byte in payload:
                if state == 0:
                    if byte == 0: break
                    expected_length = byte
                    state = 1
                elif state == 1:
                    if y == 0: domain_parts.append(chr(byte))
                    else: domain_parts[x] += chr(byte)
                    y += 1
                    if y == expected_length:
                        state = 0
                        x = x + 1
                        y = 0
            return ".".join(domain_parts)
        except:
            return ""

    def start(self):
        self.running = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', 53))
            print(f"[DNS] Server Active on Port 53. Forwarding to {self.forwarder}")
        except PermissionError:
            print("[DNS] CRITICAL: Permission denied. Run as Root/Sudo.")
            return
        except OSError as e:
            print(f"[DNS] CRITICAL: Port 53 busy: {e}")
            return

        while self.running:
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(target=self.handle_query, args=(sock, data, addr)).start()
            except Exception as e:
                print(f"[DNS] Loop Error: {e}")

    def handle_query(self, sock, data, addr):
        domain = self.parse_domain(data)
        target_ip = self.find_target(domain)
        trans_id = data[:2]

        if target_ip:
            if target_ip == '0.0.0.0':
                print(f"[DNS] BLOCKED: {domain}")
            elif target_ip == self.host_ip:
                print(f"[DNS] SELF-REDIRECT: {domain} -> {target_ip}")
            else:
                print(f"[DNS] REDIRECT: {domain} -> {target_ip}")
            
            flags = b'\x81\x80'
            counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'
            
            answer = b'\xc0\x0c'
            answer += b'\x00\x01'
            answer += b'\x00\x01'
            answer += b'\x00\x00\x01\x2c'
            answer += b'\x00\x04'
            
            try:
                ip_bytes = struct.pack("!BBBB", *map(int, target_ip.split('.')))
            except:
                ip_bytes = b'\x00\x00\x00\x00'

            response = trans_id + flags + counts + data[12:] + answer + ip_bytes
            sock.sendto(response, addr)
        else:
            try:
                proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy.settimeout(2)
                proxy.sendto(data, self.forwarder)
                response, _ = proxy.recvfrom(512)
                sock.sendto(response, addr)
                proxy.close()
            except:
                pass