#!/usr/bin/env python3
"""
Network Discovery Toolkit - Professional Network Scanner
Version: 3.1.0
Description: Ferramenta avançada de descoberta de rede com geolocalização e identificação de dispositivos
License: MIT - Apenas para uso em redes autorizadas
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import socket
import ipaddress
import sys
import platform
import json
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple
import time
import re

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

VERSION = "3.1.0"
APP_NAME = "Network Discovery Toolkit"

COLORS = {
    'bg_dark': '#0a0e17',
    'bg_medium': '#1a1f2e', 
    'bg_light': '#2a2f3e',
    'primary': '#3b82f6',
    'success': '#10b981',
    'warning': '#f59e0b',
    'error': '#ef4444',
    'info': '#8b5cf6',
    'text': '#e2e8f0',
    'text_dim': '#94a3b8'
}

# ============================================================================
# BANCO DE DADOS OUI (MAC Address para Fabricante)
# ============================================================================

OUI_DATABASE = {
    # Routers e equipamentos de rede
    '000C41': 'Cisco',
    '001122': 'Ubiquiti',
    '0013D4': 'Netgear',
    '0021B7': 'D-Link',
    '0022B0': 'TP-Link',
    '0050F2': 'MikroTik',
    '00A0C9': 'Intel',
    '00D0C9': 'Zyxel',
    '04A316': 'TP-Link',
    '08D027': 'Apple',
    '0C8476': 'Intelbras',
    '0CC47A': 'Meraki',
    '10C37B': 'Google',
    '1863A6': 'TP-Link',
    '1C7E5B': 'Amazon',
    '244B03': 'Samsung',
    '28FAA5': 'Intelbras',
    '2C54CF': 'Xiaomi',
    '2CF05A': 'Microsoft',
    '30F73B': 'Aruba',
    '34E8D4': 'Huawei',
    '3C2EFF': 'Roku',
    '40ED98': 'Sony',
    '44D9E7': 'LG',
    '4C3275': 'Raspberry Pi',
    '50C7BF': 'Apple',
    '54A051': 'ZTE',
    '58C5CB': 'Nintendo',
    '60A44C': 'Intel',
    '6C4B90': 'Dell',
    '70E284': 'Xiaomi',
    '74D02B': 'ESP32',
    '78DD08': 'Apple',
    '7C2A31': 'Nest',
    '80C16E': 'Realtek',
    '84F3EB': 'Asus',
    '8892D6': 'Broadcom',
    '8C4B14': 'Netgear',
    '90B11C': 'Arris',
    '94DBC9': 'Motorola',
    '98D6BB': 'HP',
    '9C2A70': 'Cisco',
    'A44C88': 'Dell',
    'A84C42': 'Huawei',
    'ACB5FA': 'Lenovo',
    'B0C4E7': 'Acer',
    'B42B8D': 'Synology',
    'B8A44F': 'Epson',
    'BCB017': 'Amazon',
    'C09F42': 'Intel',
    'C42A69': 'Aruba',
    'C8B3CC': 'Cisco',
    'CC2D21': 'Arris',
    'D04F7E': 'Apple',
    'D4635D': 'Xiaomi',
    'D85B6A': 'Nest',
    'DC2C26': 'Ubiquiti',
    'E0656D': 'Nokia',
    'E42F48': 'OnePlus',
    'E891B4': 'Lacie',
    'ECA86A': 'TP-Link',
    'F02B73': 'Asus',
    'F4D4E8': 'Silicon Labs',
    'F8219B': 'Arris',
    'F8DB7F': 'ESP8266'
}


# GEOLOCALIZAÇÃO


class GeoLocation:
    """Serviço de geolocalização de IP (público vs local)"""
    
    # Cache para evitar múltiplas requisições
    _cache = {}
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Verifica se é IP privado (rede local)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return True
    
    @staticmethod
    def get_public_ip() -> Optional[str]:
        """Obtém o IP público da máquina"""
        try:
            # Múltiplos serviços para redundância
            services = [
                'https://api.ipify.org',
                'https://icanhazip.com',
                'https://checkip.amazonaws.com'
            ]
            for service in services:
                try:
                    with urllib.request.urlopen(service, timeout=5) as response:
                        ip = response.read().decode('utf-8').strip()
                        if ip and ipaddress.ip_address(ip):
                            return ip
                except:
                    continue
        except:
            pass
        return None
    
    @staticmethod
    def get_ip_info(ip: str) -> Dict:
        """
        Obtém informações do IP usando API gratuita
        Retorna: país, cidade, ISP, coordenadas, etc.
        """
        # Verificar cache
        if ip in GeoLocation._cache:
            return GeoLocation._cache[ip]
        
        # IPs privados
        if GeoLocation.is_private_ip(ip):
            info = {
                'ip': ip,
                'type': 'private',
                'country': 'Rede Local',
                'country_code': 'LOCAL',
                'city': 'LAN',
                'region': 'Rede Interna',
                'isp': 'Rede Privada',
                'lat': None,
                'lon': None,
                'organization': 'Infraestrutura Local'
            }
            GeoLocation._cache[ip] = info
            return info
        
        # Consultar API pública
        try:
            # Usando ip-api.com (gratuito, sem chave, até 45 req/min)
            url = f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,query'
            
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get('status') == 'success':
                    info = {
                        'ip': data.get('query', ip),
                        'type': 'public',
                        'country': data.get('country', 'Desconhecido'),
                        'country_code': data.get('countryCode', '??'),
                        'city': data.get('city', 'Desconhecido'),
                        'region': data.get('region', 'Desconhecido'),
                        'isp': data.get('isp', 'Desconhecido'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'organization': data.get('org', 'Desconhecido')
                    }
                    GeoLocation._cache[ip] = info
                    return info
        except Exception as e:
            pass
        
        # Fallback
        info = {
            'ip': ip,
            'type': 'unknown',
            'country': 'Não disponível',
            'country_code': '??',
            'city': 'N/A',
            'region': 'N/A',
            'isp': 'N/A',
            'lat': None,
            'lon': None
        }
        GeoLocation._cache[ip] = info
        return info


# ============================================================================
# IDENTIFICADOR DE DISPOSITIVOS
# ============================================================================

class DeviceIdentifier:
    """Identifica tipo de dispositivo baseado em MAC e portas"""
    
    @staticmethod
    def get_manufacturer(mac: str) -> str:
        """Identifica fabricante pelo MAC address (OUI)"""
        if not mac or mac == 'N/A' or len(mac) < 8:
            return "Desconhecido"
        
        # Normalizar MAC (remover ':' e pegar primeiros 6 caracteres)
        mac_clean = mac.replace(':', '').replace('-', '').upper()[:6]
        
        return OUI_DATABASE.get(mac_clean, "Fabricante não identificado")
    
    @staticmethod
    def guess_device_type(manufacturer: str, hostname: str, open_ports: List[int]) -> str:
        """Tenta identificar o tipo de dispositivo"""
        manufacturer_lower = manufacturer.lower()
        hostname_lower = hostname.lower()
        ports_set = set(open_ports)
        
        # Smartphones
        if any(x in hostname_lower for x in ['iphone', 'ipad', 'samsung', 'xiaomi', 'oneplus', 'pixel']):
            return "📱 Smartphone"
        if manufacturer_lower in ['apple', 'samsung', 'xiaomi', 'huawei', 'google']:
            if 443 in ports_set or 80 in ports_set:
                return "📱 Smartphone"
        
        # Notebooks/Computadores
        if any(x in manufacturer_lower for x in ['dell', 'hp', 'lenovo', 'acer', 'asus', 'apple']):
            return "💻 Computador"
        if 445 in ports_set or 3389 in ports_set:
            return "💻 Computador/Server"
        if 22 in ports_set or 5900 in ports_set:
            return "💻 Workstation"
        
        # Servidores
        if 21 in ports_set or 25 in ports_set or 110 in ports_set:
            return "🖥️ Servidor"
        if 80 in ports_set and 443 in ports_set:
            return "🌐 Servidor Web"
        if 3306 in ports_set or 5432 in ports_set or 1433 in ports_set:
            return "🗄️ Servidor BD"
        
        # Roteadores/Switches
        if any(x in manufacturer_lower for x in ['cisco', 'ubiquiti', 'netgear', 'tplink', 'mikrotik', 'zyxel']):
            return "🌐 Roteador/Switch"
        if hostname_lower in ['router', 'gateway', 'modem', 'ap', 'accesspoint']:
            return "🌐 Roteador/Access Point"
        
        # IoT/Dispositivos Smart
        if any(x in manufacturer_lower for x in ['nest', 'amazon', 'google', 'echo', 'ring']):
            return "🏠 Dispositivo IoT"
        if any(x in hostname_lower for x in ['smart', 'iot', 'camera', 'plug', 'bulb']):
            return "🏠 IoT Device"
        
        # Impressoras
        if any(x in manufacturer_lower for x in ['epson', 'hp', 'brother', 'canon']):
            return "🖨️ Impressora"
        if 9100 in ports_set or 515 in ports_set:
            return "🖨️ Impressora"
        
        # TV/Streaming
        if any(x in manufacturer_lower for x in ['samsung', 'lg', 'sony', 'roku', 'apple']):
            if 1900 in ports_set or 5000 in ports_set:
                return "📺 Smart TV"
        if any(x in hostname_lower for x in ['tv', 'roku', 'chromecast', 'firetv']):
            return "📺 Streaming Device"
        
        # Raspberry Pi
        if manufacturer_lower == 'raspberry pi' or 'raspberry' in hostname_lower:
            return "🍓 Raspberry Pi"
        
        # ESP/Arduino
        if manufacturer_lower in ['esp32', 'esp8266', 'silicon labs']:
            return "🔌 Microcontrolador"
        
        return "📡 Dispositivo de Rede"
    
    @staticmethod
    def get_device_info(mac: str, hostname: str, ip: str, open_ports: List[int] = None) -> Dict:
        """Retorna informações completas do dispositivo"""
        if open_ports is None:
            open_ports = []
        
        manufacturer = DeviceIdentifier.get_manufacturer(mac)
        device_type = DeviceIdentifier.guess_device_type(manufacturer, hostname, open_ports)
        
        # Ícone baseado no tipo
        icon_map = {
            '📱 Smartphone': '📱',
            '💻 Computador': '💻',
            '🖥️ Servidor': '🖥️',
            '🌐 Servidor Web': '🌐',
            '🗄️ Servidor BD': '🗄️',
            '🌐 Roteador/Switch': '🌐',
            '🏠 Dispositivo IoT': '🏠',
            '🖨️ Impressora': '🖨️',
            '📺 Streaming Device': '📺',
            '📺 Smart TV': '📺',
            '🍓 Raspberry Pi': '🍓',
            '🔌 Microcontrolador': '🔌'
        }
        
        icon = icon_map.get(device_type, '📡')
        
        return {
            'manufacturer': manufacturer,
            'device_type': device_type,
            'icon': icon,
            'confidence': 'high' if manufacturer != "Desconhecido" else 'medium'
        }



# SCANNER PRINCIPAL (VERSÃO MEIHORADA)


@dataclass
class DeviceInfo:
    """Estrutura completa de informações do dispositivo"""
    ip: str
    hostname: str
    mac: str
    rtt_ms: float
    manufacturer: str = "Desconhecido"
    device_type: str = "Desconhecido"
    device_icon: str = "📡"
    open_ports: List[Dict] = field(default_factory=list)
    geo_info: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'mac': self.mac,
            'rtt_ms': self.rtt_ms,
            'manufacturer': self.manufacturer,
            'device_type': self.device_type,
            'open_ports': self.open_ports,
            'geo': self.geo_info
        }


class AdvancedNetworkScanner:
    """Scanner avançado com identificação de dispositivos"""
    
    def __init__(self, timeout: float = 0.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[DeviceInfo] = []
        self._stop_flag = False
    
    def get_network_info(self) -> Dict:
        """Obtém informações da rede"""
        info = {
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'os_version': platform.version(),
            'local_ip': self._get_local_ip(),
            'public_ip': GeoLocation.get_public_ip()
        }
        
        # Determinar rede
        parts = info['local_ip'].split('.')
        if len(parts) == 4:
            info['network'] = f"{'.'.join(parts[:3])}.0/24"
            info['gateway'] = f"{'.'.join(parts[:3])}.1"
        
        return info
    
    def _get_local_ip(self) -> str:
        """Obtém IP local"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def ping_host(self, ip: str) -> Optional[float]:
        """Ping com timeout"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        try:
            start = time.time()
            result = subprocess.run(
                ['ping', param, '1', timeout_param, str(int(self.timeout * 1000)), ip],
                capture_output=True,
                timeout=self.timeout + 0.5
            )
            end = time.time()
            
            if result.returncode == 0:
                return round((end - start) * 1000, 2)
        except:
            pass
        return None
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> List[Dict]:
        """Escaneia portas comuns em um IP"""
        if ports is None:
            # Portas mais comuns para identificação de dispositivo
            ports = [21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 8443]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({'port': port, 'protocol': 'TCP'})
            except:
                pass
        return open_ports
    
    def scan_network(self, network_cidr: str, callback: Callable = None, scan_ports: bool = False) -> List[DeviceInfo]:
        """Escaneia rede completa com identificação avançada"""
        network = ipaddress.ip_network(network_cidr, strict=False)
        hosts = list(network.hosts())
        total = len(hosts)
        
        self.results = []
        self._stop_flag = False
        
        def scan_worker(ip: ipaddress.IPv4Address, idx: int):
            if self._stop_flag:
                return
            
            ip_str = str(ip)
            rtt = self.ping_host(ip_str)
            
            if rtt is not None:
                hostname = self._resolve_hostname(ip_str)
                mac = self._get_mac_address(ip_str)
                
                # Identificar dispositivo baseado no MAC
                device_info = DeviceIdentifier.get_device_info(mac, hostname, ip_str)
                
                # Opcional: escanear portas
                open_ports = []
                if scan_ports:
                    open_ports = self.scan_ports(ip_str)
                    # Refinar tipo baseado em portas
                    port_list = [p['port'] for p in open_ports]
                    device_type = DeviceIdentifier.guess_device_type(device_info['manufacturer'], hostname, port_list)
                    device_info['device_type'] = device_type
                
                # Geolocalização (apenas para IPs públicos)
                geo_info = GeoLocation.get_ip_info(ip_str)
                
                device = DeviceInfo(
                    ip=ip_str,
                    hostname=hostname,
                    mac=mac,
                    rtt_ms=rtt,
                    manufacturer=device_info['manufacturer'],
                    device_type=device_info['device_type'],
                    device_icon=device_info['icon'],
                    open_ports=open_ports,
                    geo_info=geo_info
                )
                
                with threading.Lock():
                    self.results.append(device)
            
            if callback:
                callback(idx + 1, total, ip_str, rtt is not None)
        
        # Thread pool
        threads = []
        for idx, ip in enumerate(hosts):
            if self._stop_flag:
                break
            
            thread = threading.Thread(target=scan_worker, args=(ip, idx))
            thread.start()
            threads.append(thread)
            
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        self.results.sort(key=lambda x: tuple(map(int, x.ip.split('.'))))
        return self.results
    
    def stop_scan(self):
        self._stop_flag = True
    
    def _resolve_hostname(self, ip: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname.split('.')[0]
        except:
            return ip
    
    def _get_mac_address(self, ip: str) -> str:
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3 and ':' in parts[2]:
                            return parts[2].upper()
        except:
            pass
        return "N/A"



# INTERFACE GRÁFICA ATUALIZADA


class NetworkToolApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1500x950")
        self.root.minsize(1300, 800)
        self.root.configure(bg=COLORS['bg_dark'])
        
        self.scanner = AdvancedNetworkScanner()
        self.current_results: List[DeviceInfo] = []
        self.scanning = False
        self.scan_ports_flag = tk.BooleanVar(value=False)
        
        self._setup_ui()
        self._log("Ferramenta inicializada", "INFO")
        self._auto_detect()
    
    def _setup_ui(self):
        """Configura interface"""
        main = tk.Frame(self.root, bg=COLORS['bg_dark'])
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header
        header = tk.Frame(main, bg=COLORS['bg_medium'], height=85)
        header.pack(fill=tk.X, pady=(0, 15))
        header.pack_propagate(False)
        
        # Título
        title_frame = tk.Frame(header, bg=COLORS['bg_medium'])
        title_frame.pack(side=tk.LEFT, padx=25, pady=15)
        
        tk.Label(title_frame, text="🌐", font=('Segoe UI', 34),
                bg=COLORS['bg_medium']).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Label(title_frame, text=APP_NAME, font=('Segoe UI', 20, 'bold'),
                bg=COLORS['bg_medium'], fg=COLORS['primary']).pack(side=tk.LEFT)
        
        tk.Label(title_frame, text=f" v{VERSION}", font=('Segoe UI', 12),
                bg=COLORS['bg_medium'], fg=COLORS['text_dim']).pack(side=tk.LEFT, padx=10)
        
        # IP público
        self.public_ip_label = tk.Label(header, text="🌍 IP Público: detectando...", 
                                        font=('Segoe UI', 10),
                                        bg=COLORS['bg_medium'], fg=COLORS['success'])
        self.public_ip_label.pack(side=tk.RIGHT, padx=25)
        
        # Notebook
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        style = ttk.Style()
        style.configure('TNotebook', background=COLORS['bg_dark'])
        style.configure('TNotebook.Tab', background=COLORS['bg_medium'], 
                       padding=[20, 8], font=('Segoe UI', 10))
        
        self._create_network_tab(notebook)
        self._create_devices_tab(notebook)
        self._create_geo_tab(notebook)
        self._create_reports_tab(notebook)
        self._create_log_tab(notebook)
    
    def _create_network_tab(self, notebook):
        """Aba principal de escaneamento"""
        frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(frame, text=" Escaneamento")
        
        # Controles
        control = tk.Frame(frame, bg=COLORS['bg_medium'], relief=tk.RAISED, bd=1)
        control.pack(fill=tk.X, padx=15, pady=15)
        
        config = tk.Frame(control, bg=COLORS['bg_medium'])
        config.pack(pady=15, padx=15, fill=tk.X)
        
        tk.Label(config, text="Rede:", font=('Segoe UI', 11),
                bg=COLORS['bg_medium'], fg=COLORS['text']).pack(side=tk.LEFT, padx=5)
        
        self.network_entry = tk.Entry(config, width=22, font=('Segoe UI', 11),
                                      bg=COLORS['bg_dark'], fg=COLORS['text'])
        self.network_entry.pack(side=tk.LEFT, padx=10)
        
        tk.Label(config, text="Timeout:", font=('Segoe UI', 11),
                bg=COLORS['bg_medium'], fg=COLORS['text']).pack(side=tk.LEFT, padx=20)
        
        self.timeout_spin = tk.Spinbox(config, from_=100, to=2000, width=8,
                                       bg=COLORS['bg_dark'], fg=COLORS['text'])
        self.timeout_spin.delete(0, tk.END)
        self.timeout_spin.insert(0, "300")
        self.timeout_spin.pack(side=tk.LEFT, padx=10)
        
        tk.Checkbutton(config, text="🔍 Escanear portas (mais lento)", 
                      variable=self.scan_ports_flag,
                      bg=COLORS['bg_medium'], fg=COLORS['text'],
                      selectcolor=COLORS['bg_medium']).pack(side=tk.LEFT, padx=20)
        
        # Botões
        btn_frame = tk.Frame(control, bg=COLORS['bg_medium'])
        btn_frame.pack(pady=15)
        
        self.scan_btn = tk.Button(btn_frame, text="🔍 Iniciar Escaneamento",
                                  command=self._start_scan,
                                  bg=COLORS['primary'], fg='white',
                                  font=('Segoe UI', 11, 'bold'),
                                  padx=25, pady=8)
        self.scan_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹️ Parar",
                                  command=self._stop_scan,
                                  bg=COLORS['error'], fg='white',
                                  font=('Segoe UI', 11),
                                  padx=20, pady=8, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.export_btn = tk.Button(btn_frame, text="💾 Exportar JSON",
                                    command=self._export_results,
                                    bg=COLORS['success'], fg=COLORS['bg_dark'],
                                    font=('Segoe UI', 11),
                                    padx=20, pady=8, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=10)
        
        # Progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=10, padx=15, fill=tk.X)
        
        # Status
        self.status_label = tk.Label(frame, text="Pronto para escanear", 
                                     font=('Segoe UI', 10),
                                     bg=COLORS['bg_dark'], fg=COLORS['text_dim'])
        self.status_label.pack(pady=5)
    
    def _create_devices_tab(self, notebook):
        """Aba com lista detalhada de dispositivos"""
        frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(frame, text=" Dispositivos")
        
        # Treeview com colunas estendidas
        columns = ('icon', 'device_type', 'ip', 'hostname', 'manufacturer', 'mac', 'rtt')
        self.device_tree = ttk.Treeview(frame, columns=columns, show='headings', height=22)
        
        self.device_tree.heading('icon', text='')
        self.device_tree.heading('device_type', text='Tipo')
        self.device_tree.heading('ip', text='IP')
        self.device_tree.heading('hostname', text='Hostname')
        self.device_tree.heading('manufacturer', text='Fabricante')
        self.device_tree.heading('mac', text='MAC')
        self.device_tree.heading('rtt', text='ms')
        
        self.device_tree.column('icon', width=35, anchor='center')
        self.device_tree.column('device_type', width=140)
        self.device_tree.column('ip', width=130)
        self.device_tree.column('hostname', width=200)
        self.device_tree.column('manufacturer', width=180)
        self.device_tree.column('mac', width=140)
        self.device_tree.column('rtt', width=60, anchor='center')
        
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scroll.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=15)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=15)
        
        # Bind para mostrar detalhes
        self.device_tree.bind('<Double-1>', self._show_device_details)
    
    def _create_geo_tab(self, notebook):
        """Aba de geolocalização"""
        frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(frame, text="🌍 Geolocalização")
        
        # Informações de IP público
        info_frame = tk.LabelFrame(frame, text="🌐 Seu IP Público",
                                   font=('Segoe UI', 11, 'bold'),
                                   bg=COLORS['bg_medium'], fg=COLORS['primary'])
        info_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.geo_public_info = tk.Text(info_frame, height=6, bg=COLORS['bg_dark'],
                                       fg=COLORS['text'], font=('Consolas', 10),
                                       wrap=tk.WORD, highlightthickness=0)
        self.geo_public_info.pack(fill=tk.X, padx=10, pady=10)
        
        # Consultar IP específico
        query_frame = tk.LabelFrame(frame, text="🔍 Consultar IP Específico",
                                    font=('Segoe UI', 11, 'bold'),
                                    bg=COLORS['bg_medium'], fg=COLORS['primary'])
        query_frame.pack(fill=tk.X, padx=15, pady=15)
        
        query_inner = tk.Frame(query_frame, bg=COLORS['bg_medium'])
        query_inner.pack(pady=15, padx=15)
        
        tk.Label(query_inner, text="IP:", font=('Segoe UI', 11),
                bg=COLORS['bg_medium'], fg=COLORS['text']).pack(side=tk.LEFT, padx=5)
        
        self.geo_ip_entry = tk.Entry(query_inner, width=20, font=('Segoe UI', 11),
                                     bg=COLORS['bg_dark'], fg=COLORS['text'])
        self.geo_ip_entry.pack(side=tk.LEFT, padx=10)
        
        tk.Button(query_inner, text="Consultar", command=self._query_geo,
                 bg=COLORS['info'], fg='white', font=('Segoe UI', 10, 'bold'),
                 padx=15, pady=5).pack(side=tk.LEFT, padx=10)
        
        # Resultado
        self.geo_result = tk.Text(frame, height=15, bg=COLORS['bg_dark'],
                                  fg=COLORS['text'], font=('Consolas', 10),
                                  wrap=tk.WORD)
        self.geo_result.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def _create_reports_tab(self, notebook):
        """Aba de relatórios"""
        frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(frame, text=" Relatórios")
        
        self.report_text = scrolledtext.ScrolledText(frame, bg=COLORS['bg_dark'],
                                                      fg=COLORS['text'],
                                                      font=('Consolas', 10),
                                                      wrap=tk.WORD)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        btn_frame = tk.Frame(frame, bg=COLORS['bg_dark'])
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        tk.Button(btn_frame, text="Atualizar Relatório", command=self._update_report,
                 bg=COLORS['primary'], fg='white', font=('Segoe UI', 10),
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Exportar Relatório", command=self._export_report,
                 bg=COLORS['success'], fg=COLORS['bg_dark'], font=('Segoe UI', 10),
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
    
    def _create_log_tab(self, notebook):
        """Aba de logs"""
        frame = tk.Frame(notebook, bg=COLORS['bg_dark'])
        notebook.add(frame, text="📝 Log")
        
        self.log_area = scrolledtext.ScrolledText(frame, bg=COLORS['bg_dark'],
                                                  fg=COLORS['text_dim'],
                                                  font=('Consolas', 9),
                                                  wrap=tk.WORD)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        btn_frame = tk.Frame(frame, bg=COLORS['bg_dark'])
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        tk.Button(btn_frame, text="Limpar Log", command=self._clear_log,
                 bg=COLORS['bg_medium'], fg=COLORS['text'],
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
    
    def _auto_detect(self):
        """Auto-detecção"""
        info = self.scanner.get_network_info()
        self.network_entry.delete(0, tk.END)
        self.network_entry.insert(0, info['network'])
        self._log(f"Rede detectada: {info['network']}", "INFO")
        
        # Buscar IP público em thread
        def get_pub_ip():
            pub_ip = GeoLocation.get_public_ip()
            if pub_ip:
                geo = GeoLocation.get_ip_info(pub_ip)
                self.root.after(0, lambda: self.public_ip_label.config(
                    text=f" IP Público: {pub_ip} ({geo.get('country', 'Desconhecido')})"))
                self._log(f"IP Público: {pub_ip} - {geo.get('country', 'N/A')}", "INFO")
                
                # Mostrar na aba de geo
                self.geo_public_info.delete(1.0, tk.END)
                self.geo_public_info.insert(tk.END, f"IP: {pub_ip}\n")
                self.geo_public_info.insert(tk.END, f"País: {geo.get('country', 'N/A')} ({geo.get('country_code', '??')})\n")
                self.geo_public_info.insert(tk.END, f"Cidade: {geo.get('city', 'N/A')}\n")
                self.geo_public_info.insert(tk.END, f"ISP: {geo.get('isp', 'N/A')}\n")
                self.geo_public_info.insert(tk.END, f"Organização: {geo.get('organization', 'N/A')}")
        
        threading.Thread(target=get_pub_ip, daemon=True).start()
    
    def _start_scan(self):
        if self.scanning:
            return
        
        network = self.network_entry.get().strip()
        timeout_ms = int(self.timeout_spin.get())
        self.scanner.timeout = timeout_ms / 1000.0
        
        try:
            ipaddress.ip_network(network, strict=False)
        except:
            self._log(f"Rede inválida: {network}", "ERROR")
            messagebox.showerror("Erro", f"Rede inválida: {network}")
            return
        
        # Limpar
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        self.current_results = []
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        
        scan_ports = self.scan_ports_flag.get()
        
        def update_progress(current, total, ip, is_alive):
            percent = (current / total) * 100
            self.progress_var.set(percent)
            self.status_label.config(text=f"Escaneando: {current}/{total} - {ip}")
            self.root.update_idletasks()
        
        def scan_thread():
            self._log(f"Iniciando escaneamento de {network}", "INFO")
            if scan_ports:
                self._log("Modo de escaneamento de portas ativado (pode ser mais lento)", "WARN")
            
            start_time = time.time()
            results = self.scanner.scan_network(network, update_progress, scan_ports)
            elapsed = time.time() - start_time
            
            def update_ui():
                for device in results:
                    self.device_tree.insert('', tk.END, values=(
                        device.device_icon,
                        device.device_type,
                        device.ip,
                        device.hostname[:35],
                        device.manufacturer[:25],
                        device.mac,
                        f"{device.rtt_ms:.0f}"
                    ))
                
                self.current_results = results
                self.scanning = False
                self.scan_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.export_btn.config(state=tk.NORMAL if results else tk.DISABLED)
                
                self._log(f"Escaneamento concluído em {elapsed:.1f}s", "SUCCESS")
                self._log(f"Encontrados {len(results)} dispositivos ativos", "INFO")
                self.status_label.config(text=f"✓ Escaneamento concluído - {len(results)} dispositivos")
                
                self._update_report()
            
            self.root.after(0, update_ui)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def _stop_scan(self):
        if self.scanning:
            self.scanner.stop_scan()
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self._log("Escaneamento interrompido", "WARN")
            self.status_label.config(text="Escaneamento interrompido")
    
    def _show_device_details(self, event):
        """Mostra detalhes do dispositivo em uma janela"""
        selection = self.device_tree.selection()
        if not selection:
            return
        
        item = self.device_tree.item(selection[0])
        values = item['values']
        if len(values) < 3:
            return
        
        ip = values[2]
        device = next((d for d in self.current_results if d.ip == ip), None)
        
        if not device:
            return
        
        # Janela de detalhes
        detail_win = tk.Toplevel(self.root)
        detail_win.title(f"Detalhes - {device.hostname}")
        detail_win.geometry("600x500")
        detail_win.configure(bg=COLORS['bg_dark'])
        detail_win.transient(self.root)
        
        detail_text = tk.Text(detail_win, bg=COLORS['bg_dark'], fg=COLORS['text'],
                              font=('Consolas', 10), wrap=tk.WORD)
        detail_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Informações
        detail_text.insert(tk.END, f"{'='*50}\n")
        detail_text.insert(tk.END, f"📡 INFORMAÇÕES DO DISPOSITIVO\n")
        detail_text.insert(tk.END, f"{'='*50}\n\n")
        detail_text.insert(tk.END, f"IP: {device.ip}\n")
        detail_text.insert(tk.END, f"Hostname: {device.hostname}\n")
        detail_text.insert(tk.END, f"MAC: {device.mac}\n")
        detail_text.insert(tk.END, f"Fabricante: {device.manufacturer}\n")
        detail_text.insert(tk.END, f"Tipo: {device.device_type}\n")
        detail_text.insert(tk.END, f"Tempo resposta: {device.rtt_ms:.0f} ms\n\n")
        
        # Geolocalização
        detail_text.insert(tk.END, f"{'='*50}\n")
        detail_text.insert(tk.END, f"🌍 GEOLOCALIZAÇÃO\n")
        detail_text.insert(tk.END, f"{'='*50}\n\n")
        
        if device.geo_info.get('type') == 'private':
            detail_text.insert(tk.END, f"Tipo: Rede Local (IP Privado)\n")
            detail_text.insert(tk.END, f"País: {device.geo_info.get('country', 'N/A')}\n")
        else:
            detail_text.insert(tk.END, f"País: {device.geo_info.get('country', 'N/A')} ({device.geo_info.get('country_code', '??')})\n")
            detail_text.insert(tk.END, f"Cidade: {device.geo_info.get('city', 'N/A')}\n")
            detail_text.insert(tk.END, f"Estado/Região: {device.geo_info.get('region', 'N/A')}\n")
            detail_text.insert(tk.END, f"ISP: {device.geo_info.get('isp', 'N/A')}\n")
            if device.geo_info.get('lat'):
                detail_text.insert(tk.END, f"Coordenadas: {device.geo_info['lat']}, {device.geo_info['lon']}\n")
        
        # Portas abertas
        if device.open_ports:
            detail_text.insert(tk.END, f"\n{'='*50}\n")
            detail_text.insert(tk.END, f"🔌 PORTAS ABERTAS\n")
            detail_text.insert(tk.END, f"{'='*50}\n\n")
            for p in device.open_ports:
                detail_text.insert(tk.END, f"Porta {p['port']}/TCP - Aberta\n")
        
        detail_text.config(state=tk.DISABLED)
        
        # Botão fechar
        tk.Button(detail_win, text="Fechar", command=detail_win.destroy,
                 bg=COLORS['primary'], fg='white', padx=20, pady=5).pack(pady=10)
    
    def _query_geo(self):
        """Consulta geolocalização de um IP específico"""
        ip = self.geo_ip_entry.get().strip()
        if not ip:
            self._log("Digite um IP para consultar", "WARN")
            return
        
        def query():
            geo = GeoLocation.get_ip_info(ip)
            
            def update():
                self.geo_result.delete(1.0, tk.END)
                self.geo_result.insert(tk.END, f" INFORMAÇÕES PARA IP: {ip}\n")
                self.geo_result.insert(tk.END, f"{'='*50}\n\n")
                
                if geo.get('type') == 'private':
                    self.geo_result.insert(tk.END, "Este é um IP privado (rede local)\n")
                    self.geo_result.insert(tk.END, f"País: {geo.get('country', 'N/A')}\n")
                else:
                    self.geo_result.insert(tk.END, f"País: {geo.get('country', 'N/A')}\n")
                    self.geo_result.insert(tk.END, f"Código do País: {geo.get('country_code', '??')}\n")
                    self.geo_result.insert(tk.END, f"Cidade: {geo.get('city', 'N/A')}\n")
                    self.geo_result.insert(tk.END, f"Região: {geo.get('region', 'N/A')}\n")
                    self.geo_result.insert(tk.END, f"ISP: {geo.get('isp', 'N/A')}\n")
                    self.geo_result.insert(tk.END, f"Organização: {geo.get('organization', 'N/A')}\n")
                    if geo.get('lat'):
                        self.geo_result.insert(tk.END, f"Latitude: {geo['lat']}\n")
                        self.geo_result.insert(tk.END, f"Longitude: {geo['lon']}\n")
                
                self._log(f"Geolocalização consultada para {ip}: {geo.get('country', 'N/A')}", "INFO")
            
            self.root.after(0, update)
        
        threading.Thread(target=query, daemon=True).start()
    
    def _update_report(self):
        """Atualiza o relatório"""
        self.report_text.delete(1.0, tk.END)
        
        if not self.current_results:
            self.report_text.insert(tk.END, "Nenhum dado de escaneamento disponível.\nExecute um escaneamento primeiro.")
            return
        
        self.report_text.insert(tk.END, f"📡 RELATÓRIO DE REDE - {APP_NAME} v{VERSION}\n")
        self.report_text.insert(tk.END, f"{'='*70}\n\n")
        self.report_text.insert(tk.END, f" Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.report_text.insert(tk.END, f" Total de dispositivos: {len(self.current_results)}\n\n")
        
        # Estatísticas por tipo
        type_counts = {}
        for device in self.current_results:
            dtype = device.device_type
            type_counts[dtype] = type_counts.get(dtype, 0) + 1
        
        self.report_text.insert(tk.END, f" RESUMO POR TIPO DE DISPOSITIVO:\n")
        self.report_text.insert(tk.END, f"{'-'*40}\n")
        for dtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            self.report_text.insert(tk.END, f"  {dtype}: {count}\n")
        
        self.report_text.insert(tk.END, f"\n LISTA COMPLETA DE DISPOSITIVOS:\n")
        self.report_text.insert(tk.END, f"{'-'*40}\n")
        
        for device in self.current_results:
            self.report_text.insert(tk.END, f"{device.device_icon} {device.device_type}\n")
            self.report_text.insert(tk.END, f"   └ IP: {device.ip}\n")
            self.report_text.insert(tk.END, f"   └ Hostname: {device.hostname}\n")
            self.report_text.insert(tk.END, f"   └ Fabricante: {device.manufacturer}\n")
            self.report_text.insert(tk.END, f"   └ MAC: {device.mac}\n\n")
    
    def _export_results(self):
        """Exporta resultados para JSON"""
        if not self.current_results:
            self._log("Nada para exportar", "WARN")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_scan_{timestamp}.json"
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'tool': APP_NAME,
            'version': VERSION,
            'network': self.network_entry.get(),
            'total_devices': len(self.current_results),
            'devices': [d.to_dict() for d in self.current_results]
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            self._log(f"Resultados exportados para {filename}", "SUCCESS")
            messagebox.showinfo("Exportado", f"Arquivo salvo: {filename}")
        except Exception as e:
            self._log(f"Erro ao exportar: {e}", "ERROR")
    
    def _export_report(self):
        """Exporta relatório em texto"""
        content = self.report_text.get(1.0, tk.END)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_report_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            self._log(f"Relatório exportado para {filename}", "SUCCESS")
            messagebox.showinfo("Exportado", f"Relatório salvo: {filename}")
        except Exception as e:
            self._log(f"Erro ao exportar relatório: {e}", "ERROR")
    
    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {'INFO': 'ℹ️', 'WARN': '⚠️', 'ERROR': '❌', 'SUCCESS': '✅'}
        prefix = colors.get(level, 'ℹ️')
        self.log_area.insert(tk.END, f"[{timestamp}] {prefix} {message}\n")
        self.log_area.see(tk.END)
    
    def _clear_log(self):
        self.log_area.delete(1.0, tk.END)
        self._log("Log limpo", "INFO")


# ============================================================================
# MAIN
# ============================================================================

def main():
    
    
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()