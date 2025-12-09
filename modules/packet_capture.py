"""
Packet Capture Module - Network Traffic Sniffer
Production-Ready: AsyncIO-compatible packet capture using Scapy
"""
import asyncio
import logging
import threading
import socket
import random
import time
from collections import deque, defaultdict
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from pathlib import Path
import pandas as pd
import config

try:
    from scapy.all import sniff, wrpcap, get_if_list, get_if_addr
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    # Windows-specific interface detection
    try:
        from scapy.arch.windows import get_windows_if_list
        WINDOWS_IF_LIST_AVAILABLE = True
    except ImportError:
        WINDOWS_IF_LIST_AVAILABLE = False
    try:
        from scapy.interfaces import get_working_ifaces
        WORKING_IFACES_AVAILABLE = True
    except ImportError:
        WORKING_IFACES_AVAILABLE = False
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    WINDOWS_IF_LIST_AVAILABLE = False
    WORKING_IFACES_AVAILABLE = False
    print("WARNING: scapy library is not installed. Install it with 'pip install scapy'")
    print("NOTE: On Windows, you may also need to install Npcap: https://npcap.com/")

# Logging yapılandırması
logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    AsyncIO-compatible packet sniffer using Scapy.
    Captures network packets in background thread and stores them in memory.
    """
    
    def __init__(self, max_packets: int = 1000, interface: Optional[str] = None):
        """
        Initializes PacketSniffer.
        
        Args:
            max_packets: Maximum number of packets to keep in memory (default: 1000)
            interface: Network interface to sniff on (None = auto-detect)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is not installed. Please install it with 'pip install scapy'")
        
        self.max_packets = max_packets
        self.interface = interface or self._get_default_interface()
        self.packets: deque = deque(maxlen=max_packets)
        self.packet_data: deque = deque(maxlen=max_packets)  # Store parsed packet info
        self.running: bool = False
        self.sniff_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'start_time': None,
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'protocols': defaultdict(int)
        }
        
        logger.info(f"PacketSniffer initialized on interface: {self.interface}")
    
    def _get_active_local_ip(self) -> Optional[str]:
        """
        Determines the local IP address used for internet connectivity
        by connecting to an external host (8.8.8.8).
        
        Returns:
            str: Local IP address or None if detection fails
        """
        try:
            # Connect to external DNS server to determine which interface is used
            # This doesn't actually send data, just determines the route
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)  # Very short timeout
            try:
                # Connect to Google DNS (doesn't actually send data)
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                s.close()
                return local_ip
            except (socket.error, OSError):
                s.close()
                return None
        except Exception as e:
            logger.debug(f"Error detecting active local IP: {e}")
            return None
    
    def _get_default_interface(self) -> Optional[str]:
        """
        Gets the best available network interface for packet capture.
        Uses socket-based detection to find the interface with active internet connectivity.
        """
        try:
            # Method 1: Socket-based detection (most reliable for active internet connection)
            active_local_ip = self._get_active_local_ip()
            
            if active_local_ip:
                print(f"🔍 Detected active local IP: {active_local_ip}")
                logger.info(f"Active local IP detected: {active_local_ip}")
                
                # Now find the interface that has this IP
                if WINDOWS_IF_LIST_AVAILABLE:
                    try:
                        windows_if_list = get_windows_if_list()
                        if windows_if_list:
                            for iface_info in windows_if_list:
                                if isinstance(iface_info, dict):
                                    iface_ip = iface_info.get('ip', '')
                                    iface_name = iface_info.get('name', '')
                                    iface_desc = iface_info.get('description', iface_info.get('win_name', ''))
                                    
                                    # Match the IP address
                                    if iface_ip == active_local_ip:
                                        print(f"✅ Found active interface: {iface_desc or iface_name}")
                                        print(f"   GUID: {iface_name}")
                                        print(f"   IP: {iface_ip}")
                                        logger.info(f"Selected interface (socket-based): {iface_name} ({iface_desc}) - IP: {iface_ip}")
                                        return iface_name
                    except Exception as e:
                        logger.debug(f"get_windows_if_list() failed: {e}")
                
                # Fallback: Try get_if_list() to match IP
                try:
                    if_list = get_if_list()
                    if if_list:
                        for iface in if_list:
                            try:
                                addr = get_if_addr(iface)
                                if addr == active_local_ip:
                                    print(f"✅ Found active interface: {iface}")
                                    print(f"   IP: {addr}")
                                    logger.info(f"Selected interface (get_if_list match): {iface} - IP: {addr}")
                                    return iface
                            except:
                                continue
                except Exception as e:
                    logger.debug(f"get_if_list() IP matching failed: {e}")
            
            # Method 2: Fallback to get_windows_if_list() with best interface selection
            if WINDOWS_IF_LIST_AVAILABLE:
                try:
                    windows_if_list = get_windows_if_list()
                    if windows_if_list:
                        best_iface = None
                        best_iface_desc = None
                        best_iface_ip = None
                        
                        for iface_info in windows_if_list:
                            if isinstance(iface_info, dict):
                                name = iface_info.get('name', '')
                                ip = iface_info.get('ip', '')
                                desc = iface_info.get('description', iface_info.get('win_name', ''))
                                
                                # Skip loopback and invalid IPs
                                if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
                                    # Prefer non-loopback interfaces
                                    if 'Loopback' not in str(desc) and 'lo' not in str(desc).lower():
                                        # Prefer Ethernet/Wi-Fi over other interfaces
                                        if not best_iface or 'Ethernet' in desc or 'Wi-Fi' in desc or 'Wireless' in desc:
                                            best_iface = name
                                            best_iface_desc = desc
                                            best_iface_ip = ip
                        
                        if best_iface:
                            print(f"✅ Found interface using get_windows_if_list(): {best_iface_desc or best_iface}")
                            print(f"   GUID: {best_iface}")
                            print(f"   IP: {best_iface_ip}")
                            logger.info(f"Selected interface (get_windows_if_list fallback): {best_iface} ({best_iface_desc}) - IP: {best_iface_ip}")
                            return best_iface
                except Exception as e:
                    logger.debug(f"get_windows_if_list() fallback failed: {e}")
            
            # Method 3: Fallback to get_working_ifaces()
            if WORKING_IFACES_AVAILABLE:
                try:
                    working_ifaces = get_working_ifaces()
                    if working_ifaces:
                        best_iface = list(working_ifaces)[0]
                        print(f"✅ Found working interface using get_working_ifaces(): {best_iface}")
                        logger.info(f"Selected interface (get_working_ifaces fallback): {best_iface}")
                        return best_iface
                except Exception as e:
                    logger.debug(f"get_working_ifaces() fallback failed: {e}")
            
            # Method 4: Last resort - get_if_list() with IP check
            if_list = get_if_list()
            if if_list:
                print(f"🔍 Checking {len(if_list)} interfaces...")
                for iface in if_list:
                    try:
                        addr = get_if_addr(iface)
                        if addr and addr != '0.0.0.0' and addr != '127.0.0.1':
                            if 'Loopback' not in str(iface) and 'lo' not in str(iface).lower():
                                print(f"✅ Found active interface: {iface} (IP: {addr})")
                                logger.info(f"Selected interface (get_if_list fallback): {iface} - IP: {addr}")
                                return iface
                    except Exception as e:
                        logger.debug(f"Error checking interface {iface}: {e}")
                        continue
                
                # Absolute last resort
                if if_list:
                    print(f"⚠️  Using first available interface (may not be active): {if_list[0]}")
                    logger.warning(f"Fallback to first interface: {if_list[0]}")
                    return if_list[0]
        
        except Exception as e:
            logger.error(f"Could not detect network interface: {e}", exc_info=True)
            print(f"❌ Error detecting network interface: {e}")
        
        return None
    
    def _packet_handler(self, packet) -> None:
        """
        Callback function called by Scapy for each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            timestamp = datetime.now()
            packet_info = self._parse_packet(packet, timestamp)
            
            if packet_info:
                self.packets.append(packet)
                self.packet_data.append(packet_info)
                
                # Update statistics
                self.stats['total_packets'] += 1
                if packet_info['source_ip']:
                    self.stats['source_ips'][packet_info['source_ip']] += 1
                if packet_info['dest_ip']:
                    self.stats['dest_ips'][packet_info['dest_ip']] += 1
                if packet_info['port']:
                    self.stats['ports'][packet_info['port']] += 1
                if packet_info['protocol']:
                    self.stats['protocols'][packet_info['protocol']] += 1
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def _parse_packet(self, packet, timestamp: datetime) -> Optional[Dict[str, Any]]:
        """
        Parses a Scapy packet and extracts relevant information.
        
        Args:
            packet: Scapy packet object
            timestamp: Packet capture timestamp
        
        Returns:
            dict: Parsed packet information or None if parsing fails
        """
        try:
            packet_info = {
                'timestamp': timestamp,
                'source_ip': None,
                'dest_ip': None,
                'protocol': None,
                'port': None,
                'length': len(packet),
                'summary': packet.summary()
            }
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                packet_info['source_ip'] = ip_layer.src
                packet_info['dest_ip'] = ip_layer.dst
                packet_info['protocol'] = ip_layer.proto
                
                # Extract port information (TCP/UDP)
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info['port'] = tcp_layer.dport  # Destination port
                    packet_info['protocol'] = 'TCP'
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info['port'] = udp_layer.dport  # Destination port
                    packet_info['protocol'] = 'UDP'
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
            
            # Extract Ethernet layer information if no IP
            elif Ether in packet:
                eth_layer = packet[Ether]
                packet_info['source_ip'] = eth_layer.src
                packet_info['dest_ip'] = eth_layer.dst
                packet_info['protocol'] = 'Ethernet'
            
            return packet_info
        
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _demo_packet_loop(self) -> None:
        """
        Demo mode: Generates fake packets for screenshots.
        Simulates attack traffic from suspicious IPs.
        """
        logger.info("Demo mode: Starting fake packet generation")
        self.stats['start_time'] = datetime.now()
        
        # Demo packet templates
        demo_packets = [
            {
                'source_ip': f'185.25.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'dest_ip': '192.168.1.10',
                'protocol': 'TCP',
                'port': 3389,
                'length': random.randint(60, 1500)
            },
            {
                'source_ip': f'45.33.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'dest_ip': '192.168.1.10',
                'protocol': 'UDP',
                'port': 53,
                'length': random.randint(60, 512)
            },
            {
                'source_ip': f'185.220.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'dest_ip': '192.168.1.10',
                'protocol': 'TCP',
                'port': 445,
                'length': random.randint(100, 1500)
            },
            {
                'source_ip': f'45.146.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'dest_ip': '192.168.1.10',
                'protocol': 'TCP',
                'port': 443,
                'length': random.randint(200, 1500)
            }
        ]
        
        packet_counter = 0
        
        while self.running and not self.stop_event.is_set():
            try:
                # Generate a random demo packet
                template = random.choice(demo_packets)
                timestamp = datetime.now()
                
                packet_info = {
                    'timestamp': timestamp,
                    'source_ip': template['source_ip'],
                    'dest_ip': template['dest_ip'],
                    'protocol': template['protocol'],
                    'port': template['port'],
                    'length': template['length'],
                    'summary': f"{template['protocol']} {template['source_ip']} > {template['dest_ip']}:{template['port']}"
                }
                
                # Add to packet data
                self.packet_data.append(packet_info)
                
                # Update statistics
                self.stats['total_packets'] += 1
                self.stats['source_ips'][packet_info['source_ip']] += 1
                self.stats['dest_ips'][packet_info['dest_ip']] += 1
                self.stats['ports'][packet_info['port']] += 1
                self.stats['protocols'][packet_info['protocol']] += 1
                
                packet_counter += 1
                
                # Generate packets at realistic rate (1-3 per second)
                time.sleep(random.uniform(0.3, 1.0))
                
            except Exception as e:
                logger.error(f"Error in demo packet loop: {e}", exc_info=True)
                time.sleep(1)
        
        logger.info(f"Demo packet generation stopped. Generated {packet_counter} fake packets.")
    
    def _sniff_loop(self) -> None:
        """
        Main sniffing loop running in background thread.
        This is a blocking operation, so it runs in a separate thread.
        """
        try:
            logger.info(f"Starting packet capture on interface: {self.interface}")
            self.stats['start_time'] = datetime.now()
            
            # Scapy's sniff() is blocking, so we run it in a thread
            # Windows-specific: Use monitor=False (promiscuous mode may not work on all interfaces)
            # Use a filter to capture only IP traffic (more efficient)
            sniff_kwargs = {
                'iface': self.interface,
                'prn': self._packet_handler,
                'stop_filter': lambda x: self.stop_event.is_set(),
                'timeout': 1,  # Check stop condition every second
                'store': False,  # Don't store packets in Scapy's buffer, we handle it ourselves
            }
            
            # On Windows, try without promiscuous mode first
            # Some interfaces don't support promiscuous mode
            try:
                sniff(**sniff_kwargs)
            except Exception as e:
                logger.warning(f"Sniff failed with default settings: {e}")
                logger.info("Retrying with monitor=False (non-promiscuous mode)...")
                # Retry without promiscuous mode
                sniff_kwargs['monitor'] = False
                try:
                    sniff(**sniff_kwargs)
                except Exception as e2:
                    logger.error(f"Sniff failed even with monitor=False: {e2}")
                    raise
        
        except Exception as e:
            logger.error(f"Error in sniff loop: {e}", exc_info=True)
        finally:
            logger.info("Packet capture stopped")
            self.running = False
    
    def start(self) -> None:
        """
        Starts packet capture in background thread.
        Non-blocking, returns immediately.
        """
        if self.running:
            logger.warning("Packet capture is already running")
            return
        
        # Check demo mode
        if config.DEMO_MODE:
            logger.info("Demo mode enabled - generating fake packets for screenshots")
            self.running = True
            self.stop_event.clear()
            self.stats['start_time'] = datetime.now()
            
            # Start fake packet generator in background thread
            self.sniff_thread = threading.Thread(target=self._demo_packet_loop, daemon=True)
            self.sniff_thread.start()
            logger.info("Demo packet capture started")
            return
        
        if not self.interface:
            raise RuntimeError("No network interface available. Cannot start packet capture.")
        
        self.running = True
        self.stop_event.clear()
        self.stats['start_time'] = datetime.now()
        
        # Start sniffing in background thread
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        
        logger.info("Packet capture started")
    
    def stop(self) -> None:
        """
        Stops packet capture gracefully.
        """
        if not self.running:
            return
        
        logger.info("Stopping packet capture...")
        self.stop_event.set()
        self.running = False
        
        # Wait for thread to finish (with timeout)
        # Since we use timeout=1 in sniff(), it should stop within 1-2 seconds
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=3.0)
            if self.sniff_thread.is_alive():
                logger.warning("Sniff thread did not stop gracefully within timeout")
            else:
                logger.info("Packet capture stopped gracefully")
    
    def get_recent_packets(self, count: int = 10) -> pd.DataFrame:
        """
        Returns recent packets in DataFrame format for dashboard display.
        
        Args:
            count: Number of recent packets to return (default: 10)
        
        Returns:
            pd.DataFrame: DataFrame with columns: Time, Source IP, Dest IP, Protocol, Port, Length
        """
        if not self.packet_data:
            return pd.DataFrame(columns=['Time', 'Source IP', 'Dest IP', 'Protocol', 'Port', 'Length'])
        
        # Get last 'count' packets
        recent_packets = list(self.packet_data)[-count:]
        
        # Convert to DataFrame
        data = []
        for pkt in recent_packets:
            data.append({
                'Time': pkt['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'Source IP': pkt['source_ip'] or 'N/A',
                'Dest IP': pkt['dest_ip'] or 'N/A',
                'Protocol': pkt['protocol'] or 'Unknown',
                'Port': pkt['port'] or 'N/A',
                'Length': pkt['length']
            })
        
        return pd.DataFrame(data)
    
    def get_traffic_stats(self) -> Dict[str, Any]:
        """
        Returns traffic statistics from current buffer.
        
        Returns:
            dict: Statistics including top source IPs, ports, protocols, etc.
        """
        uptime = None
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        # Get top N items
        top_source_ips = sorted(
            self.stats['source_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_dest_ips = sorted(
            self.stats['dest_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_ports = sorted(
            self.stats['ports'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_protocols = sorted(
            self.stats['protocols'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_packets': self.stats['total_packets'],
            'packets_in_buffer': len(self.packet_data),
            'uptime_seconds': uptime,
            'interface': self.interface,
            'running': self.running,
            'top_source_ips': [{'ip': ip, 'count': count} for ip, count in top_source_ips],
            'top_dest_ips': [{'ip': ip, 'count': count} for ip, count in top_dest_ips],
            'top_ports': [{'port': port, 'count': count} for port, count in top_ports],
            'top_protocols': [{'protocol': proto, 'count': count} for proto, count in top_protocols]
        }
    
    async def start_capture_to_file(
        self,
        filename: str,
        duration: float,
        interface: Optional[str] = None
    ) -> str:
        """
        Captures packets to a PCAP file for a specified duration.
        This is an async function that runs capture in a thread pool.
        
        Args:
            filename: Output PCAP file path
            duration: Capture duration in seconds
            interface: Network interface (None = use default)
        
        Returns:
            str: Path to saved PCAP file
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is not installed")
        
        interface = interface or self.interface
        if not interface:
            raise RuntimeError("No network interface available")
        
        filepath = Path(filename)
        if not filepath.suffix:
            filepath = filepath.with_suffix('.pcap')
        
        logger.info(f"Starting PCAP capture to {filepath} for {duration} seconds...")
        
        # Run blocking capture in thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self._capture_to_file_sync,
            str(filepath),
            duration,
            interface
        )
        
        logger.info(f"PCAP capture completed: {filepath}")
        return str(filepath)
    
    def _capture_to_file_sync(
        self,
        filepath: str,
        duration: float,
        interface: str
    ) -> None:
        """
        Synchronous PCAP capture function (runs in thread pool).
        
        Args:
            filepath: Output PCAP file path
            duration: Capture duration in seconds
            interface: Network interface
        """
        packets_captured = []
        start_time = datetime.now()
        
        def packet_handler(packet):
            packets_captured.append(packet)
            # Check if duration exceeded
            elapsed = (datetime.now() - start_time).total_seconds()
            return elapsed >= duration
        
        try:
            sniff(
                iface=interface,
                prn=lambda p: packets_captured.append(p),
                timeout=duration,
                store=True
            )
            
            # Save to PCAP file
            if packets_captured:
                wrpcap(filepath, packets_captured)
                logger.info(f"Saved {len(packets_captured)} packets to {filepath}")
            else:
                logger.warning(f"No packets captured, PCAP file not created")
        
        except Exception as e:
            logger.error(f"Error during PCAP capture: {e}", exc_info=True)
            raise
    
    def clear_buffer(self) -> None:
        """Clears the packet buffer and resets statistics"""
        self.packets.clear()
        self.packet_data.clear()
        self.stats = {
            'total_packets': 0,
            'start_time': None,
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'protocols': defaultdict(int)
        }
        logger.info("Packet buffer cleared")
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


# Convenience function for quick access
def create_sniffer(max_packets: int = 1000, interface: Optional[str] = None) -> PacketSniffer:
    """
    Creates and returns a PacketSniffer instance.
    
    Args:
        max_packets: Maximum packets to keep in memory
        interface: Network interface (None = auto-detect)
    
    Returns:
        PacketSniffer: Configured sniffer instance
    """
    return PacketSniffer(max_packets=max_packets, interface=interface)


if __name__ == "__main__":
    # Test/demo code
    import time
    
    logging.basicConfig(level=logging.INFO)
    
    print("PacketSniffer Test")
    print("=" * 60)
    
    try:
        sniffer = PacketSniffer(max_packets=100)
        print(f"Interface: {sniffer.interface}")
        
        print("\nStarting capture for 10 seconds...")
        sniffer.start()
        
        time.sleep(10)
        
        print("\nStopping capture...")
        sniffer.stop()
        
        print(f"\nCaptured {len(sniffer.packet_data)} packets")
        
        # Show recent packets
        if sniffer.packet_data:
            print("\nRecent packets:")
            df = sniffer.get_recent_packets(count=5)
            print(df.to_string(index=False))
        
        # Show statistics
        print("\nTraffic Statistics:")
        stats = sniffer.get_traffic_stats()
        print(f"Total packets: {stats['total_packets']}")
        print(f"Top protocols: {stats['top_protocols']}")
        print(f"Top source IPs: {stats['top_source_ips'][:5]}")
    
    except Exception as e:
        print(f"Error: {e}")
        print("\nNOTE: On Windows, you may need to:")
        print("1. Install Npcap: https://npcap.com/")
        print("2. Run as Administrator")

