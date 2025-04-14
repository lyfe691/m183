# 📄 Penetration Test Report – Machine 1: Heal
## 🧠 Management Summary
In this penetration test, we targeted the active HackTheBox machine "Heal", which meets the required difficulty level (Medium) and appears to have an HTTP service running on port 80. The objective was to compromise the machine and retrieve the user flag, documenting all identified vulnerabilities and providing remediation recommendations.

![1744655136679](image/Dokumentation/1744655136679.png)

## 🌐 Network Setup
The VPN tunnel to HTB was established using OpenVPN on Kali Linux:

```bash
sudo openvpn Desktop/lab_lyfe691.ovpn
```
The connection successfully initialized, assigning the tun interface the IP 10.10.14.234.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo apt update
[sudo] password for kali: 
Get:1 http://mirror.init7.net/kali kali-rolling InRelease [41.5 kB]
Get:2 http://mirror.init7.net/kali kali-rolling/main amd64 Packages [20.9 MB]
Get:3 http://mirror.init7.net/kali kali-rolling/main amd64 Contents (deb) [51.4 MB]
Get:4 http://mirror.init7.net/kali kali-rolling/contrib amd64 Packages [119 kB]
Get:5 http://mirror.init7.net/kali kali-rolling/contrib amd64 Contents (deb) [327 kB]
Get:6 http://mirror.init7.net/kali kali-rolling/non-free amd64 Packages [204 kB]
Get:7 http://mirror.init7.net/kali kali-rolling/non-free amd64 Contents (deb) [914 kB]
Get:8 http://mirror.init7.net/kali kali-rolling/non-free-firmware amd64 Packages [10.6 kB]
Get:9 http://mirror.init7.net/kali kali-rolling/non-free-firmware amd64 Contents (deb) [24.3 kB]
Fetched 74.0 MB in 11s (7,045 kB/s)                                         
963 packages can be upgraded. Run 'apt list --upgradable' to see them.
                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo apt install openvpn -yd
Upgrading:                      
  openvpn

Summary:
  Upgrading: 1, Installing: 0, Removing: 0, Not Upgrading: 962
  Download size: 662 kB
  Freed space: 1,024 B

Get:1 http://mirror.init7.net/kali kali-rolling/main amd64 openvpn amd64 2.6.14-1 [662 kB]
Fetched 662 kB in 0s (2,086 kB/s)
Download complete and in download only mode
                                                                             
┌──(kali㉿kali)-[~]
└─$ openvpn --version
OpenVPN 2.6.13 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
library versions: OpenSSL 3.4.0 22 Oct 2024, LZO 2.10
DCO version: N/A
Originally developed by James Yonan
Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
Compile time defines: enable_async_push=no enable_comp_stub=no enable_crypto_ofb_cfb=yes enable_dco=yes enable_dco_arg=yes enable_debug=yes enable_dependency_tracking=no enable_dlopen=unknown enable_dlopen_self=unknown enable_dlopen_self_static=unknown enable_fast_install=needless enable_fragment=yes enable_iproute2=no enable_libtool_lock=yes enable_lz4=yes enable_lzo=yes enable_maintainer_mode=no enable_management=yes enable_option_checking=no enable_pam_dlopen=no enable_pedantic=no enable_pkcs11=yes enable_plugin_auth_pam=yes enable_plugin_down_root=yes enable_plugins=yes enable_port_share=yes enable_selinux=no enable_shared=yes enable_shared_with_static_runtimes=no enable_silent_rules=no enable_small=no enable_static=yes enable_strict=no enable_strict_options=no enable_systemd=yes enable_unit_tests=no enable_werror=no enable_win32_dll=yes enable_wolfssl_options_h=yes enable_x509_alt_username=yes with_aix_soname=aix with_crypto_library=openssl with_gnu_ld=yes with_mem_check=no with_openssl_engine=auto with_sysroot=no
                                                                             
┌──(kali㉿kali)-[~]
└─$ ls                             
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
                                                                             
┌──(kali㉿kali)-[~]
└─$ openvpn --version
OpenVPN 2.6.13 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
library versions: OpenSSL 3.4.0 22 Oct 2024, LZO 2.10
DCO version: N/A
Originally developed by James Yonan
Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
Compile time defines: enable_async_push=no enable_comp_stub=no enable_crypto_ofb_cfb=yes enable_dco=yes enable_dco_arg=yes enable_debug=yes enable_dependency_tracking=no enable_dlopen=unknown enable_dlopen_self=unknown enable_dlopen_self_static=unknown enable_fast_install=needless enable_fragment=yes enable_iproute2=no enable_libtool_lock=yes enable_lz4=yes enable_lzo=yes enable_maintainer_mode=no enable_management=yes enable_option_checking=no enable_pam_dlopen=no enable_pedantic=no enable_pkcs11=yes enable_plugin_auth_pam=yes enable_plugin_down_root=yes enable_plugins=yes enable_port_share=yes enable_selinux=no enable_shared=yes enable_shared_with_static_runtimes=no enable_silent_rules=no enable_small=no enable_static=yes enable_strict=no enable_strict_options=no enable_systemd=yes enable_unit_tests=no enable_werror=no enable_win32_dll=yes enable_wolfssl_options_h=yes enable_x509_alt_username=yes with_aix_soname=aix with_crypto_library=openssl with_gnu_ld=yes with_mem_check=no with_openssl_engine=auto with_sysroot=no
                                                                             
┌──(kali㉿kali)-[~]
└─$ openvpn Desktop/lab_lyfe691.ovpn 
2025-04-14 13:43:12 WARNING: Compression for receiving enabled. Compression has been used in the past to break encryption. Sent packets are not compressed unless "allow-compression yes" is also set.
2025-04-14 13:43:12 Note: --data-ciphers-fallback with cipher 'AES-128-CBC' disables data channel offload.
2025-04-14 13:43:12 OpenVPN 2.6.13 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2025-04-14 13:43:12 library versions: OpenSSL 3.4.0 22 Oct 2024, LZO 2.10
2025-04-14 13:43:12 DCO version: N/A
2025-04-14 13:43:12 TCP/UDP: Preserving recently used remote address: [AF_INET]38.46.226.72:1337
2025-04-14 13:43:12 Socket Buffers: R=[212992->212992] S=[212992->212992]
2025-04-14 13:43:12 UDPv4 link local: (not bound)
2025-04-14 13:43:12 UDPv4 link remote: [AF_INET]38.46.226.72:1337
2025-04-14 13:43:12 TLS: Initial packet from [AF_INET]38.46.226.72:1337, sid=d118f3ff 09ea4848
2025-04-14 13:43:13 VERIFY OK: depth=2, C=GR, O=Hack The Box, OU=Systems, CN=HTB VPN: Root Certificate Authority
2025-04-14 13:43:13 VERIFY OK: depth=1, C=GR, O=Hack The Box, OU=Systems, CN=HTB VPN: us-free-2 Issuing CA
2025-04-14 13:43:13 VERIFY KU OK
2025-04-14 13:43:13 Validating certificate extended key usage
2025-04-14 13:43:13 ++ Certificate has EKU (str) TLS Web Client Authentication, expects TLS Web Server Authentication
2025-04-14 13:43:13 ++ Certificate has EKU (oid) 1.3.6.1.5.5.7.3.2, expects TLS Web Server Authentication
2025-04-14 13:43:13 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
2025-04-14 13:43:13 VERIFY EKU OK
2025-04-14 13:43:13 VERIFY OK: depth=0, C=GR, O=Hack The Box, OU=Systems, CN=us-free-2
2025-04-14 13:43:13 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 256 bits ED25519, signature: ED25519, peer temporary key: 253 bits X25519
2025-04-14 13:43:13 [us-free-2] Peer Connection Initiated with [AF_INET]38.46.226.72:1337
2025-04-14 13:43:13 TLS: move_session: dest=TM_ACTIVE src=TM_INITIAL reinit_src=1
2025-04-14 13:43:13 TLS: tls_multi_process: initial untrusted session promoted to trusted
2025-04-14 13:43:14 SENT CONTROL [us-free-2]: 'PUSH_REQUEST' (status=1)
2025-04-14 13:43:14 PUSH: Received control message: 'PUSH_REPLY,route 10.10.10.0 255.255.254.0,route 10.129.0.0 255.255.0.0,route-ipv6 dead:beef::/64,explicit-exit-notify,tun-ipv6,route-gateway 10.10.14.1,topology subnet,ping 10,ping-restart 120,ifconfig-ipv6 dead:beef:2::10e8/64 dead:beef:2::1,ifconfig 10.10.14.234 255.255.254.0,peer-id 57,cipher AES-256-CBC'
2025-04-14 13:43:14 OPTIONS IMPORT: --ifconfig/up options modified
2025-04-14 13:43:14 OPTIONS IMPORT: route options modified
2025-04-14 13:43:14 OPTIONS IMPORT: route-related options modified
2025-04-14 13:43:14 net_route_v4_best_gw query: dst 0.0.0.0
2025-04-14 13:43:14 net_route_v4_best_gw result: via 10.0.2.2 dev eth0
2025-04-14 13:43:14 ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=eth0 HWADDR=08:00:27:04:42:0f
2025-04-14 13:43:14 GDG6: remote_host_ipv6=n/a
2025-04-14 13:43:14 net_route_v6_best_gw query: dst ::
2025-04-14 13:43:14 net_route_v6_best_gw result: via fe80::2 dev eth0
2025-04-14 13:43:14 ROUTE6_GATEWAY fe80::2 IFACE=eth0
2025-04-14 13:43:14 ERROR: Cannot ioctl TUNSETIFF tun: Operation not permitted (errno=1)
2025-04-14 13:43:14 Exiting due to fatal error
                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo openvpn Desktop/lab_lyfe691.ovpn
2025-04-14 13:43:56 WARNING: Compression for receiving enabled. Compression has been used in the past to break encryption. Sent packets are not compressed unless "allow-compression yes" is also set.
2025-04-14 13:43:56 Note: --data-ciphers-fallback with cipher 'AES-128-CBC' disables data channel offload.
2025-04-14 13:43:56 OpenVPN 2.6.13 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2025-04-14 13:43:56 library versions: OpenSSL 3.4.0 22 Oct 2024, LZO 2.10
2025-04-14 13:43:56 DCO version: N/A
2025-04-14 13:43:56 TCP/UDP: Preserving recently used remote address: [AF_INET]38.46.226.72:1337
2025-04-14 13:43:56 Socket Buffers: R=[212992->212992] S=[212992->212992]
2025-04-14 13:43:56 UDPv4 link local: (not bound)
2025-04-14 13:43:56 UDPv4 link remote: [AF_INET]38.46.226.72:1337
2025-04-14 13:43:56 TLS: Initial packet from [AF_INET]38.46.226.72:1337, sid=151c165a 358f2d2e
2025-04-14 13:43:56 VERIFY OK: depth=2, C=GR, O=Hack The Box, OU=Systems, CN=HTB VPN: Root Certificate Authority
2025-04-14 13:43:56 VERIFY OK: depth=1, C=GR, O=Hack The Box, OU=Systems, CN=HTB VPN: us-free-2 Issuing CA
2025-04-14 13:43:56 VERIFY KU OK
2025-04-14 13:43:56 Validating certificate extended key usage
2025-04-14 13:43:56 ++ Certificate has EKU (str) TLS Web Client Authentication, expects TLS Web Server Authentication
2025-04-14 13:43:56 ++ Certificate has EKU (oid) 1.3.6.1.5.5.7.3.2, expects TLS Web Server Authentication
2025-04-14 13:43:56 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
2025-04-14 13:43:56 VERIFY EKU OK
2025-04-14 13:43:56 VERIFY OK: depth=0, C=GR, O=Hack The Box, OU=Systems, CN=us-free-2
2025-04-14 13:43:57 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 256 bits ED25519, signature: ED25519, peer temporary key: 253 bits X25519
2025-04-14 13:43:57 [us-free-2] Peer Connection Initiated with [AF_INET]38.46.226.72:1337
2025-04-14 13:43:57 TLS: move_session: dest=TM_ACTIVE src=TM_INITIAL reinit_src=1
2025-04-14 13:43:57 TLS: tls_multi_process: initial untrusted session promoted to trusted
2025-04-14 13:43:58 SENT CONTROL [us-free-2]: 'PUSH_REQUEST' (status=1)
2025-04-14 13:43:59 PUSH: Received control message: 'PUSH_REPLY,route 10.10.10.0 255.255.254.0,route 10.129.0.0 255.255.0.0,route-ipv6 dead:beef::/64,explicit-exit-notify,tun-ipv6,route-gateway 10.10.14.1,topology subnet,ping 10,ping-restart 120,ifconfig-ipv6 dead:beef:2::10e8/64 dead:beef:2::1,ifconfig 10.10.14.234 255.255.254.0,peer-id 58,cipher AES-256-CBC'
2025-04-14 13:43:59 OPTIONS IMPORT: --ifconfig/up options modified
2025-04-14 13:43:59 OPTIONS IMPORT: route options modified
2025-04-14 13:43:59 OPTIONS IMPORT: route-related options modified
2025-04-14 13:43:59 net_route_v4_best_gw query: dst 0.0.0.0
2025-04-14 13:43:59 net_route_v4_best_gw result: via 10.0.2.2 dev eth0
2025-04-14 13:43:59 ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=eth0 HWADDR=08:00:27:04:42:0f
2025-04-14 13:43:59 GDG6: remote_host_ipv6=n/a
2025-04-14 13:43:59 net_route_v6_best_gw query: dst ::
2025-04-14 13:43:59 net_route_v6_best_gw result: via fe80::2 dev eth0
2025-04-14 13:43:59 ROUTE6_GATEWAY fe80::2 IFACE=eth0
2025-04-14 13:43:59 TUN/TAP device tun0 opened
2025-04-14 13:43:59 net_iface_mtu_set: mtu 1500 for tun0
2025-04-14 13:43:59 net_iface_up: set tun0 up
2025-04-14 13:43:59 net_addr_v4_add: 10.10.14.234/23 dev tun0
2025-04-14 13:43:59 net_iface_mtu_set: mtu 1500 for tun0
2025-04-14 13:43:59 net_iface_up: set tun0 up
2025-04-14 13:43:59 net_addr_v6_add: dead:beef:2::10e8/64 dev tun0
2025-04-14 13:43:59 net_route_v4_add: 10.10.10.0/23 via 10.10.14.1 dev [NULL] table 0 metric -1
2025-04-14 13:43:59 net_route_v4_add: 10.129.0.0/16 via 10.10.14.1 dev [NULL] table 0 metric -1
2025-04-14 13:43:59 add_route_ipv6(dead:beef::/64 -> dead:beef:2::1 metric -1) dev tun0
2025-04-14 13:43:59 net_route_v6_add: dead:beef::/64 via :: dev tun0 table 0 metric -1
2025-04-14 13:43:59 Initialization Sequence Completed
2025-04-14 13:43:59 Data Channel: cipher 'AES-256-CBC', auth 'SHA256', peer-id: 58, compression: 'lzo'
2025-04-14 13:43:59 Timers: ping 10, ping-restart 120
2025-04-14 13:43:59 Protocol options: explicit-exit-notify 1

```

## 🔍 Target Discovery
Target IP of Heal: 10.10.11.46
Initial port scan was performed to verify HTTP access:

```bash
nmap -p 80 10.10.11.46
```
Result:

```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-14 13:57 EDT
Nmap scan report for 10.10.11.46
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.33 seconds
```

![1744655269309](image/Dokumentation/1744655269309.png)

