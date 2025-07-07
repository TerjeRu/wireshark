# █▓▒▒░░░ WIRESHARK: A PRACTICAL ANALYSIS MANUAL ░░░▒▒▓█

> Network traffic is the definitive record of all activity on a network. While applications provide an abstraction, packet analysis allows for direct observation of the underlying protocols and data. This guide provides a series of practical, hands-on exercises for learning Wireshark, from initial setup to advanced analysis techniques.
>
> Launch your Kali Linux virtual machine and prepare for direct data inspection.

---

## 壱 - THE ENVIRONMENT: INTERFACE & FIRST CAPTURE

> The first step in packet analysis is to establish a collection point. Your Network Interface Card (NIC) is the sensor. We will activate it in promiscuous mode to capture all local network traffic, not just the packets addressed to your machine.

### ► **LIVE EXERCISE: Tapping the Stream**

1. **Root Access:** Open a terminal. Capturing from network interfaces requires elevated privileges.

   * `sudo wireshark`

2. **Select Interface:** Wireshark will present a list of available network interfaces. `eth0` typically represents a wired Ethernet connection, `wlan0` a wireless one, and `lo` the local loopback interface (for traffic within your own machine). An active interface will show a fluctuating signal graph.

   * Double-click your primary active interface to begin the capture.

3. **Observe the Traffic:** The main window will immediately begin to populate with captured packets. This is the raw, real-time data flow.

   * To generate easily identifiable traffic, open a browser and navigate to a non-encrypted website, such as `http://httpforever.com/`. Observe the corresponding increase in captured packets.

4. **Cease Capture:** Click the red square (◼️) in the top-left toolbar. The capture will stop. The resulting file (`pcap`) is a static record of the network traffic during the capture period.

---

## 弐 - THE TOOL: DECODING THE INTERFACE

> The Wireshark interface is composed of three primary panes that provide different levels of insight into the captured data. Understanding how they interrelate is fundamental to efficient analysis.

```
+--------------------------------------------------+
| Pane 1: Packet List (Summary View)               |
+--------------------------------------------------+
| Pane 2: Packet Details (Protocol Tree View)      |
+--------------------------------------------------+
| Pane 3: Packet Bytes (Raw Hexadecimal View)      |
+--------------------------------------------------+

```

### ► **LIVE EXERCISE: Trisecting Reality**

1. **Packet List (Top Pane):** This pane provides a summary of each captured packet. The columns (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`) offer high-level metadata. Clicking on any packet in this pane will update the other two panes to reflect that specific packet.

2. **Packet Details (Middle Pane):** This is the primary analysis pane, displaying the protocol stack for the selected packet. Data is shown in layers, reflecting the OSI model (e.g., Ethernet, IP, TCP, HTTP).

   * Locate an `HTTP` packet in the top pane and select it.

   * In the middle pane, click the `▸` triangle to expand the `Hypertext Transfer Protocol` layer. This reveals the specifics of the HTTP request or response.

   * Expand the layers beneath it (`Transmission Control Protocol`, `Internet Protocol`, etc.) to see how the data is encapsulated.

3. **Packet Bytes (Bottom Pane):** This pane displays the raw, unprocessed data of the selected packet in hexadecimal and ASCII. Clicking on a field in the Packet Details pane (e.g., the `Host` field in an HTTP header) will highlight the corresponding bytes in this pane, directly linking the protocol interpretation to the raw data.

---

## 参 - DISPLAY FILTERS: ISOLATING SIGNALS

> A raw capture is mostly noise. Display filters are the primary tool for isolating specific packets of interest. These filters are non-destructive; they only alter the view, not the underlying capture file.

### ► **LIVE EXERCISE: Applying Lenses**

*Use the filter bar located directly above the Packet List pane. The bar will turn green for valid syntax and red for invalid.*

1. **Filter by IP Address:**

   * `ip.addr == 8.8.8.8` (Shows all traffic to or from 8.8.8.8)

   * `ip.src == 192.168.1.100` (Shows traffic originating from this source IP)

   * `ip.dst != 192.168.1.1` (Shows traffic not destined for this IP)

2. **Filter by Protocol:**

   * `tcp` or `udp` or `icmp`

   * `dns` (Shows DNS queries and responses)

   * `http` (Shows Hypertext Transfer Protocol traffic)

3. **Filter by Port Number:**

   * `tcp.port == 443` (Shows traffic with a source or destination port of 443)

   * `tcp.dstport == 80` (Shows traffic destined for port 80)

4. **Logical Operators:** Combine filters for greater precision using `&&` (AND), `||` (OR), and `!` (NOT).

   * `ip.addr == 192.168.1.50 && tcp.port == 445` (Shows SMB traffic to/from a specific host)

   * `http || dns` (Shows both HTTP and DNS traffic)

   * `!(arp || icmp)` (Hides ARP and ICMP traffic to focus on higher-level protocols)

5. **Content Filtering:** Search for specific strings within packets.

   * `http contains "password"` (Shows HTTP packets containing the string "password". Useful for finding cleartext credentials.)

   * `tcp contains "USER"` (Shows TCP packets containing the string "USER", common in FTP authentication.)

---

## 四 - CAPTURE FILTERS: PRE-EMPTIVE DATA REDUCTION

> While display filters sift through existing data, capture filters determine what data is saved in the first place. This is essential for performance and manageability when monitoring high-volume networks.

### ► **LIVE EXERCISE: Recording with Intent**

1. **The Interface:** On the Wireshark welcome screen, before starting a capture, locate the text field labeled "Enter a capture filter...".

2. **The Syntax:** Capture filters use Berkeley Packet Filter (BPF) syntax, which is different from display filter syntax.

   * `host 8.8.8.8` (Capture traffic to or from this host)

   * `port 53` (Capture traffic with source or destination port 53)

   * `net 192.168.1.0/24` (Capture all traffic to or from this subnet)

   * `port not 22` (Ignore all SSH traffic)

3. **The Test:** Apply the capture filter `host httpforever.com` and start the capture. In your terminal, ping a different host (`ping 8.8.8.8`). This ICMP traffic will not appear in Wireshark. Now, browse to `httpforever.com`. Only the HTTP traffic related to that host will be captured.

---

## 五 - STREAM RECONSTRUCTION: FOLLOWING CONVERSATIONS

> Packets are fragments of a larger conversation. To understand the application-level data exchange, you must reassemble these fragments. Wireshark's stream-following feature reconstructs the complete data flow.

### ► **LIVE EXERCISE: Rebuilding a TCP Conversation**

1. **The Target:** Start a new capture. Use `curl` to simulate an FTP login (which uses cleartext commands).

   * `curl ftp://test.rebex.net/ --user demo:password`

2. **The Anchor:** Stop the capture. In the filter bar, type `ftp`. You will see the command and response traffic for the FTP session. Locate the packet in the `Info` column that says `Request: USER demo`.

3. **The Follow:** Right-click on that packet, then select `Follow` -> `TCP Stream`.

4. **The Dialogue:** A new window will appear, showing the reconstructed conversation. Client commands are typically shown in red, and server responses in blue. You can clearly see the `USER` and `PASS` commands and the server's replies, just as the FTP client and server exchanged them.

---

## 六 - THE HUNT: ACTIVE ANALYSIS PATTERNS

> This section focuses on identifying the network signatures of common activities, moving from simple observation to active analysis.

### ► **LIVE EXERCISE 1: Signature of a Port Scan**

1. **The Attack:** An adversary's first move is reconnaissance. Run a port scan against your own machine.

   * `nmap -sT localhost`

2. **The Trace:** Capture this traffic on your loopback (`lo`) interface. The signature is a storm of connection requests (`SYN` packets) from a single source to many different ports on a target.

3. **The Filter:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

4. **The Footprint:** The packet list will show a rapid sequence of `[SYN]` packets from `127.0.0.1` to `127.0.0.1` across a range of ports. This is the unmistakable fingerprint of a TCP connect scan.

### ► **LIVE EXERCISE 2: Exposing Leaked Credentials**

1. **The Target:** Go to `http://testphp.vulnweb.com/login.php`. Start a capture.

2. **The Bait:** Enter credentials (`test` / `test`). Submit the form.

3. **The Filter:** Form data is sent via an HTTP POST request.

   * `http.request.method == "POST"`

4. **The Data:** You'll see a single POST packet. Select it. In the details pane, find and expand the `HTML Form URL Encoded` layer. The credentials will be there, in cleartext, a ghost on the wire for anyone to see.

---

## 七 - WLAN ANALYSIS: DECONSTRUCTING WIRELESS TRAFFIC

> Analyzing 802.11 (Wi-Fi) traffic requires putting your wireless card into "monitor mode," which allows it to capture all wireless frames in the air, not just those on the network you're connected to.

### ► **LIVE EXERCISE: Capturing the WPA2 Handshake**

1. **Enable Monitor Mode:** First, identify your wireless interface (`wlan0`, etc.) with `iwconfig`. Then, use `airmon-ng` (part of the aircrack-ng suite) to create a monitor-mode interface.

   * `sudo airmon-ng start wlan0`

   * This will create a new interface, likely named `wlan0mon`.

2. **The Capture:** Start Wireshark and begin capturing on the new `wlan0mon` interface.

3. **The Trigger:** To capture a handshake, you must capture a device as it connects to the network. Use your phone or another device and connect it to your Wi-Fi network.

4. **The Filter:** The WPA2 handshake is a four-part exchange using the Extensible Authentication Protocol over LAN (EAPOL).

   * `eapol`

5. **The Evidence:** You will see four EAPOL packets between the router (Access Point) and the connecting device. Capturing this handshake is the first step in a WPA2 password cracking attempt. When finished, stop monitor mode with `sudo airmon-ng stop wlan0mon`.

---

## 八 - COMMAND-LINE ANALYSIS: `tshark`

> `tshark` is the command-line equivalent of Wireshark. It is essential for scripting, automation, and analyzing captures on systems without a graphical interface.

### ► **LIVE EXERCISE: Automated Field Extraction**

1. **The Goal:** Imagine you have a large pcap file and want to quickly extract a list of all unique source IP addresses and the HTTP hosts they requested.

2. **The Capture:** First, generate some traffic.

   * `tshark -i eth0 -a duration:30 -w /tmp/webtraffic.pcap`

   * This command captures 30 seconds of traffic from `eth0` and saves it. Browse a few websites during this time.

3. **The Command:** Now, process the file with `tshark`.

   * `tshark -r /tmp/webtraffic.pcap -T fields -e ip.src -e http.host -Y "http.host"`

   * `-r`: Specifies the input file to read.

   * `-T fields`: Sets the output format to be specific fields.

   * `-e <field>`: Specifies a field to extract (can be used multiple times).

   * `-Y <filter>`: Applies a display filter.

4. **The Output:** The terminal will print a clean, two-column list of source IPs and the hostnames they accessed, suitable for scripting or direct analysis.

---

## 九 - STATISTICAL ANALYSIS & VISUALIZATION

> Wireshark includes powerful statistical tools that aggregate data from an entire capture file, providing a high-level view of network activity.

### ► **LIVE EXERCISE: Building I/O Graphs**

1. **The Goal:** Visualize the rate of a specific type of traffic over time, which can help identify spikes and anomalies.

2. **The Capture:** Open a pcap file with varied traffic, or capture for a minute.

3. **The Tool:** Go to `Statistics` -> `I/O Graph`.

4. **The Configuration:**

   * The default graph shows all packets/tick.

   * In the filter area for Graph 2, enter `tcp.flags.syn == 1` and enable it. This will graph the rate of new TCP connection attempts.

   * You can change the Y-axis unit from "Packets/Tick" to "Bits/Tick" to see bandwidth usage.

5. **The Insight:** A sudden, massive spike on the SYN graph could indicate a SYN flood DoS attack or a network scan in progress.

---

> This manual provides a foundation. True proficiency comes from continuous, curious application of these techniques to real-world network traffic. The data stream is constant; the opportunities for analysis are endless.
>
> **// END OF LINE //**
