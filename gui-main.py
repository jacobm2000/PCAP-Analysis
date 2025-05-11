import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from scapy.all import rdpcap, IP,TCP,UDP,ARP
from collections import Counter

def analyze_pcap(filepath):
    # allows the protocol numbers to map to the proper protocol in which they coorelate with
    protocol_map = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    89: 'OSPF',
}

    try:
        
        packets = rdpcap(filepath)
        total = len(packets)
        protocols = Counter()
        src_ports=Counter()
        dst_ports=Counter()
        src_ips = Counter()
        dst_ips = Counter()
        for pkt in packets:
            if ARP in pkt:
                protocols["ARP"]+=1
                src_ips[pkt[ARP].psrc]+=1
                dst_ips[pkt[ARP].pdst]+=1
    
            elif IP in pkt:
                src_ips[pkt[IP].src]+=1
                dst_ips[pkt[IP].dst]+=1
                if TCP in pkt:
                    src_ports[pkt[TCP].sport] += 1
                    dst_ports[pkt[TCP].dport] += 1
                elif UDP in pkt:
                    src_ports[pkt[UDP].sport] += 1
                    dst_ports[pkt[UDP].dport] += 1
                proto_num=(pkt[IP].proto)
                protocols[protocol_map.get(proto_num,f'Unknown({proto_num})')]+=1
                
        if packets:
            results = f"Total packets: {total}\n\n"
            results+="Top Protocols\n"
            for proto,count in protocols.most_common(5):
                results += f'{proto}: {count}\n'
            results+= "\nTop Source IPs\n"
            for src,count in src_ips.most_common(5):
                results += f'{src}: {count}\n'
            results+= "\nTop Destination IPs\n"
            for dst,count in dst_ips.most_common(5):
                results += f'{dst}: {count}\n'
            results+="\nTop Source Ports\n"
            for srcP,count in src_ports.most_common(5):
                results+=f'{srcP}: {count}\n'
            results+="\nTop Destination Ports\n"
            for dstP,count in dst_ports.most_common(5):
                results+=f'{dstP}: {count}\n'
            return results
        else:
            return "pcap file is empty"
    except Exception as e:
            return f"Error reading file: {e}"

def open_file():
    filepath = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if filepath:
        result = analyze_pcap(filepath)
        output_area.config(state='normal')
        output_area.delete("1.0", tk.END)
        output_area.insert(tk.END, result)
        output_area.config(state='disabled')

# GUI Setup
root = tk.Tk()
root.title("Basic PCAP Analyzer")
root.geometry("700x500")

btn_open = tk.Button(root, text="Open PCAP File", command=open_file)
btn_open.pack(pady=10)

output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=25, state='disabled')
output_area.pack(padx=10, pady=10)

root.mainloop()
