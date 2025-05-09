import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from scapy.all import rdpcap, IP,ARP
from collections import Counter

def analyze_pcap(filepath):
    # allows the protocol numbers to map to the proper protcol in which they coorelate with
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
        src_ips = Counter()
        dst_ips = Counter()
        for pkt in packets:
            if ARP in pkt:
                protocols["ARP"]+=1
                results = f"Total packets: {total}\n\n"
            elif IP in pkt:
                protocols[protocol_map.get(pkt[IP].proto)]+=1
                results = f"Total packets: {total}\n\n"
        for proto,count in protocols.most_common(5):
            results += f'{proto}: {count}\n'
        return results
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
