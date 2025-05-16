import tkinter as tk
import time
from tkinter import filedialog, scrolledtext, messagebox,ttk
from scapy.all import rdpcap, IP,TCP,UDP,ARP
from collections import Counter

def analyze_pcap(filepaths):
    # allows the protocol numbers to map to the proper protocol 
    protocol_map = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    89: 'OSPF',
    }
     # allows port numbers to map to the proper protocol 
    application_ports_map = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP"
    }


    try:
        packets=[]
        #taking in all the packets from each file to then be analyzed 1 by 1
        for file in filepaths:
            packets+=rdpcap(file)
        total=len(packets)
        initialize_progress(total)
        protocols = Counter()
        application_ports=Counter()
        src_ports=Counter()
        dst_ports=Counter()
        src_ips = Counter()
        dst_ips = Counter()
       
        for pkt in packets:
            
                step_progress()
                if ARP in pkt:
                    protocols["ARP"]+=1
                    src_ips[pkt[ARP].psrc]+=1
                    dst_ips[pkt[ARP].pdst]+=1
                    
                elif IP in pkt:
                    proto_num=(pkt[IP].proto)
                   
                    src_ips[pkt[IP].src]+=1
                    dst_ips[pkt[IP].dst]+=1
                    if TCP in pkt:
                        if pkt[TCP].sport in application_ports_map:
                            application_ports[application_ports_map.get( pkt[TCP].sport)]+=1
                        if pkt[TCP].dport in application_ports_map:
                            application_ports[application_ports_map.get( pkt[TCP].dport)]+=1
                        src_ports[pkt[TCP].sport] += 1
                        dst_ports[pkt[TCP].dport] += 1
                    elif UDP in pkt:
                        if pkt[UDP].sport in application_ports_map:
                            application_ports[application_ports_map.get( pkt[UDP].sport)]+=1
                        if pkt[UDP].dport in application_ports_map:
                            application_ports[application_ports_map.get( pkt[UDP].dport)]+=1
                        src_ports[pkt[UDP].sport] += 1
                        dst_ports[pkt[UDP].dport] += 1
                   
                    protocols[protocol_map.get(proto_num,f'Unknown({proto_num})')]+=1
                
        if packets:
            results = f"Total packets: {total}\n\n"
            results+="Top Protocols\n"
            for proto,count in protocols.most_common(5):
                percentage=round((count/ total)*100,2)
                results += f'\t{proto}: {count} ({percentage}%)\n'
            results+= "\nTop Source IPs\n"
            for src,count in src_ips.most_common(5):
                percentage=round((count/ total)*100,2)
                results += f'\t{src}: {count} ({percentage}%)\n'
            results+= "\nTop Destination IPs\n"
            for dst,count in dst_ips.most_common(5):
                percentage=round((count/ total)*100,2)
                results += f'\t{dst}: {count} ({percentage}%)\n'
            results+="\nTop Source Ports\n"
            for srcP,count in src_ports.most_common(5):
                percentage=round((count/ total)*100,2)
                results+=f'\t{srcP}: {count} ({percentage}%)\n'
            results+="\nTop Destination Ports\n"
            for dstP,count in dst_ports.most_common(5):
                percentage=round((count/ total)*100,2)
                results+=f'\t{dstP}: {count} ({percentage}%)\n'
            results+="\nTop Application Ports\n"
            for ap,count in application_ports.most_common(5):
                percentage=round((count/ total)*100,2)
                results+=f'\t{ap}: {count} ({percentage}%)\n'
            stop_progress()
            return results
        else:
            return "pcap file is empty"
    except Exception as e:
            return f"Error reading file: {e}"

def open_file():
    filepaths = filedialog.askopenfilenames(filetypes=[("PCAP files", "*.pcap")])
    if filepaths:
        result = analyze_pcap(filepaths)
        output_area.config(state='normal')
        output_area.delete("1.0", tk.END)
        output_area.insert(tk.END, result)
        output_area.config(state='disabled')

def save_to_text_file():
    text = output_area.get("1.0", tk.END).strip()
    if text=="":
        messagebox.showinfo("Error", "Nothing to save.")
    else:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if file_path:
        
            try:
                with open(file_path, "w") as f:
                    f.write(text)
                messagebox.showinfo("Success", "File saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
                
def initialize_progress(num_packets): #sets the prograss bar max value so it scales to the number of packets
    progress["maximum"]=num_packets
    
def stop_progress():
    progress.stop()   # Stop animation, reset progress
    
def step_progress():
    progress["value"] +=1 # Increment progress by 1 for each packet
    root.update_idletasks() # Update the GUI to show progress
# GUI Setup
root = tk.Tk()
root.title("PCAP Summary")
root.geometry("700x600")

btn_open = tk.Button(root, text="Open PCAP File(s)", command=open_file)
btn_open.pack(pady=10)
progress=ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")
progress.pack(pady=20)
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=25, state='disabled')
output_area.pack(padx=10, pady=10)
btn_save = tk.Button(root, text="Save Summary to Text File", command=save_to_text_file)
btn_save.pack(pady=5)


root.mainloop()
