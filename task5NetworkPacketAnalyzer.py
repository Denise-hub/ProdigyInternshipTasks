import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, conf
from scapy.layers.inet import IP
import threading


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x400")

        # Creating a table to display packets
        self.tree = ttk.Treeview(root, columns=("Source", "Destination", "Protocol", "Length"), show="headings")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.column("Source", width=200)
        self.tree.column("Destination", width=200)
        self.tree.column("Protocol", width=100)
        self.tree.column("Length", width=100)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Start/Stop buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=20, pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=20, pady=10)

        # Packet sniffing flag
        self.sniffing = False

        # Packet filtering
        self.filter_protocol = "ip"  # Filter IP packets by default

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        messagebox.showinfo("Packet Sniffer", "Sniffing Stopped!")

    def sniff_packets(self):
        try:
            sniff(
                filter=self.filter_protocol,
                prn=self.process_packet,
                stop_filter=self.stop_sniffing_condition,
                store=False
            )
        except Exception as e:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            messagebox.showerror("Error", str(e))

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = packet.sprintf("%IP.proto%")
            # Inserting into the table on the GUI
            self.tree.insert("", tk.END, values=(ip_layer.src, ip_layer.dst, protocol, len(packet)))

    def stop_sniffing_condition(self, packet):
        return not self.sniffing


# Main Application
if __name__ == "__main__":
    # Ensuring Scapy uses the correct configuration for Windows
    conf.use_pcap = True

    root = tk.Tk()
    app = PacketSnifferApp(root)

    # Adding on_closing handler
    def on_closing():
        if app.sniffing:
            app.stop_sniffing()
        root.destroy()

    # Binding the window close event
    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()
