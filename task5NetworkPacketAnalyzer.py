import tkinter as tk  # Importing tkinter for GUI creation
from tkinter import ttk, messagebox  # Importing additional tkinter modules for treeview and dialogs
from scapy.all import sniff, conf  # Importing sniffing functionality from Scapy
from scapy.layers.inet import IP  # Importing the IP layer to process IP packets
import threading  # Importing threading to run sniffing in the background

# Class definition for the Packet Sniffer Application
class PacketSnifferApp:
    def __init__(self, root):
        """
        Initializes the Packet Sniffer application.
        Sets up the GUI components and initializes packet-sniffing settings.
        """
        self.root = root
        self.root.title("Network Packet Analyzer")  # Title of the application window
        self.root.geometry("900x400")  # Setting the initial window size

        # Setting up a Treeview widget to display packet details in a table format
        self.tree = ttk.Treeview(
            root,
            columns=("Source", "Destination", "Protocol", "Length", "Payload"),
            show="headings"  # Ensures only column headings are shown
        )
        self.tree.heading("Source", text="Source IP")  # Column for source IP address
        self.tree.heading("Destination", text="Destination IP")  # Column for destination IP address
        self.tree.heading("Protocol", text="Protocol")  # Column for protocol type (e.g., TCP, UDP)
        self.tree.heading("Length", text="Length")  # Column for the length of the packet
        self.tree.heading("Payload", text="Payload")  # Column for the packet's data content (payload)

        # Adjusting the column widths for better readability
        self.tree.column("Source", width=200)
        self.tree.column("Destination", width=200)
        self.tree.column("Protocol", width=100)
        self.tree.column("Length", width=100)
        self.tree.column("Payload", width=250)

        # Adding the Treeview to the main window
        self.tree.pack(fill=tk.BOTH, expand=True)  # Ensures it fills the window and resizes dynamically

        # Adding the Start Sniffing button
        self.start_button = tk.Button(
            root, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white"
        )
        self.start_button.pack(side=tk.LEFT, padx=20, pady=10)  # Placing it to the left side

        # Adding the Stop Sniffing button (disabled by default)
        self.stop_button = tk.Button(
            root, text="Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.RIGHT, padx=20, pady=10)  # Placing it to the right side

        # Variable to track whether sniffing is active
        self.sniffing = False

        # Default protocol filter (only IP packets are processed)
        self.filter_protocol = "ip"

    def start_sniffing(self):
        """
        Starts the packet sniffing process.
        This function disables the Start button and enables the Stop button.
        """
        self.sniffing = True  # Mark sniffing as active
        self.start_button.config(state=tk.DISABLED)  # Disable the Start button to prevent multiple clicks
        self.stop_button.config(state=tk.NORMAL)  # Enable the Stop button

        # Run sniffing in a separate thread to keep the GUI responsive
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        """
        Stops the packet sniffing process.
        This function enables the Start button and disables the Stop button.
        """
        self.sniffing = False  # Mark sniffing as inactive
        self.start_button.config(state=tk.NORMAL)  # Enable the Start button
        self.stop_button.config(state=tk.DISABLED)  # Disable the Stop button
        messagebox.showinfo("Packet Sniffer", "Sniffing Stopped!")  # Notify the user

    def sniff_packets(self):
        """
        Captures packets using Scapy's sniff function.
        Filters packets based on the specified protocol and processes each captured packet.
        """
        try:
            sniff(
                filter=self.filter_protocol,  # Apply protocol filter (default is IP)
                prn=self.process_packet,  # Callback to process each packet
                stop_filter=self.stop_sniffing_condition,  # Stop sniffing condition
                store=False  # Do not store packets in memory
            )
        except Exception as e:
            # Handle errors gracefully
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            messagebox.showerror("Error", str(e))  # Show error message

    def process_packet(self, packet):
        """
        Processes each captured packet and extracts relevant details.
        Populates the Treeview with the packet's source, destination, protocol, length, and payload.
        """
        if IP in packet:  # Check if the packet contains an IP layer
            ip_layer = packet[IP]  # Extract the IP layer
            protocol = packet.sprintf("%IP.proto%")  # Get the protocol type (e.g., TCP, UDP)
            payload = bytes(packet[IP].payload).decode(
                "utf-8", errors="replace"
            )  # Decode the payload, replacing invalid characters

            # Insert the packet details into the Treeview
            self.tree.insert(
                "",
                tk.END,
                values=(ip_layer.src, ip_layer.dst, protocol, len(packet), payload),
            )

    def stop_sniffing_condition(self, packet):
        """
        Condition to determine when to stop sniffing.
        Returns True if sniffing is marked as inactive.
        """
        return not self.sniffing


# Main Application Code
if __name__ == "__main__":
    # Enable Scapy compatibility for Windows (if running on Windows OS)
    conf.use_pcap = True

    # Initialize the main Tkinter window
    root = tk.Tk()
    app = PacketSnifferApp(root)

    # Function to handle the application window being closed
    def on_closing():
        """
        Handles the window close event.
        Ensures sniffing is stopped before exiting the application.
        """
        if app.sniffing:
            app.stop_sniffing()  # Stop sniffing if active
        root.destroy()  # Close the application

    # Bind the window close event to the on_closing function
    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Start the Tkinter event loop
    root.mainloop()
