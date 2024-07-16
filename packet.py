import pyshark
import pyshark.tshark.tshark

# List all available network interfaces using tshark
def list_interfaces():
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    for index, interface in enumerate(interfaces):
        print(f"{index}: {interface}")
    return interfaces

# Select a network interface from available interfaces
def select_interface(interfaces):
    while True:
        try:
            choice = int(input("Select the interface number to capture packets from: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("Please enter a valid interface number.")
        except ValueError:
            print("Please enter a numerical value.")

# Get the number of packets to capture
def get_packet_count():
    while True:
        try:
            count = int(input("Enter the number of packets to capture: "))
            if count > 0:
                return count
            else:
                print("The number must be positive.")
        except ValueError:
            print("Please enter a numerical value.")

def main():
    # List available interfaces and let the user select one
    interfaces = list_interfaces()
    selected_interface = select_interface(interfaces)
    count = get_packet_count()
    print(f"Selected interface: {selected_interface}")
    print(f"Number of packets to capture: {count}")

    # Capture packets from specific interface
    capture = pyshark.LiveCapture(interface=selected_interface, output_file='./packets.pcapng')
    capture.sniff(packet_count=count)

    # Print details of captured packets
    for packet in capture:
        try:
            print(f"Packet Number: {packet.number}")
            print(f"Timestamp: {packet.sniff_time}")
            print(f"Source: {packet.ip.src}")
            print(f"Destination: {packet.ip.dst}")
            print(f"Protocol: {packet.highest_layer}")
            print(f"Length: {packet.length}")
            print("Packet Layers:")
            for layer in packet.layers:
                print(f"Layer: {layer.layer_name}")
                print(layer)
                print("=" * 50)
            print("=" * 50)
        except AttributeError:
            print("Non-IP packet captured.")
            print(f"Packet: {packet}")
            print("=" * 50)

if __name__ == "__main__":
    main()