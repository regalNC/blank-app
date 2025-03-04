from scapy.all import rdpcap
import pandas as pd
import re
import streamlit as st
#from streamlit_autorefresh import st_autorefresh



#st_autorefresh(interval=1 * 1000, key="dataframerefresh")

def extract_pcap_info(pcap_file):
    # Read packets from the PCAP file

    ips_src   = []
    ips_dst   = []
    ports_src = []
    ports_dst = []
    fnames    = []
    pkt_nums  =[]

    packets = rdpcap(pcap_file)

    # Iterate through packets and extract relevant information
    st.write(f"Total number of frames in PCAP: {len(packets)}")

    incr_val = 0
    for i, packet in enumerate(packets):
        # if i%incr == 0:
        #     incr_val += 1
        #     if incr_val <= 100:
        #         pbar.progress(incr_val, text="Operation in progress")

        # IP layer
        if packet.haslayer("IP"):
            ip = packet.getlayer("IP")
            ipsrc = ip.src
            ipdst = ip.dst

        # TCP layer
        if packet.haslayer("TCP"):
            tcp = packet.getlayer("TCP")
            payload = bytes(tcp.payload)
            payload_text = payload.decode("utf-8", errors="ignore")
            #if re.search(r"(GET|POST|HTTP/1\.[01])", payload_text):
            if re.search(r"(^GET\s|^POST\s|^PUT\s)", payload_text):
                print(f"Packet {i + 1}:")
                header = payload_text.split("\n")[0]
                print(header[0:200])
                pkt_nums.append(i+1)
                ips_src.append(ipsrc)
                ips_dst.append(ipdst)
                ports_src.append(tcp.sport)
                ports_dst.append(tcp.dport)
                file_name = header.split()[1]
                if "/" in file_name:
                    fnames.append(payload_text.split()[1].split("/")[-1])
                else:
                    fnames.append(payload_text.split()[1])

                print(f" IP src: {ipsrc}")
                print(f" IP dst: {ipdst}")
                print(f" Source Port: {tcp.sport}")
                print(f" Destination Port: {tcp.dport}")
                print()

    data = {'pkt #': pkt_nums,'malware': fnames, 'ip src':ips_src, 'ip dst':ips_dst,
            'src port':ports_src, 'dst port':ports_dst}

    # Create DataFrame
    df = pd.DataFrame(data)
    return(df)

st.header("Malware Viewer")

uploaded_file = st.file_uploader("Choose a PCAP file with malware sent over HTTP")

if uploaded_file is not None:
    # To read file as bytes:

    #progress_text = "Operation in progress. Please wait."
    #pb = st.empty()
    #pb.progress(0, text="Operation in progress")
    #pbar = st.progress(10, text="Operation in progress")

    # Can be used wherever a "file-like" object is accepted:
    with st.spinner("Please wait..."):
        df = extract_pcap_info(uploaded_file)

    #dataframe = pd.read_csv(uploaded_file)
    st.write(df)

# Specify the path to your PCAP file
#pcap_file_path = "C:\\Users\\rgallant\\Downloads\\Slot1Port0Hostnp1-0.1740006002237.pcap"
#df = extract_pcap_info(pcap_file_path)
#print(df)
