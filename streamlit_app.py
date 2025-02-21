from scapy.all import rdpcap
import pandas as pd
import re
import streamlit as st

st.write("Start") 


st.header("Malware expander")

uploaded_file = st.file_uploader("Choose a file")

if uploaded_file is not None:
    # To read file as bytes
    
    # Can be used wherever a "file-like" object is accepted:
    df = extract_pcap_info(uploaded_file)

    #dataframe = pd.read_csv(uploaded_file)
    st.write(df)

# Specify the path to your PCAP file
#pcap_file_path = "C:\\Users\\rgallant\\Downloads\\Slot1Port0Hostnp1-0.1740006002237.pcap"
#df = extract_pcap_info(pcap_file_path)
#print(df)
