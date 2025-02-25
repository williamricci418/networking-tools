# #### IP Traffic Capture and Analysis

from scapy.all import sniff, IP, TCP, UDP
import socket
import requests
import pandas as pd
import csv

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisLookupError
import ipaddress

from datetime import datetime
import argparse
import os

## Other OS/Windows Requirements
# 1. nmap
# 2. npcap

def f_get_current_datetime_formatted():
    # Get the current date and time
    current_datetime = datetime.today()

    # Format it to show date, hour, minutes, and seconds
    formatted_datetime = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
    
    # Return value
    return formatted_datetime

def f_process_packet(packet):
    # Ensure that the packet contains IP data to avoid errors
    # Function to process packets
    if IP in packet:
        packet_info = {
            'source_ip': packet[IP].src,
            'dest_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'length': packet[IP].len
        }
        # Check for TCP protocol
        if TCP in packet:
            packet_info['source_port'] = packet[TCP].sport
            packet_info['dest_port'] = packet[TCP].dport
        # Check for UDP protocol
        elif UDP in packet:
            packet_info['source_port'] = packet[UDP].sport
            packet_info['dest_port'] = packet[UDP].dport
        return packet_info
    else:
        return None

def f_get_local_ip():
    # Get the hostname of the machine
    hostname = socket.gethostname()
    # Get the IP address using the hostname
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def f_get_public_ip():
    response = requests.get('https://httpbin.org/ip')
    public_ip = response.json()['origin']
    return public_ip

def f_get_hostname():

    # Get the hostname
    l_hostname = socket.gethostname()

    # Get the FQDN
    l_fqdn = socket.getfqdn()

    return l_hostname, l_fqdn

def f_write_packets_to_file(l_data_frame, l_file_name):    
    l_data_frame.to_csv(l_file_name, quoting=csv.QUOTE_ALL, quotechar='"', index=False)
    return 1

def f_process_packets(l_data_frame, l_exclude_destination):
    # Dictionary to store IP to FQDN mapping
    l_ip_mapping = {}
    
    # Dictionary to store IP Whois detail
    l_df_ip_whois = pd.DataFrame(columns=['ip', 'asn_description', 'network_type', 'network_name'])
    
    # Remove known and good destinations
    filtered_df = l_data_frame[~l_data_frame['dest_ip'].isin(l_exclude_destination)]
    
    # Create a list of IPs from the destination
    l_dest_list = filtered_df['dest_ip'].unique().tolist()
        
    # Attempt a reverse lookup on the IP
    for ip in l_dest_list:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if (ip_obj.is_private):
                # Skip
                print('MESSAGE -',f_get_current_datetime_formatted(),'Skipping Private IP:', ip)
            else:
                ip_fqdn = socket.gethostbyaddr(ip)[0]
                l_ip_mapping[ip] = ip_fqdn
        except socket.herror as e:
            print('MESSAGE -',f_get_current_datetime_formatted(),ip," - Error: ", e)
        
    # Update df with the FQDN as new column
    filtered_df_final = filtered_df.copy()
    filtered_df_final['fqdn'] = filtered_df['dest_ip'].map(l_ip_mapping)
    ##filtered_df.loc[:, 'fqdn'] = filtered_df['dest_ip'].map(l_ip_mapping)
    ###filtered_df.loc[:, 'fqdn'] = filtered_df['dest_ip'].apply(lambda ip: l_ip_mapping.get(ip))
    
    # Attempt an IP Whois on the IP
    for ip in l_dest_list:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if (ip_obj.is_private):
                # Skip
                print('MESSAGE -',f_get_current_datetime_formatted(), 'Skipping Private IP:', ip)
            else:
                obj = IPWhois(ip)
                result = obj.lookup_rdap()
            
                # Append to dataframe
                new_row = pd.DataFrame([{
                    'ip': ip,
                    'asn_description': result['asn_description'],
                    'network_type': result['network']['type'],
                    'network_name': result['network']['name']
                }])
                l_df_ip_whois = pd.concat([l_df_ip_whois, new_row], ignore_index = True)
        
        except IPDefinedError:
            print('MESSAGE -',f_get_current_datetime_formatted(),f"IP {ip} is a reserved or private address.")
        except WhoisLookupError:
            print('MESSAGE -',f_get_current_datetime_formatted(),f"Whois lookup failed for IP {ip}.")
        except Exception as e:
            print('MESSAGE -',f_get_current_datetime_formatted(),f"An unexpected error occurred for IP {ip}: {e}")
        
    merged_df = filtered_df_final.merge(l_df_ip_whois, left_on='dest_ip', right_on='ip', how='left')
        
    return merged_df

def f_start_capture(l_capture_unit, l_capture_length):
    if (l_capture_unit == 'count'):
        packets = sniff(filter="ip", count=l_capture_length)
    elif (l_capture_unit == 'timeout'):
        packets = sniff(filter="ip", timeout=l_capture_length)

    # Process Packets
    packet_data = [f_process_packet(packet) for packet in packets if packet is not None]

    return packet_data

def main():
    """
    Network Traffic Capture and Analysis
    ------------------------------------
    
    Required Paramters:
     --unit - String with value of "timeout" or "count".
     --length - Integer for Number packets to capture or number of seconds.
    """
    
    # Parse Commandline Arguments
    parser = argparse.ArgumentParser(description="Capture and analyze network traffic.")
    parser.add_argument("--unit", type=str, help="Value of timeout or count.")
    parser.add_argument("--length", type=int, help="Number packets to capture or nnumber of seconds.")
    
    args = parser.parse_args()
    
    capture_unit = args.unit
    capture_length = args.length

    if (not capture_length) + (not capture_unit):
        # Missing required parameters
        print(main.__doc__)
        l_status = 0
    else:
        l_status = 1
        # Get current date and time
        l_curr_date = datetime.today()
    
        formatted_date = l_curr_date.strftime('%Y-%m-%d_%H-%M-%S')

        # Get Local IP
        l_local_ip = f_get_local_ip()
        # Get Public IP
        l_public_ip = f_get_public_ip()
        # Get Hostname
        l_hostname, l_fqdn_1 = f_get_hostname()
                            
        if ('.' in l_fqdn_1):
            l_domain = l_fqdn_1.split('.', 1)[1]
        else:
            l_domain = 'unknown'
        
        l_fqdn_2 = l_local_ip + '.' + l_domain
        l_fqdn_3 = l_public_ip + '.' + l_domain

        # Build Exclude Destination List
        l_exclude_destination = []
        l_exclude_destination.append(l_local_ip)
        l_exclude_destination.append(l_public_ip)
        l_exclude_destination.append(l_fqdn_1)
        l_exclude_destination.append(l_fqdn_2)
        l_exclude_destination.append(l_fqdn_3)
        l_exclude_destination.append('168.63.129.16')
        l_exclude_destination.append('169.254.169.254')
        l_exclude_destination.append('255.255.255.255')
        l_exclude_destination.append('0.0.0.0')

        print('MESSAGE -',f_get_current_datetime_formatted(), 'Local IP: ', l_local_ip)
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Public IP: ', l_public_ip)    
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Hostname: ', l_hostname)
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Domain: ', l_domain)
        print('MESSAGE -',f_get_current_datetime_formatted(), 'FQDN 1: ', l_fqdn_1)
        print('MESSAGE -',f_get_current_datetime_formatted(), 'FQDN 2: ', l_fqdn_2)
        print('MESSAGE -',f_get_current_datetime_formatted(), 'FQDN 3: ', l_fqdn_3)

        # Print Start Date Time
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Traffic Capture Start')

        # Capture current traffic
        packet_data = f_start_capture(l_capture_unit=capture_unit, l_capture_length=capture_length)

        # Print End Date Time
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Traffic Capture End')

        # Load the processed data into a DataFrame
        df = pd.DataFrame(packet_data)
    
        # Change each column to type string
        df = df.astype(str)

        # Create file name
        l_file_to_save = 'IP-Capture-List_' + l_hostname + '_' + formatted_date + '_Raw-Data.txt'
        full_path1 = os.path.join("results", l_file_to_save)
    
        # Write Raw Data string to Text file
        f_write_packets_to_file(l_data_frame=df, l_file_name=full_path1)
    
        print('MESSAGE -',f_get_current_datetime_formatted(),'Raw Results written to: ', full_path1)
    
        # Print End Date Time
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Process Traffic Data Start')

        df_updated = f_process_packets(l_data_frame=df, l_exclude_destination=l_exclude_destination)
    
        # Print End Date Time
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Process Traffic Data End')

        # Create file name
        l_file_to_save = 'IP-Capture-List_' + l_hostname + '_' + formatted_date + '_Processed-Data.txt'
        full_path2 = os.path.join("results", l_file_to_save)
    
        # Write Processed Data string to Text file
        f_write_packets_to_file(l_data_frame=df_updated, l_file_name=full_path2)

        print('MESSAGE -',f_get_current_datetime_formatted(),'Processed Results written to: ', full_path2)

    if (l_status == 0):
        print('MESSAGE -',f_get_current_datetime_formatted(), 'Missing required parameters.')
        return 0
    else:
        return 1

if __name__ == "__main__":
    main()