import argparse
import os
import sys
from operator import itemgetter


from scapy.layers.dns import DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import *


pkts = PacketList()
def process_pcap2(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0
    konkretne_ip = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        """
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = IP(pkt_data)
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
        """

        ip_pkt = pkt_data[IP]
        if ip_pkt.dst == "147.175.204.125":
            konkretne_ip += 1

        interesting_packet_count += 1

    print('{} contains {} packets ({} interesting) (147.175.204.125 {}-krat)'.
          format(file_name, count, interesting_packet_count, konkretne_ip))


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0
    interesting = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        print(ether_pkt.answers())
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        print(ip_pkt.src)


        if ip_pkt.src == '169.215.167.248':
            print(ip_pkt.src)
            # Uninteresting source IP address
            interesting +=1
            continue

        interesting_packet_count += 1

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting))

def NULL_flood():
    src_ip_list = []
    pocet_syn = 0

    for pkt in pkts:
        flag1 = 1
        flag_dst_zaznam = 1
        if IP in pkt:
            if TCP in pkt:
                tcp_sport = pkt[TCP].sport
                tcp_dport = pkt[TCP].dport
                tcp_flag = pkt[TCP].flags
                tcp_window = pkt[TCP].window
                if tcp_flag == '':
                    pocet_syn +=1
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst

                    #zisti, ci existuju uz nejake zachytene zdrojove IP, hladaj medzi nimi
                    for zaznam in src_ip_list:

                        #nasla sa zhoda
                        if ip_src == zaznam["IP"]:
                            flag1 = 0
                            zaznam['pocet'] += 1

                            #zaznamenaj dst_ip
                            for zaznam_dst in zaznam['destination']:
                                if(ip_dst == zaznam_dst['IP']):
                                    flag_dst_zaznam = 0
                                    zaznam_dst['pocet'] += 1
                                    zaznam['destination'] = sorted(zaznam['destination'], reverse=True, key=lambda d: d['pocet'])

                            #s takouto dst sa este nekomunikovalo
                            if(flag_dst_zaznam):
                                zaznam['destination'].append({'IP': ip_dst, 'pocet': 1})

                    # IP sa vyskytuje 1-krat
                    if (flag1):
                        destination = [{'IP': ip_dst, 'pocet': 1}]
                        zaznam = {'IP': ip_src, 'pocet': 1, 'destination': destination}
                        src_ip_list.append(zaznam)

                    src_ip_list = sorted(src_ip_list, reverse=True, key=lambda d: d['pocet'])


    print('**************** Podozrenie na NULL TCP scan portov ****************')
    print('Počet zachytených TCP_SYN paketov:{}'.format(pocet_syn))
    print('\n')
    print('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov')
    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        print('======================================')
        print('{}. IP: {:20} {} krát'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        print('--------------------------------------')
        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            #print(src_ip_list[i]['destination'][j]['IP'])
            print('Ciel: {:10} \t {} krát'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        print("\n")

def DNS_ANY():
    src_ip_list = []
    pocet_dns = 0
    kl = 1
    for pkt in pkts:
        flag1 = 1
        flag_dst_zaznam = 1
        if IP in pkt:
            if UDP in pkt:
                udp_dport = pkt[UDP].dport

                if udp_dport == 53:
                    pocet_dns +=1
                    if DNSQR in pkt:
                        dns_type = pkt[DNSQR].qtype
                        ip_src = pkt[IP].src
                        ip_dst = pkt[IP].dst

                        if (dns_type == 255):
                            #zisti, ci existuju uz nejake zachytene zdrojove IP, hladaj medzi nimi
                            for zaznam in src_ip_list:
    
                                #nasla sa zhoda
                                if ip_src == zaznam["IP"]:
                                    flag1 = 0
                                    zaznam['pocet'] += 1
    
                                    #zaznamenaj dst_ip
                                    for zaznam_dst in zaznam['destination']:
                                        if(ip_dst == zaznam_dst['IP']):
                                            flag_dst_zaznam = 0
                                            zaznam_dst['pocet'] += 1
                                            zaznam['destination'] = sorted(zaznam['destination'], reverse=True, key=lambda d: d['pocet'])
    
                                    #s takouto dst sa este nekomunikovalo
                                    if(flag_dst_zaznam):
                                        zaznam['destination'].append({'IP': ip_dst, 'pocet': 1})
    
                            # IP sa vyskytuje 1-krat
                            if (flag1):
                                destination = [{'IP': ip_dst, 'pocet': 1}]
                                zaznam = {'IP': ip_src, 'pocet': 1, 'destination': destination}
                                src_ip_list.append(zaznam)
    
                        src_ip_list = sorted(src_ip_list, reverse=True, key=lambda d: d['pocet'])


    print('**************** Podozrenie na NULL TCP scan portov ****************')
    print('Počet zachytených TCP_SYN paketov:{}'.format(pocet_dns))
    print('\n')
    print('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov')
    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        print('======================================')
        print('{}. IP: {:20} {} krát'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        print('--------------------------------------')
        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            #print(src_ip_list[i]['destination'][j]['IP'])
            print('Ciel: {:10} \t {} krát'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        print("\n")


def DNS_WEB():
    query_name = []
    pocet_dns = 0

    for pkt in pkts:
        flag1 = 1
        flag2 = 1
        flag_novy=1
        if IP in pkt:
            if UDP in pkt:
                udp_dport = pkt[UDP].dport
                if udp_dport == 53:
                    if DNSQR in pkt:
                        dns_type = pkt[DNSQR].qtype
                        if (dns_type != 255):
                            pocet_dns += 1
                            dns_name = pkt[DNSQR].qname
                            ip_src = pkt[IP].src
                            ip_dst = pkt[IP].dst

                            #existujuci DNS record
                            for zaznam in query_name:
                                if (zaznam['DNS']==dns_name):
                                    flag_novy = 0
                                #zdrojove IP
                                    # dane DNS dopytovalo uz existujuca IP
                                    for zdrojove_IP in zaznam['S_IP']:
                                        if ip_src == zdrojove_IP['IP']:
                                            flag1 = 0
                                            zdrojove_IP['pocet'] += 1
                                            zaznam['S_IP'] = sorted(zaznam['S_IP'], reverse=True,
                                                                           key=lambda d: d['pocet'])
                                            break

                                    # IP sa vyskytuje 1-krat v danom DND dopyte
                                    if (flag1):
                                        zaznam['S_IP'].append({'IP': ip_src, 'pocet': 1})

                                #cieloveIP
                                    for cielove_IP in zaznam['D_IP']:
                                        if ip_dst == cielove_IP['IP']:
                                            flag2 = 0
                                            cielove_IP['pocet'] += 1
                                            zaznam['D_IP'] = sorted(zaznam['D_IP'], reverse=True,
                                                                    key=lambda d: d['pocet'])
                                            break

                                    # IP sa vyskytuje 1-krat v danom DND dopyte
                                    if (flag2):
                                        zaznam['D_IP'].append({'IP': ip_dst, 'pocet': 1})

                                    break

                            #novy DNS record
                            if (flag_novy):
                                source_IP = [{'IP': ip_src, 'pocet': 1}]
                                destination_IP = [{'IP': ip_dst, 'pocet': 1}]
                                zaznam = {'DNS': dns_name, 'S_IP': source_IP, 'D_IP': destination_IP}
                                query_name.append(zaznam)

    print('**************** Podozrenie na DNS flood ****************')
    print('Počet zachytených DNS paketov:{}'.format(pocet_dns))
    print('\n')

    for zaznam in query_name:
        print('======================================')
        print('Name: {}'.format(zaznam['DNS']))
        print('---------------- 5 najčastejších ----------------')
        for j in range({True: len(zaznam['S_IP']), False: 5}[len(zaznam['S_IP'])<5]):
            print('Zdroj: {:10} \t {} krát'.format(zaznam['S_IP'][j]['IP'], zaznam['S_IP'][j]['pocet']))
        print('---------------- 5 najčastejších ----------------')
        for j in range({True: len(zaznam['D_IP']), False: 5}[len(zaznam['D_IP']) < 5]):
            print('Ciel: {:10} \t {} krát'.format(zaznam['D_IP'][j]['IP'], zaznam['D_IP'][j]['pocet']))
        print("\n")


#icmp.type==8 or icmp.type==0
def ICMP_flood():
    src_ip_list = []
    pocet_icmp = 0

    for pkt in pkts:
        flag1 = 1
        flag_dst_zaznam = 1
        if IP in pkt:
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                if icmp_type == 8 or icmp_type == 0:
                    pocet_icmp +=1
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst

                    #zisti, ci existuju uz nejake zachytene zdrojove IP, hladaj medzi nimi
                    for zaznam in src_ip_list:

                        #nasla sa zhoda
                        if ip_src == zaznam["IP"]:
                            flag1 = 0
                            zaznam['pocet'] += 1

                            #zaznamenaj dst_ip
                            for zaznam_dst in zaznam['destination']:
                                if(ip_dst == zaznam_dst['IP']):
                                    flag_dst_zaznam = 0
                                    zaznam_dst['pocet'] += 1
                                    zaznam['destination'] = sorted(zaznam['destination'], reverse=True, key=lambda d: d['pocet'])

                            #s takouto dst sa este nekomunikovalo
                            if(flag_dst_zaznam):
                                zaznam['destination'].append({'IP': ip_dst, 'pocet': 1})

                    # IP sa vyskytuje 1-krat
                    if (flag1):
                        destination = [{'IP': ip_dst, 'pocet': 1}]
                        zaznam = {'IP': ip_src, 'pocet': 1, 'destination': destination}
                        src_ip_list.append(zaznam)

                    src_ip_list = sorted(src_ip_list, reverse=True, key=lambda d: d['pocet'])


    print('**************** Podozrenie na ICMP scan portov ****************')
    print('Počet zachytených ICMP type 0/8 paketov:{}'.format(pocet_icmp))
    print('\n')
    print('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov')

    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        print('======================================')
        print('{}. IP: {:20} {} krát'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        print('--------------------------------------')

        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            #print(src_ip_list[i]['destination'][j]['IP'])
            print('Ciel: {:10} \t {} krát'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        print("\n")

#tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
def SYN_flood():
    src_ip_list = []
    pocet_syn = 0

    for pkt in pkts:
        flag1 = 1
        flag_dst_zaznam = 1
        if IP in pkt:
            if TCP in pkt:
                tcp_sport = pkt[TCP].sport
                tcp_dport = pkt[TCP].dport
                tcp_flag = pkt[TCP].flags
                tcp_window = pkt[TCP].window
                if tcp_flag == 'S':
                    pocet_syn +=1
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst

                    #zisti, ci existuju uz nejake zachytene zdrojove IP, hladaj medzi nimi
                    for zaznam in src_ip_list:

                        #nasla sa zhoda
                        if ip_src == zaznam["IP"]:
                            flag1 = 0
                            zaznam['pocet'] += 1

                            #zaznamenaj dst_ip
                            for zaznam_dst in zaznam['destination']:
                                if(ip_dst == zaznam_dst['IP']):
                                    flag_dst_zaznam = 0
                                    zaznam_dst['pocet'] += 1
                                    zaznam['destination'] = sorted(zaznam['destination'], reverse=True, key=lambda d: d['pocet'])

                            #s takouto dst sa este nekomunikovalo
                            if(flag_dst_zaznam):
                                zaznam['destination'].append({'IP': ip_dst, 'pocet': 1})

                    # IP sa vyskytuje 1-krat
                    if (flag1):
                        destination = [{'IP': ip_dst, 'pocet': 1}]
                        zaznam = {'IP': ip_src, 'pocet': 1, 'destination': destination}
                        src_ip_list.append(zaznam)

                    src_ip_list = sorted(src_ip_list, reverse=True, key=lambda d: d['pocet'])


    print('**************** Podozrenie na TCP_SYN scan portov ****************')
    print('Počet zachytených TCP_SYN paketov:{}'.format(pocet_syn))
    print('\n')
    print('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov')
    for i in range(5):
        print('======================================')
        print('{}. IP: {:20} {} krát'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        print('--------------------------------------')
        for j in range(5):
            #print(src_ip_list[i]['destination'][j]['IP'])
            print('Ciel: {:10} \t {} krát'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        print("\n")

def print_summary():
    counter = 0
    pocet=0

    for pkt in pkts:
        if IP in pkt:
            counter += 1
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst

            print(pkt[IP].dst)
            print (counter)
            if (pkt[IP].dst == "147.175.204.138"):
                pocet+=1
        if TCP in pkt:
            tcp_sport=pkt[TCP].sport
            tcp_dport=pkt[TCP].dport


            #print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
            #print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))

            # you can filter with something like that
    print("pocet .138 = ", pocet)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    pkts = rdpcap(file_name)
    #print_summary()
    #SYN_flood()
    #ICMP_flood()
    #NULL_flood()
    #DNS_ANY()
    DNS_WEB()
    # or it possible to filter with filter parameter...!
    #process_pcap(file_name)
    sys.exit(0)