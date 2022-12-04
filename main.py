import argparse

from scapy.layers.dns import DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import *


pkts = PacketList()

def NULL_flood(three):
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


    three.write('**************** Podozrenie na NULL TCP scan portov ****************\n')
    three.write('Počet zachytených TCP_SYN paketov:{}\n'.format(pocet_syn))
    three.write('\n')
    three.write('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov\n')
    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        three.write('======================================\n')
        three.write('{}. IP: {:20} {} krát\n'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        three.write('--------------------------------------\n')
        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            #print(src_ip_list[i]['destination'][j]['IP'])
            three.write('Ciel: {:10} \t {} krát\n'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        three.write("\n")

def DNS_ANY(four):
    src_ip_list = []
    pocet_dns = 0

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


    four.write('**************** Podozrenie na DNS_ANY útok ****************\n')
    four.write('Počet zachytených DNS_ANY paketov:{}\n'.format(pocet_dns))
    four.write('\n')
    four.write('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov\n')
    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        four.write('======================================\n')
        four.write('{}. IP: {:20} {} krát\n'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        four.write('--------------------------------------\n')
        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            #print(src_ip_list[i]['destination'][j]['IP'])
            four.write('Ciel: {:10} \t {} krát\n'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        four.write("\n")


def DNS_WEB(five):
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
                            dns_name=dns_name.decode("utf-8")
                            dns_name = dns_name[:-1]
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

    five.write('**************** Podozrenie na DNS flood ****************\n')
    five.write('Počet zachytených DNS paketov:{}\n'.format(pocet_dns))
    five.write('\n')

    for zaznam in query_name:
        five.write('======================================\n')
        five.write('Name: {}\n'.format(zaznam['DNS']))
        five.write('---------------- 5 najčastejších ----------------\n')
        for j in range({True: len(zaznam['S_IP']), False: 5}[len(zaznam['S_IP'])<5]):
            five.write('Zdroj: {:10} \t {} krát\n'.format(zaznam['S_IP'][j]['IP'], zaznam['S_IP'][j]['pocet']))
        five.write('---------------- 5 najčastejších ----------------\n')
        for j in range({True: len(zaznam['D_IP']), False: 5}[len(zaznam['D_IP']) < 5]):
            five.write('Ciel: {:10} \t {} krát\n'.format(zaznam['D_IP'][j]['IP'], zaznam['D_IP'][j]['pocet']))
        five.write("\n")


#icmp.type==8 or icmp.type==0
def ICMP_flood(two):
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


    two.write('**************** Podozrenie na ICMP scan portov ****************\n')
    two.write('Počet zachytených ICMP type 0/8 paketov:{}\n'.format(pocet_icmp))
    two.write('\n')
    two.write('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov\n')

    for i in range({True: len(src_ip_list), False: 5}[len(src_ip_list)<5]):
        two.write('======================================\n')
        two.write('{}. IP: {:20} {} krát\n'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        two.write('--------------------------------------\n')

        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination'])<5]):
            two.write('Ciel: {:10} \t {} krát\n'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        two.write("\n")

#tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
def SYN_flood(one):
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


    one.write('**************** Podozrenie na TCP_SYN scan portov ****************\n')
    one.write('Počet zachytených TCP_SYN paketov:{}\n'.format(pocet_syn))
    one.write('\n')
    one.write('Najaktívnejších 5 zdrojových IP a ich 5 najčastejších cieľov\n')
    i=0
    print(pocet_syn)
    for i in range({True: len(src_ip_list[i]['IP']), False: 5}[len(src_ip_list[i]['IP']) < 5]):
        one.write('======================================\n')
        one.write('{}. IP: {:20} {} krát\n'.format(i+1, src_ip_list[i]['IP'], src_ip_list[i]['pocet']))
        one.write('--------------------------------------\n')
        for j in range({True: len(src_ip_list[i]['destination']), False: 5}[len(src_ip_list[i]['destination']) < 5]):
            one.write('Ciel: {:10} \t {} krát\n'.format(src_ip_list[i]['destination'][j]['IP'], src_ip_list[i]['destination'][j]['pocet']))
        one.write("\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    one = open("SYN_FLOOD.txt", "w")
    two = open("ICMP_SWEEP.txt", "w")
    three = open("NULL_FLOOD.txt", "w")
    four = open("DNS_ANY.txt", "w")
    five = open("DNS_WEB.txt", "w")
    if not os.path.isfile(file_name):
        print('"{}" does not exist\n'.format(file_name), file=sys.stderr)
        sys.exit(-1)


    pkts = rdpcap(file_name)
    SYN_flood(one)
    ICMP_flood(two)
    NULL_flood(three)
    DNS_ANY(four)
    DNS_WEB(five)
    sys.exit(0)