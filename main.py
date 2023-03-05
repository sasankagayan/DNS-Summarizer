from scapy.all import *
from datetime import datetime
import requests, json
import datetime
import sys
import sqlite3
import base64

# creating database and setting up connection with the database
con = sqlite3.connect('dns2.db')
cur = con.cursor()

# creates the tables dns_queries if does not exist
cur.execute("""SELECT name FROM sqlite_master WHERE name='dns_queries'""")
results = cur.fetchone()
# Primary key should be query_name**********************
if results:
    pass
else:
    cur.execute('''CREATE TABLE dns_queries(
        id INTEGER PRIMARY KEY, 
        qry_id varchar(255),
        captured_length int,
        qry_name varchar(255),
        qry_domain varchar(255),
        qry_name_length int,
        qry_request_type int,
        qry_response_type int,
        qry_response varchar(255)      
    )''')

cur.execute("""SELECT name FROM sqlite_master WHERE name='domain_analysis'""")
results_2 = cur.fetchone()
# Primary key should be query_name**********************
if results_2:
    pass
else:
    cur.execute('''CREATE TABLE domain_analysis(
        id INTEGER PRIMARY KEY, 
        domain varchar(255),
        harmless int,
        malicious int,
        suspicious int,
        undetected int,
        creation_date DATETIME 
    )''')

############# MODIFY THIS PART IF NECESSARY ###############
interface = 'ens33'
filter_bpf = 'udp and port 53'

def check_domain_api(address, api_key="3845ae0956c6747b865579ef26df781526871a857cfdc8cca001e6554ff8bbda"):
    address = address[-2:]
    address = '.'.join(address)
    url = 'https://www.virustotal.com/api/v3/domains/' + str(address)
    params = {'x-apikey': api_key}
    response = requests.get(url, headers=params)
    stats = json.loads(response.content).get('data').get('attributes').get('last_analysis_stats')
    creation_date = json.loads(response.content).get('data').get('attributes').get('creation_date')
    creation_date = datetime.datetime.fromtimestamp(creation_date)
    sql = "SELECT domain FROM domain_analysis where domain='" + address + "'"
    cur.execute(sql)
    results = cur.fetchone()
    if not results:
        cur.execute("""INSERT INTO domain_analysis(domain, harmless, malicious, suspicious, undetected, creation_date) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')"""
        % (address, stats.get('harmless'), stats.get('malicious'), stats.get('suspicious'), stats.get('suspicious'), creation_date))
        con.commit()
    time.sleep(15)

# ------ SELECT/FILTER MSGS
def select_DNS(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    try:
        if DNSQR in pkt and pkt.dport == 53:
            qname_1 = (pkt.getlayer(DNS).qd.qname).decode()
            sql_1 = "SELECT * FROM dns_queries where qry_name='" + qname_1 + "'"
            cur.execute(sql_1)
            results_1 = cur.fetchone()
            x_split_list = qname_1.rstrip(qname_1[-1]).split(".")
            domain = x_split_list[-2:]
            domain = '.'.join(domain)
            if not results_1:
                cur.execute(
                """INSERT INTO dns_queries(qry_id, captured_length, qry_name, qry_name_length, qry_request_type, qry_domain) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')"""
                % (pkt[DNS].id, pkt.len, qname_1, len(qname_1), pkt.getlayer(DNS).qd.qtype, domain))
                con.commit()
            f = open("dns_signature_key_list.txt", "r")
            if int(pkt.len) >= 300:
                print("Limit Exceeded")
                check_domain_api(x_split_list)
            available_signatures_normal = []
            available_signatures_b64 = []
            available_signatures_b32 = []
            # x_split_list = "ssh.MRXHGMTUMNYAU===.ZG5zMnRjcAo=".split(".")
            for x in f:
                x = x.rstrip("\n")
                if x in qname_1:
                    available_signatures_normal.append(x)
                    check_domain_api(x_split_list)
                for item in x_split_list:
                    # Base64
                    for i in range(5):
                        try:
                            if i == 0:
                                item_b64 = base64.b64decode(item)
                            else:
                                item_b64 = base64.b64decode(str(item) + "=")
                            item_b64 = item_b64.decode()
                            item_b64 = item_b64.rstrip("\n")
                            if item_b64 == x:
                                available_signatures_b64.append(x)
                                check_domain_api(x_split_list)
                        except:
                            pass
                    # Base32
                    for i in range(5):
                        try:
                            if i == 0:
                                item_b32 = base64.b32decode(item)
                            else:
                                item_b32 = base64.b32decode(str(item) + "=")
                            item_b32 = item_b32.decode()
                            item_b32 = item_b32.rstrip("\n")
                            if item_b32 == x:
                                available_signatures_b32.append(x)
                                check_domain_api(x_split_list)
                        except:
                            pass
            print(list(dict.fromkeys(available_signatures_normal)))
            print(list(dict.fromkeys(available_signatures_b64)))
            print(list(dict.fromkeys(available_signatures_b32)))
            print(str("===================================="))


        elif DNSRR in pkt and pkt.sport == 53:
            cur.execute(
            """SELECT id FROM dns_queries WHERE qry_id=%s"""
            % (pkt[DNS].id))
            results = cur.fetchone()
            if results:
                rdata = pkt[DNSRR].rdata
                if type(rdata) != str:
                    rdata = pkt[DNSRR].rdata.decode()
                update_query = "UPDATE dns_queries SET qry_response_type = " + str(pkt.getlayer(DNS).qd.qtype) + ",qry_response = '" + str(rdata) + "' WHERE id = " + str(results[0])
                con.execute(update_query)
                print("***********")



 #
    except Exception as e:
        print("Exception" + str(e))
# ------ START SNIFFER
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)



