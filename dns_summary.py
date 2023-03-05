import sqlite3
import csv
import requests
import json
import datetime
import time

# creating database and setting up connection with the database
con = sqlite3.connect('dns2.db')
cur = con.cursor()

def dns_summary():
    cur.execute("""SELECT qry_domain FROM dns_queries GROUP BY qry_domain""")
    domain_result = cur.fetchall()
    final_result = []
    for domain in domain_result:
        domain_dict = {
            "domain": domain[0]
        }
        sub_domain = "SELECT count(id) FROM dns_queries WHERE qry_domain='" + domain[0] + "'"
        cur.execute(sub_domain)
        sub_domain_count = cur.fetchall()
        domain_dict['sub_domain_count'] = sub_domain_count[0]
        txt_request_type = "SELECT count(id) FROM dns_queries WHERE qry_request_type = 16 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(txt_request_type)
        txt_request_type_count = cur.fetchall()
        domain_dict['txt_request_type_count'] = txt_request_type_count[0]
        txt_response_type = "SELECT count(id) FROM dns_queries WHERE qry_response_type = 16 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(txt_response_type)
        txt_response_type_count = cur.fetchall()
        domain_dict['txt_response_type_count'] = txt_response_type_count[0]
        cname_request_type = "SELECT count(id) FROM dns_queries WHERE qry_request_type = 5 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(cname_request_type)
        cname_request_type_count = cur.fetchall()
        domain_dict['cname_request_type_count'] = cname_request_type_count[0]
        cname_response_type = "SELECT count(id) FROM dns_queries WHERE qry_response_type = 5 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(cname_response_type)
        cname_response_type_count = cur.fetchall()
        domain_dict['cname_response_type_count'] = cname_response_type_count[0]
        null_request_type = "SELECT count(id) FROM dns_queries WHERE qry_request_type = 10 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(null_request_type)
        null_request_type_count = cur.fetchall()
        domain_dict['null_request_type_count'] = null_request_type_count[0]
        null_response_type = "SELECT count(id) FROM dns_queries WHERE qry_response_type = 10 AND qry_domain='" + domain[
            0] + "'"
        cur.execute(null_response_type)
        null_response_type_count = cur.fetchall()
        domain_dict['null_response_type_count'] = null_response_type_count[0]
        lengths = "SELECT SUM(captured_length), SUM(qry_name_length) FROM dns_queries WHERE qry_domain='" + domain[
            0] + "'"
        cur.execute(lengths)
        sum_of_lengths = cur.fetchall()
        domain_dict['packet_length'] = sum_of_lengths[0][0]
        domain_dict['query_length'] = sum_of_lengths[0][1]
        status_qry = "SELECT domain FROM domain_analysis where domain='" + domain[0] + "'"
        cur.execute(status_qry)
        status = cur.fetchone()
        if not status:
            domain_dict['status'] = "Normal"
        else:
            domain_dict['status'] = "Suspecious"
        final_result.append(domain_dict)
    with open('DNS_Summary.csv', 'w') as f:
        writer = csv.writer(f, delimiter='\t')
        for line in final_result:
            writer.writerow([line["domain"], line["sub_domain_count"][0], line["txt_request_type_count"][0],
                             line["txt_response_type_count"][0], line["cname_request_type_count"][0],
                             line["cname_response_type_count"][0], line["null_request_type_count"][0],
                             line["null_response_type_count"][0], line["packet_length"], line["query_length"],
                             line["status"]])


def sub_domain_summary(domain):
    sub_domain = "SELECT qry_name FROM dns_queries WHERE qry_domain='" + domain + "'"
    cur.execute(sub_domain)
    sub_domain_result = cur.fetchall()
    with open('Sub_Domain_Summary.csv', 'w') as f:
        writer = csv.writer(f, delimiter='\t')
        for line in sub_domain_result:
            writer.writerow([line[0]])

def domain_analysis_summary():
    cur.execute("""SELECT * FROM domain_analysis""")
    results = cur.fetchall()
    with open('Suspecious_Domains.csv', 'w') as f:
        writer = csv.writer(f, delimiter='\t')
        for line in results:
            writer.writerow(list(line))


def check_domain_api(domain, api_key="3845ae0956c6747b865579ef26df781526871a857cfdc8cca001e6554ff8bbda"):
    url = 'https://www.virustotal.com/api/v3/domains/' + str(domain)
    params = {'x-apikey': api_key}
    response = requests.get(url, headers=params)
    stats = json.loads(response.content).get('data').get('attributes').get('last_analysis_stats')
    creation_date = json.loads(response.content).get('data').get('attributes').get('creation_date')
    creation_date = datetime.datetime.fromtimestamp(creation_date)
    print([domain, stats.get('harmless'), stats.get('malicious'), stats.get('suspicious'), stats.get('suspicious'), creation_date])
    #with open('text.csv', 'w') as f:
        #writer = csv.writer(f, delimiter='\t')
        #writer.writerow([domain, stats.get('harmless'), stats.get('malicious'), stats.get('suspicious'), stats.get('suspicious'), creation_date])
    #time.sleep(15)


print("                                                                          ")
print("    ____  _   _______     _____                                           ")
print("   / __ \/ | / / ___/    / ___/__  ______ ___  ____ ___  ____ ________  __")
print("  / / / /  |/ /\__ \     \__ \/ / / / __ `__ \/ __ `__ \/ __ `/ ___/ / / /")
print(" / /_/ / /|  /___/ /    ___/ / /_/ / / / / / / / / / / / /_/ / /  / /_/ / ")
print("/_____/_/ |_//____/____/____/\__,_/_/ /_/ /_/_/ /_/ /_/\__,_/_/   \__, /  ")
print("                 /_____/                                         /____/   ")
print("                                                                          ")
print("Please input the number")
print("1 => DNS Summary")
print("2 => Get Sub Domains")
print("3 => Check Domain")
print("4 => Suspicious Domain Summary")
print("Please input the number")

number = input("Input the Number :")
if number == str(1):
    dns_summary()
elif number == str(2):
    domain = input("Please enter the domain :")
    sub_domain_summary(domain)
elif number == str(3):
    domain = input("Please enter the domain :")
    check_domain_api(domain)


elif number == str(4):
    domain_analysis_summary()
else:
    print("Wrong Input")




