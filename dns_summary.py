#!/usr/bin/python3

import sqlite3
import csv
import requests
import json
import datetime
import time
import configparser
import os


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

def generate_systemd_file():

    cwd = os.getcwd()
    mainfile = cwd+"/" +  str("main.py")
    service = "/usr/bin/python3" + " " + mainfile

    config = configparser.RawConfigParser()
    config.optionxform = str



    config.add_section("Unit")
    config.set("Unit", "Description", "DNS Capture")
    config.set("Unit", "After", "multi-user.target")

    config.add_section("Service")
    config.set("Service", "Type", "simple")
    config.set("Service", "Restart", "always")
    config.set("Service", "ExecStart", service)


    config.add_section("Install")
    config.set("Install", "WantedBy", "multi-user.target")

    with open("/etc/systemd/system/DNS-capture.service", 'w') as example:
        config.write(example)
    
    systemd_daemon_reload_cmd = "systemctl daemon-reload"
    os.system(systemd_daemon_reload_cmd)
    service_enable_cmd = "systemctl enable --now DNS-capture.service"
    os.system(service_enable_cmd)


print("                                                                          ")
print("    ____  _   _______     _____                                           ")
print("   / __ \/ | / / ___/    / ___/__  ______ ___  ____ ___  ____ ________  __")
print("  / / / /  |/ /\__ \     \__ \/ / / / __ `__ \/ __ `__ \/ __ `/ ___/ / / /")
print(" / /_/ / /|  /___/ /    ___/ / /_/ / / / / / / / / / / / /_/ / /  / /_/ / ")
print("/_____/_/ |_//____/____/____/\__,_/_/ /_/ /_/_/ /_/ /_/\__,_/_/   \__, /  ")
print("                 /_____/                                         /____/   ")
print("                                                                          ")
print(" ")
print("1 => Enable DNS capture as a service (Linux only)")
print("2 => DNS Summary")
print("3 => Get Sub Domains")
print("4 => Check Domain")
print("5 => Suspicious Domain Summary")
print("6 => Exit")
print(" ")

while True:
    try:
        number = input("Input the Number :")
    except ValueError:
        print("Sorry, I didn't understand that.")
        continue

    cwd = os.getcwd()
    dns_sum = cwd+ "/" +  str("DNS_Summary.csv")

    if number == str(1):
        try:
            generate_systemd_file()
            print("DNS-Capture started as a Service.")
        except PermissionError:
            print("You don't seem to have the rights to do that")
        continue
    elif number == str(2):
        dns_summary()
        print("DNS activity summary file generated ")
        consent_view = input("Do you want to preview? \n 1) Yes \n 2) No  ")
        if consent_view == str(1):
            with open(dns_sum, 'r') as f:
                print(f.read())
        else:
            continue
    elif number == str(3):
        domain = input("Please enter the domain :")
        sub_domain_summary(domain)
        print("Domain summary file genarated")
        continue
    elif number == str(4):
        domain = input("Please enter the domain :")
        check_domain_api(domain)
        continue
    elif number == str(5):
        domain_analysis_summary()
        print("Suspecious domains summary file generated")
        continue
    elif number == str(6):
        print("Exiting")
        break


