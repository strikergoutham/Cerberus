import math
import shodan
import argparse
import requests
import json
from datetime import date
import os
from dotenv import load_dotenv


load_dotenv()
slack_webhookURL = os.getenv("SLACK_WEBHOOK")
SHODAN_API_KEY = os.getenv("SHODAN_TOKEN")
message1 = "[+]Exposed Instances : "
parser = argparse.ArgumentParser()
parser.add_argument('-s', "--query",
                    help='use this option to search shodan for a particular query(include ssl: else this breaks. ex : "ssl:google.com org:company".')
args = parser.parse_args()

results_page = []
aliveDomains = {}
pages = 0.0
api = shodan.Shodan(SHODAN_API_KEY)

slack_headers = {
'Content-Type': 'application/json'
}

querystring = {
    'key': SHODAN_API_KEY
}
headers = {
    'Accept': 'application/json'
}

today = date.today()
startMsg = "*[+]Cerberus is monitoring for publicly exposed instances/load balancers.... Scan Date :* " + str(today) + "\n"
data = {"text": startMsg}
resp = requests.request(method='POST', url=slack_webhookURL, headers=slack_headers,json=data)

def searchQuery():
    global results_page,pages
    searchQuery = args.query
    if not "ssl:" in searchQuery:
        print("[-] please use ssl: option as part of shodan query")
        exit()

    try:
        results_page = api.search(searchQuery)
        total_res = int(results_page['total'])
        if total_res > 0:
            pages = total_res / 100
            deci, inti = math.modf(pages)
            if deci > 0:
                inti = inti + 1
                inti = int(inti)
        print('Results found: {}'.format(results_page['total']))
        customParseResultSSL(results_page)

        if inti > 1:
            for x in range(2,inti):
                results_page = api.search(searchQuery,page=x)
                customParseResultSSL(results_page)
    except shodan.APIError as e:
        print('Error: {}', format(e))


def customParseResultSSL(results):
    global aliveDomains
    if "ssl:" in args.query:
        if not len(results['matches']) > 0:
            print("No results found for the query.....")
            exit()
        for resultMatch in results['matches']:
            try:
                    if resultMatch['port'] == 3389:
                        keyy = resultMatch['ip_str'] + ":3389"
                        if len(resultMatch['hostnames']) > 0:
                            aliveDomains[keyy] = resultMatch['hostnames'][0]
                        else:
                            aliveDomains[keyy] = "NA"
                        continue
                    if resultMatch['port'] == 25:
                        continue
                    verifyURL = "https://"+ str(resultMatch['ip_str']) + ":" + str(resultMatch['port'])
                    resp = requests.request(method='HEAD', url=verifyURL, verify=False , timeout=3)
                    if 'Server' in resp.headers:
                        if resp.headers["Server"] == 'cloudflare' or resp.headers["Server"] == 'AkamaiGHost':
                            continue
                    keyy = resultMatch['ip_str'] +":"+ str(resultMatch['port'])
                    if len(resultMatch['hostnames']) > 0:
                        aliveDomains[keyy] = resultMatch['hostnames'][0]
                    else:
                        aliveDomains[keyy] = "NA"

            except requests.exceptions.RequestException as e:
                    print('Error: {}', format(e))
                    continue

def parseOutput():
    argsArray = args.query.split(" ")
    for element in argsArray:
        if "ssl:" in element:
            whitelistFile = element.split(":")[1] + "_sslscan_cerberus.json"
        if "ssl:*." in element:
            whitelistFile = element.split(":*.")[1] + "_sslscan_cerberus.json"

    if len(aliveDomains) > 0:
        if not os.path.exists(whitelistFile):
            with open(whitelistFile, 'w') as outfile:
                json.dump(aliveDomains,outfile)
            SendSLackMessage(aliveDomains, message1)
        else:
            with open(whitelistFile, 'r') as fp2:
                exist_list_whitelist = json.load(fp2)
            unique_list = {}
            for key in aliveDomains.keys():
                if not key in exist_list_whitelist:
                    unique_list[key] = aliveDomains[key]
            with open(whitelistFile, 'w') as outfile:
                json.dump(aliveDomains, outfile)
            SendSLackMessage(unique_list, message1)


def SendSLackMessage(result,msgtype):

    if len(result) > 0:
        today = date.today()
        Msg1 = "*"+msgtype+"*"+"\n"
        data = {"text": Msg1}
        resp = requests.request(method='POST', url=slack_webhookURL, headers=slack_headers,json=data)
        for key in result.keys():
            Msg2 = "[+] IP : "+ "*" +key + "*" + " with hostname : " + "*" + result[key] + "*" +" is exposed to internet."
            data2 = {"text": Msg2}
            resp = requests.request(method='POST', url=slack_webhookURL, headers=slack_headers,json=data2)


if __name__ == "__main__":
    searchQuery()
    parseOutput()