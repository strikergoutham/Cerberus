# Cerberus
Cerberus is an auto monitoring script which monitors for any cloud assets of a company grouped via common ssl cert used, which might have been exposed over the internet.It uses Shodan API internally to monitor/query company infra.

This is a quick hack script if you are someone who monitors for cloudassets of any company scraped by shodan and want to get notified via slack periodically.

## Features :

> Monitors for cloud assets grouped via common ssl cert.

> Reduced noise: Weeds out non accessible / outdated results , sites protected behind cloudflare and akamai 

> Capability to monitor/notify delta(new) results periodically.

> Integration with slack. 

## Setup :

### Prerequisites :

>> Requires Python 3.

>> Runs on both Windows / Linux .

>> install dependencies :
```bash
pip3 install shodan

pip3 install -U python-dotenv
```
### update .env file with slack webhook url and shodan API token.

#### Now you are ready to run Cerberus! Set it up as cron job for real time monitoring or run it as a standalone script. 

Example Usage : 
```bash
python3 cerberus.py -s "ssl:*.paypal.com org:paypal"
```
#### Initial scan is full scan, subsequent scans are delta scans( only unique results are notified via slack).
      >> Results are stored in the format *_sslscan_cerberus.json for different query(ssl)
      
#### Snapshot of test results:
![Cerberus](/ScreenShots/cerberus.PNG)

