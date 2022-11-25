import json
import requests

from typing import Tuple, Union

from os import getenv
from boefjes.job_models import BoefjeMeta


def run(boefje_meta: BoefjeMeta) -> Tuple[BoefjeMeta, Union[bytes, str]]:

    #HTTPProxyPorts = ['80','8080','8880','2052','2082','2086','2095']
    #HTTPSProxyPorts =['443','2053','2083','2087','2096','8443']
    HTTPProxyPorts = ['80']
    HTTPSProxyPorts =['443']
    # You may request a free API key from Cloudflare and use that in the Authorization for running the python script locally.
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + getenv("CLOUDFLARE_API")
    }

    response = requests.get('https://api.cloudflare.com/client/v4/zones/', headers=headers)

    for zone in response.json()['result']:
        print('Zone:'+ zone['name'])
        params = {
        'type': 'A,CNAME',
        'name': zone['name'],
        'page': '1',
        'per_page': '100',
        'order': 'type',
        'direction': 'desc',
        'match': 'all',
        }

        response2 = requests.get('https://api.cloudflare.com/client/v4/zones/' + zone['id'] + '/dns_records', params={} , headers=headers)

        for record in response2.json()['result']:
            print(record['name']+' type:'+record['type']+' Proxied:'+format(record['proxied'])+' Origin:'+record['content'])
            if record['proxied']:
                ProxiedHTTPPorts={}
                ProxiedHTTPSPorts={}
                brokenproxy=True
                for HTTPPort in HTTPProxyPorts:
                    response3 = requests.get('http://'+record['name']+':' + HTTPPort)
                    ProxiedHTTPPorts['+HTTPPort+']=response3.status_code
                    if(ProxiedHTTPPorts['+HTTPPort+'] < 500): brokenproxy=False
                for HTTPSPort in HTTPSProxyPorts:
                    response3 = requests.get('https://'+record['name']+':' + HTTPSPort)
                    ProxiedHTTPSPorts['+HTTPSPort+']=response3.status_code
                    if(ProxiedHTTPSPorts['+HTTPSPort+'] < 500): brokenproxy=False
                print('broken proxy:'+ format(brokenproxy))
                if (brokenproxy==False):
                    for HTTPPort in HTTPProxyPorts:
                        response3 = requests.get('http://'+record['name']+':' + HTTPPort, params={}, headers= {'Host': record['name']}, verify=False)
                        if(ProxiedHTTPPorts['+HTTPPort+']==response3.status_code):
                            print('Cloudflare proxy port '+HTTPPort+' vulnerable for Cloudflare bypass' )
                    for HTTPSPort in HTTPSProxyPorts:
                        response3 = requests.get('https://'+record['name']+':' + HTTPSPort, params={}, headers= {'Host': record['name']}, verify=False)
                        if(ProxiedHTTPSPorts['+HTTPSPort+']==response3.status_code):
                            print('Cloudflare proxy port '+HTTPSPort+' vulnerable for Cloudflare bypass' )

    # bogus example data for 'boefje' setup
    data = [{
        "id": "some-id"
        "broken": false
        "bypassed": true
    }]
    return boefje_meta, json.dumps(data)
