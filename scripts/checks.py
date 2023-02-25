import sys
from time import sleep
import vt
import requests
from utilities import Cache
import json
from OTXv2 import OTXv2

from OTXv2 import IndicatorTypes

cache=Cache()

def check_hash_bazaar(hash):
    """Checks a hash agains the Malware Bazaar Database"""
    cached=cache.get('mb', hash)
    if True: #cached is None:
        url="https://mb-api.abuse.ch/api/v1/"
        r = requests.post(url, data={'query':'get_info', 'hash':hash})
        if (r.status_code==404):
            cached={
                'is_known': 0,
            }
        elif (r.status_code==200):
            res=r.json()
            if res["query_status"]=="hash_not_found":
                cached={
                    'is_known': 0,
                }
            elif res["query_status"]=="ok":
                cached={
                    'is_known': 1,
                    'extra': res
                }
        cache.set('mb', hash, cached)
    return cached

def capev2_check(hash, cape_url):
    cape_api_url=cape_url+'/apiv2'
    r = requests.get(cape_api_url+'/tasks/search/md5/'+hash)
    if (r.status_code==404):
        print("\nSomething failed communicating with CAPE")
        return None
    else:
        tasks=r.json()['data']
        if len(tasks)==0:
            return False
        res={
            'score': 0,
            'detections': []
        }
        print("CAPEv2 findings for "+hash+":")
        for task in tasks:
            cape_api_url+'/tasks/get/report/'+str(task['id'])
            if task['status']=="reported":
                q = requests.get(cape_api_url+'/tasks/get/report/'+str(task['id']))
                if (q.status_code==200):
                    report=q.json()
                    print('\t target:'+task['target']+' ['+task['category']+'] score: '+str(report['malscore'])+"/10 -> "+cape_url+'/analysis/'+str(task['id'])+'/')
                    res['score']=res['score']+report['malscore']
                    if 'detections' in report:
                        res['detections'].append(report['detections'])
            elif task['status']=="running" or task['status']=="reporting" or task['status']=="pending":
                return True
        res['score']=res['score']/len(tasks)
        return res

def capev2_upload(file, cape_api_url):
    with open(file, 'rb') as f:
        r = requests.post(cape_api_url+'/tasks/create/file/', files={'file': f}) #, data={'tags': ''} # tags only used to select vm
        if (r.status_code==404):
            print("\nSomething failed communicating with CAPE")
            return -1    
        else:
            rd=r.json()
            if 'error' in rd:
                if rd['error']:
                    print("\t"+rd['error_value'])
                    return -1
            task_info=rd['data']
            id=task_info['task_ids'][0]
            print("\t"+task_info['message'])

clamav_db={}
clamav_set=set()
def clamav_load():
    """Loads the ClamAV md5 hash database"""
    with open("main.hdb") as f:
        for line in f:
            fields=line.split(':') #To remove the New Line
            clamav_db[fields[0]]={
                'name': fields[2]
            }
            clamav_set.add(fields[0])
    print("ClamAV MD5 db loaded")
 
def check_hash_clamav(hash: str):
    """Checks a hash against the ClamAV md5 hash database"""
    if (hash in clamav_set):
        return clamav_db[hash]
    else:
        return None

def check_hash_circllu(hash):
    """Checks a hash against de circl.lu known files database"""
    cached=cache.get('circllu', hash)
    if cached is None:
        url="https://hashlookup.circl.lu/lookup/md5/%s" % (hash)
        r = requests.get(url)
        if (r.status_code==404):
            cached={
                'is_known': 0,
            }
        elif (r.status_code==200):
            res=r.json()
            cached={
                'is_known': 1,
                'extra': res
            }
        cache.set('circllu', hash, cached)
    return cached

def check_hash_ms(hash: str, MS_API: str):
    cached=cache.get('ms', hash)
    if cached is None:
        url="https://malshare.com/api.php?api_key=%s&action=details&hash=%s" % (MS_API, hash)
        r = requests.post(url)
        res=r.json()
        if len(res)>0:
            if 'ERROR' in res:
                if res['ERROR']['CODE']==404:
                    cached={
                        'is_malware': 0,
                        'extra': res
                    }
                else:
                    print("UO")
            else:
                cached={
                    'is_malware': 1,
                    'extra': res
                }
        else:
            cached={
                'is_malware': 0
            }
        cache.set('ms', hash, cached)
    return cached

def check_hash_vt(hash: str, VT_API: str):
    """Receives a hash and returns an object with the result"""
    cached=cache.get('vt', hash)
    if cached is None:
        client = vt.Client(VT_API)
        file = client.get_object("/files/"+hash)
        if (file.last_analysis_stats['undetected']+file.last_analysis_stats['harmless'])>0:
            is_virus=(file.last_analysis_stats['malicious']+file.last_analysis_stats['suspicious'])/(file.last_analysis_stats['undetected']+file.last_analysis_stats['harmless'])
        else:
            is_virus=(file.last_analysis_stats['malicious']+file.last_analysis_stats['suspicious'])
        cached={
            'is_malware': is_virus>1,
            'extra': {
                'undetected': file.last_analysis_stats['undetected'],
                'malicious': file.last_analysis_stats['malicious'],
                'suspicious': file.last_analysis_stats['suspicious'],
                'harmless': file.last_analysis_stats['harmless'],
            }
        }
        print(hash, cached)
        cache.set('vt', hash, cached)
        sleep(15) #TODO: implementar throttling de verdad
    return cached

def check_hash_alienvault(hash: str, key: str):
    """Receives a hash and returns an object with the result"""
    cached=cache.get('alienvault', hash)
    if cached is None:
        otx = OTXv2(key)
        result=file(otx, hash)
        if len(result) > 0:
            print('Identified as potentially malicious')
            #print(str(result))
            cached={
                'is_malware': 1
            }
        else:
            #print('Unknown or not identified as malicious')
            cached={
                'is_malware': 0
            }
        cache.set('alienvault', hash, cached)
        #sleep(15) #TODO: implementar throttling de verdad
    return cached

# https://github.com/AlienVault-OTX/OTX-Python-SDK/
# Get a nested key from a dict, without having to do loads of ifs
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return 

# https://github.com/AlienVault-OTX/OTX-Python-SDK/
def file(otx, hash):
    alerts = []

    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1

    result = otx.get_indicator_details_full(hash_type, hash)

    avg = getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
    if avg:
        alerts.append({'avg': avg})

    clamav = getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
    if clamav:
        alerts.append({'clamav': clamav})

    avast = getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
    if avast:
        alerts.append({'avast': avast})

    microsoft = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
    if microsoft:
        alerts.append({'microsoft': microsoft})

    symantec = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
    if symantec:
        alerts.append({'symantec': symantec})

    kaspersky = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
    if kaspersky:
        alerts.append({'kaspersky': kaspersky})

    suricata = getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
    if suricata and 'trojan' in str(suricata).lower():
        alerts.append({'suricata': suricata})

    return alerts

def check_hashes_mhr(hashes: set):
    """Receives a set of hashes to check and returns a list of objects with the results"""
    data=""
    for hash in hashes:
        if cache.get('mhr', hash) is None:
            data=data+hash+"\r\n"

    if data!="":
        session = requests.session()
        response=session.get('https://hash.cymru.com/', verify=False).text
        a=response.rfind('token')
        b=response.find("'",a+1)
        c=response.find("'",b+1)
        token=response[b+1:c]
        headers = {
            "authorization": "Basic "+token, 
        }
        session.headers.update(headers)
        response = session.post('https://hash.cymru.com/v2/submitHashes', data=data, verify=False)
        rjson=json.loads(response.text)
        if 'queries_remaining' in rjson:
            print(str(rjson['queries_remaining'])+" remaining queries at MHR")
        if 'results' in rjson:
            if rjson['results'] is not None:
                for i in rjson['results']:
                    cache.set('mhr', i['hash'], i)
    res={}
    for hash in hashes:
        data=cache.get('mhr', hash)
        if data['antivirus_detection_rate'] is None:
            data['antivirus_detection_rate']=0
        res[hash]={
            'is_malware': data['antivirus_detection_rate']>0,
            'extra': data
        }
    return res