import time
import requests
import re
from checks import capev2_check, check_hash_alienvault, check_hash_clamav, check_hash_ms, check_hashes_mhr, check_hash_vt, clamav_load, capev2_upload, check_hash_circllu, check_hash_bazaar
from utilities import list_compare, md5_list, exec, body_parse, mount_image, unmount_image
import argparse
from pymisp import PyMISP


# Create venv:
#   python3 -m venv ./
# Needed packages:
#   python -m pip install vt-py
#   python -m pip install requests
#   python -m pip install pymisp
#   python -m pip install OTXv2

parser = argparse.ArgumentParser(description='Parses two body files and analyzes the hashes of the files that differ.\r\nBy default this script caches online services data.')
parser.add_argument("-c","--clean",      help="Clean body file (by default clean.body)", default='clean.body')
parser.add_argument("-p","--clean-path", help="Clean body file path (by default /mnt/windows01)", default='/mnt/windows01')
parser.add_argument("-d","--dirty",      help="Dirty body file (by default dirty.body)", default='dirty.body')
parser.add_argument("-q","--dirty-path", help="Dirty body file path (by default /mnt/windows02)", default='/mnt/windows02')

parser.add_argument("-n","--limit",      help="Limit the number of file to check", default=1000, type=int)
parser.add_argument("-s","--show",            help="Show the files that differ", action='store_true')
parser.add_argument("-x","--show-extensions", help="Show a list of extensions detected", action='store_true')

parser.add_argument("-e","--filter-extension", help="Filter only this extensions (by default only 'exe' and 'dll' files are used)", default=['exe', 'dll'], action='append')
parser.add_argument("-t","--filter-paths", help="Filter this paths (you can use regular expresions)",action='append')

parser.add_argument("-v","--virustotal",        help="Use VirusTotal, include your api token --vt XXXXXXX", default=None)
parser.add_argument("-l","--clamav",            help="Use ClamAV HASHES database (main.hdb must be in root path, only hashes are checked!)", default=False)
parser.add_argument("-m","--malshare",          help="Use Malshare, include you api token --malshare XXXXX", default=None)
parser.add_argument("-r","--mhr",               help="Use Malware Hash Registry", action='store_true')
parser.add_argument("-g","--circllu",           help="Use Circl.lu registry", action='store_true')
parser.add_argument("-f","--malware-bazaar",    help="Use Malware Bazaar registry", action='store_true')
parser.add_argument("-o","--alienvault",        help="Check Alienvault (include api token --alienvault XXXX)", default=None)


parser.add_argument("-i","--dirty-image",      help="Path to the dirty image", default=None)
parser.add_argument("-z","--scan",             help="Scan with ClamAV", action='store_true')

parser.add_argument("-a","--capev2",      help="Check the files against a capev2 sandbox (insert end point --capev2 XXXXX)", default=None)
parser.add_argument("-b","--capev2-upload",      help="Whether to send the files to the capev2 sandbox", action='store_true')

parser.add_argument("-j","--misp",      help="Check the files against a Misp instance (insert end point --misp XXXXX)", default=None)
parser.add_argument("-k","--misp-key",      help="Misp api key (--misp-key XXXXX)", default=None)

args = parser.parse_args()

MOUNT_PATH="/tmp/dirty"
if args.dirty_image is not None:
    mount_image(args.dirty_image)

interesting_extensions=set(args.filter_extension)
print("Enabled extensions: "+str(interesting_extensions))

# Load the file lists
t1=time.time()
print("Loading clean file list...")
files_clean=body_parse(args.clean, args.clean_path, None)
md5_list_clean=md5_list(files_clean)
t2=time.time()-t1
print(("Loaded "+str(len(md5_list_clean))+" files in {:02.2f} seconds").format(t2))

t1=time.time()
print("Loading dirty file list...")
files_dirty=body_parse(args.dirty, args.dirty_path, None)
md5_list_dirty=md5_list(files_dirty)
t2=time.time()-t1
print(("Loaded "+str(len(md5_list_dirty))+" in {:02.2f} seconds").format(t2))

# Compare between lists
files_difference=list_compare(md5_list_dirty, md5_list_clean)
print("There are " + str(len(files_difference)) + " different files")


if (args.show_extensions):
    extension_set=set()
    for file_md5 in files_difference:
        extension=files_dirty[file_md5]['extension'].lower()
        extension_set.add(extension)
    print("The following extensions where detected: "+str(extension_set))

if (args.filter_extension is not None):
    print("Filtering out by extensions...")
    cleanup_set=set()
    for file_md5 in files_difference:
        extension=files_dirty[file_md5]['extension'].lower()
        if (extension not in interesting_extensions):
            cleanup_set.add(file_md5)
    print("\tRemoving "+str(len(cleanup_set))+" elements")
    for e in cleanup_set:
        files_difference.remove(e)

if (args.filter_paths is not None):
    exclude_paths=args.filter_paths
    print("Cleaning by path...")
    for path in exclude_paths:
        print("\tPath filter: "+path)
        cleanup_set=set()
        pattern = re.compile(path)
        for file_md5 in files_difference:
            if pattern.match(files_dirty[file_md5]['path']):
                cleanup_set.add(file_md5)
        print("\t\tRemoving "+str(len(cleanup_set))+" elements")
        for e in cleanup_set:
            files_difference.remove(e)

print(str(len(files_difference)) + " different files after filtering")

if len(files_difference)>args.limit:
    print("Too many files (>"+str(args.limit)+"), filter out more or increase the limit with --limit")
    quit()

detected={}
for file_md5 in files_difference:
    detected[file_md5]=[]

if args.virustotal is not None or args.clamav is not None or args.malshare is not None:
    if args.clamav:
        clamav_load()
    for file_md5 in files_difference:
        file=files_dirty[file_md5]['path']+files_dirty[file_md5]['filename']
        if args.virustotal:
            res=check_hash_vt(file_md5, args.virustotal)
            if (res['is_malware']):   
                print("VT detected malware in "+file_md5+" "+file)
                detected[file_md5].append('vt')
        if args.alienvault:
            res=check_hash_alienvault(file_md5, args.alienvault)
            if (res['is_malware']):   
                print("Alienvault detected malware in "+file_md5+" "+file)
                detected[file_md5].append('alienvault')    
        if args.malshare:
            res=check_hash_ms(file_md5, args.malshare)
            if (res['is_malware']):   
                print("MS detected malware in "+file_md5+" "+file)
                detected[file_md5].append('malshare')
        if args.clamav:
            res=check_hash_clamav(file_md5)
            if (res is not None):   
                print("ClamAV detected malware in "+file_md5+" "+file)
                detected[file_md5].append('clamav_hash')
        if args.malware_bazaar:
            res=check_hash_bazaar(file_md5)
            if (res['is_known']):
                print("Malware Bazaar detected malware in "+file_md5+" "+file+" -> https://bazaar.abuse.ch/browse.php?search=md5%3"+file_md5)
                detected[file_md5].append('bazaar_hash')
        if args.circllu:
            res=check_hash_circllu(file_md5)
            if (res['is_known']):
                if files_dirty[file_md5]['filename']==res['extra']['FileName']:
                    filenames="filename is correct"
                else:
                    filenames="filenames are different: "+res['extra']['FileName']
                if res['extra']['hashlookup:trust']>50:
                    detected[file_md5].append('circllu_safe')
                    print(files_dirty[file_md5]['filename']+ " ("+file_md5+") circl.lu have this file in its database marked as safe (should be:"++")")
                elif res['extra']['hashlookup:trust']<50:
                    print(files_dirty[file_md5]['filename']+ " ("+file_md5+") circl.lu have this file in its database marked as possibly unsafe ("+filenames+")")
                    detected[file_md5].append('circllu_unsafe')
                elif res['extra']['hashlookup:trust']==50:
                    print(files_dirty[file_md5]['filename']+ " ("+file_md5+") circl.lu have this file in its database but doesn't know if its safe ("+filenames+")")
                    detected[file_md5].append('circllu_known')

if args.mhr:
    res=check_hashes_mhr(files_difference)
    for file_md5 in files_difference:
        if (res[file_md5]['is_malware']):
            file=files_dirty[file_md5]['path']+files_dirty[file_md5]['filename']
            print("MHR detected malware in "+file_md5+" "+file)
            detected[file_md5].append('mhr')

if args.show:
    for file_md5 in files_difference:
        file=files_dirty[file_md5]['path']+files_dirty[file_md5]['filename']
        print(file_md5+"\t"+file)

if args.scan:
    print("Scanning files with ClamAV...")
    # Better to check all of them at once because of the time it takes clamav to load its database
    file_list=""
    for file_md5 in files_difference:
        file=MOUNT_PATH+(files_dirty[file_md5]['path']+files_dirty[file_md5]['filename']).replace(" ", "\ ").replace("(", "\(").replace(")", "\)")
        file_list=file_list+file+" "
    r=exec("clamscan --no-summary "+file_list)
    results=r.stdout.read().decode().split("\n")
    files={}
    for file_md5 in files_difference:
        file=MOUNT_PATH+(files_dirty[file_md5]['path']+files_dirty[file_md5]['filename'])
        files[file]=file_md5
    for result in results:
        res=result.split(": ")
        if res[0] in files:
            if (res[1]!='OK'):
                file_md5=files[res[0]]
                file=(files_dirty[file_md5]['path']+files_dirty[file_md5]['filename'])
                print("ClamAV detected malware in "+file_md5+" -> "+file)
                detected[file_md5].append('clamav_scan')
                detected.add(file_md5)
            #print(res[0]+" -> "+res[1])
        else:
            print(res[0])

if args.capev2 is not None:
    for file_md5 in files_difference:
        r=capev2_check(file_md5, args.capev2)
        file=MOUNT_PATH+(files_dirty[file_md5]['path']+files_dirty[file_md5]['filename'])
        if r is None or r is False:
            if args.capev2_upload:
                print("Uploading task to CAPEv2")
                #capev2_upload(file, args.capev2)
        elif r is True:
            print(file_md5+ " The file exists in CAPEv2 but its processing, check again later.")
            #print(file_md5+ " There was some error sending the file to Capev2")
        elif 'score' in r:
            if (len(r['detections'])>0):
                print("CAPEv2 detected: "+str(r['detections'])+" in this file and gave it an score of "+str(r['score'])+"/10 so its possibly malware "+file_md5+" -> "+file)
                detected[file_md5].append('capev2_detections')
            elif (r['score']>3):
                print("CAPEv2 gave this file an score of "+str(r['score'])+"/10 so its possibly malware "+file_md5+" -> "+file)
                detected[file_md5].append('capev2_maybe')
            

if args.misp is not None:
    requests.packages.urllib3.disable_warnings() # Don't Try This at Home
    misp=PyMISP(args.misp, args.misp_key, False, 'json')
    for file_md5 in files_difference:
        result = misp.search('events', return_format='json', type='md5', value=file_md5)
        if len(result)>0:
            print("MISP findings:")
            for e in result:
                print('\t{} url: {}{}{}\n'.format(e['Event']['info'], args.misp, '/events/view/', e['Event']['id']))
            detected[file_md5].append('misp')

print("\n\nSummary of detections:")
for file_md5 in detected:
    if len(detected[file_md5])>0:
        print(file_md5+" ", (files_dirty[file_md5]['path']+files_dirty[file_md5]['filename']))
        for d in detected[file_md5]:
            print("\t"+d)

if args.dirty_image is not None:
    unmount_image(args.dirty_image)