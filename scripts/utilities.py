import pickle
import os
import subprocess

def body_parse(file, absolute_path, limit=10):
    """ This function returns a list of dicts with each file in the body file """
    files_object={}
    with open(file) as f:
        lines=0
        for line in f:
            fields=line[0:len(line)-1].split('|') #To remove the New Line
            if fields[0]=='' or fields[0]==None or fields[0]=='0': # Remove empty lines and directories
                continue
            last_bar_pos=fields[1].rfind('/')+1
            filename=None
            extension=None
            if (last_bar_pos!=-1):
                filename=fields[1][last_bar_pos:]
                last_dot_pos=filename.rfind('.')+1
                extension=filename[last_dot_pos:]
                path=fields[1][len(absolute_path):last_bar_pos]
            else:
                path=fields[1][len(absolute_path):]
            file_obj={
                'md5': fields[0],
                'filename':filename,
                'extension':extension,
                'path': path,
                'size': int(fields[6]),
                'atime': float(fields[7]),
                'mtime': float(fields[8]),
                'ctime': float(fields[9]),
                'crtime': float(fields[10]),
            }
            files_object[file_obj['md5']]=file_obj
            if limit!=None and lines>limit:
                break
            lines=lines+1
    f.close()
    return files_object

def exec(cmd):
    process = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    process.wait()
    return process

def md5_list(file_list):
    md5_=set()
    i=0
    for file in file_list:
        md5_.add(file_list[file]['md5'])
        i=i+1
    return md5_

def list_compare(a, b):
    r=set()
    for e in a:
        if e not in b:
            r.add(e)
    return r

CACHE_FILE="data_cache"

class Cache:
    def __init__(self):
        self.cache={}
        self.load()

    def get(self, service, hash):
        if service in self.cache:
            if hash in self.cache[service]:
                return self.cache[service][hash]
            else:
                return None
        else:
            print("Service not recognized ["+service+"]")
            return None

    def set(self, service, hash, res):
        if service not in self.cache:
            self.cache[service]={}
        self.cache[service][hash]=res
        self.save()

    def save(self):
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(self.cache, f)

    def load(self):
        if (os.path.exists(CACHE_FILE)):
            f=open(CACHE_FILE, 'rb')
            self.cache=pickle.load(f)
            f.close()

MOUNT_PATH="/tmp/dirty"
def unmount_image(dirty_image):
    p=exec("sudo umount "+MOUNT_PATH+"") # Check if mount path is used
    p=exec("sudo umount "+MOUNT_PATH+"image") # Check if mount path is used
    print("\tDone!")
    print("Unmounting dirty image...")

def mount_image(dirty_image):
    # TODO: Custom mount points
    print("Mounting dirty image...")
    p=exec("sudo ls") # Check that the tools we need are installed
    if (p.returncode!=0):
        print("\tWe need sudo privileges to mount the image.")
        quit()
    p=exec("ewfmount -h") # Check that the tools we need are installed
    if (p.returncode!=0):
        print("\tCheck that ewf-tools is installed.")
        quit()
    p=exec("mount | grep \""+MOUNT_PATH+"image\" ") # Check if mount path is used
    if (p.returncode==0):
        print("\tWe have something mounted on "+MOUNT_PATH+"image, lets try to unmount it")
        p=exec("sudo umount "+MOUNT_PATH+"") # Check if mount path is used
        if (p.returncode!=0):
            print("\tSomething failed, please unmount "+MOUNT_PATH+" and delete the mount point.")
            quit()
        p=exec("sudo umount "+MOUNT_PATH+"image") # Check if mount path is used
        print("\tDone!")
    #TODO: Do this with python functions...
    p=exec("ls "+MOUNT_PATH+"image") # Check if mount path exists
    if (p.returncode!=0):
        print("\tCreating mount point")
        p=exec("mkdir "+MOUNT_PATH+"image") # Create if not
        if (p.returncode!=0):
            print("\tSomething failed creating the mount point.")
            quit()
    p=exec("ls "+MOUNT_PATH+"") # Check if mount path exists
    if (p.returncode!=0):
        print("\tCreating mount point")
        p=exec("mkdir "+MOUNT_PATH+"") # Create if not
        if (p.returncode!=0):
            print("\tSomething failed creating the mount point.")
            quit()
    p=exec("sudo ewfmount "+dirty_image+" "+MOUNT_PATH+"image") # Mount image
    if (p.returncode!=0):
        print("\tSomething failed mounting the image.")
        quit()
    p=exec("sudo mount -o ro "+MOUNT_PATH+"image/ewf1 "+MOUNT_PATH+"") # Mount image
    print("\tMounted OK")