import json
import time
from subprocess import PIPE, STDOUT
import subprocess
import sys
import hashlib
try:
    import requests
except Exception as E:
    print("You need requests run the next line: \npip install requests")
    raise Exception('You need requests run the next line: \npip install requests') from E

with open("exclude.json", 'r', encoding="utf-8") as fp:
    exclude_rules = json.loads(fp.read())

def getJSonFromCommandLine(cmd):
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    apps = json.loads(response.stdout.read())
    response.kill()
    return apps

def getResponseFromCommandLine(cmd):
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    s = response.stdout.read().decode()
    response.kill()
    return s

def getBundleId(appName):
    cmd = f"osascript -e \'id of app \"{appName}\"\'"
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    bundleId = response.stdout.read().decode().split("\n")[0]
    response.kill()
    if bundleId.__contains__("execution error"):
        bundleId = "None"
    return bundleId

def useSystemProfiler():
    apps = getJSonFromCommandLine(cmd="system_profiler -json SPApplicationsDataType")["SPApplicationsDataType"]
    result_apps = []
    for app in apps:
        if app['obtained_from'] == "apple" and app['version'] != "1.0":
            continue
        if 'version' not in app:
            continue
        app['bundleId'] = getBundleId(appName=app["_name"])
        if app['bundleId'] not in exclude_rules['apps']['ignoreBundleIds']:
            del_keys = ['arch_kind', 'signed_by', 'lastModified']
            for key in del_keys:
                if key in app:
                    del app[key]
            try:
                hash_string = f"{app['_name']}{app['bundleId']}{app['version']}"
            except:
                print(app)
                time.sleep(3)

            app['app_hash'] = hashlib.md5(hash_string.encode()).hexdigest()
            result_apps.append(app)
    return result_apps

def getSystemInfo():
    osVersion = getJSonFromCommandLine(cmd="system_profiler -json SPSoftwareDataType")["SPSoftwareDataType"][0]
    del_keys = ['local_host_name', 'user_name', 'uptime', 'secure_vm', 'system_integrity', 'boot_mood', 'boot_volum']
    for key in del_keys:
        if key in osVersion:
            del osVersion[key]
    return osVersion

def getRunningPids(cveDetails:list)->dict:
    cmd = "ps -e"
    pids = getResponseFromCommandLine(cmd).split('\n')
    results = []

    for pid in pids:
        for cveDetail in cveDetails:
            if pid.__contains__(cveDetail['appPath']):
                results.append({
                    'cveDetail': cveDetail,
                    'pid': pid
                })
    return results


if __name__ == "__main__":
    commands = ['token', 'cisa', 'cisapastdue', 'severity', 'output', 'cve', 'splunk_token', 'splunk_host']

    results = {}
    print(sys.argv)
    args = {}
    for arg in sys.argv:
        if '-token' in arg:
            args['token'] = arg.split("=")[1].replace("\"", "")
    results['apps'] = useSystemProfiler()
    results['os'] = getSystemInfo()

    url = "https://feathers.pazops.com/api/macos/system_profiler"
    results_hash = hashlib.md5(json.dumps(results, sort_keys=True).encode()).hexdigest()
    results = requests.post(url=url, data=json.dumps(results, sort_keys=True)).json()
    print(json.dumps(results, indent=2, sort_keys=True))
    print(results_hash)
