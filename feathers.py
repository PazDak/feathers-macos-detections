import json
from subprocess import PIPE, STDOUT
import subprocess
import sys
try:
    import requests
except Exception as E:
    print("You need requests run the next line: \npip install requests")
    raise Exception('You need requests run the next line: \npip install requests') from E


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
    for app in apps:
        app['bundleId'] = getBundleId(appName=app["_name"])
    return apps

def getSystemInfo():
    osVersion = getJSonFromCommandLine(cmd="system_profiler -json SPSoftwareDataType")["SPSoftwareDataType"][0]
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
    results = {}
    if '-SystemProfilerApps' in sys.argv:
        results['apps'] = useSystemProfiler()
    if '-SystemProfilerOS' in sys.argv:
        results['os'] = getSystemInfo()

    if '-OnlyCVE' in sys.argv:
        url = "https://feathers.pazops.com/api/macos/system_profiler"
        results = requests.post(url=url, data=json.dumps(results)).json()
    if '-CheckRunning' in sys.argv:
        results['runningCVE'] = getRunningPids(cveDetails=results['cveDetails'])

    print(json.dumps(results, indent=2))
