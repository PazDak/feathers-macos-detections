"""
Main Execution of the Feathers MacOS Detection Agent
"""
import json
import time
from subprocess import PIPE, STDOUT
import subprocess
import sys
import hashlib
try:
    from cryptography.fernet import Fernet
except Exception as E:
    import_errors = True
    print("You need cryptography run the next line: \npip install cryptography")
    raise Exception('You need requests run the next line: \npip install cryptography') from E

try:
    import requests
except Exception as E:
    import_errors = True
    print("You need requests run the next line: \npip install requests")
    raise Exception('You need requests run the next line: \npip install requests') from E



with open("exclude.json", 'r', encoding="utf-8") as fp:
    exclude_rules = json.loads(fp.read())



def pipe_mac_terminal_command_json(cmd):
    """
    Pipes a mac terminal command and returns a Dict object
    :param cmd: input command
    :return: dict of the command as a json object
    """
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    apps = json.loads(response.stdout.read())
    response.kill()
    return apps


def pipe_mac_terminal_command(cmd):
    """
    Pipes a mac terminal command and returns a Dict object
    :param cmd: input command
    :return: string of the command as a string object
    """
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    s = response.stdout.read().decode()
    response.kill()
    return s


def get_mac_app_bundle_id(app_name):
    """
    Gets the bundle_id of an application from the terminal
    :param app_name:
    :return:
    """
    cmd = f"osascript -e \'id of app \"{app_name}\"\'"
    response = subprocess.Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    bundle_id = response.stdout.read().decode().split("\n")[0]
    response.kill()
    if bundle_id.__contains__("execution error"):
        bundle_id = "None"
    return bundle_id


def get_mac_system_apps() -> list:
    """
    Gets a list of the Mac Applications from the MacOS System terminal
    :return: list_of_apps
    """
    apps = pipe_mac_terminal_command_json(cmd="system_profiler -json SPApplicationsDataType")["SPApplicationsDataType"]
    result_apps = []
    for app in apps:
        if app['obtained_from'] == "apple" and app['version'] != "1.0":
            continue
        if 'version' not in app:
            continue
        app['bundleId'] = get_mac_app_bundle_id(app_name=app["_name"])
        if app['bundleId'] not in exclude_rules['apps']['ignoreBundleIds']:
            del_keys = ['arch_kind', 'signed_by', 'lastModified']
            for key in del_keys:
                if key in app:
                    del app[key]
            hash_string = f"{app['_name']}{app['bundleId']}{app['version']}"
            app['app_hash'] = hashlib.md5(hash_string.encode()).hexdigest()
            result_apps.append(app)
    return result_apps


def get_mac_system_info():
    """
    Gathers the Application information
    :return: osVersion Dict
    """
    os_details = pipe_mac_terminal_command_json(cmd="system_profiler -json SPSoftwareDataType")["SPSoftwareDataType"][0]
    del_keys = ['local_host_name', 'user_name', 'uptime', 'secure_vm', 'system_integrity', 'boot_mood', 'boot_volum']
    for key in del_keys:
        if key in os_details:
            del os_details[key]
    return os_details


def get_running_pids(cve_details: list) -> list:
    """
    Gets the Running PIDS based on the appPath
    :param cve_details: list of CVE Details
    :return:
    """
    cmd = "ps -e"
    pids = pipe_mac_terminal_command(cmd).split('\n')
    running_pid_results = []

    for pid in pids:
        for cveDetail in cve_details:
            if pid.__contains__(cveDetail['appPath']):
                running_pid_results.append({
                    'cveDetail': cveDetail,
                    'pid': pid
                })
    return running_pid_results


if __name__ == "__main__":
    commands = ['token', 'cisa', 'cisapastdue', 'severity', 'output', 'cve', 'splunk_token', 'splunk_host']

    results = {}
    print(sys.argv)
    args = {}
    for arg in sys.argv:
        if '-token' in arg:
            args['token'] = arg.split("=")[1].replace("\"", "")
    results['apps'] = get_mac_system_apps()
    results['os'] = get_mac_system_info()

    url = "https://feathers.pazops.com/api/macos/system_profiler"
    results_hash = hashlib.md5(json.dumps(results, sort_keys=True).encode()).hexdigest()
    results = requests.post(url=url, data=json.dumps(results, sort_keys=True)).json()
    print(json.dumps(results, indent=2, sort_keys=True))
    print(results_hash)
