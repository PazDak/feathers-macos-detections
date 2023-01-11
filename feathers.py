#!/usr/bin/env python3
"""
Main Execution of the Feathers MacOS Detection Agent
"""
import os
import datetime
import json
import time
from subprocess import PIPE, STDOUT
import subprocess
import sys
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import logging

if not os.path.exists("temp/"):
    os.mkdir("temp/")

try:
    import requests
except Exception as E:
    print("You need requests run the next line: \npip install requests")
    raise Exception('You need requests run the next line: \npip install requests') from E

try:
    with open("exclude.json", 'r', encoding="utf-8") as fp:
        exclude_rules = json.loads(fp.read())
except FileNotFoundError:
    exclude_rules = {
        "apps": {
            "ignoreBundleIds": ["com.apple.print.PrinterProxy"],
            "ignorePaths": [],
            "ignoreAppNames": [],
            "rules": {}
        }
    }

def get_jamf_ea_format(ea_key, results):
    valid_keys = ['cve.list', 'cve.count', 'cve.countCritical', 'cve.countHigh', 'cve.CISA', 'cve.CISAPastDue']
    print(ea_key)
    if ea_key not in valid_keys:
        return "invalid key"

    if ea_key == "cve.list":
        cve_list = []
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list'])> 0:
                    for vuln in app_result['vuln_data']['cve_list']:
                        cve_list.append(vuln['cve_id'])
        cve_list = list(set(cve_list))
        s = ""
        for cve in cve_list:
            s = s + f"{cve},"
        s = s[:-1]
        return s

    if ea_key == "cve.count":
        count = 0
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list']) > 0:
                    count += len(app_result['vuln_data']['cve_list'])
        return count

    if ea_key == "cve.countHigh":
        count = 0
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list']) > 0:
                    for vuln in app_result['vuln_data']['cve_list']:
                        if vuln['cvss_severity'] == "HIGH":
                            count += 1
        return count

    if ea_key == "cve.countCritical":
        count = 0
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list']) > 0:
                    for vuln in app_result['vuln_data']['cve_list']:
                        if vuln['cvss_severity'] == "CRITICAL":
                            count += 1
        return count
    if ea_key == "cve.CISA":
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list']) > 0:
                    for vuln in app_result['vuln_data']['cve_list']:
                        if 'cisa' in vuln:
                            return True
        return False

    if ea_key == "cve.CISAPastDue":
        for app_result in results['app_data']:
            if app_result['vuln_data'] != {}:
                if len(app_result['vuln_data']['cve_list']) > 0:
                    for vuln in app_result['vuln_data']['cve_list']:
                        if 'cisa' in vuln:
                            if datetime.datetime.strftime(vuln['cisa']['dueDate'], "%Y-%m-%d") > datetime.datetime.now():
                                return True
        return False

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

def get_mac_hardware_info():
    """
    Gathers specific hardware information
    :return: hardwareVersions Dict
    """
    hw_details = pipe_mac_terminal_command_json("system_profiler SPHardwareDataType -json")['SPHardwareDataType'][0]
    return {"serial_number": hw_details['serial_number'], "uuid": hw_details['platform_UUID'], "platform_hardware": hw_details['machine_model']}


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


def get_args() -> dict:
    """
    Get a dictionary of the command line provided arguments
    :return: dict of the command line args formated
    """
    _args = {}
    valid_outputs = ['cve_list', 'stats', 'cisa', 'cisa_past_due']
    _output_set = False
    for _arg in sys.argv:
        if '-token' in _arg:
            _args['token'] = _arg.split("=")[1].replace("\"", "")
            if "”" in _args['token']:
                _args['token'] = _args['token'].replace("”", "")
            if "“" in _args['token']:
                _args['token'] = _args['token'].replace("“", "")

        if '-force' in _arg:
            _args['force'] = True
        else:
            _args['force'] = False

        if '-jamfea' in _arg:
            _args['jamfea'] = _arg.split("=")[1].replace("\"", "")
            if "”" in _args['jamfea']:
                _args['jamfea'] = _args['jamfea'].replace("”", "")
            if "“" in _args['jamfea']:
                _args['jamfea'] = _args['jamfea'].replace("“", "")


        if '-output' in _arg and not _output_set:
            value = _arg.split("=")[1].replace("\"", "")
            if value in valid_outputs:
                _args['output'] = value
                _output_set = True
    return _args


def get_system_details() -> dict:
    """
    Gets the System Details
    :return:
    """
    _result = {}
    _result['apps'] = get_mac_system_apps()
    _result['os'] = get_mac_system_info()
    _result['device'] = get_mac_hardware_info()
    #ToDo build _result hash
    _result['lastRun'] = time.time()
    return _result


if __name__ == "__main__":
    commands = ['token', 'cisa', 'cisapastdue', 'severity', 'output', 'cve', 'splunk_token', 'splunk_host', 'jamfea', 'force']
    args = get_args()
    if 'token' not in args:
        raise Exception('Missing Token, required value \nExample python3 feathers.py -token="yourToken\nGet a token at https://feathers.pazops.com"')

    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {args["token"]}'}
    url = "https://feathers.pazops.com/api/macos/system_profiler"


    prev = {}

    if 'lastRun' in prev:
        time_last_run = time.time() - prev['lastRun']
        if time_last_run > 3600 or args['force']:
            results = get_system_details()
            url = "https://feathers.pazops.com/api/macos/system_profiler"
            results['vuln_info'] = requests.post(url=url, data=json.dumps(results, sort_keys=True), headers=headers, timeout=10).json()
            write_encrypted_cache(fernet_key=get_fernet_key(args['token']), data_dict=results)
        else:
            results = prev
    else:
        results = get_system_details()
        url = "https://feathers.pazops.com/api/macos/system_profiler"
        r = requests.post(url=url, data=json.dumps(results, sort_keys=True), headers=headers)
        if r.status_code != 201:
            print("<result>Failed API Call, Check Token</result>")
            exit()
        results['vuln_info'] = r.json()

    vuln_results = results['vuln_info']

    #Build the Apps List
    vuln_apps = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cve_list = []
    app_list = []

    for app_data in vuln_results['app_data']:
        if app_data['feathers_supported'] and app_data['vuln_data'].get("cve_list", None) is not None:
            # Get the Application Data
            for app in results['apps']:
                if app['app_hash'] == app_data['app_hash']:
                    app_name = app["_name"]
                    app_version = app['version']
                    app_bundle_id = app['bundleId']
                    app_path = app['path']

                    app_stats = {"app_name": app_name,"bundle_id":app_bundle_id, "app_version":app_version, "app_path": app_path, "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "cisa": False, "cisa_past_due": False, "cve_list": []}
                    for vuln in app_data['vuln_data'].get("cve_list", None):
                        #
                        cve_list.append(vuln['cve_id'])
                        stats[vuln['cvss_severity'].lower()] += 1

                        app_stats['cve_list'].append(vuln['cve_id'])
                        app_stats['stats'][vuln['cvss_severity'].lower()] += 1
                    app_list.append(app_stats)
    stats['total'] = stats['critical'] + stats['high'] + stats['medium'] + stats['low']
    cve_list = list(set(cve_list))

    if args.get('jamfea', None) is not None:
        print(f"<result>{get_jamf_ea_format(args.get('jamfea'), results=vuln_results)}</result>")
    else:
        print(json.dumps(app_list, indent=2, sort_keys=True))
