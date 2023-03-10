# feathers-macos-detections
This is an application that works with the FEATHERS-API to give vulnerability information on a macbook, this application requires 

# Support: 
No Direct support will be given on this, neither is any warranty granted. You may raise issues on this Repo, but their is no guarentee or expectation that they will be addressed. Use at your own risk

# Data Usage
This will create an encrypted local TEMP file to hold the data. You can access this file by decrypting it using the token scream in the ~/temp of where this python function is stored.

It will only call the API if the the HASH of the inputs from the system profiler commands changes. This is to save API calls and be able to use the same data on mulitple script runs and save execution on the public API OR the hash is at least 3 hours older than the current system.

# exclude.json and exclude.py
These apps help build rules to exclude certian data from being posted. You can manually edit the file or use the python to add or substract other files. Included is a set of applications on which CVE data has been determined to not be collectable. Such as printer apps. You can exclude directories, app names, bundleIds, on input and some cve data on output

# Examples

## Flags
### -token="YourToken" 
Required value, check your MacBook. Create an account and accept the End User License agreement at https://feathers.pazops.com

### Filtering Objects
#### -cisabod
Will only print CVE's that have a CVE with a Known Exposure as defined by CISA

#### -cisapastdue
Will only print CVE's that have a CVE with a Known Exposure as defined by CISA AND the resolution date is past the current system's time.

#### -severity="high"
Will exclude any CVE where the NVD severity is less than the stated value
### Output Methods
adding *-jamfea* as the final tag will convert any of the displayed outputs to be functional to work with as an Extension Attribute value to work with Jamf Pro
https://feathers.pazops.com/about/jamf_ea

#### -output="cve_list"
Displays a list of the cve's as a JSON LIST

*default*: <code>{"cve_list":["CVE-2022-1010", "CVE-2022-1011"]}</code>

*-jamfea*: <code>&lt;result&gt;CVE-2022-1010,CVE-2022-1011&lt;/result&gt;</code>


#### -output="stats"
Displays teh output as a stats object ( -jamfea will change this )

*default*: <code>{"critical":10, "high":11, "medium":1, "low":0}</code>

*-jamfea*:  <code>&lt;result&gt;true&lt;/result&gt;</code>

#### -output="apps"
Displays the apps that have CVE's as a JSON Object by default


*default*: <code>{"app_list": [{"app_name": "Google Chrome.app", "bundle_id": "com.google.chrome", "version":"101.1.1.1": "stats": {"critical":10, "high":11, "medium":1, "low":0}]}</code>

*-jamfea*: <code><result>Google Chrome.app, Safari.app</result></code>

#### -cve="CVE-2022-1010"
Will give a boolean statement on if a specific CVE exists on the device

*default*: <code>{"is_vulneable": true"}</code>

*-jamfea*:  <code>&lt;result&gt;true&lt;/result&gt;</code>

### -splunk_token="YourHECToken" -splunk_host="YourSplunkOut"
This will take the results and format them for a Splunk HEC collector. with a sourcetype of featers_vuln:mac_os:$Detection_Type based on if the detection is an app, macos, terminal, or other type.

#### -jamfea
Will formate the output to work with a Jamf extension attribute scipt
*-jamfea*: <code> &lt;result&gt;Output Object Text&lt;/result&gt;</code>


##Examples: 
<code>python3 feathers -token="YourToken"</code>

#Errors: 
