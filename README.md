# feathers-macos-detections
This is an application that works with the FEATHERS-API to give vulnerability information on a macbook, this application requires 

# Data Usage


# Examples

## Flags
### -token="YourToken" 
Required value, check your MacBook. Create an account and accept the End User License agreement at https://feathers.pazops.com

### -severity="high"
Will exclude any CVE where the NVD severity is less than the stated value

### -output="cve_list"
Displays a list of the cve's as a JSON LIST
{"cve_list":["CVE-2022-1010", "CVE-2022-1011"]}

*-jamfea*:&lt;result&gt;CVE-2022-1010,CVE-2022-1011&lt;/result&gt;

### -output="stats"
Displays teh output as a stats object ( -jamfea will change this )

*default*: {"critical":10, "high":11, "medium":1, "low":0}

*-jamfea*:  &lt;result&gt;true&lt;/result&gt;

### -output="apps"
Displays the apps that have CVE's as a JSON Object by default
{"app_list": [{"app_name": "Google Chrome.app", "bundle_id": "com.google.chrome", "version":"101.1.1.1": "stats": {"critical":10, "high":11, "medium":1, "low":0}]}

### -cve="CVE-2022-1010"
Will give a boolean statement on if a specific CVE exists on the device

*default*: {"is_vulneable": true"}

*-jamfea*:  &lt;result&gt;true&lt;/result&gt;

### -cisabod
Will only print CVE's that have a CVE with a Known Exposure as defined by CISA

### -cisapastdue
Will only print CVE's that have a CVE with a Known Exposure as defined by CISA AND the resolution date is past the current system's time.

### -jamfea
Will formate the output to work with a Jamf extension attribute scipt
*-jamfea*:  &lt;result&gt;Output Object Text&lt;/result&gt;


##Examples: 
<code>python3 feathers -token="YourToken"<code>

#Errors: 
