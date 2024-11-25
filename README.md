# misp2defender
This script is designed to automate the process of extracting Indicators of Compromise (IOCs) from a MISP instance and pushing them into Microsoft Defender for Endpoint (MDE), with block mode enabled. By leveraging this integration, you can streamline your security operations by ensuring that relevant threat intelligence is actionable within your endpoint protection environment.

## Features
* Able to fetch hashes, IP addresses, URLs and domains from MISP and push into Defender for Endpoint based on specified tags.
* Pushes IoCs to MDE and maps the correct blocking type automatically. 
* Supports transfer of up to 15,000 indicators in a memory-efficient manor.

## Pre-requisites

MISP
* A running and accessible MISP instance.
* An API key with read-only permissions.

Microsoft Defender for Endpoint
* A valid MDE subscription.
* A configured Azure application with permission to update TI indicators.

## Installation & Usage

1. Clone the repository.
2. Install the required dependencies: ``` pip install -r requirements.txt ```
3. Create a misp_defender_config.ini configuration file in the repository directory.
```
[MISP]
BaseURL = https://your_misp_instance.com
AuthKey = <MISP AUTH KEY>
VerifyTLS = True
Tags = category="Ransomware", Defender 
[MSDefender]
Tenant_id = <YOUR TENANT ID>
Client_id = <YOUR CLIENT ID>
Client_secret = <YOUR CLIENT SECRET>
```
The Tags variable supports numerous tag types, seperated by a comma. When numerous tags are specified, the MISP instance searches for events matching these tags in an OR operation. So in the above example, all IoCs that belong to events matching either ```category="Ransomware"``` or ```Defender``` will be pushed into MDE.

4. Run the script: ``` python3 misp_to_defender.py ```

## Log Output
All logs from the script will automatically go into a misp_to_defender.log file in the directory you run the script from, as well as the console.


