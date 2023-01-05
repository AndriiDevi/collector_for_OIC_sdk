# Collector-for-OIC-sdk
This small script works in pair with [Cisco OIC SDK](https://software.cisco.com/download/home/286329931/type/286330359/release/2.0)

It collects SNMP and CLI data from Cisco devices by using csv seed file (CSPC seed format) and cenerate json file which is required as input for OIC SDK

# Installation
```
git clone https://github.com/AndriiDevi/collector_for_OIC_sdk.git

pip install -r requirements.txt
```


To collect cli commands, netmiko lib should know `device_type` to be able to establish ssh session. Netmiko SNMPDetect class tries to automatically determine the device type. Typically this method will use the MIB-2 SysDescr and regular expressions. The autodetect feature is not always able to detect device_type. I recommend to setup device_type manually in seed file if possible (column G : 'DCR Device Type'), It will also speed up collection process.

`device_types` are available on [link](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md) and below:

•	cisco_asa
•	cisco_ftd
•	cisco_ios
•	cisco_nxos
•	cisco_s300
•	cisco_tp
•	cisco_viptela
•	cisco_wlc
•	cisco_xe
•	cisco_xr

# configuration

collector_config.py contains dict with all configurable params which you can modify like snmp retries, snmp timeout, seed file name, oids to be collected, cli commands to be collected, etc. it also contains seed file headers to quickly identify the param you are looking for.

ATM the script does not support concurrency so it will pull devices one by one.

