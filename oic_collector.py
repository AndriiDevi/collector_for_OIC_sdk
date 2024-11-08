import csv
import os
import logging.handlers
from concurrent.futures import ThreadPoolExecutor
import re
import json
from collector_config import Config
from pysnmp.entity.rfc3413.oneliner import cmdgen


import logging
import time
from netmiko import ConnectHandler
from netmiko.snmp_autodetect import SNMPDetect


def setup_logger(log_file, level=logging.INFO):
    logger = logging.getLogger()  # get the root logger

    if not logger.handlers:  # check if the logger already has handlers
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(funcName)s] [%(message)s]')
        handler.setFormatter(formatter)

        logger.setLevel(level)
        logger.addHandler(handler)
    return logger
def seed_parsing(config):
    """The function is taking CSPC seed file as an input and returns list of dict with device parameters"""
    print(f"{config.seed_path}/{config.seed_file_name}")
    if os.path.isfile(f"{config.seed_path}/{config.seed_file_name}") != True:
        raise FileNotFoundError(f'seed file {config.seed_path}/{config.seed_file_name} not found')
    else:
        devices_list = []
        with open(config.seed_file_name, 'r') as file:
            reader = csv.DictReader(file, fieldnames=config.seed_headers)
            for device in reader:
                devices_list.append(device)
        if devices_list:
            return devices_list
        else:
            raise TypeError('device list is empty, please check seed file format')


def make_OIC_json_file(collected_devices):
    """Takes input list of devices with collected data and make oic.json file"""
    try:
        final_file_format = {
          "device_data": collected_devices,
          "syslog_data": [],
          "oic_metadata": {
              "collectorless_connector_name": "legacy",
              "collectorless_connector_version": "0.0.0",
              "nms_version": "0.0.0"
          }
        }
        with open("oic.json", "w") as file:
          file.write(json.dumps(final_file_format))
        logging.info('oic.json has been successfully created')
    except Exception as e:
        logging.error(f'unable to create json file with an error: {e}')

def main():

    main_logger = setup_logger("oic_collector.log")
    main_logger.info("--------------------------------------------------------------------------------")
    main_logger.info("------------------------ SCRIPT JOB STARTED ------------------------------------")
    main_logger.info("--------------------------------------------------------------------------------")

    config = Config()
    main_logger.info(f"the number of concurrent threads - {config.threads}")

    devices = seed_parsing(config)
    start_time = time.time()
    dev_count = 0

    all_count = len(devices)
    main_logger.info(f"The device count - {all_count}")


    with ThreadPoolExecutor(max_workers=config.threads) as executor:
        all_dev = list(executor.map(lambda device: Device_pooling(device).main_collection(config), devices))
    all_dev = [dev for dev in all_dev if dev is not None]  # Filter out None results
    make_OIC_json_file(all_dev)
    main_logger.info(f"time taken {round((time.time() - start_time) / 60, 1)} min")
    main_logger.info(f"The device count -- {all_count}")
    main_logger.info(
        f'average collection time per device: {round(((time.time() - start_time) / all_count) / 60, 1)} min')

    main_logger.info('=========================== script job finished ===========================')
def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

class Device_pooling:
    count = 1

    def __init__(self, device_dict):
        self.ip_address = device_dict.get('IP Address')
        self.hostname = device_dict.get('Host Name', device_dict.get('IP Address'))
        self.snmpv2_ro = device_dict.get('Snmp RO')
        self.snmpv3_user_name = device_dict.get('SnmpV3 User Name')
        self.snmpv3_auth_password = device_dict.get('Snmp V3 Auth Pass')
        self.snmpv3_engine_id = device_dict.get('Snmp V3 Engine ID')
        self.snmpv3_auth_algorithm = device_dict.get('Snmp V3 Auth Algorithm')
        self.ssh_user = device_dict.get('Primary User(Tacacs User)')
        self.ssh_password = device_dict.get('Primary Pass(Tacacs Pass)')
        self.ssh_enable_password = device_dict.get('Primary Enable Pass')
        self.snmpv3_priv_algorithm = device_dict.get('Snmp V3 Priv Algorithm')
        self.snmpv3_priv_password = device_dict.get('Snmp V3 Priv Pass')
        self.user_field_1 = device_dict.get('User Field 1','')
        self.user_field_2 = device_dict.get('User Field 2','')
        self.user_field_3 = device_dict.get('User Field 3','')
        self.user_field_4 = device_dict.get('User Field 4','')
        self.ssh_device_type = device_dict.get('DCR Device Type')
        self.device_id = Device_pooling.count
        Device_pooling.count += 1
        self.logger = setup_logger("oic_collector.log")

        #qh = logging.handlers.QueueHandler(log_queue)
        #self.logger.addHandler(qh)
        #self.logger.setLevel(logging.INFO)

    def main_collection(self, config):
        """main function to collect data per device"""
        self.logger.info(f'--------- collection started for: {self.ip_address} ----------')
        if self.snmpv3_user_name:
            result = ''
            self.logger.info(f"snmp v3 selected for {self.hostname}, {self.ip_address}")
            snmpv3_user_config = self.snmp_v3_userdata_generator()
            if snmpv3_user_config:
                result = self.snmp_V3_poling(config, snmpv3_user_config)
                if result:
                    self.device_type_detect_snmp_V3()
                    if self.ssh_device_type:
                        ssh_data = self.ssh_pooling(config)
                        if ssh_data:
                            result["cli_data"] = ssh_data
                    else:
                        self.logger.error('unable to  collect cli commands as required parameter <device_type> is missing')
                    #else:
                    #    device_type = "cisco_xr"
                    #    ssh_data = self.ssh_pooling(config)
                    #    if ssh_data:
                    #        result["cli_data"] = ssh_data

            return result
        elif self.snmpv2_ro:
            self.logger.info(f'snmp v2c selected for {self.hostname}, {self.ip_address}')
            result = self.snmp_v2c_pooling(config)
            if result:
                if result:
                    self.device_type_detect_snmp_V2c()
                    if self.ssh_device_type:
                        ssh_data = self.ssh_pooling(config)
                        if ssh_data:
                            result["cli_data"] = ssh_data
                    else:
                        self.logger.error(f'unable to  collect cli commands for {self.hostname}, {self.ip_address} as required parameter <device_type> is missing')
                    #else:
                    #    device_type = "cisco_xr"
                    #    ssh_data = self.ssh_pooling(config, device_type)
                    #    if ssh_data:
                    #        result["cli_data"] = ssh_data
                return result
            else:
                return None
        else:
            self.logger.error(f'device: {self.ip_address} does not have any snmp credentials, excluding from collection. Please check seed file')


    def snmp_v2c_pooling(self, config):
        """"collecting snmp OIDs with snmpv2c version. Takes mandatory scaral and tabular OIDs from config file.
        It starts to collect scalar OIDs and if failed, do not proceed with tabular OIds"""
        oids_collected = []

        cmdGen = cmdgen.CommandGenerator()

        # getting data from scalar OIDs
        errorIndication_s, errorStatus_s, errorIndex_s, varBinds_s = cmdGen.getCmd(
            cmdgen.CommunityData(self.snmpv2_ro),
            cmdgen.UdpTransportTarget((self.ip_address, 161), timeout=config.snmp_timeout, retries=config.snmp_retries),
            *config.oids_to_collect_scalar,
            lookupMib=True, lookupValues=False,lexicographicMode=False,
        )
        # Check for errors and print out results
        if errorIndication_s:
            self.logger.error(f" scalar OIDs collection FAILED for {self.hostname}, {self.ip_address} -> {errorIndication_s} ")
            self.logger.warning(f'tabular OIDs collection stopped for {self.hostname}, {self.ip_address} since scalar OID collection FAILED')
            return None
        else:
            if errorStatus_s:
                self.logger.error(f" scalar OIDs collection FAILED  -> {errorIndication_s} ")
                self.logger.error('%s at %s' % (
                    errorStatus_s.prettyPrint(),
                    errorIndex_s and varBinds_s[int(errorIndex_s) - 1] or '?'
                )
                      )
            else:
                for name, val in varBinds_s:
                    if val.prettyPrint() and val.prettyPrint() != "No more variables left in this MIB View":
                        if hasattr(val, 'getOid'):
                            oids_collected.append(
                                {"oid": f".{name.getOid().prettyPrint()}", "data_type": "OID",
                                 "value": val.getOid().prettyPrint()})
                        elif re.search(r"IpAddress", val.prettyPrintType()):
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "IpAddress",
                                                   "value": val.prettyPrint()})
                        elif re.search(r"Integer", val.prettyPrintType()):
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "INTEGER",
                                                   "value": val.prettyPrint()})
                        else:
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "STRING",
                                               "value": val.prettyPrint()})

        # gettin data from tabular oids #######
        errorIndication_t, errorStatus_t, errorIndex_t, varBindTable_t = cmdGen.bulkCmd(
            cmdgen.CommunityData(self.snmpv2_ro),
            cmdgen.UdpTransportTarget((self.ip_address, 161),
                                      timeout=config.snmp_timeout, retries=config.snmp_retries),
            0,
            25,
            *config.oids_to_collect_tabular,
            lookupMib=True, lookupValues=False, lexicographicMode=False,

        )

        if errorIndication_t:
            self.logger.error(f"tabular OIDs collection FAILED for {self.hostname}, {self.ip_address} -> {errorIndication_t} ")
            return None
        else:
            if errorStatus_t:
                self.logger.error(f"tabular OIDs collection FAILED  for {self.hostname}, {self.ip_address}-> {errorIndication_t} ")
                self.logger.error('%s at %s' % (
                    errorStatus_t.prettyPrint(),
                    errorIndex_t and varBindTable_t[-1][int(errorIndex_t) - 1] or '?'
                )
                      )
            else:
                for varBindTableRow in varBindTable_t:
                    for name, val in varBindTableRow:
                        if val.prettyPrint() and val.prettyPrint() != "No more variables left in this MIB View":
                            if hasattr(val, 'getOid'):
                                oids_collected.append(
                                    {"oid": f".{name.getOid().prettyPrint()}", "data_type": "OID",
                                     "value": val.getOid().prettyPrint()})
                            elif re.search(r"IpAddress", val.prettyPrintType()):
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "IpAddress",
                                                       "value": val.prettyPrint()})
                            elif re.search(r"Integer", val.prettyPrintType()):
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "INTEGER",
                                                       "value": val.prettyPrint()})
                            else:
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "STRING",
                                                       "value": val.prettyPrint()})
        template = {"id": f"device_{self.device_id}",
                    "ip": self.ip_address,
                    "name": self.hostname,
                    "primary_device_name": self.hostname,
                    "cli_data": [],
                    "snmp_data": oids_collected,
                    "device_metadata": {
                        "IPAddress": self.ip_address,
                        "PrimaryDeviceName": self.hostname,
                        "UserField1": self.user_field_1,
                        "UserField2": self.user_field_2,
                        "UserField3": self.user_field_3,
                        "UserField4": self.user_field_4
                    }}
        if oids_collected:
            self.logger.info(f'OIDs collection -> SUCCESS for {self.hostname}, {self.ip_address}')
            return template
        else:
            self.logger.error(f'OIDs collection list is empty or FAILED for {self.hostname}, {self.ip_address}')
            return None

    def snmp_v3_userdata_generator(self):
        """Creates UsmUserData config for self.snmp_V3_poling to be able to connect to device"""
        self.logger.info(f"starting v3 config with {self.snmpv3_priv_algorithm} for {self.hostname}, {self.ip_address}")
        if self.snmpv3_auth_algorithm and self.snmpv3_priv_algorithm:
            if self.snmpv3_auth_algorithm == "SHA":
                if self.snmpv3_priv_algorithm in ("AES-128", "AES-192", "AES-256"):
                    if self.snmpv3_priv_algorithm == "AES-128":
                        self.logger.info(f'AES-128 selected for {self.hostname}, {self.ip_address}')
                        snmpv3_config = cmdgen.UsmUserData(self.snmpv3_user_name, self.snmpv3_auth_password,
                                                           self.snmpv3_priv_password,
                                                           authProtocol=cmdgen.usmHMACSHAAuthProtocol,
                                                           privProtocol=cmdgen.usmAesCfb128Protocol,
                                                           )
                        return snmpv3_config
                    elif self.snmpv3_priv_algorithm == "AES-192":
                        self.logger.info(f'AES-192 selected for {self.hostname}, {self.ip_address}')
                        snmpv3_config = cmdgen.UsmUserData(self.snmpv3_user_name, self.snmpv3_auth_password,
                                                           self.snmpv3_priv_password,
                                                           authProtocol=cmdgen.usmHMACSHAAuthProtocol,
                                                           privProtocol=cmdgen.usmAesCfb192Protocol,
                                                           )
                        return snmpv3_config
                    elif self.snmpv3_priv_algorithm == "AES-256":
                        self.logger.info(f'AES-256 selected for {self.hostname}, {self.ip_address}')
                        snmpv3_config = cmdgen.UsmUserData(self.snmpv3_user_name, self.snmpv3_auth_password,
                                                           self.snmpv3_priv_password,
                                                           authProtocol=cmdgen.usmHMACSHAAuthProtocol,
                                                           privProtocol=cmdgen.usmAesCfb256Protocol,
                                                           )
                        return snmpv3_config

                else:
                    self.logger.error(f"snmpv3_priv_algorithm: {self.snmpv3_priv_algorithm} is not supported by module for {self.hostname}, {self.ip_address}")
                    return None

            else:

                snmpv3_config = cmdgen.UsmUserData(self.snmpv3_user_name, self.snmpv3_auth_password,
                                                   self.snmpv3_priv_password
                                                   )
                return snmpv3_config
        else:

            snmpv3_config = cmdgen.UsmUserData(self.snmpv3_user_name, self.snmpv3_auth_password)
            return snmpv3_config

    def snmp_V3_poling(self, config, userdata):
        """"collecting snmp OIDs with snmpV3 version. Takes mandatory scaral and tabular OIDs from config file.
            It starts to collect scalar OIDs and if failed, do not proceed with tabular OIds"""
        oids_collected = []
        cmdGen = cmdgen.CommandGenerator()

        # getting data from scalar oids #
        errorIndication_s, errorStatus_s, errorIndex_s, varBinds_s = cmdGen.getCmd(
            userdata,
            cmdgen.UdpTransportTarget((self.ip_address, 161), timeout=config.snmp_timeout, retries=config.snmp_retries),
            *config.oids_to_collect_scalar,
            lookupMib=True, lookupValues=False, lexicographicMode=False,

        )

        # Check for errors and print out results
        if errorIndication_s:
            self.logger.error(
                f" scalar OIDs collection FAILED for {self.hostname}, {self.ip_address} -> {errorIndication_s} ")
            self.logger.warning(f'tabular OIDs collection stopped for {self.hostname}, {self.ip_address} since scalar OID collection FAILED')
            return None
        else:
            if errorStatus_s:
                self.logger.error(
                    f" scalar OIDs collection FAILED  for {self.hostname}, {self.ip_address} -> {errorIndication_s} ")
                self.logger.error('%s at %s' % (
                    errorStatus_s.prettyPrint(),
                    errorIndex_s and varBinds_s[int(errorIndex_s) - 1] or '?'
                )
                      )
            else:
                for name, val in varBinds_s:
                    if val.prettyPrint() and val.prettyPrint() != "No more variables left in this MIB View":
                        if hasattr(val, 'getOid'):
                            oids_collected.append(
                                {"oid": f".{name.getOid().prettyPrint()}", "data_type": "OID",
                                 "value": val.getOid().prettyPrint()})
                        elif re.search(r"IpAddress", val.prettyPrintType()):
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "IpAddress",
                                                   "value": val.prettyPrint()})
                        elif re.search(r"Integer", val.prettyPrintType()):
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "INTEGER",
                                                   "value": val.prettyPrint()})
                        else:
                            oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "STRING",
                                                   "value": val.prettyPrint()})

        # gettin data from tabular oids #
        errorIndication_t, errorStatus_t, errorIndex_t, varBindTable_t = cmdGen.bulkCmd(
            userdata,
            cmdgen.UdpTransportTarget((self.ip_address, 161), timeout=config.snmp_timeout, retries=config.snmp_retries),
            0,
            25,
            *config.oids_to_collect_tabular,
            lookupMib=True, lookupValues=False, lexicographicMode=False

        )

        if errorIndication_t:
            self.logger.error(
                f" tabular OIDs collection FAILED for {self.hostname}, {self.ip_address} -> {errorIndication_t} ")
            return None
        else:
            if errorStatus_t:
                self.logger.error(
                    f" tabular OIDs collection FAILED for {self.hostname}, {self.ip_address} -> {errorStatus_t} ")
                self.logger.error('%s at %s' % (
                    errorStatus_t.prettyPrint(),
                    errorIndex_t and varBindTable_t[-1][int(errorIndex_t) - 1] or '?'
                )
                      )
            else:
                for varBindTableRow in varBindTable_t:
                    for name, val in varBindTableRow:
                        if val.prettyPrint() and val.prettyPrint() != "No more variables left in this MIB View":
                            if hasattr(val, 'getOid'):
                                oids_collected.append(
                                    {"oid": f".{name.getOid().prettyPrint()}", "data_type": "OID",
                                     "value": val.getOid().prettyPrint()})
                            elif re.search(r"IpAddress", val.prettyPrintType()):
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "IpAddress",
                                                       "value": val.prettyPrint()})
                            elif re.search(r"Integer", val.prettyPrintType()):
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "INTEGER",
                                                       "value": val.prettyPrint()})
                            else:
                                oids_collected.append({"oid": f".{name.getOid().prettyPrint()}", "data_type": "STRING",
                                                       "value": val.prettyPrint()})
        template = {"id": f"device{self.device_id}",
                    "ip": self.ip_address,
                    "name": self.hostname,
                    "primary_device_name": self.hostname,
                    "cli_data": [],
                    "snmp_data": oids_collected,
                    "device_metadata": {
                        "IPAddress": self.ip_address,
                        "PrimaryDeviceName": self.hostname,
                        "UserField1": self.user_field_1,
                        "UserField2": self.user_field_2,
                        "UserField3": self.user_field_3,
                        "UserField4": self.user_field_4
                    }}
        if oids_collected:
            self.logger.info(f'OIDs collection for {self.hostname}, {self.ip_address} -> SUCCESS ')
            return template
        else:
            self.logger.error(f'OIDs collection list is empty or FAILED for {self.hostname}, {self.ip_address}')
            return None

    def device_type_detect_snmp_V2c(self):
        """It detects device_type param via snmpv2 protocol which is needed for SSH pooling.
        The function does not return anything, it is just updating self param (self.ssh_device_type) if detected."""
        if self.ssh_device_type:
            self.logger.info(f'device_type found in seed file {self.ssh_device_type} for device: {self.ip_address}')
        else:
            try:
                my_snmp = SNMPDetect(
                    self.ip_address, snmp_version="v2c", community=self.snmpv2_ro,
                )
                device_type = my_snmp.autodetect()
                if device_type:
                    self.logger.info(f'device_type: {device_type} was detected successfully for {self.ip_address} ')
                    self.ssh_device_type = device_type
                else:
                    self.logger.error(f"unable to detect device_type for device: {self.ip_address}")
            except Exception as e:
                self.logger.error(f"unable to detect device type for {self.ip_address} with error {e}")

    def netmiko_SNMPdetect_generator_snmpv3(self):
        encrypt_proto = ''
        if self.snmpv3_auth_algorithm:
            if self.snmpv3_auth_algorithm.lower() == 'sha':
                self.logger.info(f'SHA algorithm selected for SNMP detect generator for {self.hostname}, {self.ip_address}')
                if self.snmpv3_priv_algorithm:
                    encrypt_proto = self.snmpv3_priv_algorithm.lower().replace('-', '')
                try:
                    my_snmp = SNMPDetect(
                        self.ip_address,
                        user=self.snmpv3_user_name,
                        auth_key=self.snmpv3_auth_password,
                        encrypt_key=self.snmpv3_priv_password,
                        auth_proto=self.snmpv3_auth_algorithm.lower(),
                        encrypt_proto=encrypt_proto
                    )
                    return my_snmp
                except Exception as e:
                    self.logger.error(f"unable to generate SNMP detect object for  {self.ip_address} with error {e}")
                    return None
            elif self.snmpv3_auth_algorithm.lower() == 'md5':
                self.logger.info(f'MD5 algorithm selected for SNMP detect generator for {self.hostname}, {self.ip_address}')
                if self.snmpv3_priv_algorithm:
                    encrypt_proto = self.snmpv3_priv_algorithm.lower().replace('-', '')
                try:
                    my_snmp = SNMPDetect(
                        self.ip_address,
                        user=self.snmpv3_user_name,
                        auth_key=self.snmpv3_auth_password,
                        encrypt_key=self.snmpv3_priv_password,
                        auth_proto=self.snmpv3_auth_algorithm.lower(),
                        encrypt_proto=encrypt_proto
                    )
                    return my_snmp
                except Exception as e:
                    self.logger.error(f"unable to generate SNMP detect object for  {self.ip_address} with error {e}")
                    return None
        else:
            self.logger.info(f'No SNMPv3 encryption protocol found. Will use basic constructor for {self.hostname}, {self.ip_address}')
            try:
                my_snmp = SNMPDetect(
                    self.ip_address,
                    user=self.snmpv3_user_name,
                    auth_key=self.snmpv3_auth_password,
                    encrypt_key=self.snmpv3_priv_password
                )
                return my_snmp
            except Exception as e:
                self.logger.error(f"unable to generate SNMPdetect object for  {self.ip_address} with error {e}")
                return None


    def device_type_detect_snmp_V3(self):
        """It detects device_type param via snmpV3 protocol which is needed for SSH pooling.
        The function does not return anything, it is just updating self param (self.ssh_device_type) if detected."""
        if self.ssh_device_type:
            self.logger.info(f'device_type found in seed file: {self.ssh_device_type} for {self.ip_address}')
        else:
            snmp_object = self.netmiko_SNMPdetect_generator_snmpv3()

            try:
                device_type = snmp_object.autodetect()

                if device_type:
                    self.logger.info(f'device_type: {device_type} was detected successfully for {self.ip_address} ')
                    self.ssh_device_type = device_type
                else:
                    self.logger.error(f"was unable to detect device_type for device {self.ip_address}")
            except Exception as e:
                self.logger.error(f"unable to detect device type for {self.ip_address} with error {e}")

    def ssh_connect(self):
        """Creates ssh connect object which is passing to self.ssh_pooling"""
        device = {
            'device_type': self.ssh_device_type,
            "host": self.ip_address,
            "username": self.ssh_user,
            "password": self.ssh_password,
            "secret": self.ssh_enable_password
        }
        try:
            net_connect = ConnectHandler(**device)
            if self.ssh_password:
                net_connect.enable()
                self.logger.info(f'switched to enable mode for {self.hostname}, {self.ip_address}')
            else:
                self.logger.warning(f'no enable password found for {self.hostname}, {self.ip_address}, some cli commands may not be collected properly, please check seed file')
            return net_connect
        except Exception as e:
            self.logger.error(f"ssh connection failed to  : {self.ip_address} with en error: {e}")
            return None
    def ssh_pooling(self, config):

        net_connect = self.ssh_connect()
        collected_cli = []
        if net_connect:

            for command in config.cli_to_collect:
                try:
                    command_output = net_connect.send_command(f"{command}\n", read_timeout=config.cli_timeout)
                    collected_cli.append({"command": command, "result": command_output})
                    self.logger.info(f'command {command} collected for for {self.hostname}, {self.ip_address}')
                except Exception as e:
                    self.logger.error(f"for {self.hostname}, {self.ip_address}, failed to collect command: {command} with en error: {e}")
            net_connect.disconnect()
        return collected_cli


if __name__ == '__main__':

    main()

