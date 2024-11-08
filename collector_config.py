import os
"""config file where you can play with params in config dict"""
config = {'masking':False,
          'oids_scalar': ('.1.3.6.1.2.1.1.1.0',          # sysDescr  oid
                          '.1.3.6.1.2.1.1.2.0',          # sysObjectID   oid
                          '.1.3.6.1.2.1.1.5.0'),         # sysName   oid
          'oids_tabular': ('.1.3.6.1.2.1.4.20.1',         # IP-MIB_ipAddrTable dataset
                          '.1.3.6.1.2.1.47.1.1.1.1',     # ENTITY-MIB_entPhysical dataset
                          '.1.3.6.1.2.1.2.2.1',          # IF-MIB_ifTable dataset
                          '.1.3.6.1.4.1.9.9.92.1.1.1'),  # CISCO-ENTITY-ASSET-MIB_ceAssetTable dataset
          'cli': ('show inventory',
                  'show interface',
                  'show environment power',
                  'show environment power input',
                  'show environment power detail',
                  'show environment power detail ampere',
                  'show module',
                  'show interface snmp-ifindex'),
          'cli_timeout': 10, #seconds
          'snmp_timeout': 15, #seconds
          'snmp_retries': 1,
          'seed_path': os.getcwd(),
          'seed_file_name':'oicseed1.csv',
          'threads': 10,
          'seed_headers' : ['IP Address',               #A
                            'Host Name',                #B
                            'Domain Name',              #C
                            'Device Identity',          #D
                            'Display Name',             #E
                            'SysObjectID',              #F
                            'DCR Device Type',          #G this field will be used for device_type in ssh collection https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md
                            'MDF Type',                 #H
                            'Snmp RO',                  #I
                            'Snmp RW',                  #J
                            'SnmpV3 User Name',         #K
                            'Snmp V3 Auth Pass',        #L
                            'Snmp V3 Engine ID',        #M
                            'Snmp V3 Auth Algorithm',   #N
                            'RX Boot Mode User',        #O
                            'RX Boot Mode Pass',        #P
                            'Primary User(Tacacs User)',#Q
                            'Primary Pass(Tacacs Pass)',#R
                            'Primary Enable Pass',      #S
                            'Http User',                #T
                            'Http Pass',                #U
                            'Http Mode',                #V
                            'Http Port',                #W
                            'Https Port',               #X
                            'Cert Common Name',         #Y
                            'Secondary User',           #Z
                            'Secondary Pass',           #AA
                            'Secondary Enable Pass',    #AB
                            'Secondary Http User',      #AC
                            'Secondary Http Pass',      #AD
                            'Snmp V3 Priv Algorithm',   #AE
                            'Snmp V3 Priv Pass',        #AF
                            'User Field 1',             #AG
                            'User Field 2',
                            'User Field 3',
                            'User Field 4',
                            'Status_Msg'],
          }
class Config:

    def __init__(self):
        self.cli_to_collect = config.get('cli')
        self.oids_to_collect_scalar = config.get('oids_scalar')
        self.oids_to_collect_tabular = config.get('oids_tabular')
        self.cli_timeout = config.get('cli_timeout')
        self.snmp_timeout = config.get('snmp_timeout')
        self.snmp_retries = config.get('snmp_retries')
        self.threads = config.get('threads')
        self.seed_path = config.get('seed_path')
        self.seed_file_name = config.get('seed_file_name')
        self.seed_headers = config.get('seed_headers')
        self.masking = config.get('masking')

