import os
config = {'masking':False,
          'oids': ('.1.3.6.1.2.1.1.1.0','.1.3.6.1.2.1.1.2.0','.1.3.6.1.2.1.1.5.0','.1.3.6.1.2.1.4.20.1','.1.3.6.1.2.1.47.1.1.1.1','.1.3.6.1.4.1.9.9.92.1.1.1'),
          'cli':('show run','show start'),
          'cli_timeout': 30,
          'snmp_timeout': 30,
          'seed_path': os.getcwd(),
          'seed_file_name':'seed.csv',
          'threads': 20,
          'seed_headers' : ['IP Address','Host Name','Domain Name','Device Identity','Display Name',
              'SysObjectID','DCR Device Type','MDF Type','Snmp RO','Snmp RW','SnmpV3 User Name',
              'Snmp V3 Auth Pass','Snmp V3 Engine ID','Snmp V3 Auth Algorithm','RX Boot Mode User',
              'RX Boot Mode Pass','Primary User(Tacacs User)','Primary Pass(Tacacs Pass)',
              'Primary Enable Pass','Http User','Http Pass','Http Mode','Http Port','Https Port',
              'Cert Common Name','Secondary User','Secondary Pass','Secondary Enable Pass',
              'Secondary Http User','Secondary Http Pass','Snmp V3 Priv Algorithm',
              'Snmp V3 Priv Pass','User Field 1','User Field 2','User Field 3','User Field 4','Status_Msg'],
          }
class Config():

    def __init__(self):
        self.cli_to_collect = config.get('cli')
        self.oids_to_collect = config.get('oids')
        self.cli_timeout = config.get('cli_timeout')
        self.snmp_timeout = config.get('snmp_timeout')
        self.threads = config.get('threads')
        self.seed_path = config.get('seed_path')
        self.seed_file_name = config.get('seed_file_name')
        self.seed_headers = config.get('seed_headers')
        self.masking = config.get('masking')
