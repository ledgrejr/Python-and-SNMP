from pysnmp.hlapi import *
import sys

def extract_if_mib_value(object_type):
    """Extracts the prettyprinted value from an smi.rfc1902.ObjectType"""
    s = object_type.prettyPrint()
    return s.rsplit("=", 1)[-1].strip()

for line in open('IPs.txt','r'):
  with open('output.csv','w+') as fout:
    for _, _, _, varBinds in nextCmd(SnmpEngine(),CommunityData('public', mpModel=0),
    UdpTransportTarget((line.strip(), 161)),ContextData(),ObjectType(ObjectIdentity('IF-MIB', 'ifDescr')),
    ObjectType(ObjectIdentity('IF-MIB', 'ifOperStatus')),lexicographicMode=False):
      print('Checking ' + line)
      descr, status = varBinds
      iface_name = extract_if_mib_value(descr)
      iface_status = extract_if_mib_value(status)
      if iface_name == ('1/A23' or '2/A23' or '1/B7' or '2/B7' or '1/A24' or '2/A24' or '1/B8' or '2/B8' or '1/24' or '2/24' or '3/24'):
        if iface_status == 'down':
          print('{} \t {} \t {}'.format(line,iface_name,iface_status))
          fout.write('{} \t {} \t {}'.format(line,iface_name,iface_status))
