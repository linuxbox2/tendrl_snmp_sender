#!/bin/python

import sys
from pysnmp.hlapi import *
from pysnmp import debug

# use specific fcd lags or 'all' for full debugging
#debug.setLogger(debug.Debug('secmod'))

class SnmpEndpoint(object):
    """
    Base class for SNMP endpoint (credential and host+port pair)
    """

    def __init__(self):
        self.proto = 0
        self.host = None
        self.port = None
        self.engineid = None

class V2Endpoint(SnmpEndpoint):
    """
    Class encapsulating an SNMPv2c community, host+port pair
    """

    def __init__(self, host="localhost", port=162, engineid=None,
                 community=None):
        self.proto = 2
        self.host = host
        self.port = port
        self.engineid = engineid
        self.community = community

class V3Endpoint(SnmpEndpoint):
    """
    Class encapsulating an SNMPv3 User Security object, host+port pair
    """

    def __init__(self, host="localhost", port=162, engineid=None,
                 usm_user=None):
        self.proto = 3
        self.host = host
        self.port = port
        self.engineid = engineid
        self.usm_user = usm_user

class SnmpAlert(object):
    """
    Class encapsulating an SNMP alert from Tendrl--potentially to be
    re-derived as inheriting from a general base, or just replaced
    with one (as all this class does is bundle the flat alert map)
    """

    def __init__(self, alert_id=None, alert_fields=None):
        self.alert_id = alert_id
        self.alert_fields = alert_fields
        self.alert_type = self.alert_fields['type']
        self.alert_fields.pop('type', None)
        self.alert_node = alert_fields['node-id']
        self.alert_fields.pop('node-id', None)

    def getPDU(self):
        kvs = len(self.alert_fields.keys())
        # count of name-value pairs coming
        pdu = [ObjectType(ObjectIdentity('1.3.6.1.4.2312.19.1.0'),
                          Integer32(kvs))]
        for k in self.alert_fields:
            # field name
            pdu.append(
                ObjectType(ObjectIdentity('1.3.6.1.4.2312.19.1.1'),
                           OctetString(k)))
            # field value
            pdu.append(
                ObjectType(ObjectIdentity('1.3.6.1.4.2312.19.1.2'),
                           OctetString(self.alert_fields[k])))
        return pdu

    def toString(self):
        str = ""
        str = "<SnmpAlert#%s" % (self.alert_id)
        for k in self.alert_fields:
            str += " %s : %s" % (k, self.alert_fields[k])
        str += ">"
        return str

class SnmpSender(object):
    """
    Send an SNMPv3 alert
    """
    def __init__(self):
        pass

    def trapV2(self, endpoint=None, alert=None):
        """
        Send trap to one endpoint
        """
        errorIndication, errorStatus, errorIndex, varBinds = next(
            sendNotification(
                SnmpEngine(snmpEngineID=OctetString(
                    hexValue=endpoint.engineid)),
                CommunityData(endpoint.community, mpModel=1),
                UdpTransportTarget((endpoint.host, endpoint.port)),
                ContextData(),
                'trap',
                # sequence of custom OID-value pairs
                alert.getPDU()))
        if errorIndication:
            print("result: {} {} {}".format(errorIndication, errorStatus,
                                            errorIndex))

    def trapV3(self, endpoint=None, alert=None):
        """
        Send trap to one endpoint
        """
        errorIndication, errorStatus, errorIndex, varBinds = next(
            sendNotification(
                SnmpEngine(snmpEngineID=OctetString(
                    hexValue=endpoint.engineid)),
                endpoint.usm_user,
                UdpTransportTarget((endpoint.host, endpoint.port)),
                ContextData(),
                'trap',
                # sequence of custom OID-value pairs
                alert.getPDU()))
        if errorIndication:
            print("result: {} {} {}".format(errorIndication, errorStatus,
                                            errorIndex))

    def trapMulti(self, endpoints=None, alert=None):
        """
        Send trap to multiple endpoints
        """
        for endpoint in endpoints:
            if endpoint.proto == 3:
                self.trapV3(endpoint, alert)
            else:
                if endpoint.proto == 2:
                    self.trapV2(endpoint, alert)

def main():
    alert_data1 = {'alert-id' : '6405962e-bc46-11e6-a4a6-cec0c932ce01',
                   'node-id' : '5205962e-bc46-11e6-a4a6-cec0c932cz01',
                   'time-stamp' : '1481046935.536',
                   'resource': 'cluster',
                   'current-value': 'down',
                   'cluster-id' : '6406062e-be46-11e6-a4a6-cec0c932ce01',
                   'cluster-name': 'foobar',
                   'storage-type': 'gluster',
                   'type' : 'status',
                   'severity': 'critical'}

    alert1_id = alert_data1['alert-id']

    alert1 = SnmpAlert(alert1_id, alert_data1)
    print(alert1.toString())

    v2_endpoint = V2Endpoint(host="localhost",
                             port=162,
                             engineid='8000000001020304',
                             community='public')

    v3_user = UsmUserData(userName="myuser",
                         authKey="mymd5pass",
                         privKey="mydespass",
                         authProtocol=usmHMACMD5AuthProtocol,
                         privProtocol=usmDESPrivProtocol)

    v3_endpoint = V3Endpoint(host="localhost",
                             port=162,
                             engineid='8000000001020304',
                             usm_user = UsmUserData(
                                 userName='myuser',
                                 authKey='mymd5pass',
                                 privKey='mydespass',
                                 authProtocol=usmHMACMD5AuthProtocol,
                                 privProtocol=usmDESPrivProtocol))

    # send an alert to a list of endpoints
    sender = SnmpSender()
    sender.trapMulti([v2_endpoint, v3_endpoint], alert1)

if __name__ == "__main__":
    main()

#eof
