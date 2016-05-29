import nexusswitch
import functools
import itertools
import traceback
from lxml import etree
import sys
import logging

LOGFILE = "productiontest.log"
SCREENLOGLEVEL = logging.DEBUG
FILELOGLEVEL = logging.DEBUG

logger = logging.getLogger()
logger.setLevel(SCREENLOGLEVEL)
logformat = logging.Formatter('%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')
logh = logging.FileHandler(LOGFILE)
logh.setLevel(FILELOGLEVEL)

ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(SCREENLOGLEVEL)

logh.setFormatter(logformat)

ch.setFormatter(logformat)

logger.addHandler(logh)
logger.addHandler(ch)

logger.info("Started")

sw1 = nexusswitch.NxosSwitch("switch1")
sw2 = nexusswitch.NxosSwitch("switch2")
sw1.connect(username='admin', password='cisco', command_timeout=300)
sw2.connect(username='admin', password='cisco', command_timeout=300)

sw1.show_hostname()
sw1.show_chassis_id()
sw1.show_system_version()

sw2.show_hostname()
sw2.show_chassis_id()
sw2.show_system_version()

##sw1.get_interfaces()
##sw2.get_interfaces()
##
##def find_element(tag, schema, parsed_doc):
##    """
##    Takes a tag or list of tags, a schema and lxml object, returns a list of content for all instances of tag
##
##    @param tag: str or list of str
##    @param schema: str
##    @param parsed_doc: object
##    @return: dict of form {taq : content}
##    """
##    if isinstance(tag, str):
##        tag = [tag]
##    tags = ["{0}{1}".format(schema, t) for t in tag]
##    content = {}
##    for element in parsed_doc.iter():
##        if element.tag in tags:
##            t = tag[tags.index(element.tag)].replace('-', '_')
##            if t in content:
##                if isinstance(content[t], str):
##                    content[t] = [content[t], element.text]
##                else:
##                    content[t].append(element.text)
##            else:
##                content[t] = element.text
##    return content
##
##def parse_get_nsmap(parsed_doc):
##    """
##
##    @param parsed_doc:
##    """
##    nsdict = parsed_doc.nsmap
##    if 'mod' in nsdict:
##        return "{{{}}}".format(nsdict['mod'])
##    elif None in nsdict:
##        return "{{{}}}".format(nsdict[None])
##    else:
##        return ''
##
##
##def macparser(xmldoc, switch=None):
##    parser = etree.XMLParser(remove_blank_text=True)
##    macparsed = etree.fromstring(xmldoc, parser=parser)
##    macschema = parse_get_nsmap(macparsed)
##    macdict = find_element(['disp_mac_addr', 'disp_vlan', 'disp_type', 'disp_port'], macschema, macparsed)
##    if 'disp_mac_addr' in macdict:
##        macstr = "Mac address {} in vlan {} on port {}, type {}\n".format(macdict['disp_mac_addr'], macdict['disp_vlan'], macdict['disp_port'], macdict['disp_type'])
##        if 'po' in macdict['disp_port']:
##            macstr = macstr + "    {} ports: {}\n".format(macdict['disp_port'], switch.vdcs[switch.current_vdc].interfaces[macdict['disp_port'].title()].port_channel_members)
##        return macstr
##    else:
##        return None
##
##print sw1.show_command_multiple('show mac address-table address', ('0010.0401.3394', '0010.0401.3395', '0010.0401.3384',
##                                                             '0010.0401.3385', '90:e2:ba:36:47:f8',
##                                                             '90:e2:ba:36:47:f9', '90:e2:ba:36:50:30', '90:e2:ba:36:50:31',
##                                                             '0025.9097.0fac', '0025.9097.0fad', '0025.9061.1604',
##                                                             '0025.9061.1605', '0025.9097.0f56', '0025.9097.0f57',
##                                                             '0025.9096.5efe', '0025.9096.5eff', '0025.9097.10d6',
##                                                             '0025.9097.10d7', '0025.9097.0e14', '0025.9097.0e15',
##                                                             '0025.9069.860e', '0025.9069.860f', '0025.9091.1710',
##                                                             '0025.9091.1711', '0025.9091.6576', '0025.9091.6577',
##                                                             '90e2.ba2c.a048', '90e2.ba2c.a049', '90e2.ba2c.a024',
##                                                             '90e2.ba2c.a025', '90e2.ba2c.9e58', '90e2.ba2c.9e59',
##                                                             '0025.9091.1772', '0025.9091.1773', '0025.9091.1724',
##                                                             '0025.9091.170a', '0025.9091.170b'), parser=macparser, optdict={'switch' : sw1})
##print
##print
##print
##print
##print sw2.show_command_multiple('show mac address-table address', ('0010.0401.3394', '0010.0401.3395', '0010.0401.3384',
##                                                             '0010.0401.3385', '90:e2:ba:36:47:f8',
##                                                             '90:e2:ba:36:47:f9', '90:e2:ba:36:50:30', '90:e2:ba:36:50:31',
##                                                             '0025.9097.0fac', '0025.9097.0fad', '0025.9061.1604',
##                                                             '0025.9061.1605', '0025.9097.0f56', '0025.9097.0f57',
##                                                             '0025.9096.5efe', '0025.9096.5eff', '0025.9097.10d6',
##                                                             '0025.9097.10d7', '0025.9097.0e14', '0025.9097.0e15',
##                                                             '0025.9069.860e', '0025.9069.860f', '0025.9091.1710',
##                                                             '0025.9091.1711', '0025.9091.6576', '0025.9091.6577',
##                                                             '90e2.ba2c.a048', '90e2.ba2c.a049', '90e2.ba2c.a024',
##                                                             '90e2.ba2c.a025', '90e2.ba2c.9e58', '90e2.ba2c.9e59',
##                                                             '0025.9091.1772', '0025.9091.1773', '0025.9091.1724',
##                                                             '0025.9091.170a', '0025.9091.170b'), parser=macparser, optdict={'switch' : sw2})
##
##def parse_xml_heirarchy(htag, tag, schema, parsed_doc):
##    """
##
##    @param htag: str, tag to indicate place heirarchy
##    @param tag: str or list of str, tags to find within the heirarchy
##    @param schema: str
##    @param parsed_doc: object
##    @return: list of dictionaries [{taq : content}]
##    """
##    content = []
##    for element in parsed_doc.iter("{0}{1}".format(schema, htag)):
##        v = find_element(tag, schema, element)
##        content.append(v)
##    return content
##
##def fex_parser(xmldoc):
##    parser = etree.XMLParser(remove_blank_text=True)
##    fexparsed = etree.fromstring(xmldoc, parser=parser)
##    fexschema = parse_get_nsmap(fexparsed)
##    fexinfos = find_element('chas_id', fexschema, fexparsed)
##    fexlist = parse_xml_heirarchy('TABLE_fbr_state', ['fbr_index'], fexschema, fexparsed)
##    output = ''
##    for i in range(len(fexinfos['chas_id'])):
##        output = output + 'FEX {}\n'.format(fexinfos['chas_id'][i])
##        output = output + '    Fabric Interfaces: {}\n'.format(str(fexlist[i]['fbr_index']))
##    return output
##        
##    
##    
##
##print
##print
##print
##print
##print sw1._send_xml_cli_show('show queuing interface | egrep "discarded|information"')
##print
##print
##print
##print
##print sw2._send_xml_cli_show('show queuing interface | egrep "discarded|information"')
##print
##print
##print
##print
##print sw1.show_command_multiple('show queuing interface', ('Ethernet109/1/11', 'Ethernet109/1/12', 'Ethernet109/1/10', 'Ethernet103/1/19', 'Ethernet103/1/18', 'Ethernet103/1/17',
##                                                        'Ethernet103/1/16', 'Ethernet103/1/15', 'Ethernet103/1/14', 'Ethernet103/1/6', 'Ethernet109/1/8', 'Ethernet109/1/7',
##                                                        'Ethernet109/1/6', 'Ethernet109/1/5', 'Ethernet109/1/4', 'Ethernet109/1/3', 'Ethernet109/1/2', 'Ethernet109/1/1'))
##print
##print
##print
##print
##print sw2.show_command_multiple('show queuing interface', ('Ethernet109/1/11', 'Ethernet109/1/11', 'Ethernet109/1/9', 'Ethernet109/1/10', 'Ethernet103/1/19', 'Ethernet103/1/18',
##                                                        'Ethernet103/1/17', 'Ethernet103/1/16', 'Ethernet103/1/15', 'Ethernet103/1/14', 'Ethernet103/1/6', 'Ethernet109/1/8',
##                                                        'Ethernet109/1/7', 'Ethernet109/1/6', 'Ethernet109/1/5', 'Ethernet109/1/4', 'Ethernet109/1/3', 'Ethernet109/1/1'))
##print
##print
##print
##print
##print sw1.show_command_multiple('show fex detail', '', parser=fex_parser)
##print
##print
##print
##print
##print sw2.show_command_multiple('show fex detail', '', parser=fex_parser)

                                
