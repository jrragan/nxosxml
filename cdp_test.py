from lxml import etree
cdpoutput = """<?xml version="1.0" encoding="ISO-8859-1"?>
<nf:rpc-reply xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="http://www.cisco.com/nxos:1.0:cdpd">
 <nf:data>
  <show>
   <cdp>
    <neighbors>
     <__XML__OPT_Cmd_show_cdp_neighbors_detail___readonly__>
      <__readonly__>
       <TABLE_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>83886080</ifindex>
         <device_id>atl-za-nf02-sw02.homedepot.com(SSI1519065P)</device_id>
         <sysname>atl-za-nf02-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>10.255.255.2</v4addr>
         <platform_id>N5K-C5548UP</platform_id>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>mgmt0</intf_id>
         <port_id>mgmt0</port_id>
         <ttl>162</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 5.2(1)N1(1)</version>
         <version_no>v2</version_no>
         <duplexmode>full</duplexmode>
         <mtu>1500</mtu>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.255.255.2</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436330496</ifindex>
         <device_id>atl-za-nf02-sw02.homedepot.com(SSI1519065P)</device_id>
         <sysname>atl-za-nf02-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>10.255.255.2</v4addr>
         <platform_id>N5K-C5548UP</platform_id>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet1/31</intf_id>
         <port_id>Ethernet1/31</port_id>
         <ttl>162</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 5.2(1)N1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>1500</mtu>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.255.255.2</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436334592</ifindex>
         <device_id>atl-za-nf02-sw02.homedepot.com(SSI1519065P)</device_id>
         <sysname>atl-za-nf02-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>10.255.255.2</v4addr>
         <platform_id>N5K-C5548UP</platform_id>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet1/32</intf_id>
         <port_id>Ethernet1/32</port_id>
         <ttl>162</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 5.2(1)N1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>1500</mtu>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.255.255.2</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436731904</ifindex>
         <device_id>atl-za-agg-sw01.homedepot.com(JAF1443BPDK)</device_id>
         <sysname>atl-za-agg-sw01</sysname>
         <numaddr>1</numaddr>
         <v4addr>165.130.80.2</v4addr>
         <platform_id>N7K-C7010</platform_id>
         <capability>router</capability>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/1</intf_id>
         <port_id>Ethernet2/19</port_id>
         <ttl>152</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 6.1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>0</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.1.1.103</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436736000</ifindex>
         <device_id>atl-za-agg-sw01.homedepot.com(JAF1443BPDK)</device_id>
         <sysname>atl-za-agg-sw01</sysname>
         <numaddr>1</numaddr>
         <v4addr>165.130.80.2</v4addr>
         <platform_id>N7K-C7010</platform_id>
         <capability>router</capability>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/2</intf_id>
         <port_id>Ethernet2/20</port_id>
         <ttl>152</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 6.1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>0</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.1.1.103</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436740096</ifindex>
         <device_id>atl-za-agg-sw02.homedepot.com(JAF1427DFLC)</device_id>
         <sysname>atl-za-agg-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>165.130.80.3</v4addr>
         <platform_id>N7K-C7010</platform_id>
         <capability>router</capability>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/3</intf_id>
         <port_id>Ethernet2/19</port_id>
         <ttl>171</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 6.1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>0</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.1.1.102</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436744192</ifindex>
         <device_id>atl-za-agg-sw02.homedepot.com(JAF1427DFLC)</device_id>
         <sysname>atl-za-agg-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>165.130.80.3</v4addr>
         <platform_id>N7K-C7010</platform_id>
         <capability>router</capability>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/4</intf_id>
         <port_id>Ethernet2/20</port_id>
         <ttl>171</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 6.1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>0</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.1.1.102</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436748288</ifindex>
         <device_id>atl-za-nf02-sw02.homedepot.com(SSI1519065P)</device_id>
         <sysname>atl-za-nf02-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>10.255.255.2</v4addr>
         <platform_id>N5K-C5548UP</platform_id>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/5</intf_id>
         <port_id>Ethernet2/5</port_id>
         <ttl>162</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 5.2(1)N1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>1500</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.255.255.2</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>436752384</ifindex>
         <device_id>atl-za-nf02-sw02.homedepot.com(SSI1519065P)</device_id>
         <sysname>atl-za-nf02-sw02</sysname>
         <numaddr>1</numaddr>
         <v4addr>10.255.255.2</v4addr>
         <platform_id>N5K-C5548UP</platform_id>
         <capability>switch</capability>
         <capability>IGMP_cnd_filtering</capability>
         <capability>unknown enum:&lt;10&gt;</capability>
         <intf_id>Ethernet2/6</intf_id>
         <port_id>Ethernet2/6</port_id>
         <ttl>162</ttl>
         <version>Cisco Nexus Operating System (NX-OS) Software, Version 5.2(1)N1(1)</version>
         <version_no>v2</version_no>
         <nativevlan>1</nativevlan>
         <duplexmode>full</duplexmode>
         <mtu>1500</mtu>
         <syslocation>snmplocation</syslocation>
         <num_mgmtaddr>1</num_mgmtaddr>
         <v4mgmtaddr>10.255.255.2</v4mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
        <ROW_cdp_neighbor_detail_info>
         <ifindex>526582976</ifindex>
         <device_id>5cf3fc25619b</device_id>
         <sysname>nsnac04</sysname>
         <numaddr>1</numaddr>
         <v4addr>165.130.209.48</v4addr>
         <platform_id>CSACS-1121-K9</platform_id>
         <capability>host</capability>
         <intf_id>Ethernet100/1/20</intf_id>
         <port_id>eth0</port_id>
         <ttl>140</ttl>
         <version>Cisco Application Deployment Engine OS version: 2.0.3.058 Copyright (c) 2013 Cisco Systems.</version>
         <version_no>v2</version_no>
         <mtu>0</mtu>
         <num_mgmtaddr>0</num_mgmtaddr>
        </ROW_cdp_neighbor_detail_info>
       </TABLE_cdp_neighbor_detail_info>
      </__readonly__>
     </__XML__OPT_Cmd_show_cdp_neighbors_detail___readonly__>
    </neighbors>
   </cdp>
  </show>
 </nf:data>
</nf:rpc-reply>"""

def find_element(tag, schema, parsed_doc):
    """
    Takes a tag or list of tags, a schema and lxml object, returns a list of content for all instances of tag

    @param tag: str or list of str
    @param schema: str
    @param parsed_doc: object
    @return: dict of form {taq : content}
    """
    if isinstance(tag, str):
        tag = [tag]
    tags = ["{0}{1}".format(schema, t) for t in tag]
    content = {}
    for element in parsed_doc.iter():
        if element.tag in tags:
            t = tag[tags.index(element.tag)]
            content[t.replace('-', '_')] = element.text
    return content

def parse_xml_heirarchy(htag, tag, schema, parsed_doc):
    """

    @param htag: str, tag to indicate place heirarchy
    @param tag: str or list of str, tags to find within the heirarchy
    @param schema: str
    @param parsed_doc: object
    @return: list of dictionaries [{taq : content}]
    """
    content = []
    for element in parsed_doc.iter("{0}{1}".format(schema, htag)):
        v = find_element(tag, schema, element)
        content.append(v)
    return content


def parse_get_nsmap(parsed_doc):
    """

    @param parsed_doc:
    """
    nsdict = parsed_doc.nsmap
    if None in nsdict:
        return "{{{}}}".format(nsdict[None])
    else:
        return ''

parser = etree.XMLParser(remove_blank_text=True)
cdpparsed = etree.fromstring(cdpoutput, parser=parser)

CDPSCHEMA = parse_get_nsmap(cdpparsed)

cdplist = parse_xml_heirarchy('ROW_cdp_neighbor_detail_info', ['device_id', 'v4addr', 'platform_id', 'intf_id', 'port_id', 'version', 'v4mgmtaddr'], CDPSCHEMA, cdpparsed)

print cdplist

