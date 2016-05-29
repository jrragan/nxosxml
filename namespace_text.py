from lxml import etree
output = """<?xml version="1.0" encoding="ISO-8859-1"?>
<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nxos="http://www.cisco.com/nxos:1.0" message-id="364244">
  <nc:data>
    <show>
      <version>
        <__XML__OPT_Cmd_sysmgr_show_version___readonly__>
          <__readonly__>
            <header_str>Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
Copyright (c) 2002-2012, Cisco Systems, Inc. All rights reserved.
The copyrights to certain works contained herein are owned by
other third parties and are used and distributed under license.
Some parts of this software are covered under the GNU Public
License. A copy of the license is available at
http://www.gnu.org/licenses/gpl.html.
</header_str>
            <bios_ver_str>3.6.0</bios_ver_str>
            <loader_ver_str>N/A</loader_ver_str>
            <kickstart_ver_str>5.2(1)N1(1)</kickstart_ver_str>
            <sys_ver_str>5.2(1)N1(1)</sys_ver_str>
            <power_seq_ver_str>Module 1: version v1.0</power_seq_ver_str>
            <power_seq_ver_str>             Module 2: version v1.0</power_seq_ver_str>
            <power_seq_ver_str>             Module 3: version v2.0</power_seq_ver_str>
            <ucontroller_ver_str>v1.2.0.1</ucontroller_ver_str>
            <power_seq_ver_str>Module 1: v1.0.0.0</power_seq_ver_str>
            <bios_cmpl_time>05/09/2012</bios_cmpl_time>
            <kick_file_name>bootflash:///n5000-uk9-kickstart.5.2.1.N1.1.bin</kick_file_name>
            <kick_cmpl_time> 7/12/2012 19:00:00</kick_cmpl_time>
            <kick_tmstmp>07/12/2012 22:08:13</kick_tmstmp>
            <isan_file_name>bootflash:///n5000-uk9.5.2.1.N1.1.bin</isan_file_name>
            <isan_cmpl_time> 7/12/2012 19:00:00</isan_cmpl_time>
            <isan_tmstmp>07/12/2012 23:23:16</isan_tmstmp>
            <chassis_id>Nexus5548 Chassis</chassis_id>
            <module_id>O2 32X10GE/Modular Universal Platform Supervisor</module_id>
            <cpu_name>Intel(R) Xeon(R) CPU        </cpu_name>
            <memory>8263848</memory>
            <mem_type>kB</mem_type>
            <proc_board_id>FOC15410UQJ</proc_board_id>
            <host_name>atl-za-nf02-sw01</host_name>
            <bootflash_size>2007040</bootflash_size>
            <kern_uptm_days>414</kern_uptm_days>
            <kern_uptm_hrs>18</kern_uptm_hrs>
            <kern_uptm_mins>9</kern_uptm_mins>
            <kern_uptm_secs>25</kern_uptm_secs>
            <rr_usecs>174987</rr_usecs>
            <rr_ctime> Thu Jan 10 05:49:54 2013
</rr_ctime>
            <rr_reason>Reset due to upgrade</rr_reason>
            <rr_sys_ver>5.0(3)N2(1)</rr_sys_ver>
            <rr_service></rr_service>
          </__readonly__>
        </__XML__OPT_Cmd_sysmgr_show_version___readonly__>
      </version>
    </show>
  </nc:data>
</nc:rpc-reply>"""

parser = etree.XMLParser(remove_blank_text=True)
versionparsed = etree.fromstring(output, parser=parser)

def find_element(tag, schema, parsed_doc):
    if isinstance(tag, str):
        tag = [tag]
    tags = ["{{{0}}}{1}".format(schema, t) for t in tag]
    content = {}
    print tag
    for element in parsed_doc.iter():
        print element.tag
        if element.tag in tags:
            t = tag[tags.index(element.tag)]
            content[t] = element.text
    print content
    return content


