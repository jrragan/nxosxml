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

auszaaggsw1 = nexusswitch.NxosSwitch("7k1")
auszaaggsw1.connect(username='admin', password='cisco')
auszaaggsw1.show_hostname()
auszaaggsw1.show_chassis_id()
auszaaggsw1.show_system_version()
auszaaggsw1.show_vdcs()
auszaaggsw1.show_vdcs_detail()
auszaaggsw1.switchto_vdc('FPATH')
auszaaggsw1.get_vlans_detail(vdc='all')

auszaaggsw1.show_vlans_list(vdc='all')
