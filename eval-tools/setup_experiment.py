'''
Copyright 2017-2020 University of Pennsylvania

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Joel Hypolite, UPenn
'''

import os
import sys
import time
import subprocess
import getopt
import configparser

config = configparser.ConfigParser()
config.read('setup_experiment.ini')

cmd_rtsym = config['deepmatch']['cmd_rtsym']
cmd_nfpmem = config['deepmatch']['cmd_nfpmem']
nfp = config['deepmatch']['nfp']
v_dfa = config['deepmatch']['v_dfa']
f_dfa = config['deepmatch']['f_dfa']
v_flow_pool = config['deepmatch']['v_flow_pool']
f_flow_pool = config['deepmatch']['f_flow_pool']
v_pkt_pool = config['deepmatch']['v_pkt_pool']
f_pkt_pool = config['deepmatch']['f_pkt_pool']

v_cputime = "_cputime"

#################
def main(choice):
    # set the dfa
    if choice in 'avd':
        result = getVar(v_dfa)
        for line in result.splitlines():
            t1 = line.split()[1].strip()
            t2 = line.split()[2].strip()
            locate = t1 + ":" + t2
            print "setting %s @ %s with %s"%(v_dfa, locate, f_dfa)
            setVar(f_dfa, locate)

    if choice in 'avs':
        # set flow_stack
        result = getVar(v_flow_pool)
        t1 = result.split()[1].strip()
        t2 = result.split()[2].strip()
        locate = t1 + ":" + t2
        print "setting %s @ %s with %s"%(v_flow_pool, locate, f_flow_pool)
        setVar(f_flow_pool, locate)

        # set pkt_stack
        result = getVar(v_pkt_pool)
        t1 = result.split()[1].strip()
        t2 = result.split()[2].strip()
        locate = t1 + ":" + t2
        print "setting %s @ %s with %s"%(v_pkt_pool, locate, f_pkt_pool)
        setVar(f_pkt_pool, locate)

    # check cputime and start the time writer
    if choice in 'at':
        result = getVar(v_cputime)
        t1 = result.split()[1].strip()
        t2 = result.split()[2].strip()
        locate = t1 + ":" + t2
        print "setting %s @ %s with epoch_times"%(v_cputime, locate)
        cputime(locate)

def getVar(svar):
    rtsym = subprocess.Popen([cmd_rtsym, '-n', str(nfp), '-L'], stdout=subprocess.PIPE,)
    grep = subprocess.Popen(['grep', svar], stdin=rtsym.stdout, stdout=subprocess.PIPE,)

    out, err = grep.communicate()
    result = out.decode()
    return result

def setVar(fname, locate):
    nfpmem = subprocess.check_output([cmd_nfpmem, '-n', str(nfp), '-i', fname, '-w', str(4), locate])

def cputime(locate):
    while True:
      epoch_time = int(time.time())
      if epoch_time%10 == 0:
          print "setting %s @ %s with epoch_time=%s [%d]"%(v_cputime, locate, hex(epoch_time), epoch_time)

      nfpmem= subprocess.check_output([cmd_nfpmem, '-n', str(nfp), '-w', str(4), locate, hex(epoch_time)])
      time.sleep(1)

#########################################
# uage: ./
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s -o [a|v|d|s|t]"%sys.argv[0])
        print("    [a : all], [v : set dfa and stack], [d: set dfa], [s: set stack], [t : time]")
        exit(1)

    myopts, args = getopt.getopt(sys.argv[1:],"o:")
    for o,a in myopts:
        if o == '-o':
            main(a)
        else:
            print("Usage: %s -o [a|v|d|s|t]"%sys.argv[0])
            print("    [a : all], [v : set dfa and stack], [d: set dfa], [s: set stack], [t : time]")
