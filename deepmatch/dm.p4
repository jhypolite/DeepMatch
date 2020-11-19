/*
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
*/

#include "includes/headers.p4"
#include "includes/parser.p4"

/*********************
 ACTIONS
  *******************/
primitive_action processPkt();

action do_processPkt() {
    processPkt();
}

action do_forwardPacket(theport) {
    modify_field(standard_metadata.egress_spec, theport);  
}

action do_dropPacket() {
    drop();
}

/*************************
 TABLE
  ************************/
table processPkt_table {
    actions { do_processPkt; }
}

table forwardPacket_table {
    reads {
        meta.processPayloadResult : exact;
    } actions {  
        do_forwardPacket;
        do_dropPacket;
    }
}

/***********************
 CONTROL
  **********************/
control ingress {
   if(ethernet.etherType == ETHERTYPE_IPV4) {
      apply(processPkt_table);
   }
   apply(forwardPacket_table);
}
