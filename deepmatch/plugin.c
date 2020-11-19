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

#include <stdint.h>
#include <nfp/me.h>
#include <memory.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <pif_plugin.h>
#include <std/hash.h>
#include <pktdma/pktdma.h>
#include "includes/dmx_options.h"


///////////////////////////////////////////////////////
__inline uint8_t check_tcp_http(uint16_t dport) {
    uint8_t start, end, middle;
    uint8_t size = sizeof(httpPorts)/sizeof(uint16_t);
    end = size - 1;

    start = 0;
    while (start <= end) {
        middle = start + (end - start)/2;
        if(dport == httpPorts[middle]) {
            return 1;
        } else if (httpPorts[middle] > dport) {
            end = middle - 1;
        } else {
            start = middle + 1;
        }
    }
    return 0;
}

////////////////////////////////////////////////////////////
/*
tcp-flags
 S: 0x02
 A: 0x10
 F: 0x01
 R: 0x04
*/
__inline uint8_t fsm_trans(uint8_t fsm_state, uint8_t tcp_flags) {
    if ( (fsm_state == FSM_0) && (tcp_flags & 0x02) && (tcp_flags & 0x10) ) { // 0, SYN-ACK
        return FSM_E;
    } else if ( (fsm_state == FSM_C) && (tcp_flags & 0x02) && (tcp_flags & 0x10) ) { // C, SYN-ACK
        return FSM_E;
    } else if ( (fsm_state == FSM_0) && (tcp_flags & 0x02) ) { // 0, SYN
        return FSM_S;
    } else if ( (fsm_state == FSM_C) && (tcp_flags & 0x02) ) { // C, SYN
        return FSM_S;
    } else if ( (fsm_state == FSM_S) && !(tcp_flags & 0x01) && !(tcp_flags & 0x02) && !(tcp_flags & 0x04) ) {
        return FSM_E;
    } else if ( (fsm_state == FSM_E) && !(tcp_flags & 0x01) && !(tcp_flags & 0x02) && !(tcp_flags & 0x04) ) {
        return FSM_E;
    } else if ( (tcp_flags & 0x01) && !(fsm_state == FSM_C) && !(fsm_state == FSM_W) ) {    // FIN
        return FSM_F;
    } else if ( (fsm_state == FSM_W) && (tcp_flags & 0x01) ) {    // FIN
        return FSM_C;
    } else if (fsm_state == FSM_F) {    // FIN
        return FSM_C;
    } else if (tcp_flags & 0x04) {    // RST
        return FSM_C;
    } else {
        return fsm_state;
    }
}


////////////////////////////////////////////////////////////
__inline void init_flow_ht(uint16_t flow_id) {
#if defined(PHAST_ATOMIC_OPS)
    memset_mem((__mem void *)&flow_ht[flow_id].value, 0, 8);
#else
    flow_ht[flow_id].ctrl_bits.active = TRUE;      
    flow_ht[flow_id].ctrl_bits.eseq_valid = FALSE;
    flow_ht[flow_id].value.oooqLen = 0;
    flow_ht[flow_id].value.cs = 0;
    flow_ht[flow_id].value.eseq = 0;
#endif
}

///////////////////////////////////////////////////////
__inline uint8_t select_dfa(uint16_t tcp_dport, uint8_t dfa_choice) {
#if defined(PHAST_DFA_MAL_BACKDOOR)
    if (dfa_choice == 0) {   // tcp
        if (check_tcp_http(tcp_dport) == 0) {
            dfa_choice = 1;
        }
    }
#elif defined(PHAST_DFA_MAL_OTHER)
    if (dfa_choice == 0) {  // tcp
        if (tcp_dport == 25) {
            dfa_choice = 1;
        } else if (check_tcp_http(tcp_dport) == 0) {
            dfa_choice = 2;
        }
    } else if (dfa_choice == 1) {  // udp
            dfa_choice = 3;
    }
#elif defined(PHAST_DFA_MAL_CNC)
    if (dfa_choice == 0) {  // tcp
        if (check_tcp_http(tcp_dport) == 0) {
            dfa_choice = 1;
        }
    } else if (dfa_choice == 1) {  // udp
        dfa_choice = 2;
    } else if (dfa_choice == 2) {  // icmp
        dfa_choice = 3;
    }
#endif

    return dfa_choice;  // default if nothing hits
}


///////////////////////////////////////////////////////
__inline uint16_t get_flow_hash(EXTRACTED_HEADERS_T *headers, uint8_t rev_head) { 
    PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
    PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
    uint32_t  hash_key[3];
    volatile uint32_t hv, hv_high;
    volatile uint16_t hv_low;   // hash_value for flow id

    // identify the flow for this packet
    if (rev_head == TRUE) {  // account for tcp->flag=RST
        hash_key[0] = ipv4->dstAddr;
        hash_key[1] = ipv4->srcAddr;
        hash_key[2] = (tcp->dstPort << 16) | tcp->srcPort;
    } else {
        hash_key[0] = ipv4->srcAddr;
        hash_key[1] = ipv4->dstAddr;
        hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
    }

    hv = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
    hv_high = (hv & FLOW_HASH_HIGH) >> FLOW_HASH_SHIFT;
    hv_low = hv & FLOW_HASH_LOW;
    hv_low ^= (uint16_t) hv_high;

    return (hv_low & FLOW_HASH_TABLE_SIZE);
}

///////////////////////////////////////////////////////
__inline uint16_t get_pkt_hash(EXTRACTED_HEADERS_T *headers, uint32_t tcp_seq, uint8_t rev_head) { 
    PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
    PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
    uint32_t  hash_key[4];
    volatile uint32_t hv, hv_high;
    volatile uint16_t hv_low;   // hash_value for flow id

    // identify the flow for this packet
    if (rev_head == TRUE) {  // account for tcp->flag=RST
        hash_key[0] = ipv4->dstAddr;
        hash_key[1] = ipv4->srcAddr;
        hash_key[2] = (tcp->dstPort << 16) | tcp->srcPort;
    } else {
        hash_key[0] = ipv4->srcAddr;
        hash_key[1] = ipv4->dstAddr;
        hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
    }
    hash_key[3] = tcp_seq;

    hv = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
    hv_high = (hv & PKT_HASH_HIGH) >> PKT_HASH_SHIFT;
    hv_low = hv & PKT_HASH_LOW;
    hv_low = (uint16_t) hv_high;

    return (hv_low & PKT_HASH_TABLE_SIZE);
}


///////////////////////////////////////////////////////
void delete_ooo (EXTRACTED_HEADERS_T *headers, uint16_t flow_id) { 
    if (flow_ht[flow_id].value.oooqLen == 0) {
        return;
    } else {
        PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
        PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
        __xrw uint32_t gen_xfer;      // test-set-lock register
        __xrw uint32_t pstack_xfer;      // test-set-lock register
        __xwrite uint32_t clear_mem[4] = {0};
        uint16_t i;

        for(i=0; i<FLOW_PARTION_SZ; i++) {
            if(pkt_ht[flow_ht[flow_id].partition][i].ctrl_bits.active == TRUE) {
                // delete the pkt_ht entry
#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- packet ////
                gen_xfer = 1;
                while(1) {
                    mem_test_set(&gen_xfer,  (__mem void *)(p_lock[flow_ht[flow_id].partition]+i), sizeof(gen_xfer));
                    if(gen_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif

               // clear an entry
               mem_write_atomic(clear_mem, &pkt_ht[flow_ht[flow_id].partition][i], sizeof(clear_mem));

#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- pstack ////
                pstack_xfer = 1;
                while(1) {
                    mem_test_set(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[flow_id].partition], sizeof(pstack_xfer));
                    if(pstack_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif

                p_dealloc(flow_ht[flow_id].partition, i);

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- pstack ///
                pstack_xfer = 0;
                mem_write_atomic(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[flow_id].partition], sizeof(pstack_xfer));
                ////////////////////
#endif  

#if defined(PHAST_ATOMIC_OPS)
                mem_decr32((__mem void *)&flow_ht[flow_id].value.oooqLen);
#else
                flow_ht[flow_id].value.oooqLen -= 1;
#endif

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- packet ///
                gen_xfer = 0;
                mem_write_atomic(&gen_xfer,  (__mem void *)(p_lock[flow_ht[flow_id].partition]+i), sizeof(gen_xfer));
                ////////////////////
#endif

            }
        } 
    }
}


///////////////////////////////////////////////////////
// opts (bit1:process_flow and bit2:checking_ooo): 0=F/F,  1=T/F, 2=F/T, 3=T/T
// opts (bits 7 and 8 are checked only if not-TCP): only_7_set: icmp, only_8_set: udp, neither_set: ipv4
// return retval: bit1: miss/hit, bits 17-32: tcs (current state)
uint32_t dm_loop(EXTRACTED_HEADERS_T *headers, uint16_t flow_id, uint16_t cstate, uint16_t i_start, uint16_t psize, uint8_t opts) { 
        PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
        __xread uint32_t pl_data[CHUNK_LW];
        __lmem uint32_t pl_mem;
        uint32_t retval = 0;
        uint16_t i, val, tcs;
        uint8_t to_read;

        uint8_t fs_check;
        __mem uint8_t *payload;

        val = 0;
        if(DM_BIT_CHECK(opts, 0)) {    //    if (process_flow == TRUE) { 
            if (tcp->flags & 0x02) {
                tcs = 0;
            } else {
                tcs = cstate; 
            }
       
            fs_check = select_dfa((flow_ht[flow_id].key[2] & 0x0000FFFF), 0);  // pass flow.dport; protocol must be TCP
        } else {
            tcs = 0;
            if(pif_plugin_hdr_udp_present(headers)) {
                fs_check = select_dfa(0,1);  // not tcp so ignore the port, set udp(1)
            } else if(pif_plugin_hdr_icmp_present(headers)) {
                fs_check = select_dfa(0,2);  // not tcp so ignore the port, set icmp(2)
            } else if(pif_plugin_hdr_tcp_present(headers)) {       //  For TCP when xflow is turned off
                fs_check = select_dfa(tcp->dstPort,0);
            } else {
                fs_check = select_dfa(0,3);  // not tcp so ignore the port, set ipv4(3)
            }
        }

        if(DM_BIT_CHECK(opts, 1)) {       //    if (checking_ooo == TRUE) {
            payload = (__mem uint8_t *)ctm_checker;
            payload += i_start;
        } else {
            // get pointer to payload
            payload = pif_pkt_info_global.pkt_buf;
            payload += pif_pkt_info_global.pkt_pl_off;
        }

        while (psize) {
            to_read = (psize > CHUNK_B) ? CHUNK_B : psize; 
            mem_read8(&pl_data, payload, to_read);

            payload += to_read;
            psize -= to_read;

            for (i=0; i < CHUNK_LW; i++) {
                pl_mem = pl_data[i];

                tcs = dfa_trans[0][tcs][(pl_mem >> 24) & 0xff];
                val |= tcs;
                if (--to_read == 0) {
                    break;
                }

                tcs = dfa_trans[0][tcs][(pl_mem >> 16) & 0xff];
                val |= tcs;
                if (--to_read == 0) {
                    break;
                }

                tcs = dfa_trans[0][tcs][(pl_mem >> 8) & 0xff];
                val |= tcs;
                if (--to_read == 0) {
                    break;
                }

                tcs = dfa_trans[0][tcs][pl_mem & 0xff];
                val |= tcs;
                if (--to_read == 0) {
                    break;
                }
            }

        }

        retval = (tcs << 16) | (val >> 15);	
        return retval;    // retval holds 1) current DFA state, 2) DFA result: HIT/MISS
}


///////////////////////////////////////////////////////
uint8_t process_ooo(EXTRACTED_HEADERS_T *headers, uint16_t flow_id, uint16_t hv_flow) {

    // do not process  ooo_queue if eseq_valid is false
    if ( flow_ht[flow_id].ctrl_bits.eseq_valid == FALSE) {
        return FALSE;
    } else {
        PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
        PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
        uint32_t retval=0;

        // read eseaq here in case some other thread updates it when we lose the lock later
        uint32_t c_eseq = flow_ht[flow_id].value.eseq;

#if defined(PHAST_LOCK)
        // test set lock register
        __xrw uint32_t gen_xfer;
        __xrw uint32_t pstack_xfer;
#endif
        volatile uint16_t hv_pkt;  // hash_value for packet storage
        uint16_t p_bucket, p_p_bucket;
        uint8_t p_found_entry;

        while (flow_ht[flow_id].value.oooqLen > 0) {
            p_p_bucket = 0;
            p_found_entry = FALSE;
            hv_pkt = get_pkt_hash(headers, c_eseq, FALSE);

            ////////////////////////////////////////////////////////////////////////////////////
            // PKT BUCKET: Find the bucket
            p_bucket = pht_idx[flow_ht[flow_id].partition][hv_pkt];

            while(p_bucket != 0) {
                //  the current live packet idetifies the flow-packet-pool to check against
                if( (flow_ht[flow_id].key[0] == ipv4->srcAddr) && 
                    (flow_ht[flow_id].key[1] == ipv4->dstAddr) &&
                    (flow_ht[flow_id].key[2] == (tcp->srcPort << 16) | tcp->dstPort) &&
                    (pkt_ht[flow_ht[flow_id].partition][p_bucket].key == c_eseq) ) {
                    p_found_entry = TRUE;
                    break;
                } else {
                    p_p_bucket = p_bucket;
                    p_bucket = pkt_ht[flow_ht[flow_id].partition][p_bucket].next_loc;
                }
            }

            // PKT BUCKET: should have correct bucket now
            ///////////////////////////////////////////////////////////////////////////////////
            if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.active == TRUE) {
                __xwrite uint32_t clear_mem[4] = {0};

                if(pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len == 0) {

                    uint8_t t_flags = 0;

                    if( pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.fin == TRUE ) { 
#if defined(PHAST_ATOMIC_OPS)
                        mem_incr32((__mem void *)&flow_ht[flow_id].value.eseq);
#else
                        c_eseq++;
#endif                     
                        DM_BIT_SET(retval, DM_HANDLE_FIN);  
                    } else if( pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.rst == TRUE ) { 
                        DM_BIT_SET(retval, DM_HANDLE_RST);   
                    }
                    if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.fin == TRUE) {
                        t_flags |= (1 << 0);
                    }
                    if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.syn == TRUE) {
                        t_flags |= (1 << 1);
                    }
                    if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.rst == TRUE) {
                        t_flags |= (1 << 2);
                    }
                    if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.ack == TRUE) {
                        t_flags |= (1 << 4);
                    }
                    flow_ht[flow_id].ctrl_bits.FSM = fsm_trans(flow_ht[flow_id].ctrl_bits.FSM, t_flags); 

                } else if(pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len > 0) {
                    uint16_t cstate = flow_ht[flow_id].value.cs;

#if defined(PHAST_LOCK)
                    // RELEASE MUTEX -- flow ///
                    pstack_xfer = 0;
                    mem_write_atomic(&pstack_xfer,(__mem void *)(f_lock+hv_flow), sizeof(pstack_xfer));
                    ////////////////////
#endif

                    // get the packet
                    pktdma_mu_to_ctm(ctm_checker, (__mem void *)emem_pool[flow_ht[flow_id].partition][p_bucket], OOO_SLOT_SIZE);

                    // process the packet
                    retval = dm_loop(headers, flow_id, cstate, pkt_ht[flow_ht[flow_id].partition][p_bucket].value.offset, pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len, 3);


#if defined(PHAST_LOCK)
                    // AQUIRE MUTEX -- flow ////
                    pstack_xfer = 1;
                    while(1) {
                        mem_test_set(&pstack_xfer, (__mem void *)(f_lock+hv_flow), sizeof(pstack_xfer));
                        if(pstack_xfer == 0) {
                            break;
                        }
                        sleep(LOCK_SLEEP);
                    }
                    ////////////////////
#endif

                    if(DM_BIT_CHECK(retval, DM_RESULT)) {     // fs_check==HIT                         
                        if( pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.fin == TRUE ) {
                            c_eseq = c_eseq + pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len + 1;
                            DM_BIT_SET(retval, DM_HANDLE_FIN);   
                        } else { 
                            c_eseq = c_eseq + pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len;
                        }

                       flow_ht[flow_id].ctrl_bits.FSM = FSM_C;
                    } else {
                        uint8_t t_flags = 0;

                        if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.fin == TRUE) {
                            t_flags |= (1 << 0);
                        }
                        if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.syn == TRUE) {
                            t_flags |= (1 << 1);
                        }
                        if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.rst == TRUE) {
                            t_flags |= (1 << 2);
                        }
                        if (pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.ack == TRUE) {
                            t_flags |= (1 << 4);
                        }

                        if( pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.fin == TRUE ) { 
                            c_eseq = c_eseq + pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len + 1;
                            DM_BIT_SET(retval, DM_HANDLE_FIN);    
                        } else if( pkt_ht[flow_ht[flow_id].partition][p_bucket].ctrl_bits.rst == TRUE ) { 
                            c_eseq = c_eseq + pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len;
                            DM_BIT_SET(retval, DM_HANDLE_RST);   
                        }else {
                            c_eseq = c_eseq + pkt_ht[flow_ht[flow_id].partition][p_bucket].value.len;
                        }

                        flow_ht[flow_id].ctrl_bits.FSM = fsm_trans(flow_ht[flow_id].ctrl_bits.FSM, t_flags); 
                        flow_ht[flow_id].value.cs = (retval >> 16);   // tcs;
                    }
                }

#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- packet ////
                gen_xfer = 1;
                while(1) {
                    mem_test_set(&gen_xfer,  (__mem void *)(p_lock[flow_ht[flow_id].partition]+hv_pkt), sizeof(gen_xfer));
                    if(gen_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif
               
                ////////////////////////////////////////////////////////////////////////////////////
                // PKT BUCKET: delete bucket
#if defined(PHAST_ATOMIC_OPS)
                memcpy_mem_mem((__mem void *)&pkt_ht[flow_ht[flow_id].partition][p_p_bucket].next_loc, (__mem void *)&pkt_ht[flow_ht[flow_id].partition][p_bucket].next_loc, 2);
                mem_write_atomic(clear_mem, &pkt_ht[flow_ht[flow_id].partition][p_bucket], sizeof(clear_mem));
#else

                if (p_p_bucket != 0) {
                    pkt_ht[flow_ht[flow_id].partition][p_p_bucket].next_loc = pkt_ht[flow_ht[flow_id].partition][p_bucket].next_loc;
                }

                if(pht_idx[flow_ht[flow_id].partition][hv_pkt] == p_bucket) {
                    if(pkt_ht[flow_ht[flow_id].partition][p_bucket].next_loc != 0) {
                        pht_idx[flow_ht[flow_id].partition][hv_pkt] = pkt_ht[flow_ht[flow_id].partition][p_bucket].next_loc;
                    } else {
                        pht_idx[flow_ht[flow_id].partition][hv_pkt] = 0;   //p_p_bucket;
                    }
                }

                mem_write_atomic(clear_mem, &pkt_ht[flow_ht[flow_id].partition][p_bucket], sizeof(clear_mem));

#endif

#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- pstack ////
                pstack_xfer = 1;
                while(1) {
                    mem_test_set(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[flow_id].partition], sizeof(pstack_xfer));
                    if(pstack_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif

                p_dealloc(flow_ht[flow_id].partition, p_bucket);

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- pstack ///
                pstack_xfer = 0;
                mem_write_atomic(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[flow_id].partition], sizeof(pstack_xfer));
                ////////////////////
#endif

#if defined(PHAST_ATOMIC_OPS)                
                mem_decr32((__mem void *)&flow_ht[flow_id].value.oooqLen);
#else
                flow_ht[flow_id].value.oooqLen -= 1;
#endif

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- packet ///
                gen_xfer = 0;
                mem_write_atomic(&gen_xfer,  (__mem void *)(p_lock[flow_ht[flow_id].partition]+hv_pkt), sizeof(gen_xfer));
                ////////////////////
#endif

                // PKT BUCKET:
                ///////////////////////////////////////////////////////////////////////////////////
                if(DM_BIT_CHECK(retval, DM_RESULT)) {  
                    flow_ht[flow_id].value.eseq = c_eseq;
                    return retval;
                }
            } else {
                break;  // next packet not found in hash storage
            }
        }// WHILE

        DM_BIT_CLEAR(retval, DM_RESULT);  // clear bit to return that there was not a hit
        flow_ht[flow_id].value.eseq = c_eseq;

        return retval;   //return FALSE; 
    }
}

///////////////////////////////////////////////////////
int pif_plugin_processPkt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data){
    PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
    PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);

#if defined(PHAST_LOCK)
    // test set lock registers
    __xrw uint32_t f_m_xfer;      // replaces: flow_xfer, flow_xfer2, mpool_xfer
    __xrw uint32_t fstack_p_xfer; // replaces: fstack_xfer, pkt_xfer
    __xrw uint32_t pstack_xfer;   // replaces: pstack_xfer
#endif;

#if defined(PHAST_ATOMIC_OPS)
    __xrw uint32_t flow_key_rw[3];
#endif

    volatile uint16_t hv;
    volatile uint16_t hv2;    // hash_values for flow id, reverse direction, packet storage (includes seqNo) 
    uint32_t ret_result=0;    // see dm_loop() for what it returns
    uint16_t payload_size;
    uint16_t f_bucket, p_bucket, t_p_bucket;
    uint8_t dm_ops = 0;

    // Only track TCP flows for now
    if(pif_plugin_hdr_tcp_present(headers) && (PHAST_XFLOW_ENABLED == TRUE)) {    // PROCESS TCP
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // FIND OR CREATE FLOW HASH ENTRY
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // calculate TCP payload size
        payload_size = ipv4->totalLen - ( (ipv4->ihl + tcp->dataOffset) * 4);

        // identify the flow for this packet
        DM_BIT_CLEAR(dm_ops, DM_FOUND_ENTRY);    //f_found_entry = FALSE;
        t_p_bucket = 0;
        hv = get_flow_hash(headers, FALSE);

        ////////////////////////////////////////////////////////////////////////////////////
        // FLOW BUCKET: search for the right flow table location (track cur and prev bucket)
#if defined(PHAST_LOCK)
        // AQUIRE MUTEX -- flow ////
        f_m_xfer = 1;
        while(1) {
            mem_test_set(&f_m_xfer, (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
            if(f_m_xfer == 0) {
                break;
            }
            sleep(LOCK_SLEEP);
        }
        ////////////////////
#endif

        // lock must be here to lock the READ of fht_idx[hv] which some other thread may update
        f_bucket = fht_idx[hv];

        // 1) check to see if flow entry already exists
        while(f_bucket != 0) {
#if defined(PHAST_ATOMIC_OPS)
            mem_read_atomic(flow_key_rw, flow_ht[f_bucket].key, sizeof(flow_key_rw));
            if( (flow_key_rw[0] == ipv4->srcAddr) && (flow_key_rw[1] == ipv4->dstAddr) && (flow_key_rw[2] == (tcp->srcPort << 16) | tcp->dstPort) ) {
#else
            if( (flow_ht[f_bucket].key[0] == ipv4->srcAddr) && (flow_ht[f_bucket].key[1] == ipv4->dstAddr) && 
                (flow_ht[f_bucket].key[2] == (tcp->srcPort << 16) | tcp->dstPort) ) {
#endif
                DM_BIT_SET(dm_ops, DM_FOUND_ENTRY) ;    //f_found_entry = TRUE;
                break;
            } else {
                t_p_bucket = f_bucket;
                f_bucket = flow_ht[f_bucket].next_loc;
            }
        }

        // 2) flow entry not found, so create a new one (unless it is a RST)
        if( (DM_BIT_CHECK(dm_ops, DM_FOUND_ENTRY) == FALSE) && !(tcp->flags & 0x04) ) { 
#if defined(PHAST_ATOMIC_OPS)
            __addr40 uint32_t *flow_key_addr;
#endif

#if defined(PHAST_LOCK)
            // AQUIRE MUTEX -- fstack ////
            fstack_p_xfer = 1;
            while(1) {
                mem_test_set(&fstack_p_xfer,(__mem void *)&fstack_lock, sizeof(fstack_p_xfer));
                if(fstack_p_xfer == 0) {
                     break;
                }
                sleep(LOCK_SLEEP);
            }
            ////////////////////
#endif           
            f_bucket = f_alloc();
#if defined(PHAST_LOCK)
            // RELEASE MUTEX -- fstack ///
            fstack_p_xfer = 0;
            mem_write_atomic(&fstack_p_xfer,(__mem void *)&fstack_lock, sizeof(fstack_p_xfer));
            ////////////////////
#endif

            if(fht_idx[hv] == 0) {
                fht_idx[hv] = f_bucket;
            } else {
                flow_ht[t_p_bucket].next_loc = f_bucket;
            }
            flow_ht[f_bucket].next_loc = 0;

#if defined(PHAST_ATOMIC_OPS)
            flow_key_addr = flow_ht[f_bucket].key;
            flow_key_rw[0] = ipv4->srcAddr;
            flow_key_rw[1] = ipv4->dstAddr;
            flow_key_rw[2] = (tcp->srcPort << 16) | tcp->dstPort;
            mem_write_atomic(flow_key_rw, flow_key_addr, sizeof(flow_key_rw));
#else
            flow_ht[f_bucket].key[0] = ipv4->srcAddr;
            flow_ht[f_bucket].key[1] = ipv4->dstAddr;
            flow_ht[f_bucket].key[2] = (tcp->srcPort << 16) | tcp->dstPort;
#endif
            flow_ht[f_bucket].partition = f_bucket;    // # of flow and # of pkt_pool partitions are the same
            flow_ht[f_bucket].ctrl_bits.active = TRUE;
        }

        // FLOW BUCKET: should have correct bucket now
        //////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // DETERMINE EXECUTION STRATEGY
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        if( (DM_BIT_CHECK(dm_ops, DM_FOUND_ENTRY) == FALSE) && (tcp->flags & 0x04) ) { 
            // handle the case of a RST being the only packet in the flow-less session
            // NOTE: hv and f_bucket have no real meaning, since no flow was ever established
            DM_BIT_SET(dm_ops, DM_HANDLE_RST);  
            if(payload_size > 0) {
                DM_BIT_SET(dm_ops, DM_DO_DFA);
            }
        } else if( (tcp->flags & 0x02) || ( (tcp->seqNo == flow_ht[f_bucket].value.eseq) && (flow_ht[f_bucket].ctrl_bits.eseq_valid == TRUE) ) ) {
            DM_BIT_SET(dm_ops, DM_DO_DFA);  
        } else if( DM_BIT_CHECK(dm_ops, DM_FOUND_ENTRY) && (flow_ht[f_bucket].ctrl_bits.active == FALSE) ) {
            DM_BIT_SET(dm_ops, DM_CHECK_OOO); 
        } else if( (tcp->seqNo > flow_ht[f_bucket].value.eseq) || (flow_ht[f_bucket].ctrl_bits.eseq_valid == FALSE) ) {
            DM_BIT_SET(dm_ops, DM_DO_DMA);  
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // PRIMARY EXECUTION STRATEGY
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if(DM_BIT_CHECK(dm_ops, DM_DO_DFA)) {   
            if( tcp->flags & 0x02 ) {   // SYN or SYN-ACK
                if ( (flow_ht[f_bucket].ctrl_bits.FSM == FSM_0) || (flow_ht[f_bucket].ctrl_bits.FSM == FSM_C) ) {
                    if (flow_ht[f_bucket].ctrl_bits.FSM == FSM_C) {
                        init_flow_ht(f_bucket);
                    }
                    if (payload_size > 0) {
                        uint16_t cstate = flow_ht[f_bucket].value.cs;

#if defined(PHAST_LOCK)
                        // RELEASE MUTEX -- flow ///
                        f_m_xfer = 0;
                        mem_write_atomic(&f_m_xfer,(__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                        ////////////////////
#endif
                        ret_result = dm_loop(headers, f_bucket, cstate, 0, payload_size, 1);

#if defined(PHAST_LOCK)
                        // AQUIRE MUTEX -- flow ////
                        f_m_xfer = 1;
                        while(1) {
                            mem_test_set(&f_m_xfer, (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                            if(f_m_xfer == 0) {
                                break;
                            }
                            sleep(LOCK_SLEEP);
                        }
                        ////////////////////
#endif
                    }
                    DM_BIT_SET(dm_ops, DM_CHECK_OOO);  
                }
            } else if(DM_BIT_CHECK(ret_result, DM_HANDLE_RST))  {     // (RST may have content -- not part of FLOW)
                if(payload_size > 0) {
#if defined(PHAST_LOCK)
                    // RELEASE MUTEX -- flow ///
                    f_m_xfer = 0;
                    mem_write_atomic(&f_m_xfer,(__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                    ////////////////////
#endif
                    ret_result = dm_loop(headers, 0, 0, 0, payload_size, 0);   // not part of FLOW

#if defined(PHAST_LOCK)
                    // AQUIRE MUTEX -- flow ////
                    f_m_xfer = 1;
                    while(1) {
                        mem_test_set(&f_m_xfer, (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                        if(f_m_xfer == 0) {
                            break;
                        }
                        sleep(LOCK_SLEEP);
                    }
                    ////////////////////
#endif
                }
            } else {
                if(payload_size > 0) {
                    uint16_t cstate = flow_ht[f_bucket].value.cs;
#if defined(PHAST_LOCK)
                    // RELEASE MUTEX -- flow ///
                    f_m_xfer = 0;
                    mem_write_atomic(&f_m_xfer,(__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                    ////////////////////
#endif
                    ret_result = dm_loop(headers, f_bucket, cstate, 0, payload_size, 1);

#if defined(PHAST_LOCK)
                    // AQUIRE MUTEX -- flow ////
                    f_m_xfer = 1;
                    while(1) {
                        mem_test_set(&f_m_xfer, (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                        if(f_m_xfer == 0) {
                            break;
                        }
                        sleep(LOCK_SLEEP);
                    }
                    ////////////////////
#endif
                }
            }
            DM_BIT_SET(dm_ops,DM_CHECK_OOO); 
         
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // UPDATE SHARED STATE
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            if(payload_size == 0) {
                if ( tcp->flags & 0x02 ) {   ///////  SYN
                    flow_ht[f_bucket].value.eseq = tcp->seqNo + 1;
                    flow_ht[f_bucket].ctrl_bits.eseq_valid = TRUE;
                } else if ( tcp->flags & 0x01 ) {   ///////  FIN
                    flow_ht[f_bucket].value.eseq = tcp->seqNo + 1;
                    DM_BIT_SET(dm_ops, DM_HANDLE_FIN);   
                } else if ( tcp->flags & 0x04 ) {   ///////  RST
                    DM_BIT_SET(dm_ops, DM_HANDLE_RST);   
                }

                flow_ht[f_bucket].ctrl_bits.FSM = fsm_trans(flow_ht[f_bucket].ctrl_bits.FSM, tcp->flags);
            } else if(DM_BIT_CHECK(ret_result,DM_RESULT) ) {       // fs_check==HIT 
                DM_BIT_SET(dm_ops, DM_RESULT);   //RESULT = HIT (note that it is MISS:0 by default)

                if (DM_BIT_CHECK(dm_ops, DM_FOUND_ENTRY)) {    // found_entry==TRUE (not RST w/o flow)
                    if ( tcp->flags & 0x02 ) {   ///////  SYN
                        flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size + 1;
                        flow_ht[f_bucket].ctrl_bits.eseq_valid = TRUE;    // NOT NECESSARY
                    } else if ( tcp->flags & 0x01 ) {   ///////  FIN
                        flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size + 1;
                        DM_BIT_SET(dm_ops, DM_HANDLE_FIN);  
                    } else {
                        flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size;
                    }
       
                   flow_ht[f_bucket].ctrl_bits.FSM = FSM_C;
               }
            } else if( (DM_BIT_CHECK(ret_result,DM_RESULT) == FALSE) && (DM_BIT_CHECK(dm_ops,DM_FOUND_ENTRY)) ) { 
                if ( (tcp->flags & 0x02 ) || (tcp->flags & 0x01) ) {   ///////  SYN || FIN
                    flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size + 1;

                    if ( tcp->flags & 0x01 ) {   ///////  FIN             
                        DM_BIT_SET(dm_ops, DM_HANDLE_FIN);  
                    }
                } else if ( tcp->flags & 0x04 ) {  //// RST
                    flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size;
                    DM_BIT_SET(dm_ops, DM_HANDLE_RST); 
                } else {
                    flow_ht[f_bucket].value.eseq = tcp->seqNo + payload_size;
                }

                flow_ht[f_bucket].ctrl_bits.FSM = fsm_trans(flow_ht[f_bucket].ctrl_bits.FSM, tcp->flags);           
                flow_ht[f_bucket].value.cs = (ret_result >> 16);   // tcs;
            }

            if( (DM_BIT_CHECK(dm_ops,DM_FOUND_ENTRY) == FALSE) && (tcp->flags & 0x04) ) {    
               dm_ops &= 0x41;  // keep DM_RESULT (bit 0) and DM_HANDLE_RST (bit 6)
            }

            if( DM_BIT_CHECK(dm_ops,DM_CHECK_OOO) && (flow_ht[f_bucket].ctrl_bits.FSM == FSM_C) ) { 
                DM_BIT_CLEAR(dm_ops,DM_CHECK_OOO); 
            }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        } else if(DM_BIT_CHECK(dm_ops, DM_DO_DMA)) {      

#if defined(PHAST_LOCK)
            // RELEASE MUTEX -- flow ///
            f_m_xfer = 0;
            mem_write_atomic(&f_m_xfer,(__mem void *)(f_lock+hv), sizeof(f_m_xfer));
            ////////////////////
#endif            

                DM_BIT_CLEAR(dm_ops, DM_FOUND_ENTRY); 
                t_p_bucket = 0;
                hv2 = get_pkt_hash(headers, tcp->seqNo, FALSE);

#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- packet ////
                fstack_p_xfer = 1;
                while(1) {
                    mem_test_set(&fstack_p_xfer,  (__mem void *)(p_lock[flow_ht[f_bucket].partition]+hv2), sizeof(fstack_p_xfer));
                    if(fstack_p_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif
                ////////////////////////////////////////////////////////////////////////////////////
                // PKT BUCKET: Goto bucket then append to the end      
                p_bucket = pht_idx[flow_ht[f_bucket].partition][hv2];

                while(p_bucket != 0) {
                    t_p_bucket = p_bucket;
                    p_bucket = pkt_ht[flow_ht[f_bucket].partition][p_bucket].next_loc;
                }

#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- pstack ////
                pstack_xfer = 1;
                while(1) {
                    mem_test_set(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[f_bucket].partition], sizeof(pstack_xfer));
                    if(pstack_xfer == 0) {
                        break;
                    }
                    sleep(LOCK_SLEEP);
                }
                ////////////////////
#endif
                p_bucket = p_alloc(flow_ht[f_bucket].partition);

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- pstack ///
                pstack_xfer = 0;
                mem_write_atomic(&pstack_xfer,(__mem void *)&pstack_lock[flow_ht[f_bucket].partition], sizeof(pstack_xfer));
                ////////////////////
#endif


                if(pht_idx[flow_ht[f_bucket].partition][hv2] == 0) {
                    pht_idx[flow_ht[f_bucket].partition][hv2] = p_bucket;
                } else {
                    pkt_ht[flow_ht[f_bucket].partition][t_p_bucket].next_loc = p_bucket;
                }
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].next_loc = 0;   // does this default to "0"?
                // now set the packet metadata using p_bucket
                DM_BIT_SET(dm_ops, DM_FOUND_ENTRY);    //f_found_entry = TRUE;  

                // PKT BUCKET: should have correct bucket now
                ///////////////////////////////////////////////////////////////////////////////////

#if defined(PHAST_LOCK)
                // RELEASE MUTEX -- packet ///
                fstack_p_xfer = 0;
                mem_write_atomic(&fstack_p_xfer,  (__mem void *)(p_lock[flow_ht[f_bucket].partition]+hv2), sizeof(fstack_p_xfer));
                ////////////////////
#endif

                // perform the actual DMA
                if( (payload_size > 0) && (p_bucket != PKT_NUM_SLOTS_ERROR) ) {
                    pktdma_ctm_to_mu((__mem void *)emem_pool[flow_ht[f_bucket].partition][p_bucket], pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_len + PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num));
                }            

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // UPDATE SHARED STATE
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if defined(PHAST_LOCK)
            // AQUIRE MUTEX -- packet ////
            fstack_p_xfer = 1;
            while(1) {
                mem_test_set(&fstack_p_xfer,  (__mem void *)(p_lock[flow_ht[f_bucket].partition]+hv2), sizeof(fstack_p_xfer));
                if(fstack_p_xfer == 0) {
                    break;
                }
                sleep(LOCK_SLEEP);
            }
            ////////////////////
#endif

            pkt_ht[flow_ht[f_bucket].partition][p_bucket].ctrl_bits.active = TRUE; 

            if ( tcp->flags & 0x01) {   // fin
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].ctrl_bits.fin = TRUE; 
            } 
            if ( tcp->flags & 0x02) {   // syn
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].ctrl_bits.syn = TRUE;  
            } 
            if ( tcp->flags & 0x04) {   // rst
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].ctrl_bits.rst = TRUE; 
            } 
            if ( tcp->flags & 0x10) {   // ack
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].ctrl_bits.ack = TRUE; 
            } 

            pkt_ht[flow_ht[f_bucket].partition][p_bucket].key = tcp->seqNo;

            if (payload_size > 0) {
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].value.offset = 14 + ( (ipv4->ihl + tcp->dataOffset) * 4 ); 
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].value.len =  payload_size;
            } else {
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].value.offset = 0;  
                pkt_ht[flow_ht[f_bucket].partition][p_bucket].value.len = 0;   
            }

#if defined(PHAST_LOCK)
            // RELEASE MUTEX -- packet ///
            fstack_p_xfer = 0;
            mem_write_atomic(&fstack_p_xfer,  (__mem void *)(p_lock[flow_ht[f_bucket].partition]+hv2), sizeof(fstack_p_xfer));
                ////////////////////
#endif

#if defined(PHAST_LOCK)
            // AQUIRE MUTEX -- flow ////
            f_m_xfer = 1;
            while(1) {
                mem_test_set(&f_m_xfer, (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
                if(f_m_xfer == 0) {
                    break;
                }
                sleep(LOCK_SLEEP);
            }
            ////////////////////
#endif

            // update packet metadata
#if defined(PHAST_ATOMIC_OPS)
            mem_incr32((__mem void *)&flow_ht[f_bucket].value.oooqLen);
#else
            flow_ht[f_bucket].value.oooqLen += 1;
#endif

            if (flow_ht[f_bucket].ctrl_bits.eseq_valid == TRUE) {  
                DM_BIT_SET(dm_ops,DM_CHECK_OOO);  
            } 
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // SECONDARY EXECUTION STRATEGY
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        if(DM_BIT_CHECK(dm_ops,DM_CHECK_OOO)) {  

            // AQUIRE MUTEX -- check_ooo_lock ////
            pstack_xfer = 1;
            mem_test_set(&pstack_xfer,(__mem void *)&check_ooo_lock[flow_ht[f_bucket].partition], sizeof(pstack_xfer));
            if(pstack_xfer == 0) {
                if (flow_ht[f_bucket].value.oooqLen > 0) {
                    ret_result = process_ooo(headers, f_bucket, hv);

                    // PARSE RET_RESULT AGAIN AND SET DM_OPTS FOR del_ooo and handle_rst 
                    if(DM_BIT_CHECK(ret_result,DM_RESULT)) {   
                        DM_BIT_SET(dm_ops,DM_RESULT);   
                    }
                    if(DM_BIT_CHECK(ret_result,DM_HANDLE_RST)) {   
                        DM_BIT_SET(dm_ops,DM_HANDLE_RST);  
                    }
                    if(DM_BIT_CHECK(ret_result,DM_HANDLE_FIN)) {  
                        DM_BIT_SET(dm_ops,DM_HANDLE_FIN);  
                    }
                }

                // RELEASE MUTEX -- check_ooo_lock ///
                pstack_xfer = 0;
                mem_write_atomic(&pstack_xfer,(__mem void *)&check_ooo_lock[flow_ht[f_bucket].partition], sizeof(pstack_xfer));
                ////////////////////
            }
            ////////////////////
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if( flow_ht[f_bucket].ctrl_bits.FSM == FSM_C ) {    //if we  transitioned to FSM='C'
            t_p_bucket = 0;
            DM_BIT_CLEAR(dm_ops,DM_FOUND_ENTRY); 

            //  Have to compute this again becasue we did not save t_p_bucket
            /////////////////////////////////////////////////////////////////////////////////////
            // FLOW BUCKET: search for the right flow table location (track cur and prev bucket)
            f_bucket = fht_idx[hv];

            while (f_bucket != 0) {
                if( (flow_ht[f_bucket].key[0] == ipv4->srcAddr) && (flow_ht[f_bucket].key[1] == ipv4->dstAddr) &&
                    (flow_ht[f_bucket].key[2] == (tcp->srcPort << 16) | tcp->dstPort) ) {
                    DM_BIT_SET(dm_ops,DM_FOUND_ENTRY);  
                    break;
                } else {
                    t_p_bucket = f_bucket;
                    f_bucket = flow_ht[f_bucket].next_loc;
                }
            }
            // FLOW BUCKET: should have correct bucket now
            ///////////////////////////////////////////////////////////////////////////////////

            if(DM_BIT_CHECK(dm_ops,DM_FOUND_ENTRY)) {  
#if defined(PHAST_ATOMIC_OPS)
                 __xwrite uint32_t clear_mem[7] = {0};
#endif

                // get rid of any orphan packets
                if (flow_ht[f_bucket].value.oooqLen > 0) {
                    delete_ooo(headers, f_bucket);
                }

                // now delete the flow entry if it exists
                ////////////////////////////////////////////////////////////////////////////////////
                // FLOW BUCKET: delete bucket
#if defined(PHAST_ATOMIC_OPS)
                memcpy_mem_mem((__mem void *)&flow_ht[t_p_bucket].next_loc, (__mem void *)&flow_ht[f_bucket].next_loc, 2);
                mem_write_atomic(clear_mem, &flow_ht[f_bucket], sizeof(clear_mem));
#else
                if (t_p_bucket != 0) {
                    flow_ht[t_p_bucket].next_loc = flow_ht[f_bucket].next_loc;
                }

                flow_ht[f_bucket].partition = 0;
                flow_ht[f_bucket].value.eseq = 0;
                flow_ht[f_bucket].value.oooqLen = 0;
                flow_ht[f_bucket].value.cs = 0;
                flow_ht[f_bucket].key[0] = 0;
                flow_ht[f_bucket].key[1] = 0;
                flow_ht[f_bucket].key[2] = 0;
                flow_ht[f_bucket].ctrl_bits.FSM = FALSE; 
                flow_ht[f_bucket].ctrl_bits.eseq_valid = FALSE;  
                flow_ht[f_bucket].ctrl_bits.active = FALSE; 

                if(fht_idx[hv] == f_bucket) {
                    if(flow_ht[f_bucket].next_loc != 0) {
                        fht_idx[hv] = flow_ht[f_bucket].next_loc;
                        flow_ht[f_bucket].next_loc = 0;
                    } else {
                        fht_idx[hv] = t_p_bucket;
                    }
                }
#endif
           
#if defined(PHAST_LOCK)
                // AQUIRE MUTEX -- fstack ////
                pstack_xfer = 1;
                    while(1) {
                        mem_test_set(&pstack_xfer,(__mem void *)&fstack_lock, sizeof(pstack_xfer));
                        if(pstack_xfer == 0) {
                            break;
                        }
                        sleep(LOCK_SLEEP);
                    }
                    ////////////////////
#endif

                 f_dealloc(f_bucket);

#if defined(PHAST_LOCK)
                    // RELEASE MUTEX -- fstack ///
                    pstack_xfer = 0;
                    mem_write_atomic(&pstack_xfer,(__mem void *)&fstack_lock, sizeof(pstack_xfer));
                    ////////////////////
#endif

            }
        }

#if defined(PHAST_LOCK)
        // RELEASE MUTEX -- flow ///
        f_m_xfer = 0;
        mem_write_atomic(&f_m_xfer,  (__mem void *)(f_lock+hv), sizeof(f_m_xfer));
        ////////////////////
#endif

        //////////////////////////////////////////////////////////////////////////////////////////////////////////   
        if( DM_BIT_CHECK(dm_ops,DM_HANDLE_RST) || DM_BIT_CHECK(dm_ops,DM_HANDLE_FIN) ) {
            // get hash index for other direction
            DM_BIT_CLEAR(dm_ops,DM_FOUND_ENTRY); 
            t_p_bucket = 0;
            hv2 = get_flow_hash(headers, TRUE);

#if defined(PHAST_LOCK)
            // AQUIRE MUTEX -- flow ////
            f_m_xfer = 1;
            while(1) {
                mem_test_set(&f_m_xfer,  (__mem void *)(f_lock+hv2), sizeof(f_m_xfer));
                if(f_m_xfer == 0) {
                    break;
                }
                sleep(LOCK_SLEEP);
            }
            ////////////////////
#endif
            /////////////////////////////////////////////////////////////////////////////////////
            // FLOW BUCKET: search for the right flow table location (track cur and prev bucket)
            p_bucket = fht_idx[hv2];

            while (p_bucket != 0) {
                if( (flow_ht[p_bucket].key[0] == ipv4->dstAddr) && (flow_ht[p_bucket].key[1] == ipv4->srcAddr) &&
                    (flow_ht[p_bucket].key[2] == (tcp->dstPort << 16) | tcp->srcPort) ) {
                    DM_BIT_SET(dm_ops,DM_FOUND_ENTRY); 
                    break;
                } else {
                    t_p_bucket = p_bucket;
                    p_bucket = flow_ht[p_bucket].next_loc;
                }
            }
            // FLOW BUCKET: should have correct bucket now
            ///////////////////////////////////////////////////////////////////////////////////
 
            if(DM_BIT_CHECK(dm_ops,DM_FOUND_ENTRY)) { 
                if(DM_BIT_CHECK(dm_ops,DM_HANDLE_FIN)) {  
                    if( flow_ht[p_bucket].ctrl_bits.FSM != FSM_C ) {
                        flow_ht[p_bucket].ctrl_bits.FSM = FSM_W;  // FSM_W
                    }
                } else {                 // to_handle_rst
#if defined(PHAST_ATOMIC_OPS)
                     __xwrite uint32_t clear_mem[7] = {0};
#endif

                     if(flow_ht[p_bucket].value.oooqLen > 0) {
                         ret_result = process_ooo(headers, p_bucket, hv2);

                         // PARSE RET_RESULT AGAIN TO SEE IF THERE WAS A HIT
                         if(DM_BIT_CHECK(ret_result,DM_RESULT)) {   
                             DM_BIT_SET(dm_ops,DM_RESULT); 
                         }
                     }

                     // now delete the flow entry if it exists
                     ////////////////////////////////////////////////////////////////////////////////////
                     // FLOW BUCKET: delete bucket
#if defined(PHAST_ATOMIC_OPS)
                     memcpy_mem_mem((__mem void *)&flow_ht[t_p_bucket].next_loc, (__mem void *)&flow_ht[p_bucket].next_loc, 2);
                     mem_write_atomic(clear_mem, &flow_ht[p_bucket], sizeof(clear_mem));
#else
                     if (t_p_bucket != 0) {
                         flow_ht[t_p_bucket].next_loc = flow_ht[p_bucket].next_loc;
                     }
                     

                     flow_ht[p_bucket].partition = 0;
                     flow_ht[p_bucket].value.eseq = 0;
                     flow_ht[p_bucket].value.oooqLen = 0;
                     flow_ht[p_bucket].value.cs = 0;
                     flow_ht[p_bucket].key[0] = 0;
                     flow_ht[p_bucket].key[1] = 0;
                     flow_ht[p_bucket].key[2] = 0;    
                     flow_ht[p_bucket].ctrl_bits.FSM = FALSE; 
                     flow_ht[p_bucket].ctrl_bits.eseq_valid = FALSE;                 
                     flow_ht[p_bucket].ctrl_bits.active = FALSE;

                     if(fht_idx[hv2] == p_bucket) {
                         if(flow_ht[p_bucket].next_loc != 0) {
                             fht_idx[hv2] = flow_ht[p_bucket].next_loc;
                             flow_ht[p_bucket].next_loc = 0;
                         } else {
                             fht_idx[hv2] = t_p_bucket;
                         }
                     }        
#endif                  

#if defined(PHAST_LOCK)
                     // AQUIRE MUTEX -- fstack ////
                     pstack_xfer = 1;
                     while(1) {
                         mem_test_set(&pstack_xfer,(__mem void *)&fstack_lock, sizeof(pstack_xfer));
                         if(pstack_xfer == 0) {
                             break;
                         }
                         sleep(LOCK_SLEEP);
                     }
                     ////////////////////
#endif

                     f_dealloc(p_bucket);

#if defined(PHAST_LOCK)
                     // RELEASE MUTEX -- fstack ///
                     pstack_xfer = 0;
                     mem_write_atomic(&pstack_xfer,(__mem void *)&fstack_lock, sizeof(pstack_xfer));
                     ////////////////////
#endif
       
                    // FLOW BUCKET:
                    ///////////////////////////////////////////////////////////////////////////////////
                }
            }

#if defined(PHAST_LOCK)
            // RELEASE MUTEX -- flow ///
            f_m_xfer = 0;
            mem_write_atomic(&f_m_xfer,  (__mem void *)(f_lock+hv2), sizeof(f_m_xfer));
            ////////////////////
#endif
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////   

        pif_plugin_meta_set__meta__processPayloadResult(headers, DM_BIT_CHECK(dm_ops, DM_RESULT));
        return PIF_PLUGIN_RETURN_FORWARD;

               ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    } else {  // CASE 2: NOT-XFLOW MODE  or NOT TCP    //////////////////////////////////////////////////////////////////////////
        PIF_PLUGIN_udp_T *udp = pif_plugin_hdr_get_udp(headers);

        // calculate payload size -- different ways depending on the protocol
        if (pif_plugin_hdr_tcp_present(headers) && (PHAST_XFLOW_ENABLED == FALSE)) {
            payload_size = ipv4->totalLen - ( (ipv4->ihl + tcp->dataOffset) * 4);
        } else if (pif_plugin_hdr_udp_present(headers)) {  // udp: udp header is always 8 bytes
            payload_size = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off;   //udp->hd_length - 8;
        } else if (pif_plugin_hdr_icmp_present(headers)) {  // icmp: ipv4_len - 
            payload_size = (pif_plugin_hdr_get_ipv4(headers))->totalLen - ((pif_plugin_hdr_get_ipv4(headers))->ihl * 4) - 8;
        }  else {  // unknown protocol
            payload_size = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off;
        }

        if(payload_size == 0) {
            pif_plugin_meta_set__meta__processPayloadResult(headers, 0); // skip packet
            return PIF_PLUGIN_RETURN_FORWARD;
        } else {
            ret_result = dm_loop(headers, 0, 0, 0, payload_size, 0);
            pif_plugin_meta_set__meta__processPayloadResult(headers, DM_BIT_CHECK(ret_result, DM_RESULT));
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }   // END: TCP vs NOT-TCP if statement
}        

///////////////////////////////////////////////////////
/////  FLOW HASH TABLE    //////////
///////////////////////////////////////////////////////
uint8_t f_dealloc(uint16_t num) { 
    if (flow_stack.top == 1) {  
        return 0;  // FAILED should never happen but if does then deallocate flow's memory and report error
    } else {
        flow_stack.top -= 1;
        flow_stack.stk[flow_stack.top] = num;
        return 1;  // SUCCESS
    }
}

///////////////////////////////////////////////////////
uint16_t f_alloc() {
    if (flow_stack.top == FLOW_STORAGE_SIZE) { 
        return FLOW_NUM_SLOTS_ERROR;   // need to deallocate this flow's memory and report error
    } else {
        uint16_t num;

        num = flow_stack.stk[flow_stack.top];
        flow_stack.stk[flow_stack.top] = 0;
        flow_stack.top++;
        return num; 
    }
}

///////////////////////////////////////////////////////
/////  PACKET HASH TABLE    //////////
///////////////////////////////////////////////////////
uint8_t p_dealloc(uint16_t flow_part, uint16_t num) {
    if (pkt_stack[flow_part].top == 1) {
        return 0;  // FAILED should never happen but if does then deallocate flow's memory and report error
    } else {
        pkt_stack[flow_part].top--;
        pkt_stack[flow_part].stk[pkt_stack[flow_part].top] = num;
        return 1;  // SUCCESS
    }
}

///////////////////////////////////////////////////////
uint16_t p_alloc(uint16_t flow_part) {
    if (pkt_stack[flow_part].top == FLOW_PARTION_SZ) {
        return PKT_NUM_SLOTS_ERROR;   // need to deallocate this flow's memory and report error
    } else {
        uint16_t num;

        num = pkt_stack[flow_part].stk[pkt_stack[flow_part].top];
        pkt_stack[flow_part].stk[pkt_stack[flow_part].top] = 0;
        pkt_stack[flow_part].top++;
        return num;
    }
}

