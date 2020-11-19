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

/********************
 dm_options.h
 ********************/


/*************************
  MISC GLOBALS
  ************************/

#define TRUE 1
#define FALSE 0

#define PHAST_XFLOW_ENABLED 1

#define CHUNK_LW 8
#define CHUNK_B 32   //(CHUNK_LW * 4)

#define LOCK_SLEEP 200

typedef enum { 
    DM_RESULT = 0,
    DM_FOUND_ENTRY = 1,
    DM_DO_DFA = 2,
    DM_DO_DMA = 3,
    DM_CHECK_OOO = 4,
    DM_HANDLE_FIN = 5,
    DM_HANDLE_RST = 6
} DM_FlagVals;

#define DM_BIT_SET(X,N)   ((X) |=  (1 << (N)) ) 
#define DM_BIT_CLEAR(X,N) ((X) &= ~(1 << (N)) )
#define DM_BIT_CHECK(X,N) ( ((X) >> (N)) & 1 )

// the following is a variable used by snort.  Usefull when using snort rulesets. each CLS has its own copy
_declspec(cls) uint16_t httpPorts[] = {80,81,311,383,591,593,901,1220,1414,1741,1830,2301,2381,2809,3037,3128,3702,4343,4848,5250,6988,7000,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8085,8088,8090,8118,8123,8180,8181,8243,8280,8300,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,11371,34443,34444,41080,50002,55555};

/*************************************************
  SIZE FLOW & PACKET HASH TABLES & PACKET STORAGE
  ***********************************************/
// 321 flows; support 100 OoO packets per flow
#define FLOW_HASH_TABLE_SIZE  0x1FF
#define FLOW_HASH_HIGH        0xFFFFFE00
#define FLOW_HASH_LOW         0x01FF
#define FLOW_HASH_SHIFT       9
#define FLOW_STORAGE_SIZE     321
#define FLOW_PARTION_SZ       100
#define FLOW_NUM_SLOTS_ERROR  777
#define PKT_HASH_TABLE_SIZE   0x3FF
#define PKT_HASH_HIGH         0xFFFFFC00
#define PKT_HASH_LOW          0x03FF
#define PKT_HASH_SHIFT        10
#define PKT_NUM_SLOTS_ERROR   777
#define OOO_SLOT_SIZE         1536

/***********************************
  HASH TABLE FOR FLOW MAINTENANCE
  **********************************/

// each bucket has a lock
volatile __export __mem uint32_t f_lock[FLOW_HASH_TABLE_SIZE];

// indexes to the flow hash table
volatile __export __mem uint32_t fht_idx[FLOW_HASH_TABLE_SIZE];

// The stack manages the assignment of flow hash table entries
typedef struct stack_flow {
    uint16_t stk[FLOW_STORAGE_SIZE];
    int16_t top;
 } STACK_flow;

volatile __export __mem STACK_flow flow_stack;

uint8_t  f_dealloc(uint16_t);
uint16_t f_alloc(void);

volatile __export __mem uint32_t fstack_lock;

typedef enum { 
    FSM_0 = 0,  // Initial
    FSM_S = 1,  // Received SYN
    FSM_E = 2,  // Established
    FSM_F = 3,  // Received FIN
    FSM_W = 4,  // Waiting for final ACK
    FSM_C = 5   // Closed
} tcp_fsm_t;

typedef __declspec(packed) struct {
    tcp_fsm_t FSM:3;
    uint8_t active:1;
    uint8_t eseq_valid:1;
} flow_ctrl_bits_T;

typedef struct flow_bucket_value_Type {
    uint32_t eseq;         // expected sequence number
    uint16_t oooqLen;      // number of packets in the ooo pool
    uint16_t cs;           // saved dfa state
} flow_bucket_value_T;

// the flow hash table
typedef struct flow_ht_entry_Type {
    uint32_t key[3];       // sip, dip, sport|dport
    flow_bucket_value_T value;
    uint16_t partition;    // slice of memory used for packet storage
    uint16_t next_loc;     // linked list ptr
    flow_ctrl_bits_T ctrl_bits; 
} flow_ht_entry_T;

__shared __export __addr40 __mem flow_ht_entry_T flow_ht[FLOW_STORAGE_SIZE];

/*************************************
  HASH TABLE FOR Out-Of-Order PACKETS
  ***********************************/

// each bucket has a lock
volatile __export __mem uint32_t p_lock[FLOW_STORAGE_SIZE][PKT_HASH_TABLE_SIZE];

// indexes to the packet hash table
volatile __export __mem uint16_t pht_idx[FLOW_STORAGE_SIZE][PKT_HASH_TABLE_SIZE];

// The stack manages the assignment of packet hash table entries
typedef struct stack_pkt {
    uint16_t stk[FLOW_PARTION_SZ];
    int16_t top; 
} STACK_pkt;

volatile __export __mem STACK_pkt pkt_stack[FLOW_STORAGE_SIZE];

uint8_t  p_dealloc(uint16_t, uint16_t);
uint16_t p_alloc(uint16_t);

volatile __export __mem uint32_t pstack_lock[FLOW_STORAGE_SIZE];

typedef __declspec(packed) struct {
    uint8_t active:1;
    uint8_t syn:1;
    uint8_t fin:1;
    uint8_t rst:1;
    uint8_t ack:1;
} pkt_ctrl_bits_T;

typedef struct pkt_bucket_value_Type {
    uint16_t len;           // payload length
    uint16_t offset;        // payload offset
} pkt_bucket_value_T;

// the pkt hash table
typedef struct pkt_ht_entry_Type {
    uint32_t key;        // tcp->seqNo
    pkt_bucket_value_T value;
    uint16_t next_loc;   // linked list ptr
    pkt_ctrl_bits_T ctrl_bits; 
} pkt_ht_entry_T;

__shared __export __addr40 __mem pkt_ht_entry_T pkt_ht[FLOW_STORAGE_SIZE][FLOW_PARTION_SZ];

// process_ooo lock. Serialize flow processing
volatile __export __mem uint32_t check_ooo_lock[FLOW_STORAGE_SIZE];

/*********************************
  Out-Of-Order PACKET MALLOC POOL
  *******************************/

// store packets DMA'ed from ctm to emem
volatile __export __emem __addr40 uint8_t emem_pool[FLOW_STORAGE_SIZE][FLOW_PARTION_SZ][OOO_SLOT_SIZE];

// store packets DMA'ed from emem to ctm
_declspec(ctm) uint8_t ctm_checker[OOO_SLOT_SIZE];  //each thread has its own private variable

/*************************
  SET DFA SIZE PARAMETERS
  ************************/

#if defined(PHAST_DFA_MAL_TOOLS)

#define NUM_DFA 1
#define DFA_STATES 172
#define MAX_CHAR 256

#elif defined(PHAST_DFA_MAL_BACKDOOR)

#define NUM_DFA 2
#define DFA_STATES 1679
#define MAX_CHAR 256

#elif defined(PHAST_DFA_MAL_OTHER)

#define NUM_DFA 4
#define DFA_STATES 3446
#define MAX_CHAR 256

#elif defined(PHAST_DFA_MAL_CNC)

#define NUM_DFA 4
#define DFA_STATES 43887
#define MAX_CHAR 256

#elif defined(PHAST_DFA_MAL_CUSTOM)

#define NUM_DFA 1
#define DFA_STATES 69
#define MAX_CHAR 256

#elif defined(PHAST_DFA_MAL_CUSTOM2)

#define NUM_DFA 1
#define DFA_STATES 4
#define MAX_CHAR 256

#endif

/*****************************
  SET DFA LOCATION PARAMETERS
  ****************************/
////////////////////////////////////////////////////////////////////
#if defined(PHAST_DLOC_CLS)
_declspec(cls export scope(island)) uint16_t dfa_trans[NUM_DFA][DFA_STATES][MAX_CHAR];
#elif defined(PHAST_DLOC_CTM)
_declspec(ctm export scope(island)) uint16_t dfa_trans[NUM_DFA][DFA_STATES][MAX_CHAR];
#elif defined(PHAST_DLOC_IMEM)
_declspec(imem export scope(island)) uint16_t dfa_trans[NUM_DFA][DFA_STATES][MAX_CHAR];
#elif defined(PHAST_DLOC_EMEM)
_declspec(emem export scope(island)) uint16_t dfa_trans[NUM_DFA][DFA_STATES][MAX_CHAR];
#endif

