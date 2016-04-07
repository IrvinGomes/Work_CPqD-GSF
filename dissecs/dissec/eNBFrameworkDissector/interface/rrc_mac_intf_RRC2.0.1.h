/******************************************************************************
*
*   FILE NAME:
*       rrc_mac_intf.h
*
*   DESCRIPTION:
*       This file contains types used for representation of MAC API inside RRC.
*       Based on LTE_MAC_Rel_1.2_API_Manual_Rev_2.4.doc and
*       eNB_RRC_R1_0_API_v0_1.doc.
*
*   DATE            AUTHOR      REFERENCE       REASON
*   23 Apr 2009     VasylS      ---------       Initial
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/

#ifndef _RRC_MAC_INTF_H_
#define _RRC_MAC_INTF_H_

#include "rrc_defines.h"

#define RRC_MAC_MAX_CREATE_LC       10
#define RRC_MAC_MAX_RECONFIGURE_LC  10
#define RRC_MAC_MAX_DELETE_LC       10

typedef enum
{
    MAC_FAILURE,
    MAC_SUCCESS,
    MAC_PARTIAL_SUCCESS
} rrc_mac_return_et;

typedef enum
{
    MAC_DELETE_LC_DOWNLINK = 1,
    MAC_DELETE_LC_UPLINK = 2,
    MAC_DELETE_LC_BOTH = 3
} rrc_mac_delete_lc_types_et;

typedef enum
{
    MAC_SFN_DOES_NOT_EXIST = 0
} rrc_mac_config_cell_error_code_et;

typedef enum
{
    MAC_LOG_CH_EXISTS = 0,
    MAC_LOG_CH_NOT_EXISTS = 1
} rrc_mac_logical_channel_error_code_et;

#pragma pack(push, 1)

/******************************************************************************
*   MAC Cell messages
******************************************************************************/

/******************************************************************************
*   RRC_MAC_CONFIG_CELL_REQ
******************************************************************************/
typedef struct _rrc_mac_pucch_config_info_t
{
    U8  delta_pucch_shift;      /*^ M, 0, B, 1, 3 ^*/
    U8  nrb_cqi;                /*^ M, 0, H, 0, 98 ^*/
    U8  ncs_an;                 /*^ M, 0, H, 0, 7 ^*/
    U16 n1pucch_an;             /*^ M, 0, H, 0, 2047 ^*/
} rrc_mac_pucch_config_info_t;

typedef struct _rrc_mac_phich_config_info_t
{
    U8  phich_duration;             /*^ M, 0, H, 0, 1 ^*/
    U8  phich_resource;             /*^ M, 0, H, 0, 3 ^*/
} rrc_mac_phich_config_info_t;

typedef struct _rrc_mac_rach_config_info_t
{
    U8  ra_response_window_size;                /*^ M, 0, B, 2, 10 ^*/
    U8  mac_contention_resolution_timer;        /*^ M, 0, B, 8, 64 ^*/
    U8  max_harq_msg3tx;                        /*^ M, 0, B, 1, 8 ^*/
    U8  prach_configuration_index;              /*^ M, 0, H, 0, 63 ^*/
    U8  prach_frequency_offset;                 /*^ M, 0, H, 0, 94 ^*/
} rrc_mac_rach_config_info_t;

#define RRC_MAC_RACH_CONFIG_INFO_PRESENT        0x01
#define RRC_MAC_PHICH_CONFIG_INFO_PRESENT       0x02
#define RRC_MAC_PUCCH_CONFIG_INFO_PRESENT       0x04
#define RRC_MAC_SIBTYPE1_MSG_REQ_PRESENT        0x08
#define RRC_MAC_SI_MSG_REQ_PRESENT              0x10

typedef struct _rrc_mac_config_cell_req_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    U8  dl_res_blocks;
/*^ M, 0, B, 1, 100 ^*/

    U8  ul_res_blocks;
/*^ M, 0, B, 1, 100 ^*/

    U8  max_harq_retrans;
/*^ M, 0, B, 6, 8 ^*/

    U8  num_of_tx_antennas;
/*^ M, 0, B, 1, 4 ^*/

    U8  ul_cyclic_lenth_prefix;
/*^ M, 0, B, 1, 2 ^*/

    U8  start_ra_rnti_range;
/*^ M, 0, B, 1, 60 ^*/

    U8  end_ra_rnti_range;
/*^ M, 0, B, 1, 60 ^*/


    rrc_mac_rach_config_info_t  rach_config_info;
/*^ TLV, RRC_MAC_RACH_CONFIG_INFO, RRC_MAC_RACH_CONFIG_INFO_PRESENT ^*/

    rrc_mac_phich_config_info_t phich_config_info;
/*^ TLV, RRC_MAC_PHICH_CONFIG_INFO, RRC_MAC_PHICH_CONFIG_INFO_PRESENT ^*/

    rrc_mac_pucch_config_info_t pucch_config_info;
/*^ TLV, RRC_MAC_PUCCH_CONFIG_INFO, RRC_MAC_PUCCH_CONFIG_INFO_PRESENT ^*/


    rrc_counter_t               mib_msg_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_mib_msg_req_t       mib_msg_req[RRC_MIB_MSGS];
/*^ TLV, SEQUENCE, RRC_MAC_MIB_MSG_REQ ^*/

    rrc_mac_sibtype1_msg_req_t  sib1_msg_req;
/*^ TLV, RRC_MAC_SIBTYPE1_MSG_REQ, RRC_MAC_SIBTYPE1_MSG_REQ_PRESENT ^*/

    rrc_mac_si_msg_req_t        si_msg_req;
/*^ TLV, RRC_MAC_SI_MSG_REQ, RRC_MAC_SI_MSG_REQ_PRESENT ^*/

    U32     mod_period;
    /*^ M, 0, B, 64, 4096 ^*/

    U8      sfn_gap;
    /*^ M, 0, B, 1, 32 ^*/

} rrc_mac_config_cell_req_t; /*^ API, RRC_MAC_CONFIG_CELL_REQ ^*/

/******************************************************************************
*   RRC_MAC_CONFIG_CELL_CNF
******************************************************************************/
typedef struct _rrc_mac_config_cell_error_code_t
{
    U8  error_code;
/*^ M, 0, H, 0, 0 ^*/   /* rrc_mac_config_cell_error_code_et */

} rrc_mac_config_cell_error_code_t;

#define RRC_MAC_CONFIG_CELL_ERROR_CODE_PRESENT  0x01

typedef struct _rrc_mac_config_cell_cnf_t
{
    rrc_bitmask_t   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_response_t  response;
/*^ M, 0, H, 0, 2 ^*/ /* rrc_mac_return_et */


    rrc_mac_config_cell_error_code_t    config_cell_error_code;
/*^ TLV, RRC_MAC_CONFIG_CELL_ERROR_CODE, RRC_MAC_CONFIG_CELL_ERROR_CODE_PRESENT ^*/

} rrc_mac_config_cell_cnf_t; /*^ API, RRC_MAC_CONFIG_CELL_CNF ^*/

/******************************************************************************
*   RRC_MAC_SFN_REQ
******************************************************************************/
typedef struct _rrc_mac_sfn_req_t
{
    U8 dummy;
} rrc_mac_sfn_req_t; /*^ API, EMPTY, RRC_MAC_SFN_REQ ^*/

/******************************************************************************
*   RRC_MAC_SFN_CNF
******************************************************************************/
typedef struct _rrc_mac_sfn_sf_info_t
{
    rrc_sfn_t   sfn;    /*^ M, 0, H, 0, 1023 ^*/
    rrc_sf_t    sf;     /*^ M, 0, H, 0, 9 ^*/
} rrc_mac_sfn_sf_info_t;

#define RRC_MAC_SFN_SN_INFO_PRESENT     0x01

typedef struct _rrc_mac_sfn_cnf_t
{
    rrc_bitmask_t           optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_response_t          response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_mac_return_et */


    rrc_mac_sfn_sf_info_t   sfn_sf_info;
/*^ TLV, RRC_MAC_SFN_SF_INFO, RRC_MAC_SFN_SN_INFO_PRESENT ^*/

} rrc_mac_sfn_cnf_t; /*^ API, RRC_MAC_SFN_CNF ^*/

/******************************************************************************
*   RRC_MAC_SFN_IND
******************************************************************************/
typedef struct _rrc_mac_sfn_ind_t
{
    rrc_sfn_t   sfn;    /*^ M, 0, H, 0, 1023 ^*/
    rrc_sf_t    sf;     /*^ M, 0, H, 0, 9 ^*/
} rrc_mac_sfn_ind_t; /*^ API, RRC_MAC_SFN_IND ^*/





/******************************************************************************
*   RRC_MAC_RECONFIG_CELL_REQ
******************************************************************************/

typedef struct _rrc_mac_reconfig_cell_req_t
{
 #define RRC_RECONFIG_MAC_RACH_CONFIG_INFO_PRESENT        0x01
 #define RRC_RECONFIG_MAC_MIB_MSG_REQ_PRESENT             0x02
 #define RRC_RECONFIG_MAC_SIB_TYPE_1_MSG_PRESENT          0x04
 #define RRC_RECONFIG_MAC_SI_MSG_REQ_PRESENT              0x08
 #define RRC_RECONFIG_MAC_MOD_PERIOD_PRESENT              0x10
 #define RRC_RECONFIG_MAC_SFN_GAP_PRESENT                 0x20

    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_sfn_t   sfn;    /*^ M, 0, H, 0, 1023 ^*/

    rrc_sf_t	sf;	/*^M, O, H, 0, 9 ^*/	

    rrc_mac_rach_config_info_t  rach_config_info;
/*^ TLV, RRC_MAC_RACH_CONFIG_INFO, RRC_RECONFIG_MAC_RACH_CONFIG_INFO_PRESENT ^*/

    rrc_counter_t               mib_msg_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_mib_msg_req_t       mib_msg_req[RRC_MIB_MSGS];
/*^ TLV, SEQUENCE,RRC_MAC_MIB_MSG_REQ ^*/

    rrc_mac_sibtype1_msg_req_t  sib1_msg_req;
/*^ TLV, RRC_MAC_SIBTYPE1_MSG_REQ, RRC_RECONFIG_MAC_SIB_TYPE_1_MSG_PRESENT ^*/

    rrc_mac_si_msg_req_t        si_msg_req;
/*^ TLV, RRC_MAC_SI_MSG_REQ, RRC_RECONFIG_MAC_SI_MSG_REQ_PRESENT ^*/
 
    rrc_mac_mod_period_info_t   mod_period_info;
/*^ TLV, RRC_MAC_MOD_PERIOD_INFO, RRC_RECONFIG_MAC_MOD_PERIOD_PRESENT ^*/
    
    rrc_mac_sfn_gap_info_t      sfn_gap_info;
/*^ TLV, RRC_MAC_SFN_GAP_INFO, RRC_RECONFIG_MAC_SFN_GAP_PRESENT ^*/

} rrc_mac_reconfig_cell_req_t; /*^ API, RRC_MAC_RECONFIG_CELL_REQ ^*/



/******************************************************************************
*   RRC_MAC_RECONFIG_CELL_CNF
******************************************************************************/
typedef struct _rrc_mac_reconfig_cell_cnf_t
{
    rrc_response_t  response;   /*^ M, 0, H, 0, 1 ^*/ /* rrc_mac_return_et */
} rrc_mac_reconfig_cell_cnf_t; /*^ API, RRC_MAC_RECONFIG_CELL_CNF ^*/

/******************************************************************************
*   RRC_MAC_DELETE_CELL_REQ
******************************************************************************/
typedef struct _rrc_mac_delete_cell_req_t
{
    U8 dummy;
} rrc_mac_delete_cell_req_t; /*^ API, EMPTY, RRC_MAC_DELETE_CELL_REQ ^*/

/******************************************************************************
*   RRC_MAC_DELETE_CELL_CNF
******************************************************************************/
typedef struct _rrc_mac_delete_cell_cnf_t
{
    rrc_response_t  result;     /*^ M, 0, H, 0, 1 ^*/ /* rrc_mac_return_et */
} rrc_mac_delete_cell_cnf_t; /*^ API, RRC_MAC_DELETE_CELL_CNF ^*/

/******************************************************************************
*   MAC UE messages
******************************************************************************/

/******************************************************************************
*   RRC_MAC_CREATE_UE_ENTITY_REQ
******************************************************************************/
#define RRC_MAC_SR_CONFIG_INFO_PRESENT  0x01
#define RRC_MAC_CQI_INFO_PRESENT        0x02

typedef struct _rrc_mac_add_ue_info_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_rnti_t  crnti;                          /*^ M, 0, B, 1, 65523 ^*/
    U8  ue_priority;                            /*^ M, 0, H, 0, 3 ^*/
    U8  dl_num_harq_process;                    /*^ M, 0, B, 6, 8 ^*/
    U8  dl_mod_scheme;                          /*^ M, 0, B, 2, 6 ^*/
    U32 dl_coding_rate;
    U8  dl_max_rb;                              /*^ M, 0, B, 1, 100 ^*/
    U8  ul_max_rb;                              /*^ M, 0, B, 1, 100 ^*/
    U8  ul_mod_scheme;                          /*^ M, 0, B, 2, 6 ^*/
    U32 ul_coding_rate;
    U8  transmission_mode;                      /*^ M, 0, B, 1, 7 ^*/
    U8  num_of_layer;                           /*^ M, 0, B, 1, 2 ^*/
    U8  code_book_index;                        /*^ M, 0, H, 0, 3 ^*/

    rrc_mac_sr_config_info_t    sr_config_info;
/*^ TLV, RRC_MAC_SR_CONFIG_INFO, RRC_MAC_SR_CONFIG_INFO_PRESENT ^*/

    rrc_mac_cqi_info_t          cqi_info;
/*^ TLV, RRC_MAC_CQI_INFO, RRC_MAC_CQI_INFO_PRESENT ^*/

} rrc_mac_add_ue_info_t;

#define RRC_MAC_ADD_UE_INFO_PRESENT 0x01

typedef struct _rrc_mac_create_ue_entity_req_t
{
    rrc_bitmask_t           optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_ue_index_t          ue_index;

    rrc_mac_add_ue_info_t   add_ue_info;
/*^ TLV, RRC_MAC_ADD_UE_INFO, RRC_MAC_ADD_UE_INFO_PRESENT ^*/


    rrc_counter_t           create_lc_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_create_lc_req_t create_lc_req[RRC_MAC_MAX_CREATE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_CREATE_LC_REQ ^*/

} rrc_mac_create_ue_entity_req_t; /*^ API, RRC_MAC_CREATE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_MAC_CREATE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_mac_dl_lc_config_resp_t
{
    U8 dummy;
} rrc_mac_dl_lc_config_resp_t;

typedef struct _rrc_mac_ul_lc_config_resp_t
{
    U8 dummy;
} rrc_mac_ul_lc_config_resp_t;

#define RRC_MAC_UL_LC_CONFIG_RESP_PRESENT 0x01
#define RRC_MAC_DL_LC_CONFIG_RESP_PRESENT 0x02

typedef struct _rrc_mac_create_lc_error_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lch_id;         /*^ M, 0, H, 0, 10 ^*/
    rrc_response_t              response;
/*^ M, 0, H, 0, 1 ^*/   /* rrc_mac_logical_channel_error_code_et */


    rrc_mac_ul_lc_config_resp_t ul_lc_config_resp;
/*^ TLV, EMPTY, RRC_MAC_UL_LC_CONFIG_RESP, RRC_MAC_UL_LC_CONFIG_RESP_PRESENT ^*/

    rrc_mac_dl_lc_config_resp_t dl_lc_config_resp;
/*^ TLV, EMPTY, RRC_MAC_DL_LC_CONFIG_RESP, RRC_MAC_DL_LC_CONFIG_RESP_PRESENT ^*/

} rrc_mac_create_lc_error_t;

typedef struct _rrc_mac_create_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    rrc_response_t  response_code;
/*^ M, 0, H, 0, 2 ^*/ /* rrc_mac_return_et */


    rrc_counter_t               create_lc_error_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_create_lc_error_t   create_lc_error[RRC_MAC_MAX_CREATE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_CREATE_LC_ERROR ^*/

} rrc_mac_create_ue_entity_cnf_t; /*^ API, RRC_MAC_CREATE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   RRC_MAC_DELETE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_mac_delete_ue_entity_req_t
{
    rrc_ue_index_t  ue_index;
} rrc_mac_delete_ue_entity_req_t; /*^ API, RRC_MAC_DELETE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_MAC_DELETE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_mac_delete_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    rrc_response_t  response;   /*^ M, 0, H, 0, 1 ^*/ /* rrc_mac_return_et */
} rrc_mac_delete_ue_entity_cnf_t; /*^ API, RRC_MAC_DELETE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   RRC_MAC_RECONFIGURE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_mac_delete_lc_req_t
{
    rrc_lc_id_t lch_id;             /*^ M, 0, H, 0, 10 ^*/
    U8          lc_type;
/*^ M, 0, B, 1, 3 ^*/   /* rrc_mac_delete_lc_types_et */

} rrc_mac_delete_lc_req_t;

typedef struct _rrc_mac_dl_lc_reconfig_req_t
{
    U8  lch_priority;                   /*^ M, 0, B, 1, 16 ^*/
} rrc_mac_dl_lc_reconfig_req_t;

typedef struct _rrc_mac_ul_lc_reconfig_req_t
{
    U8 lc_g_id;
} rrc_mac_ul_lc_reconfig_req_t;

#define RRC_MAC_UL_LC_RECONFIG_REQ_PRESENT 0x01
#define RRC_MAC_DL_LC_RECONFIG_REQ_PRESENT 0x02

typedef struct _rrc_mac_reconfigure_lc_req_t
{
    rrc_bitmask_t                   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                     lch_id; /*^ M, 0, H, 0, 10 ^*/

    rrc_mac_ul_lc_reconfig_req_t    ul_lc_reconfig_req;
/*^ TLV, RRC_MAC_UL_LC_RECONFIGURE_REQ, RRC_MAC_UL_LC_RECONFIG_REQ_PRESENT ^*/

    rrc_mac_dl_lc_reconfig_req_t    dl_lc_reconfig_req;
/*^ TLV, RRC_MAC_DL_LC_RECONFIGURE_REQ, RRC_MAC_DL_LC_RECONFIG_REQ_PRESENT ^*/

} rrc_mac_reconfigure_lc_req_t;

typedef struct _rrc_mac_code_book_index_info_t
{
    U8  code_book_index;                /*^ M, 0, H, 0, 3 ^*/
} rrc_mac_code_book_index_info_t;

typedef struct _rrc_mac_num_of_layer_info_t
{
    U8  num_of_layer;                   /*^ M, 0, B, 1, 4 ^*/
} rrc_mac_num_of_layer_info_t;

typedef struct _rrc_mac_tx_mode_info_t
{
    U8  transmission_mode;              /*^ M, 0, B, 1, 7 ^*/
} rrc_mac_tx_mode_info_t;

typedef struct _rrc_mac_ul_max_rb_info_t
{
    U8  ul_max_rb;                      /*^ M, 0, B, 1, 100 ^*/
} rrc_mac_ul_max_rb_info_t;

typedef struct _rrc_mac_dl_max_rb_info_t
{
    U8  dl_max_rb;                      /*^ M, 0, B, 1, 100 ^*/
} rrc_mac_dl_max_rb_info_t;

#define RRC_MAC_RECONF_CQI_INFO_PRESENT                 0x01
#define RRC_MAC_DL_MAX_RB_INFO_PRESENT                  0x02
#define RRC_MAC_UL_MAX_RB_INFO_PRESENT                  0x04
#define RRC_MAC_TX_MODE_INFO_PRESENT                    0x08
#define RRC_MAC_NUM_OF_LAYER_INFO_PRESENT               0x10
#define RRC_MAC_CODE_BOOK_INDEX_INFO_PRESENT            0x20
#define RRC_MAC_RECONF_SR_CONFIG_INFO_PRESENT           0x40
#define RRC_MAC_SIMULTANEOUS_ACK_NACK_CQI_INFO_PRESENT  0x80

typedef struct _rrc_mac_reconfig_ue_info_t
{
    rrc_bitmask_t                   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_mac_cqi_info_t              cqi_info;
/*^ TLV, RRC_MAC_CQI_INFO, RRC_MAC_RECONF_CQI_INFO_PRESENT ^*/

    rrc_mac_dl_max_rb_info_t        dl_max_rb_info;
/*^ TLV, RRC_MAC_DL_MAX_RB_INFO, RRC_MAC_DL_MAX_RB_INFO_PRESENT ^*/

    rrc_mac_ul_max_rb_info_t        ul_max_rb_info;
/*^ TLV, RRC_MAC_UL_MAX_RB_INFO, RRC_MAC_UL_MAX_RB_INFO_PRESENT ^*/

    rrc_mac_tx_mode_info_t          tx_mode_info;
/*^ TLV, RRC_MAC_TX_MODE_INFO, RRC_MAC_TX_MODE_INFO_PRESENT ^*/

    rrc_mac_num_of_layer_info_t     num_of_layer_info;
/*^ TLV, RRC_MAC_NUM_OF_LAYER_INFO, RRC_MAC_NUM_OF_LAYER_INFO_PRESENT ^*/

    rrc_mac_code_book_index_info_t  code_book_index_info;
/*^ TLV, RRC_MAC_CODE_BOOK_INDEX_INFO, RRC_MAC_CODE_BOOK_INDEX_INFO_PRESENT ^*/

    rrc_mac_sr_config_info_t        sr_config_info;
/*^ TLV, RRC_MAC_SR_CONFIG_INFO, RRC_MAC_RECONF_SR_CONFIG_INFO_PRESENT ^*/

} rrc_mac_reconfig_ue_info_t;

#define RRC_MAC_RECONFIG_UE_INFO_PRESENT 0x01

typedef struct _rrc_mac_reconfigure_ue_entity_req_t
{
    rrc_bitmask_t                   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_ue_index_t                  ue_index;

    rrc_mac_reconfig_ue_info_t      reconfig_ue_info;
/*^ TLV, RRC_MAC_RECONFIG_UE_INFO, RRC_MAC_RECONFIG_UE_INFO_PRESENT ^*/


    rrc_counter_t                   create_lc_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_create_lc_req_t         create_lc_req[RRC_MAC_MAX_CREATE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_CREATE_LC_REQ ^*/


    rrc_counter_t                   reconfigure_lc_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_reconfigure_lc_req_t
        reconfigure_lc_req[RRC_MAC_MAX_RECONFIGURE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_RECONFIGURE_LC_REQ ^*/


    rrc_counter_t                   delete_lc_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_delete_lc_req_t         delete_lc_req[RRC_MAC_MAX_DELETE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_DELETE_LC_REQ ^*/

} rrc_mac_reconfigure_ue_entity_req_t;
/*^ API, RRC_MAC_RECONFIGURE_UE_ENTITY_REQ ^*/


/******************************************************************************
*   RRC_MAC_RECONFIGURE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_mac_delete_lc_error_t
{
    rrc_lc_id_t     lch_id;             /*^ M, 0, H, 0, 10 ^*/
    rrc_response_t  response;
/*^ M, 0, H, 0, 1 ^*/       /* rrc_mac_logical_channel_error_code_et */

    U8              lc_type;
/*^ M, 0, H, 0, 2 ^*/       /* rrc_mac_delete_lc_types_et */

} rrc_mac_delete_lc_error_t;

#define RRC_MAC_RECONF_UL_LC_CONFIG_RESP_PRESENT 0x01
#define RRC_MAC_RECONF_DL_LC_CONFIG_RESP_PRESENT 0x02

typedef struct _rrc_mac_reconfigure_lc_error_t
{
    rrc_bitmask_t   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_lc_id_t     lch_id;                 /*^ M, 0, H, 0, 10 ^*/
    rrc_response_t  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_mac_return_et */


    rrc_mac_ul_lc_config_resp_t ul_lc_config_resp;
/*^ TLV, EMPTY, RRC_MAC_UL_LC_CONFIG_RESP, RRC_MAC_RECONF_UL_LC_CONFIG_RESP_PRESENT ^*/

    rrc_mac_dl_lc_config_resp_t dl_lc_config_resp;
/*^ TLV, EMPTY, RRC_MAC_DL_LC_CONFIG_RESP, RRC_MAC_RECONF_DL_LC_CONFIG_RESP_PRESENT ^*/

} rrc_mac_reconfigure_lc_error_t;

typedef struct _rrc_mac_reconfigure_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    rrc_response_t  response_code;

    rrc_counter_t                   create_lc_error_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_create_lc_error_t       create_lc_error[RRC_MAC_MAX_CREATE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_CREATE_LC_ERROR ^*/


    rrc_counter_t                   reconfigure_lc_error_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_reconfigure_lc_error_t
        reconfigure_lc_error[RRC_MAC_MAX_RECONFIGURE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_RECONFIGURE_LC_ERROR ^*/


    rrc_counter_t                   delete_lc_error_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_delete_lc_error_t       delete_lc_error[RRC_MAC_MAX_DELETE_LC];
/*^ TLV, SEQUENCE, RRC_MAC_DELETE_LC_ERROR ^*/

} rrc_mac_reconfigure_ue_entity_cnf_t;
/*^ API, RRC_MAC_RECONFIGURE_UE_ENTITY_CNF ^*/


/******************************************************************************
*   RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND
******************************************************************************/
typedef struct _rrc_mac_ue_entity_power_headroom_ind_t
{
    rrc_ue_index_t  ue_index;
    rrc_rnti_t      crnti;              /*^ M, 0, B, 1, 65523 ^*/
    U16             power_headroom;     /*^ M, 0, H, 0, 63 ^*/
} rrc_mac_ue_entity_power_headroom_ind_t;
/*^ API, RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND ^*/


/******************************************************************************
*   RRC_MAC_UE_DRX_CMD_REQ
******************************************************************************/
typedef struct _rrc_mac_ue_drx_cmd_req_t
{
    rrc_ue_index_t  ue_index;
} rrc_mac_ue_drx_cmd_req_t; /*^ API, RRC_MAC_UE_DRX_CMD_REQ ^*/

/******************************************************************************
*   RRC_MAC_UE_CON_REJ_REQ
******************************************************************************/
typedef struct _rrc_mac_ue_con_rej_req_t
{
    rrc_rnti_t  tcrnti;             /*^ M, 0, B, 1, 65523 ^*/
    U8          ccch_msg_buf[0];    /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_mac_ue_con_rej_req_t; /*^ API, RRC_MAC_UE_CON_REJ_REQ ^*/

/******************************************************************************
*   MAC common channel messages
******************************************************************************/

/******************************************************************************
*   RRC_MAC_BCCH_CONFIG_REQ
******************************************************************************/

#define RRC_MAC_BCCH_SIBTYPE1_MSG_REQ_PRESENT   0x01
#define RRC_MAC_BCCH_SI_MSG_REQ_PRESENT         0x02

typedef struct _rrc_mac_bcch_config_req_t
{
    rrc_bitmask_t   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_counter_t               mib_msg_req_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_mib_msg_req_t       mib_msg_req[RRC_MIB_MSGS];
/*^ TLV, SEQUENCE, RRC_MAC_MIB_MSG_REQ ^*/

    rrc_mac_sibtype1_msg_req_t  sib1_msg_req;
/*^ TLV, RRC_MAC_SIBTYPE1_MSG_REQ, RRC_MAC_BCCH_SIBTYPE1_MSG_REQ_PRESENT ^*/

    rrc_mac_si_msg_req_t        si_msg_req;
/*^ TLV, RRC_MAC_SI_MSG_REQ, RRC_MAC_BCCH_SI_MSG_REQ_PRESENT ^*/

} rrc_mac_bcch_config_req_t; /*^ API, RRC_MAC_BCCH_CONFIG_REQ ^*/

/******************************************************************************
*   RRC_MAC_PCCH_MSG_REQ
******************************************************************************/
typedef struct _rrc_mac_pcch_msg_req_t
{
    rrc_sfn_t   paging_frame;       /*^ M, 0, H, 0, 1023 ^*/
    rrc_sf_t    paging_sub_frame;   /*^ M, 0, H, 0, 9 ^*/
    U8          paging_repetition_required;  /*^ M, 0, H, 0, 1 ^*/
    U8          paging_msg_buf[0];  /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_mac_pcch_msg_req_t; /*^ API, ONLY_PUP, RRC_MAC_PCCH_MSG_REQ ^*/

/******************************************************************************
*   RRC_MAC_CCCH_MSG_REQ
******************************************************************************/
typedef struct _rrc_mac_ccch_msg_req_t
{
    rrc_rnti_t  rnti;               /*^ M, 0, B, 1, 65523 ^*/
    U8          ccch_msg_buf[0];    /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_mac_ccch_msg_req_t; /*^ API, ONLY_PUP, RRC_MAC_CCCH_MSG_REQ ^*/

/******************************************************************************
*   RRC_MAC_CCCH_MSG_IND
******************************************************************************/
typedef struct _rrc_mac_ccch_msg_ind_t
{
    rrc_rnti_t  rnti;               /*^ M, 0, B, 1, 65523 ^*/
    U8          ccch_msg_buf[0];    /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_mac_ccch_msg_ind_t; /*^ API, ONLY_PUP, RRC_MAC_CCCH_MSG_IND ^*/

/******************************************************************************
*   RRC_MAC_RESET_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_mac_reset_ue_entity_req_t
{
     rrc_ue_index_t  ue_index; 
} rrc_mac_reset_ue_entity_req_t;/*^ API, RRC_MAC_RESET_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_MAC_RESET_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_mac_reset_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index; 
    rrc_response_t  response;     
} rrc_mac_reset_ue_entity_cnf_t; /*^ API, RRC_MAC_RESET_UE_ENTITY_CNF ^*/

/******************************************************************************
*   RRC_MAC_RADIO_LINK_FAILURE_IND
******************************************************************************/
typedef struct _rrc_mac_radio_link_failure_ind_t
{
     rrc_ue_index_t  ue_index;
} rrc_mac_radio_link_failure_ind_t;/*^ API, RRC_MAC_RADIO_LINK_FAILURE_IND ^*/


#pragma pack(pop)

#endif /* _RRC_MAC_INTF_H_ */

