/******************************************************************************
 *
 *   FILE NAME:
 *       rrc_rlc_intf.h
 *
 *   DESCRIPTION:
 *       This file contains types used for representation of RLC API inside RRC.
 *       Based on LTE_RLC_API_Rel_1.0_Rev_1.1.doc and LTE_RRC_API_0_31.doc.
 *
 *   DATE            AUTHOR      REFERENCE       REASON
 *   07 Apr 2009     VasylN      ---------       Initial
 *
 *   Copyright (c) 2009, Aricent Inc. All Rights Reserved
 *
 ******************************************************************************/

#ifndef _RRC_RLC_INTF_H_
#define _RRC_RLC_INTF_H_

#include "rrc_defines.h"

/* UE specific RRC defines */
#define RRC_RLC_MAX_NUM_LC  20

typedef enum
{
    RLC_FAILURE,
    RLC_SUCCESS,
    RLC_PARTIAL_SUCCESS
} rrc_rlc_return_et;

#pragma pack(push, 1)

/******************************************************************************
 * RLC create UE tags
 ******************************************************************************/
typedef struct _rrc_rlc_create_tx_um_rlc_t
{
    rrc_lc_id_t         lc_id;
    rrc_sn_field_l_t    sn_field_length;
} rrc_rlc_create_tx_um_rlc_t;

typedef struct _rrc_rlc_create_rx_um_rlc_t
{
    rrc_lc_id_t         lc_id;
    rrc_sn_field_l_t    sn_field_length;
    rrc_t_reordering_t  t_reordering;
} rrc_rlc_create_rx_um_rlc_t;

typedef struct _rrc_rlc_create_tx_rx_um_rlc_t
{
    rrc_lc_id_t         lc_id;
    rrc_sn_field_l_t    sn_field_length_tx;
    rrc_sn_field_l_t    sn_field_length_rx;
    rrc_t_reordering_t  t_reordering;
} rrc_rlc_create_tx_rx_um_rlc_t;

typedef struct _rrc_rlc_create_tx_rx_am_rlc_t
{
    rrc_lc_id_t         lc_id;
    U16                 t_poll_retransmission;
    U16                 poll_pdu;
    U16                 poll_byte;
    U16                 max_re_tx_thrsh_ld;
    rrc_t_reordering_t  t_reordering;
    U16                 t_status_prohibit;
} rrc_rlc_create_tx_rx_am_rlc_t;

/******************************************************************************
 * RLC delete UE tags
 ******************************************************************************/
typedef struct _rrc_rlc_delete_tx_um_rlc_t
{
    rrc_lc_id_t lc_id;
} rrc_rlc_delete_tx_um_rlc_t;

typedef struct _rrc_rlc_delete_rx_um_rlc_t
{
    rrc_lc_id_t lc_id;
} rrc_rlc_delete_rx_um_rlc_t;

typedef struct _rrc_rlc_delete_tx_rx_um_rlc_t
{
    rrc_lc_id_t lc_id;
} rrc_rlc_delete_tx_rx_um_rlc_t;

typedef struct _rrc_rlc_delete_tx_rx_am_rlc_t
{
    rrc_lc_id_t lc_id;
} rrc_rlc_delete_tx_rx_am_rlc_t;

/******************************************************************************
 * RLC reconfigure UE tags
 ******************************************************************************/
typedef struct _rrc_rlc_reconfig_tx_um_rlc_t
{
    rrc_lc_id_t lc_id;
} rrc_rlc_reconfig_tx_um_rlc_t;

typedef struct _rrc_rlc_reconfig_rx_um_rlc_t
{
    rrc_lc_id_t lc_id;
    rrc_t_reordering_t  t_reordering;
} rrc_rlc_reconfig_rx_um_rlc_t;

typedef struct _rrc_rlc_reconfig_tx_rx_um_rlc_t
{
    rrc_lc_id_t lc_id;
    rrc_t_reordering_t  t_reordering;
} rrc_rlc_reconfig_tx_rx_um_rlc_t;

typedef struct _rrc_rlc_reconfig_tx_rx_am_rlc_t
{
    rrc_lc_id_t lc_id;
    U16                 t_poll_retransmission;
    U16                 poll_pdu;
    U16                 poll_byte;
    U16                 max_re_tx_thrsh_ld;
    rrc_t_reordering_t  t_reordering;
    U16                 t_status_prohibit;
} rrc_rlc_reconfig_tx_rx_am_rlc_t;

/******************************************************************************
 * XXX_ENTITY_ERROR
 ******************************************************************************/
typedef struct _rrc_rlc_create_entity_error_t
{
    rrc_lc_id_t     lc_id;
    rrc_response_t  response;               /* rrc_rlc_return_et */
} rrc_rlc_create_entity_error_t;

typedef struct _rrc_rlc_delete_entity_error_t
{
    rrc_lc_id_t     lc_id;
    rrc_response_t  response;               /* rrc_rlc_return_et */
} rrc_rlc_delete_entity_error_t;

typedef struct _rrc_rlc_reconfig_entity_error_t
{
    rrc_lc_id_t     lc_id;
    rrc_response_t  response;               /* rrc_rlc_return_et */
} rrc_rlc_reconfig_entity_error_t;

typedef struct _rrc_rlc_re_establish_entity_error_t
{
    rrc_lc_id_t     lc_id;
    rrc_response_t  response;               /* rrc_rlc_return_et */
} rrc_rlc_re_establish_entity_error_t;

/******************************************************************************
 * RLC reetablish UE tags
 ******************************************************************************/

typedef struct _rrc_rlc_entity_lcid_t
{
    rrc_lc_id_t     lc_id;
} rrc_rlc_entity_lcid_t;

/******************************************************************************
 *   RLC_CREATE_UE_ENTITY_REQ
 ******************************************************************************/
typedef struct _rrc_rlc_create_ue_entity_req_t
{
    rrc_ue_index_t                  ue_index;
    U16                             rnti;

    rrc_counter_t                   num_create_tx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_um_rlc_t      create_tx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_rx_um_rlc_t      create_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_tx_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_rx_um_rlc_t   create_tx_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_tx_rx_am_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_rx_am_rlc_t   create_tx_rx_am_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_RX_AM_RLC_ENTITY ^*/

} rrc_rlc_create_ue_entity_req_t; /*^ API, RRC_RLC_CREATE_UE_ENTITY_REQ ^*/

/******************************************************************************
 *   RLC_CREATE_UE_ENTITY_CNF
 ******************************************************************************/
typedef struct _rrc_rlc_create_ue_entity_cnf_t
{
    rrc_ue_index_t                  ue_index;
    rrc_response_t                  response_code;
    /*^ M, 0, H, 0, 2 ^*/ /* rrc_rlc_return_et */


    rrc_counter_t                   num_create_entity_error;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_entity_error_t   create_error_entities[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_ENTITY_ERROR ^*/

} rrc_rlc_create_ue_entity_cnf_t; /*^ API, RRC_RLC_CREATE_UE_ENTITY_CNF ^*/

/******************************************************************************
 *   RLC_RECONFIG_UE_ENTITY_REQ
 ******************************************************************************/
typedef struct _rrc_rlc_reconfig_ue_entity_req_t
{
    rrc_ue_index_t                  ue_index;

    rrc_counter_t                   num_create_tx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_um_rlc_t      create_tx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_rx_um_rlc_t      create_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_tx_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_rx_um_rlc_t   create_tx_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_create_tx_rx_am_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_tx_rx_am_rlc_t   create_tx_rx_am_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_TX_RX_AM_RLC_ENTITY ^*/


    rrc_counter_t                   num_delete_tx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_delete_tx_um_rlc_t      delete_tx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_DELETE_TX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_delete_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_delete_rx_um_rlc_t      delete_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_DELETE_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_delete_tx_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_delete_tx_rx_um_rlc_t   delete_tx_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_DELETE_TX_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_delete_tx_rx_am_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_delete_tx_rx_am_rlc_t   delete_tx_rx_am_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_DELETE_TX_RX_AM_RLC_ENTITY ^*/


    rrc_counter_t                   num_reconfig_tx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_reconfig_tx_um_rlc_t    reconfig_tx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RECONFIG_TX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_reconfig_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_reconfig_rx_um_rlc_t    reconfig_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RECONFIG_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_reconfig_tx_rx_um_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_reconfig_tx_rx_um_rlc_t reconfig_tx_rx_um_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RECONFIG_TX_RX_UM_RLC_ENTITY ^*/


    rrc_counter_t                   num_reconfig_tx_rx_am_rlc;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_reconfig_tx_rx_am_rlc_t reconfig_tx_rx_am_rlc[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RECONFIG_TX_RX_AM_RLC_ENTITY ^*/

} rrc_rlc_reconfig_ue_entity_req_t; /*^ API, RRC_RLC_RECONFIG_UE_ENTITY_REQ ^*/

/******************************************************************************
 *   RLC_RECONFIG_UE_ENTITY_CNF
 ******************************************************************************/
typedef struct _rrc_rlc_reconfig_ue_entity_cnf_t
{
    rrc_ue_index_t                  ue_index;
    rrc_response_t                  response_code;

    rrc_counter_t                   num_create_entity_error;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_create_entity_error_t   create_error_entities[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_CREATE_ENTITY_ERROR ^*/


    rrc_counter_t                   num_delete_entity_error;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_delete_entity_error_t   delete_error_entities[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_DELETE_ENTITY_ERROR ^*/


    rrc_counter_t                   num_reconfig_entity_error;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_reconfig_entity_error_t reconfig_error_entities[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RECONFIG_ENTITY_ERROR ^*/

} rrc_rlc_reconfig_ue_entity_cnf_t; /*^ API, RRC_RLC_RECONFIG_UE_ENTITY_CNF ^*/

/******************************************************************************
 *   RLC_DELETE_UE_ENTITY_REQ
 ******************************************************************************/
typedef struct _rrc_rlc_delete_ue_entity_req_t
{
    rrc_ue_index_t ue_index;
} rrc_rlc_delete_ue_entity_req_t; /*^ API, RRC_RLC_DELETE_UE_ENTITY_REQ ^*/

/******************************************************************************
 *   RLC_DELETE_UE_ENTITY_CNF
 ******************************************************************************/
typedef struct _rrc_rlc_delete_ue_entity_cnf_t
{
    rrc_ue_index_t ue_index;
    rrc_response_t response;
    /*^ M, 0, H, 0, 1 ^*/ /* rrc_rlc_return_et */

} rrc_rlc_delete_ue_entity_cnf_t; /*^ API, RRC_RLC_DELETE_UE_ENTITY_CNF ^*/

/******************************************************************************
 *   RLC_RE_ESTABLISH_UE_ENTITY_REQ
 ******************************************************************************/
typedef struct _rrc_rlc_re_establish_ue_entity_req_t
{
    rrc_ue_index_t ue_index;

    rrc_counter_t           num_entity_lc_id;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_entity_lcid_t   entity_lcids[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_ENTITY_LCID ^*/

} rrc_rlc_re_establish_ue_entity_req_t;
/*^ API, RRC_RLC_RE_ESTABLISH_UE_ENTITY_REQ ^*/


/******************************************************************************
 *   RLC_RE_ESTABLISH_UE_ENTITY_CNF
 ******************************************************************************/
typedef struct _rrc_rlc_re_establish_ue_entity_cnf_t
{
    rrc_response_t                      response_code;
    /*^ M, 0, H, 0, 2 ^*/ /* rrc_rlc_return_et */


    rrc_counter_t                       num_error_entity;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_rlc_re_establish_entity_error_t error_entities[RRC_RLC_MAX_NUM_LC];
    /*^ TLV, SEQUENCE, RRC_RLC_RE_ESTABLISH_ENTITY_ERROR ^*/

} rrc_rlc_re_establish_ue_entity_cnf_t;
/*^ API, RRC_RLC_RE_ESTABLISH_UE_ENTITY_CNF ^*/

/******************************************************************************

*   RRC_RLC_UE_ENTITY_ERROR_IND
******************************************************************************/

 

typedef struct _rlc_ue_entity_error_ind_t
{
    rrc_ue_index_t ue_index;
    rrc_lc_id_t     lc_id;

}rlc_ue_entity_error_ind_t; /*^ API, RRC_RLC_UE_ENTITY_ERROR_IND ^*/





typedef enum
{
    RLC_INVALID_UE_INDEX =   3,
    RLC_UE_ID_EXISTS =   4,
    RLC_UE_NOT_EXISTS =  5,
    RLC_INTERNAL_ERROR = 11,
    RLC_SYNTAX_ERROR  =  12,
    RLC_INVALID_LC_ID =  31,
    RLC_ENTITY_EXISTS  = 32,
    RLC_ENTITY_NOT_EXISTS =  33,
    RLC_UE_ENTITY_IN_USE  =  34

}rrc_rlc_error_code_et;



#pragma pack(pop)

#endif /* _RRC_RLC_INTF_H_ */

