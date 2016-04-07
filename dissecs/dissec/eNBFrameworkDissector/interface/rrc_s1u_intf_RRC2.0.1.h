/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (C) 2009 Aricent Inc. All Rights Reserved.
 *
 ****************************************************************************
 * File Details
 * ------------
 *  $Id: rrc_s1u_intf.h,v 1.4 2010/07/22 11:31:25 gur21006 Exp $
 ****************************************************************************
 *
 *  File Description :
 *      rrc_s1u_intf.h
 *      This file contains types used for
 *      representation of S1-U API inside RRC.
 *      Based on LTE_Relay_API_30_Oct_RRC.doc
 *      and LTE_L3_API_Rel_1_0_Rev_0_37.doc.
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------
 *
 * $Log: rrc_s1u_intf.h,v $
 * Revision 1.4  2010/07/22 11:31:25  gur21006
 * uecc_llim changes done at llim
 *
 * Revision 1.3  2010/07/09 15:16:00  gur21006
 * Code Comments Incorporated
 *
 * Revision 1.2  2010/01/04 16:10:03  ukr15916
 * no message
 *
 * Revision 1.1.4.1  2009/11/26 18:33:42  ukr16018
 * Merge S1AP and RRC (from branch dev_rel_1_0).
 *
 * Revision 1.1.2.9  2009/11/19 15:00:37  ukr16018
 * W80.
 *
 * Revision 1.1.2.8  2009/11/19 09:52:11  ukr15916
 * tabs -> spaces
 *
 * Revision 1.1.2.7  2009/11/16 11:47:03  ukr18877
 * Code comments applied in LLIM
 *
 * Revision 1.1.2.6  2009/11/09 10:17:39  ukr18877
 * S1-U interface changed
 *
 * Revision 1.1.2.5  2009/11/05 10:15:17  ukr16018
 * S1U interface updated
 *
 * Revision 1.1.2.4  2009/11/04 14:12:00  ukr16018
 * S1U interface updated
 *
 * Revision 1.1.2.3  2009/11/03 15:00:11  ukr18877
 * Bug in S1U interface fixed
 *
 * Revision 1.1.2.2  2009/11/03 14:55:08  ukr18877
 * S1U composer/parser added
 *
 * Revision 1.1.2.1  2009/11/03 13:08:19  ukr16018
 * Initial version of rrc_s1u_intf.h added
 *
 *
 *
 ****************************************************************************/

#ifndef INCLUDED_RRC_S1U_INTF_H
#define INCLUDED_RRC_S1U_INTF_H

/****************************************************************************
 * Project Includes
 ****************************************************************************/

#include "rrc_defines.h"

/****************************************************************************
 * Exported Includes
 ****************************************************************************/



/****************************************************************************
 * Exported Definitions
 ****************************************************************************/

#define RRC_S1U_MAX_NUM_LC      8

typedef enum
{
    S1U_SUCCESS,
    S1U_RESOURCES_NOT_AVAILABLE,
    S1U_CTXT_NOT_FOUND,
    S1U_DUPLICATE_PEER_TEID,
    S1U_INV_SAP_CFG,
    S1U_IPV6_ADDR_RECEIVED
} rrc_s1u_cause_et;

typedef enum
{
    S1U_SEQ_ENABLE,
    S1U_SEQ_DISABLE
} rrc_s1u_disable_et;

/****************************************************************************
 * Exported Types
 ****************************************************************************/

#pragma pack(push, 1)

/******************************************************************************
*   S1U_CREATE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_s1u_create_ue_entity_req_t
{
    rrc_ue_index_t ue_index;                    /*^ M, 0, H, 0, 600 ^*/
} rrc_s1u_create_ue_entity_req_t; /*^ API, RRC_S1U_CREATE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   S1U_CREATE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_s1u_create_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;                   /*^ M, 0, H, 0, 600 ^*/
    U8              response_code;              /* rrc_s1u_cause_et */
} rrc_s1u_create_ue_entity_cnf_t; /*^ API, RRC_S1U_CREATE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   S1U_DELETE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_s1u_delete_ue_entity_req_t
{
    rrc_ue_index_t ue_index;                    /*^ M, 0, H, 0, 600 ^*/
} rrc_s1u_delete_ue_entity_req_t; /*^ API, RRC_S1U_DELETE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   S1U_DELETE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_s1u_delete_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;                   /*^ M, 0, H, 0, 600 ^*/
    U8              response_code;              /* rrc_s1u_cause_et */
} rrc_s1u_delete_ue_entity_cnf_t; /*^ API, RRC_S1U_DELETE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   S1U_RECONFIGURE_UE_ENTITY_REQ
******************************************************************************/

typedef struct _rrc_s1u_ie_gsn_addr_t
{
    rrc_counter_t   data_length;
/*^ M, 0, BUFFER_SIZE, NOT_PRESENT_IN_MESSAGE ^*/

    U8              data[RRC_S1U_MAX_GSN_ADDR];
/*^ M, 0, OCTET_STRING, LIMITED_TILL_THE_END ^*/

} rrc_s1u_ie_gsn_addr_t;

typedef struct _rrc_s1u_ie_qos_profile_t
{
    U8              allocation_retention_priority;
    rrc_counter_t   qos_profile_data_length;
/*^ M, 0, BUFFER_SIZE, NOT_PRESENT_IN_MESSAGE ^*/

    U8              qos_profile_data[RRC_S1U_MAX_QOS_PROFILE_DATA];
/*^ M, 0, OCTET_STRING, LIMITED_TILL_THE_END ^*/

} rrc_s1u_ie_qos_profile_t;

typedef struct _rrc_s1u_ie_seq_num_t
{
    U16 ul_sequence_number;                     /*^ M, 0, H, 0, 32767 ^*/
    U16 dl_sequence_number;                     /*^ M, 0, H, 0, 32767 ^*/
} rrc_s1u_ie_seq_num_t;

typedef struct _rrc_s1u_ie_seq_disable_t
{
    U8  disable;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_s1u_disable_et */

} rrc_s1u_ie_seq_disable_t;

typedef struct _rrc_s1u_reordering_reqd_t
{
    U8  reordering_reqd;                        /*^ M, 0, H, 0, 1 ^*/
} rrc_s1u_reordering_reqd_t;

typedef struct _rrc_s1u_ie_teid_peer_t
{
    rrc_gtp_teid_t teid;
} rrc_s1u_ie_teid_peer_t;

typedef struct _rrc_s1u_ie_teid_self_t
{
    rrc_gtp_teid_t teid;
} rrc_s1u_ie_teid_self_t;

typedef struct _rrc_s1u_ie_tunnel_info_t
{
#define RRC_S1U_IE_TUNNEL_INFO_TEID_PEER_PRESENT    0x01
#define RRC_S1U_IE_SETUP_TRANSPORT_ADDR_PRESENT     0x02
    
    rrc_bitmask_t               bitmask;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/

    U8                          sap_flag;
    rrc_s1u_ie_teid_peer_t              teid_peer;
    /*^ TLV, RRC_S1U_IE_TEID_PEER_TAG, RRC_S1U_IE_TUNNEL_INFO_TEID_PEER_PRESENT ^*/

    rrc_s1u_ie_gsn_addr_t       transport_addr;
/*^ TLV, RRC_S1U_IE_GSN_ADDR_TAG, RRC_S1U_IE_SETUP_TRANSPORT_ADDR_PRESENT ^*/
}rrc_s1u_ie_tunnel_info_t;



typedef struct _rrc_s1u_ie_buffer_ind_t
{
    U8 buffer_ind; /*^ M, 0, H, 0, 1 ^*/
}rrc_s1u_ie_buffer_ind_t;



#define RRC_S1U_IE_SETUP_BUFFER_IND_PRESENT         0x01
#define RRC_S1U_IE_SETUP_TEID_SELF_PRESENT          0x02
#define RRC_S1U_IE_SETUP_QOS_PROFILE_PRESENT        0x04
#define RRC_S1U_IE_SETUP_SEQ_NUM_PRESENT            0x08
#define RRC_S1U_IE_SETUP_SEQ_FLAG_PRESENT           0x10
#define RRC_S1U_IE_SETUP_REORDERING_REQD_PRESENT    0x20

typedef struct _rrc_s1u_ie_relay_setup_sap_req_t
{
    rrc_bitmask_t               bitmask;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/
    
    rrc_lc_id_t                 lc_id;          /*^ M, 0, B, 3, 10 ^*/
    U32                         qos_id;
    
    rrc_s1u_ie_buffer_ind_t       buffer_ind;
/*^ TLV, RRC_S1U_IE_BUFFER_IND_TAG, RRC_S1U_IE_SETUP_BUFFER_IND_PRESENT ^*/

    rrc_s1u_ie_teid_self_t        teid_self;
/*^ TLV, RRC_S1U_IE_TEID_SELF_TAG, RRC_S1U_IE_SETUP_TEID_SELF_PRESENT ^*/

    rrc_s1u_ie_qos_profile_t    qos_profile;
/*^ TLV, RRC_S1U_IE_QOS_PROFILE_TAG, RRC_S1U_IE_SETUP_QOS_PROFILE_PRESENT ^*/

    rrc_s1u_ie_seq_num_t        seq_num;
/*^ TLV, RRC_S1U_IE_SEQ_NUM_TAG, RRC_S1U_IE_SETUP_SEQ_NUM_PRESENT ^*/

    rrc_s1u_ie_seq_disable_t    seq_flag;
/*^ TLV, RRC_S1U_IE_SEQ_DISABLE_TAG, RRC_S1U_IE_SETUP_SEQ_FLAG_PRESENT ^*/

    rrc_s1u_reordering_reqd_t   reordering_reqd;
/*^ TLV, RRC_S1U_IE_REORDERING_REQD_TAG, RRC_S1U_IE_SETUP_REORDERING_REQD_PRESENT ^*/
 
    rrc_counter_t             num_tunnel_info;
 /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/
    
    rrc_s1u_ie_tunnel_info_t      tunnel_info[RRC_S1U_MAX_TUNNELS_PER_LC];
 /*^ TLV, SEQUENCE, RRC_S1U_IE_TUNNEL_INFO_TAG ^*/
} rrc_s1u_ie_relay_setup_sap_req_t;


typedef struct _rrc_s1u_ie_relay_rel_sap_req_t
{
    rrc_lc_id_t     lc_id;
} rrc_s1u_ie_relay_rel_sap_req_t;

typedef struct _rrc_s1u_reconfigure_ue_entity_req_t
{
    rrc_ue_index_t ue_index;                    /*^ M, 0, H, 0, 600 ^*/

    rrc_counter_t                       num_setup_sap_req;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_s1u_ie_relay_setup_sap_req_t    setup_sap_req[RRC_S1U_MAX_NUM_LC];
/*^ TLV, SEQUENCE, RRC_S1U_IE_RELAY_SETUP_SAP_REQ_TAG ^*/


    rrc_counter_t                       num_rel_sap_req;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_s1u_ie_relay_rel_sap_req_t      rel_sap_req[RRC_S1U_MAX_NUM_LC];
/*^ TLV, SEQUENCE, RRC_S1U_IE_RELAY_REL_SAP_REQ_TAG ^*/

} rrc_s1u_reconfigure_ue_entity_req_t;
/*^ API, RRC_S1U_RECONFIGURE_UE_ENTITY_REQ ^*/


/******************************************************************************
*   RRC_S1U_RECONFIGURE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_s1u_ie_teid_data_i_t
{
    rrc_gtp_teid_t teid;
} rrc_s1u_ie_teid_data_i_t;


#define RRC_S1U_IE_TUNNEL_INFO_CNF_TEID_SELF_PRESENT       0x01
#define RRC_S1U_IE_TUNNEL_INFO_CNF_TEID_PEER_PRESENT       0x02
#define RRC_S1U_IE_TUNNEL_INFO_CNF_TRANSPORT_ADDR_PRESENT  0x04

typedef struct _rrc_s1u_ie_tunnel_info_cnf_t
{
    rrc_bitmask_t               bitmask;
    /*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/

    U8                  cause;   /*^ M, 0, H, 0, 5 ^*/  /* rrc_s1u_cause_et */
    U16                 rb_direction; /*^ M, 0, H, 0, 1 ^*/

    rrc_s1u_ie_teid_self_t  teid_self;
    /*^ TLV, RRC_S1U_IE_TEID_SELF_TAG, RRC_S1U_IE_TUNNEL_INFO_CNF_TEID_SELF_PRESENT ^*/

    rrc_s1u_ie_teid_peer_t  teid_peer;
    /*^ TLV, RRC_S1U_IE_TEID_PEER_TAG, RRC_S1U_IE_TUNNEL_INFO_CNF_TEID_PEER_PRESENT ^*/

    rrc_s1u_ie_gsn_addr_t     transport_addr;
    /*^ TLV, RRC_S1U_IE_GSN_ADDR_TAG, RRC_S1U_IE_TUNNEL_INFO_CNF_TRANSPORT_ADDR_PRESENT ^*/

}rrc_s1u_ie_tunnel_info_cnf_t;


#define RRC_S1U_IE_SETUP_SAP_CNF_SEQ_NUM_PRESENT 0x01

typedef struct _rrc_s1u_ie_relay_setup_sap_cnf_t
{
    rrc_bitmask_t               bitmask;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lc_id;          /*^ M, 0, B, 3, 10 ^*/
    U8                          cause;          /* rrc_s1u_cause_et */
    
    rrc_counter_t                  num_sap_cnf;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_s1u_ie_tunnel_info_cnf_t   tunnel_info_cnf[RRC_S1U_MAX_TUNNELS_PER_LC];
    /*^ TLV, SEQUENCE, RRC_S1U_IE_TUNNEL_INFO_CNF_TAG ^*/


    rrc_s1u_ie_seq_num_t        seq_num;
/*^ TLV, RRC_S1U_IE_SEQ_NUM_TAG, RRC_S1U_IE_SETUP_SAP_CNF_SEQ_NUM_PRESENT ^*/
    /* present if cause contains success */

} rrc_s1u_ie_relay_setup_sap_cnf_t;

#define RRC_S1U_IE_REL_CNF_SEQ_NUM_PRESENT      0x01

typedef struct _rrc_s1u_ie_relay_rel_sap_cnf_t
{
    rrc_bitmask_t               bitmask;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lc_id;          /*^ M, 0, B, 3, 10 ^*/
    U8                          cause;          /* rrc_s1u_cause_et */

    rrc_s1u_ie_seq_num_t        seq_num;
/*^ TLV, RRC_S1U_IE_SEQ_NUM_TAG, RRC_S1U_IE_REL_CNF_SEQ_NUM_PRESENT ^*/
    /* present if cause contains success */

} rrc_s1u_ie_relay_rel_sap_cnf_t;

typedef struct _rrc_s1u_reconfigure_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;                   /*^ M, 0, H, 0, 600 ^*/

    rrc_counter_t                       num_setup_sap_cnf;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_s1u_ie_relay_setup_sap_cnf_t    setup_sap_cnf[RRC_S1U_MAX_NUM_LC];
/*^ TLV, SEQUENCE, RRC_S1U_IE_RELAY_SETUP_SAP_CNF_TAG ^*/


    rrc_counter_t                       num_rel_sap_cnf;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_s1u_ie_relay_rel_sap_cnf_t      rel_sap_cnf[RRC_S1U_MAX_NUM_LC];
/*^ TLV, SEQUENCE, RRC_S1U_IE_RELAY_REL_SAP_CNF_TAG ^*/

} rrc_s1u_reconfigure_ue_entity_cnf_t;
/*^ API, RRC_S1U_RECONFIGURE_UE_ENTITY_CNF ^*/


/******************************************************************************
*   S1U_ERROR_IND
******************************************************************************/
typedef struct _rrc_s1u_error_ind_t
{
    rrc_ue_index_t  ue_index;                   /*^ M, 0, H, 0, 600 ^*/
    rrc_lc_id_t     lc_id;                      /*^ M, 0, B, 3, 10 ^*/
} rrc_s1u_error_ind_t; /*^ API, RRC_S1U_ERROR_IND ^*/

/******************************************************************************
*   S1U_PATH_FAILURE_IND
******************************************************************************/
#define RRC_TRANSPORT_ADDR_PRESENT      0x01

typedef struct _rrc_s1u_path_failure_ind_t
{
    rrc_bitmask_t           bitmask;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_s1u_ie_gsn_addr_t   transport_addr;
/*^ TLV, RRC_S1U_IE_GSN_ADDR_TAG, RRC_TRANSPORT_ADDR_PRESENT ^*/

} rrc_s1u_path_failure_ind_t; /*^ API, RRC_S1U_PATH_FAILURE_IND ^*/

#pragma pack(pop)

/****************************************************************************
 * Exported Constants
 ****************************************************************************/

/****************************************************************************
 * Exported Variables
 ****************************************************************************/

/****************************************************************************
 * Exported Functions
 ****************************************************************************/

#endif  /* INCLUDED_RRC_S1U_INTF_H */

