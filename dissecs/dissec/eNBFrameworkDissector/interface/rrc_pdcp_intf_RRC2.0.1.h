/******************************************************************************
*
*   FILE NAME:
*       rrc_pdcp_intf.h
*
*   DESCRIPTION:
*       This file contains types used for representation of PDCP API inside RRC.
*       Based on LTE_PDCP_API_Rel_1.0_Rev_1.1.doc and LTE_RRC_API_0_31.doc.
*
*   DATE            AUTHOR      REFERENCE       REASON
*   07 Apr 2009     VasylN      ---------       Initial
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/

#ifndef _RRC_PDCP_INTF_H_
#define _RRC_PDCP_INTF_H_

#include "rrc_defines.h"

/******************************************************************************
*   PDCP API Internal Representation
******************************************************************************/

#define RRC_PDCP_MAX_SRB                2
#define RRC_PDCP_MAX_DRB                8

/* Enum values for PDCP RLC mode */
typedef enum
{
    PDCP_RLC_MODE_UM = 0,
    PDCP_RLC_MODE_AM
} rrc_pdcp_rlc_mode_et;

/* Enum values for PDCP discard timer */
#define RRC_PDCP_DISC_TIMER_MS_50       0
#define RRC_PDCP_DISC_TIMER_MS_100      1
#define RRC_PDCP_DISC_TIMER_MS_150      2
#define RRC_PDCP_DISC_TIMER_MS_300      3
#define RRC_PDCP_DISC_TIMER_MS_500      4
#define RRC_PDCP_DISC_TIMER_MS_750      5
#define RRC_PDCP_DISC_TIMER_MS_1500     6
#define RRC_PDCP_DISC_TIMER_MS_INFINITY 7

/* Enum values for PDCP SN size */
#define RRC_PDCP_SN_SIZE_7 7
#define RRC_PDCP_SN_SIZE_12 12

typedef enum
{
    PDCP_FAILURE,
    PDCP_SUCCESS,
    PDCP_PARTIAL_SUCCESS
} rrc_pdcp_return_et;

typedef enum 
{
    PDCP_ERR_CONTEXT_NOT_INITIALIZED = 512,/*0x200*/
    PDCP_ERR_CONTEXT_ALREADY_INITIALIZED ,
    PDCP_ERR_UE_CONTEXT_ALREADY_CREATED ,
    PDCP_ERR_UE_CONTEXT_NOT_INITIALIZED ,
    PDCP_ERR_ENTITY_ALREADY_CREATED  ,
    PDCP_ERR_ENTITY_WRONG_DIRECTION  ,
    PDCP_ERR_ENTITY_WRONG_TYPE   ,
    PDCP_ERR_ENTITY_NOT_FOUND    ,
    PDCP_ERR_ENTITY_SET_SN_SIZE  ,
    PDCP_ERR_ENTITY_SET_STATUS_REPORT_REQUIRED   ,
    PDCP_ERR_TLV_PARSING_INVALID_LENGTH  ,
    PDCP_ERR_TLV_PARSING_INVALID_UE_ID = 768,/*0x300*/
    PDCP_ERR_TLV_PARSING_INVALID_OPTIONAL_PARAMETERS_LENGTH ,
    PDCP_ERR_TLV_PARSING_INVALID_TAG_LENGTH ,
    PDCP_ERR_TLV_PARSING_INVALID_LC_ID  ,
    PDCP_ERR_TLV_PARSING_INVALID_TAG_PARAMETER_VALUE  ,
    PDCP_ERR_TLV_PARSING_INVALID_CRNTI  ,
    PDCP_ERR_TLV_PARSING_INVALID_TAG_ID ,
    PDCP_ERR_TLV_PARSING_INVALID_RNTI_RANGE ,
    PDCP_ERR_TLV_PARSING_INVALID_API_ID 
}rrc_pdcp_error_code_et;

#pragma pack(push, 1)

/******************************************************************************
*   Common types
******************************************************************************/
typedef struct _rrc_pdcp_config_disc_timer_t
{
    U16 disc_timer;
} rrc_pdcp_config_disc_timer_t;

typedef struct _rrc_pdcp_config_sn_size_t
{
    U8 sn_size;
} rrc_pdcp_config_sn_size_t;

typedef struct _rrc_pdcp_config_st_rep_required_t
{
    U8 st_rep_required;
} rrc_pdcp_config_st_rep_required_t;


typedef struct _rrc_pdcp_cr_srb_entity_t
{
    rrc_lc_id_t                 lc_id;
    U16                         rlc_mode;
/* rrc_pdcp_rlc_mode_et */

    rrc_rb_direction_t          rb_direction;
/* rrc_rb_direction_et */

} rrc_pdcp_cr_srb_entity_t;

#define RRC_PDCP_CR_DRB_CONFIG_ROHC_PRESENT                 0x01
#define RRC_PDCP_CR_DRB_CONFIG_DISC_TIMER_PRESENT           0x02
#define RRC_PDCP_CR_DRB_CONFIG_SN_SIZE_PRESENT              0x04
#define RRC_PDCP_CR_DRB_CONFIG_ST_REPORT_REQUIRED_PRESENT   0x08

typedef struct _rrc_pdcp_cr_drb_entity_t
{
    rrc_bitmask_t                   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                     lc_id;
    U16                             rlc_mode;
/* rrc_pdcp_rlc_mode_et */

    rrc_rb_direction_t              rb_direction;
/* rrc_rb_direction_et */

    rrc_pdcp_config_rohc_t          config_rohc;
/*^ TLV, RRC_PDCP_CONFIGURE_ROHC_TAG, RRC_PDCP_CR_DRB_CONFIG_ROHC_PRESENT ^*/

    rrc_pdcp_config_disc_timer_t    config_disc_timer;
/*^ TLV, RRC_PDCP_CONFIGURE_DISCARD_TIMER_TAG, RRC_PDCP_CR_DRB_CONFIG_DISC_TIMER_PRESENT ^*/

    rrc_pdcp_config_sn_size_t       config_sn_size;
/*^ TLV, RRC_PDCP_CONFIGURE_SN_SIZE_TAG, RRC_PDCP_CR_DRB_CONFIG_SN_SIZE_PRESENT ^*/

    rrc_pdcp_config_st_rep_required_t st_rep_required;
/*^ TLV, RRC_PDCP_CONFIGURE_ST_REPORT_REQUIRED_TAG, RRC_PDCP_CR_DRB_CONFIG_ST_REPORT_REQUIRED_PRESENT ^*/

} rrc_pdcp_cr_drb_entity_t;

typedef struct _rrc_pdcp_del_srb_entity_t
{
    rrc_lc_id_t lc_id;
} rrc_pdcp_del_srb_entity_t;

typedef struct _rrc_pdcp_del_drb_entity_t
{
    rrc_lc_id_t lc_id;
} rrc_pdcp_del_drb_entity_t;


typedef struct _rrc_pdcp_rcfg_srb_entity_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lc_id;
    rrc_rb_direction_t          rb_direction;
/* rrc_rb_direction_et */

} rrc_pdcp_rcfg_srb_entity_t;

#define RRC_PDCP_RCFG_DRB_CONFIG_ROHC_PRESENT   0x01
#define RRC_PDCP_RCFG_DRB_CONFIG_ST_REPORT_REQUIRED_PRESENT   0x02

typedef struct _rrc_pdcp_rcfg_drb_entity_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lc_id;
    rrc_rb_direction_t          rb_direction;       /* rrc_rb_direction_et */

    rrc_pdcp_config_rohc_t      config_rohc;
/*^ TLV, RRC_PDCP_CONFIGURE_ROHC_TAG, RRC_PDCP_RCFG_DRB_CONFIG_ROHC_PRESENT ^*/

    rrc_pdcp_config_st_rep_required_t st_rep_required;
/*^ TLV, RRC_PDCP_CONFIGURE_ST_REPORT_REQUIRED_TAG, RRC_PDCP_RCFG_DRB_CONFIG_ST_REPORT_REQUIRED_PRESENT ^*/
    
} rrc_pdcp_rcfg_drb_entity_t;

typedef struct _rrc_pdcp_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_entity_error_t;

typedef struct _rrc_pdcp_cr_srb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_cr_srb_entity_error_t;

typedef struct _rrc_pdcp_cr_drb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_cr_drb_entity_error_t;

typedef struct _rrc_pdcp_del_srb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_del_srb_entity_error_t;

typedef struct _rrc_pdcp_del_drb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_del_drb_entity_error_t;

typedef struct _rrc_pdcp_rcfg_srb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_rcfg_srb_entity_error_t;

typedef struct _rrc_pdcp_rcfg_drb_entity_error_t
{
    rrc_lc_id_t lc_id;
    rrc_response_t  response;                       /* rrc_pdcp_return_et */
} rrc_pdcp_rcfg_drb_entity_error_t;

typedef struct _rrc_pdcp_data_status_error_t
{
    U8  error_code;
    U8  p_buffer[0]; /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_pdcp_data_status_error_t;

#define RRC_PDCP_CR_SRB_CONFIG_INT_PRESENT      0x01
#define RRC_PDCP_CR_SRB_CONFIG_CIPH_PRESENT     0x02
#define RRC_PDCP_CR_DRB_CONFIG_CIPH_PRESENT     0x04
        

/******************************************************************************
*   PDCP_CREATE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_pdcp_cr_ue_entity_req_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/
      
    rrc_ue_index_t              ue_index;
    U16                         crnti;

    rrc_counter_t               num_cr_srb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_srb_entity_t    cr_srb_entities[RRC_PDCP_MAX_SRB];
    /*^ TLV, SEQUENCE, RRC_PDCP_CREATE_SRB_ENTITY_TAG ^*/


    rrc_counter_t               num_cr_drb_entity;
    /*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_drb_entity_t    cr_drb_entities[RRC_PDCP_MAX_DRB];
    /*^ TLV, SEQUENCE, RRC_PDCP_CREATE_DRB_ENTITY_TAG ^*/
    
    rrc_pdcp_config_int_t       config_integrity_protection;
    /*^ TLV, RRC_PDCP_CONFIGURE_INTEGRITY_PROTECTION_TAG, RRC_PDCP_CR_SRB_CONFIG_INT_PRESENT ^*/

    rrc_pdcp_config_ciph_t      config_srb_ciphering;
    /*^ TLV, RRC_PDCP_CONFIGURE_SRB_CIPHERING_TAG, RRC_PDCP_CR_SRB_CONFIG_CIPH_PRESENT ^*/

    rrc_pdcp_config_ciph_t          config_drb_ciphering;
    /*^ TLV, RRC_PDCP_CONFIGURE_DRB_CIPHERING_TAG, RRC_PDCP_CR_DRB_CONFIG_CIPH_PRESENT ^*/

} rrc_pdcp_cr_ue_entity_req_t; /*^ API, RRC_PDCP_CREATE_UE_ENTITY_REQ ^*/


/******************************************************************************
*   PDCP_CREATE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_pdcp_cr_ue_entity_cnf_t
{
    rrc_bitmask_t                   optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_ue_index_t                  ue_index;
    rrc_response_t                  response_code;
/*^ M, 0, H, 0, 2 ^*/ /* rrc_pdcp_return_et */


    rrc_counter_t                   num_cr_srb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_srb_entity_error_t  cr_srb_error_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_SRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                   num_cr_drb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_drb_entity_error_t  cr_drb_error_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_DRB_ENTITY_ERROR_TAG ^*/

} rrc_pdcp_cr_ue_entity_cnf_t; /*^ API, RRC_PDCP_CREATE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   PDCP_DELETE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_pdcp_del_ue_entity_req_t
{
    rrc_ue_index_t  ue_index;
} rrc_pdcp_del_ue_entity_req_t; /*^ API, RRC_PDCP_DELETE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   PDCP_DELETE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_pdcp_del_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    rrc_response_t  response;   /*^ M, 0, H, 0, 1 ^*/ /* rrc_pdcp_return_et */
} rrc_pdcp_del_ue_entity_cnf_t; /*^ API, RRC_PDCP_DELETE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   PDCP_RECONFIG_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_pdcp_reconf_ue_entity_req_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/
     
    rrc_ue_index_t              ue_index;

    rrc_counter_t               num_cr_srb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_srb_entity_t    cr_srb_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_SRB_ENTITY_TAG ^*/


    rrc_counter_t               num_cr_drb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_drb_entity_t    cr_drb_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_DRB_ENTITY_TAG ^*/

    rrc_pdcp_config_int_t       config_integrity_protection;
/*^ TLV, RRC_PDCP_CONFIGURE_INTEGRITY_PROTECTION_TAG, RRC_PDCP_CR_SRB_CONFIG_INT_PRESENT ^*/
 
    rrc_pdcp_config_ciph_t      config_srb_ciphering;
/*^ TLV, RRC_PDCP_CONFIGURE_SRB_CIPHERING_TAG, RRC_PDCP_CR_SRB_CONFIG_CIPH_PRESENT ^*/

    rrc_pdcp_config_ciph_t      config_drb_ciphering;
/*^ TLV, RRC_PDCP_CONFIGURE_DRB_CIPHERING_TAG, RRC_PDCP_CR_DRB_CONFIG_CIPH_PRESENT ^*/

    rrc_counter_t               num_del_srb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_del_srb_entity_t   del_srb_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_DELETE_SRB_ENTITY_TAG ^*/


    rrc_counter_t               num_del_drb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_del_drb_entity_t   del_drb_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_DELETE_DRB_ENTITY_TAG ^*/


    rrc_counter_t               num_reconfig_srb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_rcfg_srb_entity_t  rcfg_srb_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_RECONFIG_SRB_ENTITY_TAG ^*/


    rrc_counter_t               num_reconfig_drb_entity;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_rcfg_drb_entity_t  rcfg_drb_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_RECONFIG_DRB_ENTITY_TAG ^*/

} rrc_pdcp_reconf_ue_entity_req_t; /*^ API, RRC_PDCP_RECONFIG_UE_ENTITY_REQ ^*/

/******************************************************************************
*   PDCP_RECONFIG_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_pdcp_reconfig_ue_entity_cnf_t
{
    rrc_ue_index_t                      ue_index;
    rrc_response_t                      response_code;

    rrc_counter_t                       num_cr_srb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_srb_entity_error_t      cr_srb_error_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_SRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                       num_cr_drb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_cr_drb_entity_error_t      cr_drb_error_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_CREATE_DRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                       num_del_srb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_del_srb_entity_error_t    del_srb_error_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_DELETE_SRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                       num_del_drb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_del_drb_entity_error_t    del_drb_error_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_DELETE_DRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                       num_rcfg_srb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_rcfg_srb_entity_error_t  rcfg_srb_error_entities[RRC_PDCP_MAX_SRB];
/*^ TLV, SEQUENCE, RRC_PDCP_RECONFIG_SRB_ENTITY_ERROR_TAG ^*/


    rrc_counter_t                       num_rcfg_drb_entity_error;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_pdcp_rcfg_drb_entity_error_t  rcfg_drb_error_entities[RRC_PDCP_MAX_DRB];
/*^ TLV, SEQUENCE, RRC_PDCP_RECONFIG_DRB_ENTITY_ERROR_TAG ^*/

} rrc_pdcp_reconfig_ue_entity_cnf_t;
/*^ API, RRC_PDCP_RECONFIG_UE_ENTITY_CNF ^*/


/******************************************************************************
*   PDCP_SRB_DATA_REQ
******************************************************************************/
typedef struct _rrc_pdcp_srb_data_req_t
{
    U32             transaction_id;
    rrc_ue_index_t  ue_index;
    rrc_lc_id_t     lc_id;
    U8              service_requested;
    U8              p_buffer[0]; /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_pdcp_srb_data_req_t; /*^ API, ONLY_PUP, RRC_PDCP_SRB_DATA_REQ ^*/

/******************************************************************************
*   PDCP_SRB_DATA_IND
******************************************************************************/
typedef struct _rrc_pdcp_srb_data_ind_t
{
    rrc_ue_index_t  ue_index;
    rrc_lc_id_t     lc_id;
    U8              p_buffer[0]; /*^ M, 0, OCTET_STRING, TILL_THE_END ^*/
} rrc_pdcp_srb_data_ind_t; /*^ API, ONLY_PUP, RRC_PDCP_SRB_DATA_IND ^*/

/******************************************************************************
*   PDCP_SRB_DATA_STATUS_IND
******************************************************************************/

#define RRC_PDCP_SRB_DATA_STATUS_ERROR_PRESENT  0x01

typedef struct _rrc_pdcp_srb_data_status_ind_t
{
    U32                                 transaction_id;
    rrc_bitmask_t                       optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_ue_index_t                      ue_index;
    rrc_lc_id_t                         lc_id;
    rrc_response_t                      response_code;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_pdcp_return_et */

    rrc_pdcp_data_status_error_t        srb_data_status_error;
/*^ TLV, RRC_PDCP_SRB_DATA_STATUS_ERROR_TAG, RRC_PDCP_SRB_DATA_STATUS_ERROR_PRESENT ^*/

} rrc_pdcp_srb_data_status_ind_t; /*^ API, RRC_PDCP_SRB_DATA_STATUS_IND ^*/

/******************************************************************************
*   PDCP_SUSPEND_UE_ENTITY_REQ
******************************************************************************/

typedef struct _rrc_pdcp_suspend_ue_entity_req_t
{
    rrc_ue_index_t                      ue_index;
} rrc_pdcp_suspend_ue_entity_req_t; /*^ API, RRC_PDCP_SUSPEND_UE_ENTITY_REQ ^*/

/******************************************************************************
*   PDCP_SUSPEND_UE_ENTITY_CNF
******************************************************************************/

typedef struct _rrc_pdcp_suspend_ue_entity_cnf_t
{
    rrc_ue_index_t                      ue_index;
    rrc_response_t                      response_code;
} rrc_pdcp_suspend_ue_entity_cnf_t; /*^ API, RRC_PDCP_SUSPEND_UE_ENTITY_CNF ^*/



#pragma pack(pop)

#endif /* _RRC_PDCP_INTF_H_ */

