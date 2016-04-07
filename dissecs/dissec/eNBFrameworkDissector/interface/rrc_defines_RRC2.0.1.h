/******************************************************************************
*
*   FILE NAME:
*       rrc_defines.h
*
*   DESCRIPTION:
*       This file contains basic RRC types definitions.
*
*   DATE            AUTHOR      REFERENCE       REASON
*   31 Mar 2009     VasylN      ---------       Initial
*   24 May 2010     TSinha      <TODO>          Added support for E-RAB 
*                                               Management Procedures
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/

#ifndef _RRC_DEFINES_H_
#define _RRC_DEFINES_H_

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

/* Basic types */
#include <sys/types.h>

/* CSPL types */
#include <cspl.h>
#include <stacklayer.h>


/* make global visibility for static functions used in unit tests */
#ifdef RRC_DEBUG
#define STATIC
#else
#define STATIC static
#endif

/* Values for rrc_return_et, rrc_return_t */
typedef enum
{
    RRC_FAILURE,
    RRC_SUCCESS,
    RRC_PARTIAL_SUCCESS 
} rrc_return_et;


/* Values for rrc_bool_et, rrc_bool_t */
typedef enum
{
    RRC_FALSE,
    RRC_TRUE
} rrc_bool_et;

/*Reconfig mode values */
typedef enum
{
    NO_MODE,
    PHY_ONLY,
    MAC_ONLY,
    PHY_MAC_BOTH
}rrc_reconfig_mode_et;


/* RRC types */
typedef unsigned long long  U64;
typedef U16             rrc_bitmask_t;
typedef U16             rrc_error_t;
typedef U16             rrc_ue_index_t;
typedef U8              rrc_lc_id_t;
typedef U16             rrc_response_t;
typedef U16             rrc_tag_t;
typedef U16             rrc_length_t;
typedef U16             rrc_counter_t;
typedef U16             rrc_sfn_t;
typedef U8              rrc_sf_t;
typedef U16             rrc_rnti_t;
typedef U16             rrc_transaction_id_t;
typedef U8              rrc_cell_index_t;
typedef U16             rrc_sn_field_l_t;
typedef U16             rrc_t_reordering_t;
typedef void            rrc_void_t;
typedef size_t          rrc_size_t;
typedef QTIMER          rrc_timer_t;
typedef U16             rrc_timer_duration_t;
typedef U8              rrc_return_t;
typedef U8              rrc_bool_t;
typedef U16             rrc_module_id_t;
typedef U16             rrc_rb_direction_t;
typedef U16             rrc_phys_cell_id_t;
typedef U32             rrc_gtp_teid_t;
typedef U8              rrc_retry_count_t;


#define RRC_ASN_CNTXT OSCTXT

#define ENDIAN_INIT 1
#define IS_LITTLE_ENDIAN(endian_check) (*((U8*)&endian_check)?1:0)

#define ENDIAN_INIT 1
#define IS_LITTLE_ENDIAN(endian_check) (*((U8*)&endian_check)?1:0)
/* Means that encapsulating shell should release the buffer after processing of
 *  the message */

#define RRC_BUFFER_SHOULD_BE_RELEASED 1

/* Settings for ASN buffer */
#define ASN_RRC_BUF_TYPE FALSE
#define ASN_S1AP_BUF_TYPE TRUE

/* Special value for rrc_transaction_id_t */
#define RRC_TRANSACTION_ID_ABSENT       0xFFFF


#define RRC_NULL        0

#ifndef _PNULL_
#define _PNULL_
#define PNULL           ((void *)0)
#endif

#define RRC_VERSION_ID          0x01

/* Maximum number of supported UEs for Release 1.0 */
#define RRC_MAX_NUM_SUPPORTED_UE        600

#define RRC_SRB0_LC_ID                  0
#define RRC_SRB1_LC_ID                  1
#define RRC_SRB2_LC_ID                  2

#define RRC_MAX_NUM_SRB                 3
#define RRC_MAX_NUM_DRB                 11

#define RRC_MAX_INTEGRITY_ALGORITHMS    2
#define RRC_MAX_CIPHERING_ALGORITHMS    3

#define RRC_S1U_MAX_GSN_ADDR            20
#define RRC_S1U_MAX_QOS_PROFILE_DATA    254

#define RRC_MAX_FSM                 0x0A
#define RRC_MAX_STATE_PER_FSM       0x06
#define RRC_MAX_API_TRANSITION      0x02
#define RRC_MAX_PROC_TIMER          0x0f
#define MAX_ERAB_COUNT              16


/* ERAB SETUP START */

#define RRC_MIN_QCI_GBR_LIMIT       1
#define RRC_MAX_QCI_GBR_LIMIT       4
#define RRC_MIN_QCI_NON_GBR_LIMIT   5
#define RRC_MAX_QCI_NON_GBR_LIMIT   9

#define MAX_MME_ERAB_LIST_COUNT     256
#define MAX_SUPPORTED_E_RAB_ID      15


/* ERAB SETUP STOP */
#if 0
#define ERAB_FAILURE                0x00
#define ERAB_SUCCESS                0x01
#define ERAB_PARTIAL_SUCCESS        0x02
#define ERAB_FATAL                  0x03
#endif

/* Used in S1AP (and RRM) */
#define RRC_CELL_IDENTITY_BITS      28
#define RRC_CSG_ID_BITS             27

/* SFN is 10 bits wide: 0, 1, 2, ... SFN_UPPER_LIMIT - 1 */
#define SFN_UPPER_LIMIT             1024
#define SF_MAX_LIMIT              10
/* UL DL ARFCN DIFFERENCE */
#define UL_DL_ARFCN_DIFFRENCE 18000

/* Value for External Module Ids */
#define RRC_MIN_EXT_MODULE_ID   1
#define RRC_OAM_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 0)
#define RRC_RRM_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 1)
#define RRC_MODULE_ID       (RRC_MIN_EXT_MODULE_ID + 2)
#define RRC_S1U_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 3)
#define RRC_PDCP_MODULE_ID  (RRC_MIN_EXT_MODULE_ID + 4)
#define RRC_RLC_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 5)
#define RRC_MAC_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 6)
#define RRC_PHY_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 7)
#define RRC_MME_MODULE_ID   (RRC_MIN_EXT_MODULE_ID + 8) /*now used only for FT*/
#define RRC_MAX_EXT_MODULE_ID   RRC_MME_MODULE_ID

#ifdef MODE_PROFILER_DEFINED
#define RRC_WRONG_MODULE_ID   0xfe
#endif

/* Value for Internal Module Ids */
#define RRC_MIN_INT_MODULE_ID   0x10
#define RRC_OAMH_MODULE_ID  (RRC_MIN_INT_MODULE_ID + 0)
#define RRC_UECC_MODULE_ID  (RRC_MIN_INT_MODULE_ID + 1)
#define RRC_CSC_MODULE_ID   (RRC_MIN_INT_MODULE_ID + 2)
#define RRC_LLIM_MODULE_ID  (RRC_MIN_INT_MODULE_ID + 3)
#define RRC_S1AP_MODULE_ID  (RRC_MIN_INT_MODULE_ID + 4)
#define RRC_MAX_INT_MODULE_ID   RRC_S1AP_MODULE_ID


/*Error Codes for RRC_PDCP*/
#define    RRC_PDCP_ERROR_CODE_BASE           0x0100
#define    RRC_PDCP_ERR_CONTEXT_NOT_INITIALIZED        RRC_PDCP_ERROR_CODE_BASE + 0
#define    RRC_PDCP_ERR_CONTEXT_ALREADY_INITIALIZED    RRC_PDCP_ERROR_CODE_BASE + 1
#define    RRC_PDCP_ERR_UE_CONTEXT_ALREADY_CREATED     RRC_PDCP_ERROR_CODE_BASE + 2
#define    RRC_PDCP_ERR_UE_CONTEXT_NOT_INITIALIZED     RRC_PDCP_ERROR_CODE_BASE + 3
#define    RRC_PDCP_ERR_ENTITY_ALREADY_CREATED         RRC_PDCP_ERROR_CODE_BASE + 4
#define    RRC_PDCP_ERR_ENTITY_WRONG_DIRECTION         RRC_PDCP_ERROR_CODE_BASE + 5
#define    RRC_PDCP_ERR_ENTITY_WRONG_TYPE              RRC_PDCP_ERROR_CODE_BASE + 6
#define    RRC_PDCP_ERR_ENTITY_NOT_FOUND               RRC_PDCP_ERROR_CODE_BASE + 7
#define    RRC_PDCP_ERR_ENTITY_SET_SN_SIZE             RRC_PDCP_ERROR_CODE_BASE + 8

#define    RRC_PDCP_ERR_ENTITY_SET_STATUS_REPORT_REQUIRED  RRC_PDCP_ERROR_CODE_BASE + 9

#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_LENGTH     RRC_PDCP_ERROR_CODE_BASE + 10
#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_UE_ID      RRC_PDCP_ERROR_CODE_BASE + 11

#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_OPTIONAL_PARAMETERS_LENGTH RRC_PDCP_ERROR_CODE_BASE + 12

#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_TAG_LENGTH RRC_PDCP_ERROR_CODE_BASE + 13
#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_LC_ID      RRC_PDCP_ERROR_CODE_BASE + 14

#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_TAG_PARAMETER_VALUE RRC_PDCP_ERROR_CODE_BASE + 15

#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_CRNTI      RRC_PDCP_ERROR_CODE_BASE + 16
#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_TAG_ID     RRC_PDCP_ERROR_CODE_BASE + 17
#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_RNTI_RANGE RRC_PDCP_ERROR_CODE_BASE + 18
#define    RRC_PDCP_ERR_TLV_PARSING_INVALID_API_ID     RRC_PDCP_ERROR_CODE_BASE + 19


/*Error Codes for RRC_RLC*/
#define    RRC_RLC_ERROR_CODE_BASE           0x0200
#define    RRC_RLC_INVALID_UE_INDEX          RRC_RLC_ERROR_CODE_BASE + 0          
#define    RRC_RLC_UE_ID_EXISTS              RRC_RLC_ERROR_CODE_BASE + 1          
#define    RRC_RLC_UE_NOT_EXISTS             RRC_RLC_ERROR_CODE_BASE + 2          
#define    RRC_RLC_INTERNAL_ERROR            RRC_RLC_ERROR_CODE_BASE + 3          
#define    RRC_RLC_SYNTAX_ERROR              RRC_RLC_ERROR_CODE_BASE + 4          
#define    RRC_RLC_INVALID_LC_ID             RRC_RLC_ERROR_CODE_BASE + 5          
#define    RRC_RLC_ENTITY_EXISTS             RRC_RLC_ERROR_CODE_BASE + 6          
#define    RRC_RLC_ENTITY_NOT_EXISTS         RRC_RLC_ERROR_CODE_BASE + 7          
#define    RRC_RLC_UE_ENTITY_IN_USE          RRC_RLC_ERROR_CODE_BASE + 8          


/*Error Codes for RRC_RLC*/
#define    RRC_S1U_ERROR_CODE_BASE           0x0300
#define    RRC_S1U_SUCCESS                   RRC_S1U_ERROR_CODE_BASE + 0
#define    RRC_S1U_RESOURCES_NOT_AVAILABLE   RRC_S1U_ERROR_CODE_BASE + 1
#define    RRC_S1U_CTXT_NOT_FOUND            RRC_S1U_ERROR_CODE_BASE + 2
#define    RRC_S1U_DUPLICATE_PEER_TEID       RRC_S1U_ERROR_CODE_BASE + 3
#define    RRC_S1U_INV_SAP_CFG               RRC_S1U_ERROR_CODE_BASE + 4
#define    RRC_S1U_IPV6_ADDR_RECEIVED        RRC_S1U_ERROR_CODE_BASE + 5

/*Error Codes for RRC_UECC_LLIM (Per LC)*/
#define    RRC_UECC_LLIM_ERROR_CODE_BASE     0x0400
#define    RRC_UECC_LLIM_TIMER_EXPIRY        RRC_UECC_LLIM_ERROR_CODE_BASE + 0
#define    RRC_UECC_LLIM_ROLLBACK_FAILURE    RRC_UECC_LLIM_ERROR_CODE_BASE + 1    





/******************************************************************************
*   Interface types
******************************************************************************/

#pragma pack(push, 1)

/******************************************************************************
*   These types are shared CSC-LLIM with PHY and RRM
******************************************************************************/
typedef struct _rrc_phy_phich_configuration_t
{
    U8  phich_resource;     /*^ M, 0, H, 0, 3 ^*/ /* phich_resource_et */
    U8  phich_duration;     /*^ M, 0, H, 0, 1 ^*/ /* phich_duration_et */
} rrc_phy_phich_configuration_t;

typedef struct _rrc_phy_pucch_configuration_t
{
    U8  delta_pucch_shift;      /*^ M, 0, B, 1, 3 ^*/ /* pucch_delta_shift_et */
    U8  nrb_cqi;                /*^ M, 0, H, 0, 98 ^*/
    U8  ncs_an;                 /*^ M, 0, H, 0, 7 ^*/
    U16 n1pucch_an;             /*^ M, 0, H, 0, 2047 ^*/
} rrc_phy_pucch_configuration_t;

typedef struct{
  U8      group_hopping_enabled;  /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
  U8      group_assign_pusch;     /*^ M, 0, H, 1, 29 ^*/
  U8      seq_hopping_enabled;    /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
  U8      cyclic_shift;           /*^ M, 0, H, 1, 7 ^*/
}ul_ref_signals_pusch_t;

typedef struct _rrc_phy_pusch_configuration_t
{
    U8  pusch_hopping_offset; /*^ M, 0, H, 1, 63 ^*/
    U8  num_of_sub_bands;       /*^ M, 0, B, 2, 4 ^*/
    U8  pusch_hopping_mode;
/*^ M, 0, H, 0, 1 ^*/ /* pusch_hopping_mode_et */
    ul_ref_signals_pusch_t  ul_ref_signal;
} rrc_phy_pusch_configuration_t;

typedef struct _rrc_phy_prach_configuration_t
{
    U8  prach_config_sequence;  /*^ M, 0, H, 0, 63 ^*/
    U16 root_seq_index;         /*^ M, 0, H, 0, 837 ^*/
    U8  prach_freq_offset;      /*^ M, 0, H, 0, 104 ^*/
    U8  zero_cor_zone_config;   /*^ M, 0, H, 0, 15 ^*/
    U8  high_speed_flag;        /*^ M, 0, H, 0, 1 ^*/ /* high_speed_flag_et */
} rrc_phy_prach_configuration_t;

typedef struct _rrc_phy_sync_signals_t
{
    S8  prim_syn_signal_power;  /*^ M, 0, B, -60, 20 ^*/
    S8  sec_syn_signal_power;   /*^ M, 0, B, -60, 20 ^*/
    U8  sec_syn_signal_m_seq1;  /*^ M, 0, H, 0, 30 ^*/
    U8  sec_syn_signal_m_seq2;  /*^ M, 0, H, 0, 30 ^*/
} rrc_phy_sync_signals_t;

typedef struct _rrc_phy_reference_signal_t
{
    S8  ref_signal_power;       /*^ M, 0, B, -60, 50 ^*/
ul_ref_signals_pusch_t    ul_ref_signals_pusch;  /*^ M, 0, N, 0, 0 ^*/
} rrc_phy_reference_signal_t;


typedef struct
{
  S8        ref_signal_power;       /*^ M, 0, B, -60, 50 ^*/
  U8        pb;                     /*^ M, 0, H, 0, 3 ^*/   /* rrm_pb_et */
}pdsch_config_common_t;


typedef struct _rrc_phy_pdsch_configuration_t
{
pdsch_config_common_t pdsch_config; /*^ M, 0, N, 0, 0 ^*/
}rrc_phy_pdsch_configuration_t;

#define SOUNDING_RS_UL_CONFIG_COMMON_SETUP_SRS_MAX_UP_PTS_PRESENCE_FLAG     0x01

typedef struct
{
  U16       presence_bitmask;          /*^ BITMASK ^*/
  U8        srs_bw_config;
/*^ M, 0, H, 1, 7 ^*/    /* rrm_srs_bw_config_et */

  U8        srs_subframe_config;
/*^ M, 0, H, 1, 15 ^*/   /* rrm_srs_subframe_config_et */

  U8        ack_nack_srs_simul_trans;
/*^ M, 0, H, 0, 1 ^*/    /* rrc_bool_et */

  U8        srs_max_up_pts;
/*^ O, SOUNDING_RS_UL_CONFIG_COMMON_SETUP_SRS_MAX_UP_PTS_PRESENCE_FLAG,H,0,0 ^*/
/* rrm_srs_max_up_pts_et */ /*OM. O since 331.860*/
}sounding_rs_ul_config_common_setup_t;


#define SOUNDING_RS_UL_CONFIG_COMMON_SETUP_PRESENCE_FLAG      0x01

typedef struct
{
    U16                                  presence_bitmask;       /*^ BITMASK ^*/
    sounding_rs_ul_config_common_setup_t setup;
/*^ O, SOUNDING_RS_UL_CONFIG_COMMON_SETUP_PRESENCE_FLAG, H, 0, 0 ^*/
}sounding_rs_ul_config_common_t;

typedef struct _rrc_config_phy_cell_parameters_t
{
    U8  duplexing_mode;
/*^ M, 0, H, 0, 1 ^*/                       /* duplexing_mode_et */
     U8                            freq_band_indicator;      /*^ M, 0, B, 1, 64 ^*/
    U16 ul_earfcn;
    U16 dl_earfcn;
    U8  num_of_antennas;                    /*^ M, 0, H, 1, 4 ^*/
    U8  ul_tx_bandwidth;
/*^ M,0, H, 0, 5 ^*/  /* ul_tx_bandwidth_et */

    U8  dl_tx_bandwidth;
/*^ M, 0, H, 0, 5 ^*/  /* dl_tx_bandwidth_et */

    U8  subcarrier_spacing;
/*^ M, 0, H, 0, 1 ^*/                       /* subcarrier_spacing_et */

    U8  ul_cyclic_prefix;
/*^ M, 0, H, 0, 1 ^*/                       /* cyclic_prefix_et */

    U8  dl_cyclic_prefix;
/*^ M, 0, H, 0, 1 ^*/                       /* cyclic_prefix_et */

    sounding_rs_ul_config_common_t	  srs_bandwidth_configuration;
/*^ M, 0, H, 0, 0 ^*/

    rrc_phys_cell_id_t  phys_cell_id;       /*^ M, 0, H, 0, 503 ^*/

} rrc_config_phy_cell_parameters_t;

typedef struct _rrc_phy_cell_parameters_t
{
    U16 dl_earfcn;
    U8  num_of_antennas;                    /*^ M, 0, B, 1, 4 ^*/
    U8  subcarrier_spacing;
/*^ M, 0, H, 0, 1 ^*/                       /* subcarrier_spacing_et */
    U8  dl_cyclic_prefix;
/*^ M, 0, H, 0, 1 ^*/                       /* cyclic_prefix_et */
    U8  rb_size;
/*^ M, 0, H, 0, 1 ^*/                       /* rb_size_et */

    rrc_phys_cell_id_t  phys_cell_id;       /*^ M, 0, H, 0, 503 ^*/
} rrc_phy_cell_parameters_t;

typedef struct _rrc_rcfg_phy_cell_parameters_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_RRM_RECONFIG_PHY_CELL_PARAMS_DL_EARFCN_PRESENT 0x01
#define RRC_RRM_RECONFIG_PHY_CELL_PARAMS_NUM_OF_ANTENNAS   0x02
#define RRC_RRM_RECONFIG_PHY_CELL_PARAMS_DL_CYCLIC_PREFIX  0x04
#define RRC_RRM_RECONFIG_PHY_CELL_PARAMS_RB_SIZE           0x08
#define RRC_RRM_RECONFIG_PHY_CELL_ID                       0x10
    U16 dl_earfcn;                          
    /*^ O, RRC_RRM_RECONFIG_PHY_CELL_PARAMS_DL_EARFCN_PRESENT ^*/
    U8  num_of_antennas;                    
    /*^ O, RRC_RRM_RECONFIG_PHY_CELL_PARAMS_NUM_OF_ANTENNAS, B, 1, 4 ^*/
    U8  dl_cyclic_prefix;
    /*^ O, RRC_RRM_RECONFIG_PHY_CELL_PARAMS_DL_CYCLIC_PREFIX, H, 0, 1 ^*/   /* cyclic_prefix_et */
    U8  rb_size;
    /*^ O, RRC_RRM_RECONFIG_PHY_CELL_PARAMS_RB_SIZE, H, 0, 1 ^*/    /* rb_size_et */
    rrc_phys_cell_id_t  phys_cell_id; /*^ O, RRC_RRM_RECONFIG_PHY_CELL_ID ^*/
} rrc_recfg_phy_cell_parameters_t;

/******************************************************************************
*   End of these types are shared CSC-LLIM with PHY and RRM
******************************************************************************/

/******************************************************************************
*   These types are shared CSC-LLIM with MAC
******************************************************************************/
#define RRC_MAX_MIB_LENGTH      10
#define RRC_MAX_SIBTYPE1_LENGTH 1024
#define RRC_MAX_SI_LENGTH       1024

#define RRC_MAX_SI_MSGS         10
#define RRC_MIB_MSGS            256
#define RRC_MAX_SI_MSG_PARAMS   3

typedef enum {
    RRC_SI_SYNC_SYS_TIME,
    RRC_SI_ASYNC_SYS_TIME,
    RRC_SI_LONG_CODE_STATE_1_XRTT
} rrc_mac_si_msg_param_type_et;

typedef struct _rrc_mac_si_msg_param_t
{
    U8  id;     /*^ M, 0, H, 0, 2 ^*/ /* rrc_mac_si_msg_param_type_et */
    U32 offset; /* in bits */
    U32 length; /* in bits */
} rrc_mac_si_msg_param_t;

typedef struct _rrc_mac_si_msg_info_t
{
    U8		si_index;	/*^ M, 0, H, 0, 10 ^*/	
    U8          periodicity;
/*^ M, 0, B, 1, 7 ^*/       /* Bug in MAC API document - we must update RRC */

    rrc_sfn_t   starting_sfn;   /*^ M, 0, H, 0, 1023 ^*/
    rrc_sf_t    starting_sf;    /*^ M, 0, H, 0, 9 ^*/

    rrc_counter_t           si_msg_buf_length;
    U8                      si_msg_buf[RRC_MAX_SI_LENGTH];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/


    rrc_counter_t           si_msg_param_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_si_msg_param_t  si_msg_param[RRC_MAX_SI_MSG_PARAMS];
/*^ TLV, SEQUENCE, RRC_MAC_SI_MSG_INFO_PARAM ^*/

} rrc_mac_si_msg_info_t;

typedef struct _rrc_mac_si_msg_req_t
{
    U8  si_window_size;         /*^ M, 0, B, 1, 40 ^*/
    U8  num_si_message;         /*^ M, 0, H, 0, 10 ^*/

    rrc_counter_t           si_msg_info_counter;
/*^ M, 0, TLV_SEQUENCE_COUNTER, NOT_PRESENT_IN_MESSAGE ^*/

    rrc_mac_si_msg_info_t   si_msg_info[RRC_MAX_SI_MSGS];
/*^ TLV, SEQUENCE, RRC_MAC_SI_MSG_INFO ^*/

} rrc_mac_si_msg_req_t;

typedef struct _rrc_mac_sibtype1_msg_req_t
{
    U8		si_mapping_changed;	/*^ M, 0, H, 0, 1 ^*/	
    rrc_sfn_t   sfn;    /*^ M, 0, H, 0, 1023 ^*/

    rrc_counter_t   sibtype1_msg_buf_counter;
/*^ M, 0, BUFFER_SIZE, NOT_PRESENT_IN_MESSAGE ^*/

    U8              sibtype1_msg_buf[RRC_MAX_SIBTYPE1_LENGTH];
/*^ M, 0, OCTET_STRING, LIMITED_TILL_THE_END ^*/

} rrc_mac_sibtype1_msg_req_t;

typedef struct _rrc_mac_mib_msg_req_t
{
    rrc_sfn_t   sfn;    /*^ M, 0, H, 0, 1023 ^*/

    rrc_counter_t   mib_msg_buf_counter;
/*^ M, 0, BUFFER_SIZE, NOT_PRESENT_IN_MESSAGE ^*/

    U8              mib_msg_buf[RRC_MAX_MIB_LENGTH];
/*^ M, 0, OCTET_STRING, LIMITED_TILL_THE_END ^*/

} rrc_mac_mib_msg_req_t;


typedef struct _rrc_mac_mod_period_info_t
{
    U32         mod_period; /*^ M, 0, B, 64, 4096 ^*/
}rrc_mac_mod_period_info_t;

typedef struct _rrc_mac_sfn_gap_info_t
{
    U8         sfn_gap; /*^ M, 0, B, 1, 32 ^*/
}rrc_mac_sfn_gap_info_t;







/******************************************************************************
*   End of these types are shared CSC-LLIM with MAC
******************************************************************************/

/******************************************************************************
*   These types are shared CSC-LLIM with MAC and RRM
******************************************************************************/

typedef enum
{
    MAC_RA_RESP_WIN_SIZE_SF2,
    MAC_RA_RESP_WIN_SIZE_SF3,
    MAC_RA_RESP_WIN_SIZE_SF4,
    MAC_RA_RESP_WIN_SIZE_SF5,
    MAC_RA_RESP_WIN_SIZE_SF6,
    MAC_RA_RESP_WIN_SIZE_SF7,
    MAC_RA_RESP_WIN_SIZE_SF8,
    MAC_RA_RESP_WIN_SIZE_SF10
} mac_ra_resp_win_size_et;

typedef enum
{
    MAC_CONT_RES_TIMER_SF8,
    MAC_CONT_RES_TIMER_SF16,
    MAC_CONT_RES_TIMER_SF24,
    MAC_CONT_RES_TIMER_SF32,
    MAC_CONT_RES_TIMER_SF40,
    MAC_CONT_RES_TIMER_SF48,
    MAC_CONT_RES_TIMER_SF56,
    MAC_CONT_RES_TIMER_SF64
} mac_cont_resol_timer_et;

typedef struct _rrc_mac_config_t
{
    U8  dl_res_blocks;          /*^ M, 0, B, 1, 100 ^*/
    U8  ul_res_blocks;          /*^ M, 0, B, 1, 100 ^*/
    U8  max_harq_retrans;       /*^ M, 0, B, 6, 8 ^*/
    U8  start_ra_rnti_range;    /*^ M, 0, B, 1, 60 ^*/
    U8  end_ra_rnti_range;      /*^ M, 0, B, 1, 60 ^*/

} rrc_mac_config_t;


/******************************************************************************
*   These types are shared CSC-LLIM with RRM
******************************************************************************/

typedef struct _rrc_rrm_cell_config_t
{
    rrc_phy_cell_parameters_t   cell_parameters;
    rrc_phy_sync_signals_t      sync_signals;
    rrc_mac_config_t            mac_config;
} rrc_rrm_cell_config_t;

/******************************************************************************
*   End of these types are shared CSC-LLIM with RRM
******************************************************************************/

/******************************************************************************
*   These types are shared UECC-LLIM with PHY
*   Actually this is rrc_phy_physical_config_dedicated_t
******************************************************************************/
typedef struct _rrc_phy_scheduling_request_config_param_t
{
    U16 sr_pucch_resource_index;  /*^ M, 0, H, 0, 2047 ^*/
    U8  sr_configuration_index;   /*^ M, 0, H, 0, 155 ^*/
    U8  dsr_trans_max;            /*^ M, 0, H, 0, 4 ^*/ /* dsr_trans_max_et */
} rrc_phy_scheduling_request_config_param_t;

typedef struct _rrc_phy_scheduling_request_config_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_SCHEDULING_REQUEST_CONFIG_PARAM_PRESENT 0x01

    rrc_phy_scheduling_request_config_param_t   scheduling_request_config_param;
/*^ O, RRC_PHY_SCHEDULING_REQUEST_CONFIG_PARAM_PRESENT ^*/

} rrc_phy_scheduling_request_config_t;

typedef struct _rrc_phy_ue_transmit_antenna_selection_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_UE_TRANSMIT_ANTENNA_SELECTION_TYPE_PRESENT  0x01

    U8  ue_transmit_antenna_selection_type;
/*^ O, RRC_PHY_UE_TRANSMIT_ANTENNA_SELECTION_TYPE_PRESENT, H, 0, 1 ^*/
/* ue_transmit_antenna_selection_type_et */

} rrc_phy_ue_transmit_antenna_selection_t;

typedef struct _rrc_phy_codebook_subset_restriction_t
{
    U16 type;  /*^ M, 0, H, 0, 7 ^*/ /* codebook_subset_restriction_type_et */

    U8  value[8];   /*^ M, O, OCTET_STRING, FIXED ^*/
} rrc_phy_codebook_subset_restriction_t;

typedef struct _rrc_phy_antenna_information_dedicated_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_CODEBOOK_SUBSET_RESTRICTION_PRESENT 0x01

    U8  transmission_mode;     /*^ M, 0, H, 0, 6 ^*/ /* transmission_mode_et */

    rrc_phy_codebook_subset_restriction_t   codebook_subset_restriction;
/*^ O, RRC_PHY_CODEBOOK_SUBSET_RESTRICTION_PRESENT ^*/

    rrc_phy_ue_transmit_antenna_selection_t ue_transmit_antenna_selection;
} rrc_phy_antenna_information_dedicated_t;

typedef struct _rrc_phy_antenna_information_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_ANTENNA_INFORMATION_EXPLICIT_VALUE_PRESENT  0x01

    rrc_phy_antenna_information_dedicated_t antenna_information_explicit_value;
/*^ O, RRC_PHY_ANTENNA_INFORMATION_EXPLICIT_VALUE_PRESENT ^*/

} rrc_phy_antenna_information_t;

typedef struct _rrc_phy_sounding_rs_ul_config_dedicated_param_t
{
    U8  srs_bandwidth;         /*^ M, 0, H, 0, 3 ^*/ /* srs_bandwidth_et */
    U8  srs_hopping_bandwidth;
/*^ M, 0, H, 0, 3 ^*/ /* srs_hopping_bandwidth_et */

    U8  frequency_domain_position;  /*^ M, 0, H, 0, 23 ^*/
    U8  duration;                   /*^ M, 0, H, 0, 1 ^*/  /* rrc_bool_et */
    U16 srs_configuration_index;    /*^ M, 0, H, 0, 1023 ^*/
    U8  transmission_comb;          /*^ M, 0, H, 0, 1 ^*/
    U8  cyclic_shift;               /*^ M, 0, H, 0, 7 ^*/  /* cyclic_shift_et */
} rrc_phy_sounding_rs_ul_config_dedicated_param_t;

typedef struct _rrc_phy_sounding_rs_ul_config_dedicated_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_SOUNDING_RS_UL_CONFIG_DEDICATED_PARAM_PRESENT   0x01

    rrc_phy_sounding_rs_ul_config_dedicated_param_t
        sounding_rs_ul_config_dedicated_param;
/*^ O, RRC_PHY_SOUNDING_RS_UL_CONFIG_DEDICATED_PARAM_PRESENT ^*/

} rrc_phy_sounding_rs_ul_config_dedicated_t;

typedef struct _rrc_phy_subband_cqi_param_param_t
{
    U8  k; /*^ M, 0, B, 1, 4 ^*/
} rrc_phy_subband_cqi_param_param_t;

typedef struct _rrc_phy_cqi_format_indicator_periodic_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_SUBBAND_CQI_PARAM_PRESENT   0x01

    rrc_phy_subband_cqi_param_param_t   subband_cqi_param;
/*^ O, RRC_PHY_SUBBAND_CQI_PARAM_PRESENT ^*/

} rrc_phy_cqi_format_indicator_periodic_t;

typedef struct _rrc_phy_cqi_reporting_periodic_param_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_CQI_RI_CONFIG_INDEX_PRESENT 0x01

    U16 cqi_pucch_resource_index; /*^ M, 0, H, 0, 1185 ^*/
    U16 cqi_pmi_config_index;     /*^ M, 0, H, 0, 1023 ^*/

    rrc_phy_cqi_format_indicator_periodic_t cqi_format_indicator_periodic;

    U16 ri_config_index;
/*^ O, RRC_PHY_CQI_RI_CONFIG_INDEX_PRESENT, H, 0, 1023 ^*/

    U8  simultaneous_ack_nack_and_cqi;  /*^ M, 0, H, 0, 1 ^*/  /* rrc_bool_et */
} rrc_phy_cqi_reporting_periodic_param_t;

typedef struct _rrc_phy_cqi_reporting_periodic_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_CQI_REPORTING_PERIODIC_PARAM_PRESENT    0x01

    rrc_phy_cqi_reporting_periodic_param_t  cqi_reporting_periodic_param;
/*^ O, RRC_PHY_CQI_REPORTING_PERIODIC_PARAM_PRESENT ^*/

} rrc_phy_cqi_reporting_periodic_t;

typedef struct _rrc_phy_cqi_reporting_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_CQI_REPORTING_PERIODIC_PRESENT          0x01
#define RRC_PHY_CQI_REPORTING_MODE_APERIODIC_PRESENT    0x02

    U8  cqi_reporting_mode_aperiodic;
/*^ O, RRC_PHY_CQI_REPORTING_MODE_APERIODIC_PRESENT, H, 0, 4 ^*/
/* cqi_reporting_mode_aperiodic_et */

    S8  nom_pdsch_rs_epre_offset; /*^ M, 0, B, -1, 6 ^*/

    rrc_phy_cqi_reporting_periodic_t    cqi_reporting_periodic;
/*^ O, RRC_PHY_CQI_REPORTING_PERIODIC_PRESENT ^*/

} rrc_phy_cqi_reporting_t;

typedef struct _rrc_phy_tpc_index_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define TPC_INDEX_FORMAT_3_PRESENT  0x01
#define TPC_INDEX_FORMAT_3A_PRESENT 0x02

    U8  index_of_format3;     /*^ O, TPC_INDEX_FORMAT_3_PRESENT, B, 1, 15 ^*/
    U8  index_of_format3a;    /*^ O, TPC_INDEX_FORMAT_3A_PRESENT, B, 1, 31 ^*/
} rrc_phy_tpc_index_t;

typedef struct _rrc_phy_tpc_pdcch_config_param_t
{
    U8                  tpc_rnti[2];    /*^ M, O, OCTET_STRING, FIXED ^*/
    rrc_phy_tpc_index_t tpc_index;
} rrc_phy_tpc_pdcch_config_param_t;

typedef struct _rrc_phy_tpc_pdcch_configuration_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_TPC_PDCCH_CONFIG_PARAM_PRESENT  0x01

    rrc_phy_tpc_pdcch_config_param_t    tpc_pdcch_config_param;
/*^ O, RRC_PHY_TPC_PDCCH_CONFIG_PARAM_PRESENT ^*/

} rrc_phy_tpc_pdcch_configuration_t;

typedef enum
{
  RRC_FC0,
  RRC_FC1,
  RRC_FC2,
  RRC_FC3,
  RRC_FC4,
  RRC_FC5,
  RRC_FC6,
  RRC_FC7,
  RRC_FC8,
  RRC_FC9,
  RRC_FC11,
  RRC_FC13,
  RRC_FC15,
  RRC_FC17,
  RRC_FC19
}rrc_filter_coefficient_et;

typedef struct _rrc_phy_uplink_power_control_dedicated_t
{
    S8  p0_ue_pusch;           /*^ M, 0, B, -8, 7 ^*/
    U8  delta_mcs_enabled;     /*^ M, 0, H, 0, 1 ^*/ /* delta_mcs_enabled_et */
    U8  accumulation_enabled;  /*^ M, 0, H, 0, 1 ^*/   /* rrc_bool_et */
    S8  p0_ue_pucch;           /*^ M, 0, B, -8, 7 ^*/
    U8  p_srs_offset;          /*^ M, 0, H, 0, 15 ^*/
    U8  filter_coefficient;    /*^ M, 0, H, 0, 14 ^*/ /* rrc_filter_coefficient_et */
} rrc_phy_uplink_power_control_dedicated_t;

typedef struct _rrc_phy_pusch_configuration_dedicated_t
{
    U8  beta_offset_ack_index; /*^ M, 0, H, 0, 15 ^*/
    U8  beta_offset_ri_index; /*^ M, 0, H, 0, 15 ^*/
    U8  beta_offset_cqi_index; /*^ M, 0, H, 0, 15 ^*/
} rrc_phy_pusch_configuration_dedicated_t;

typedef struct _rrc_phy_ack_nack_repetition_param_t
{
    U8  factor; /*^ M, 0, H, 0, 2 ^*/  /* ack_nack_repetition_factor_et */
    U16 an_rep; /*^ M, 0, H, 0, 2047 ^*/
} rrc_phy_ack_nack_repetition_param_t;

typedef struct _rrc_phy_pucch_configuration_dedicated_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_ACK_NACK_REPETITION_PARAM_PRESENT   0x01
#define RRC_PHY_TDD_ACK_NACK_FEEDBACK_MODE_PRESENT  0x02

    rrc_phy_ack_nack_repetition_param_t ack_nack_repetition_param;
/*^ O, RRC_PHY_ACK_NACK_REPETITION_PARAM_PRESENT ^*/

    U8                                  tdd_ack_nack_feedback_mode;
/*^ O, RRC_PHY_TDD_ACK_NACK_FEEDBACK_MODE_PRESENT, H, 0, 1 ^*/
/* tdd_ack_nack_feedback_mode_et */

} rrc_phy_pucch_configuration_dedicated_t;

typedef struct _rrc_phy_pdsch_configuration_dedicated_t
{
    U8  p_a;    /*^ M, 0, H, 0, 7 ^*/ /* pdsch_configuration_dedicated_p_a_et */
} rrc_phy_pdsch_configuration_dedicated_t;

typedef struct _rrc_phy_physical_config_dedicated_t
{
    U16     bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_PDSCH_CONFIGURATION_DEDICATED_PRESENT   0x001
#define RRC_PHY_PUCCH_CONFIGURATION_DEDICATED_PRESENT   0x002
#define RRC_PHY_PUSCH_CONFIGURATION_DEDICATED_PRESENT   0x004
#define RRC_PHY_UPLINK_POWER_CONTROL_DEDICATED_PRESENT  0x008
#define RRC_PHY_TPC_PDCCH_CONFIG_PUCCH_PRESENT          0x010
#define RRC_PHY_TPC_PDCCH_CONFIG_PUSCH_PRESENT          0x020
#define RRC_PHY_CQI_REPORTING_PRESENT                   0x040
#define RRC_PHY_SOUNDING_RS_UL_CONFIG_DEDICATED_PRESENT 0x080
#define RRC_PHY_ANTENNA_INFORMATION_PRESENT             0x100
#define RRC_PHY_SCHEDULING_REQUEST_CONFIG_PRESENT       0x200

    rrc_phy_pdsch_configuration_dedicated_t     pdsch_configuration_dedicated;
/*^ O, RRC_PHY_PDSCH_CONFIGURATION_DEDICATED_PRESENT ^*/

    rrc_phy_pucch_configuration_dedicated_t     pucch_configuration_dedicated;
/*^ O, RRC_PHY_PUCCH_CONFIGURATION_DEDICATED_PRESENT ^*/

    rrc_phy_pusch_configuration_dedicated_t     pusch_configuration_dedicated;
/*^ O, RRC_PHY_PUSCH_CONFIGURATION_DEDICATED_PRESENT ^*/

    rrc_phy_uplink_power_control_dedicated_t    uplink_power_control_dedicated;
/*^ O, RRC_PHY_UPLINK_POWER_CONTROL_DEDICATED_PRESENT ^*/

    rrc_phy_tpc_pdcch_configuration_t           tpc_pdcch_config_pucch;
/*^ O, RRC_PHY_TPC_PDCCH_CONFIG_PUCCH_PRESENT ^*/

    rrc_phy_tpc_pdcch_configuration_t           tpc_pdcch_config_pusch;
/*^ O, RRC_PHY_TPC_PDCCH_CONFIG_PUSCH_PRESENT ^*/

    rrc_phy_cqi_reporting_t                     cqi_reporting;
/*^ O, RRC_PHY_CQI_REPORTING_PRESENT ^*/

    rrc_phy_sounding_rs_ul_config_dedicated_t   sounding_rs_ul_config_dedicated;
/*^ O, RRC_PHY_SOUNDING_RS_UL_CONFIG_DEDICATED_PRESENT ^*/

    rrc_phy_antenna_information_t               antenna_information;
/*^ O, RRC_PHY_ANTENNA_INFORMATION_PRESENT ^*/

    rrc_phy_scheduling_request_config_t         scheduling_request_config;
/*^ O, RRC_PHY_SCHEDULING_REQUEST_CONFIG_PRESENT ^*/

} rrc_phy_physical_config_dedicated_t;

/******************************************************************************
*   End of these types are shared UECC-LLIM with PHY
******************************************************************************/

/******************************************************************************
*   These types are shared UECC-LLIM with MAC
******************************************************************************/

/* Enum values for MAC RLC mode */
typedef enum
{
    MAC_RLC_MODE_TM = 0,
    MAC_RLC_MODE_UM,
    MAC_RLC_MODE_AM
} rrc_mac_rlc_mode_et;

typedef struct _rrc_mac_dl_lc_create_req_t
{
    U8  lch_priority;                   /*^ M, 0, B, 1, 16 ^*/
    U8  rlc_sn_field_length;            /*^ M, 0, B, 5, 10 ^*/
} rrc_mac_dl_lc_create_req_t;

typedef struct _rrc_mac_ul_lc_create_req_t
{
    U8  lc_g_id;                        /*^ M, 0, H, 0, 3 ^*/
} rrc_mac_ul_lc_create_req_t;

#define RRC_MAC_UL_LC_CREATE_REQ_PRESENT 0x01
#define RRC_MAC_DL_LC_CREATE_REQ_PRESENT 0x02

typedef struct _rrc_mac_create_lc_req_t
{
    rrc_bitmask_t               optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_lc_id_t                 lch_id;                 /*^ M, 0, H, 0, 10 ^*/
    U8                          rlc_mode;
/*^ M, 0, H, 0, 2 ^*/ /* rrc_mac_rlc_mode_et */


    rrc_mac_ul_lc_create_req_t  ul_lc_create_req;
/*^ TLV, RRC_MAC_UL_LC_CREATE_REQ, RRC_MAC_UL_LC_CREATE_REQ_PRESENT ^*/

    rrc_mac_dl_lc_create_req_t  dl_lc_create_req;
/*^ TLV, RRC_MAC_DL_LC_CREATE_REQ, RRC_MAC_DL_LC_CREATE_REQ_PRESENT ^*/

} rrc_mac_create_lc_req_t;

/******************************************************************************
*   End of these types are shared UECC-LLIM with MAC
******************************************************************************/

/******************************************************************************
*   These types are shared UECC-LLIM with PDCP and OAM
******************************************************************************/


#define RRC_S1U_MAX_TUNNELS_PER_LC 3


/* Enum for PDCP RB direction */
typedef enum
{
    RRC_PDCP_RB_DIR_TX = 0,
    RRC_PDCP_RB_DIR_RX,
    RRC_PDCP_RB_DIR_BOTH
} rrc_rb_direction_et;

/* Enum for PDCP integrity protection algorithm id */
typedef enum
{
    RRC_PDCP_INT_ALG_EIA0 = 0,
    RRC_PDCP_INT_ALG_EIA1 = 1,
    RRC_PDCP_INT_ALG_EIA2
} rrc_int_algorithm_et;

/* Enum for PDCP ciphering algorithm id */
typedef enum
{
    RRC_PDCP_CIPH_ALG_EEA0 = 0,
    RRC_PDCP_CIPH_ALG_EEA1,
    RRC_PDCP_CIPH_ALG_EEA2
} rrc_ciph_algorithm_et;

#define RRC_PDCP_SECURITY_KEY_SIZE      16

typedef struct _rrc_pdcp_config_int_t
{
    U16 algorithm_id;                       /* rrc_int_algorithm_et */
    U8  key[RRC_PDCP_SECURITY_KEY_SIZE];    /*^ M, 0, OCTET_STRING, FIXED ^*/
} rrc_pdcp_config_int_t;

typedef struct _rrc_pdcp_config_ciph_t
{
    U16 algorithm_id;                       /* rrc_ciph_algorithm_et */
    U8  key[RRC_PDCP_SECURITY_KEY_SIZE];    /*^ M, 0, OCTET_STRING, FIXED ^*/
} rrc_pdcp_config_ciph_t;

typedef struct _rrc_pdcp_config_rohc_t
{
    U16 profile_id;
    U16 max_cid;                            /* default value is 15 */
} rrc_pdcp_config_rohc_t;

#define K_RRC_ENC_ALG_P1 0x03
#define K_RRC_INT_ALG_P1 0x04
#define K_UP_ENC_ALG_P1  0x05

/******************************************************************************
*   End of these types are shared UECC-LLIM with PDCP
******************************************************************************/

/******************************************************************************
*   These types are shared UECC-LLIM with MAC
******************************************************************************/

typedef enum
{
    MAC_RELEASE = 0,
    MAC_SETUP
} rrc_mac_request_type_et;

typedef struct _rrc_mac_ri_config_index_info_t
{
    U16  ri_config_index;               /*^ M, 0, H, 0, 1023 ^*/
} rrc_mac_ri_config_index_info_t;

#define RRC_MAC_RI_CONFIG_INDEX_INFO_PRESENT 0x01

typedef struct _rrc_mac_cqi_pmi_config_index_info_t
{
    rrc_bitmask_t           optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    U16  cqi_pmi_config_index;
/*^ M, 0, H, 0, 1023 ^*/

    U16  cqi_pucch_resource_index;
/*^ M, 0, H, 0, 1185 ^*/

    U8  simultaneous_ack_nack_and_cqi;
/*^ M, 0, H, 0, 1 ^*/

    rrc_mac_ri_config_index_info_t  ri_config_index_info;
/*^ TLV, RRC_MAC_RI_CONFIG_INDEX_INFO, RRC_MAC_RI_CONFIG_INDEX_INFO_PRESENT ^*/

} rrc_mac_cqi_pmi_config_index_info_t;

#define RRC_MAC_CQI_PMI_CONFIG_INDEX_INFO_PRESENT 0x01

typedef struct _rrc_mac_cqi_periodic_config_info_t
{
    rrc_bitmask_t           optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    U8  request_type;                               /*^ M, 0, H, 0, 1 ^*/

    rrc_mac_cqi_pmi_config_index_info_t cqi_pmi_config_index_info;
/*^ TLV, RRC_MAC_CQI_PMI_CONFIG_INDEX_INFO, RRC_MAC_CQI_PMI_CONFIG_INDEX_INFO_PRESENT ^*/

} rrc_mac_cqi_periodic_config_info_t;

typedef struct _rrc_mac_cqi_aperiodic_config_info_t
{
    U8  cqi_aperiodic_mode;         /*^ M, 0, B, 12, 31 ^*/
} rrc_mac_cqi_aperiodic_config_info_t;

#define RRC_MAC_CQI_APERIODIC_CONFIG_INFO_PRESENT 0x01
#define RRC_MAC_CQI_PERIODIC_CONFIG_INFO_PRESENT  0x02

typedef struct _rrc_mac_cqi_info_t
{
    rrc_bitmask_t                       optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    rrc_mac_cqi_aperiodic_config_info_t cqi_aperiodic_config_info;
/*^ TLV, RRC_MAC_CQI_APERIODIC_CONFIG_INFO, RRC_MAC_CQI_APERIODIC_CONFIG_INFO_PRESENT ^*/

    rrc_mac_cqi_periodic_config_info_t  cqi_periodic_config_info;
/*^ TLV, RRC_MAC_CQI_PERIODIC_CONFIG_INFO, RRC_MAC_CQI_PERIODIC_CONFIG_INFO_PRESENT ^*/

} rrc_mac_cqi_info_t;

typedef struct _rrc_mac_sr_setup_info_t
{
    U16 sr_pucch_resource_index;    /*^ M, 0, H, 0, 2047 ^*/
    U8  sr_configuration_index;     /*^ M, 0, H, 0, 154 ^*/
} rrc_mac_sr_setup_info_t;

#define RRC_MAC_SR_SETUP_INFO_PRESENT 0x01

typedef struct _rrc_mac_sr_config_info_t
{
    rrc_bitmask_t           optional_elems_present;
/*^ M, 0, BITMASK, NOT_PRESENT_IN_MESSAGE ^*/


    U8  request_type;                               /*^ M, 0, H, 0, 1 ^*/

    rrc_mac_sr_setup_info_t sr_setup_info;
/*^ TLV, RRC_MAC_SR_SETUP_INFO, RRC_MAC_SR_SETUP_INFO_PRESENT ^*/

} rrc_mac_sr_config_info_t;

/******************************************************************************
*   End of these types are shared UECC-LLIM with MAC
******************************************************************************/

/******************************************************************************
*   These types are shared CSC-UECC with RRM
******************************************************************************/
#define MAX_MNC_OCTET_SIZE                  3
#define MCC_OCTET_SIZE                      3
#define MAX_PLMN_ID_INFO_SIZE               6
#define CSG_ID_OCTET_SIZE                   4
#define TAC_OCTET_SIZE                      2
#define CELL_ID_OCTET_SIZE                  4


typedef struct
{
  U8        count;                      /*^ M, 0, B, 2, 3 ^*/
  U8        mnc[MAX_MNC_OCTET_SIZE];    /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}mnc_t;


#define PLMN_IDENTITY_MCC_PRESENCE_FLAG     0x01

typedef struct
{
  U16       presence_bitmask;       /*^ BITMASK ^*/
  U8        mcc[MCC_OCTET_SIZE];    /*^ O, 1, OCTET_STRING, FIXED ^*/
  mnc_t     mnc;                    /*^ M, 0, N, 0, 0 ^*/
}plmn_identity_t;


typedef enum
{
  RRM_RRC_CELL_RESERVED,
  RRM_RRC_CELL_NOT_RESERVED
}rrm_cell_res_for_operator_use_et;


typedef struct
{
  plmn_identity_t   plmn_identity;              /*^ M, 0, N, 0, 0 ^*/
  U8                cell_res_for_operator_use;
/*^ M, 0, H, 1, 1 ^*/   /* rrm_cell_res_for_operator_use_et */

}plmn_identity_info_t;


typedef struct
{
  U8                    count;      /*^ M, 0, B, 1, 6 ^*/
  plmn_identity_info_t  plmn_identity_info[MAX_PLMN_ID_INFO_SIZE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}plmn_id_info_list_t;

/******************************************************************************
 *   End of these types are shared CSC-UECC with RRM
 ******************************************************************************/


/* Values for rrc_response_et, rrc_response_t */
typedef enum
{
    FAILURE,
    SUCCESS,
    PARTIAL_SUCCESS,
    FATAL
}rrc_response_et;

/* Values for rrc_response_et, rrc_response_t */
typedef enum
{
    ERAB_FAILURE,    
    ERAB_SUCCESS,
    ERAB_PARTIAL_SUCCESS,
    ERAB_FATAL
} rrc_erab_response_et;


typedef enum
{
    RRC_NO_ERROR,
    RRC_TIMER_EXPIRY,
    RRC_INTERACTION_WITH_OTHER_PROCEDURE,
    RRC_RADIO_LINK_FAILURE_TRIGGERED,
    RRC_RADIO_LINK_FAILURE_TRIGGERED_ROLLBACK_FAILURE,
    RRC_HANDOVER_TRIGGERED,
    RRC_HANDOVER_ROLLBACK_TRIGGERED_FAILURE,
    RRC_REESTABLISHMENT_TRIGGERED,
    RRC_REESTABLISHMENT_TRIGGERED_ROLLBACK_FAILURE,
    RRC_MEMORY_ALLOCATION_FAILURE,
    RRC_INVALID_RESPONSE_RECEIVED,
    RRC_INTERNAL_ERROR,
    RRC_ERROR_CODE_LAST
}rrc_erab_error_codes_t;


#pragma pack(pop)

#endif /* _RRC_DEFINES_H_ */
