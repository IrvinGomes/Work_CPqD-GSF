/*********************************************************************
 *
 *  FILE NAME   : rrc_rrm_intf.h
 *
 *  DESCRIPTION : File contains the RRM interface API structures.
 *
 *  REVISION HISTORY :
 *
 *  DATE              Name           Reference               Comments
 *  May 15, 2009      Pankaj A       LTE_RRC_API_v0.2.doc    --------
 *  May 26, 2009                                    Added MAC Main Config params
 *  Aug 04, 2009      AlexK                   Some updates to match ASN1 ver 860
 *  Aug 13, 2009      Oleksandr M    sib8 message added
 *  May 31, 2010      Vimal          <TODO>                  Added support for E-RAB 
 *                                                           Management
 *
 *  Copyright (c) 2009, Aricent Inc.
 *
 *******************************************************************/

#ifndef __RRC_RRM_INTF__
#define __RRC_RRM_INTF__

#include "rrc_defines.h"

/* hashdefined value used in RRMIM APIs*/

#define MAX_NUM_CELLS                       1
#define MAX_AC_VALUE                        5
#define MAX_MBSFN_SUBFRAME_CONFIG           8
#define MAX_HNB_ID_SIZE                     48
#define MAX_NUM_UE                          7
#define MAX_CELL_INTRA                      16
#define MAX_CELL_BLACK_LIST                 16
#define MAX_HNB_ID_OCTET_SIZE               48
#define MSG_ID_OCTET_SIZE                   2
#define SERIAL_NUMBER_OCTET_SIZE            2
#define WARNING_TYPE_OCTET_SIZE             2
#define SECURITY_INFORMATION_OCTET_SIZE     50
#define DATA_CODING_SCHEME_OCTET_SIZE       1
#define MAX_EARFCN                          65535
#define M_TMSI_OCTET_SIZE                   4
#define MME_OCTET_SIZE                      1
#define C_RNTI_OCTET_SIZE                   2
#define TPC_RNTI_OCTET_SIZE                 2
#define N_2_TX_ANTENNA_TM_3_OCTET_SIZE      1
#define N_4_TX_ANTENNA_TM_3_OCTET_SIZE      1
#define N_2_TX_ANTENNA_TM_4_OCTET_SIZE      1
#define N_4_TX_ANTENNA_TM_4_OCTET_SIZE      8
#define N_2_TX_ANTENNA_TM_5_OCTET_SIZE      1
#define N_4_TX_ANTENNA_TM_5_OCTET_SIZE      2
#define N_2_TX_ANTENNA_TM_6_OCTET_SIZE      1
#define N_4_TX_ANTENNA_TM_6_OCTET_SIZE      2
#define MAX_NUM_OF_SRB                      1

/*TS 36.413 9.2.1.53 - Warning Message Contents M  OCTET STRING (SIZE(1..9600))
Now we can't pass message of 9600 bytes so we set this length to 84 */
#define WARNING_MSG_SEGMENT_OCTET_SIZE      84

#define MAX_SI_MESSAGE                      10
#define MAX_SIB_MESSAGE                     32
#define MAX_SIB_MESSAGE_1                   MAX_SIB_MESSAGE - 1
#define MAX_EUTRA_CARRIER_FREQ              8
#define SUB_FRAME_ALLOC_ONE_FRAME_OCTET_SIZE    1
#define SUB_FRAME_ALLOC_FOUR_FRAME_OCTET_SIZE   3
#define STMSI_RANDOM_VALUE_OCTET_SIZE       5
#define MAX_N1_PUCCH_AN_PERSIST_SIZE        4
#define LONG_CODE_STATE_1_XRTT_OCTET_SIZE   6
#define XRTT_SID_OCTET_SIZE                 2
#define XRTT_NID_OCTET_SIZE                 2
#define XRTT_REG_PERIOD_OCTET_SIZE          1
#define XRTT_REG_ZONE_OCTET_SIZE            2
#define XRTT_TOTAL_ZONE_OCTET_SIZE          1
#define XRTT_ZONE_TIMER_OCTET_SIZE          1
#define SYNC_SYS_TIME_OCTET_SIZE            5
#define ASYNC_SYS_TIME_OCTET_SIZE           7
#define MAX_PHYS_CELL_ID_LIST_CDMA2000      16
#define MAX_NCELLS_PER_BS_LIST_CDMA2000     16
#define MAX_NEIGH_CELL_LIST_CDMA2000        16
#define MAX_CDMA_BAND_CLASS                 32
#define MAX_FREQ                            8
#define MAX_GNFG                            16
#define NCC_PERMITTED_OCTET_SIZE            1
#define MAX_EXPL_ARFCNS                     31
#define MAX_VAR_BITMAP_OF_ARFCNS            16
#define MAX_UTRA_FDD_CARRIER                16
#define MAX_UTRA_TDD_CARRIER                16
#define MAX_MEAS_OBJECT_ID                  32
#define MAX_CELL_MEAS                       32
#define MAX_PN_OFFSET                       511
#define MAX_REPORT_CONFIG_ID                32
#define MAX_MEAS_ID                         32
#define MAX_CELL_REPORT                     8
#define MAX_S1U_QOS_PROFILE_DATA_OCTET_SIZE 254
#define MAX_RAT_CAPABILITY					8
#define MAX_BAND_EUTRA						64
#define MAX_ASN_BUFFER						256




#pragma pack(push, 1)

/* rrm_cause_t */

typedef struct
{
    U8      type;
    U16     value;
} rrm_cause_t;

/*****************************************************************************
    RRC_RRM_UE_RELEASE_REQ
******************************************************************************/

typedef struct
{
  U16        ue_index;
}rrc_rrm_ue_release_req_t;  /*^ API, RRC_RRM_UE_RELEASE_REQ ^*/

/******************************************************************************
    RRC_RRM_UE_RELEASE_RESP
******************************************************************************/

typedef struct
{
  U16       ue_index;
  U8        response;       /*^ M, 0, H, 0, 1 ^*/   /* rrc_return_et */
}rrc_rrm_ue_release_resp_t;   /*^ API, RRC_RRM_UE_RELEASE_RESP ^*/

/******************************************************************************
    RRC_RRM_CELL_SETUP_REQ
******************************************************************************/

typedef enum
{
  RRC_RRM_PHICH_R_ONE_SIXTH,
  RRC_RRM_PHICH_R_HALF,
  RRC_RRM_PHICH_R_ONE,
  RRC_RRM_PHICH_R_TWO
}rrm_phich_resource_et;


typedef enum
{
  RRM_RRC_PHICH_D_NORMAL,
  RRM_RRC_PHICH_D_EXTENDED
}rrm_phich_duration_et;



typedef struct
{
  U8    phich_resource;     /*^ M, 0, H, 1, 3 ^*/   /* rrm_phich_resource_et */
  U8    phich_duration;     /*^ M, 0, H, 1, 1 ^*/   /* rrm_phich_duration_et */
}phich_config_t;




typedef enum
{
  RRM_RRC_BW_N_6,
  RRM_RRC_BW_N_15,
  RRM_RRC_BW_N_25,
  RRM_RRC_BW_N_50,
  RRM_RRC_BW_N_75,
  RRM_RRC_BW_N_100
}rrm_band_width_et;


typedef struct
{
  U8                dl_band_width;
/*^ M, 0, H, 1, 5 ^*/  /* rrm_band_width_et */
  phich_config_t    phich_config;    /*^ M, 0, N, 0, 0 ^*/
}mib_info_t;


typedef enum
{
  RRM_RRC_CELL_BARRED,
  RRM_RRC_CELL_NOT_BARRED
}rrm_cell_barred_et;


typedef enum
{
    RRC_RRM_INETR_FREQ_RESELECTION_ALLOWED,
    RRC_RRM_INETR_FREQ_RESELECTION_NOT_ALLOWED
}rrm_intra_freq_reselect_et;


#define CELL_ACCESS_INFO_CSG_ID_PRESENCE_FLAG   0x01


typedef struct
{
  U16      presence_bitmask;                /*^ BITMASK ^*/
  U8       tac[TAC_OCTET_SIZE];             /*^ M, 0, OCTET_STRING, FIXED ^*/
  U8       cell_Id[CELL_ID_OCTET_SIZE];     /*^ M, 0, OCTET_STRING, FIXED ^*/
  U8       cell_barred;
/*^ M, 0, H, 1, 1 ^*/   /* rrm_cell_barred_et */

  U8       intra_freq_reselection;
/*^ M, 0, H, 1, 1 ^*/   /* rrm_intra_freq_reselect_et */

  U8       csg_indication;
/*^ M, 0, H, 0, 1 ^*/   /* rrc_bool_et */

  U8       csg_identity[CSG_ID_OCTET_SIZE]; /*^ O, 1, OCTET_STRING, FIXED ^*/
  plmn_id_info_list_t   plmn_Id_info_list;  /*^ M, 0, N, 0, 0 ^*/
}cell_access_related_info_t;




#define CELL_SELECT_INFO_Q_RX_LEV_MIN_OFFSET_PRESENCE_FLAG  0x01

typedef struct
{
  U16       presence_bitmask;       /*^ BITMASK ^*/
  S8        q_rx_lev_min;           /*^ M, 0, B, -70, -22 ^*/
  U8        q_rx_lev_min_offset;    /*^ O, 1, B, 1, 8 ^*/
}cell_selection_Info_t;


typedef enum
{
  RRM_RRC_SI_WINDOW_LEN_MS_1,
  RRM_RRC_SI_WINDOW_LEN_MS_2,
  RRM_RRC_SI_WINDOW_LEN_MS_5,
  RRM_RRC_SI_WINDOW_LEN_MS_10,
  RRM_RRC_SI_WINDOW_LEN_MS_15,
  RRM_RRC_SI_WINDOW_LEN_MS_20,
  RRM_RRC_SI_WINDOW_LEN_MS_40
}rrm_si_window_length_et;




typedef enum
{
  RRM_RRC_RF_8,
  RRM_RRC_RF_16,
  RRM_RRC_RF_32,
  RRM_RRC_RF_64,
  RRM_RRC_RF_128,
  RRM_RRC_RF_256,
  RRM_RRC_RF_512
}rrm_si_periodicity_et;




typedef enum
{
  RRM_RRC_SIB_TYPE_3,
  RRM_RRC_SIB_TYPE_4,
  RRM_RRC_SIB_TYPE_5,
  RRM_RRC_SIB_TYPE_6,
  RRM_RRC_SIB_TYPE_7,
  RRM_RRC_SIB_TYPE_8,
  RRM_RRC_SIB_TYPE_9,
  RRM_RRC_SIB_TYPE_10,
  RRM_RRC_SIB_TYPE_11
}rrm_sib_type_et;




typedef struct
{
  U8            count;
/*^ M, 0, N, 0, 31 ^*/     /* MAX_SIB_MESSAGE_1  */

  U8            sib_type[MAX_SIB_MESSAGE_1];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/  /* rrm_sib_type_et */

}sib_mapping_info_t;


typedef struct
{
  sib_mapping_info_t   sib_mapping_info; /*^ M, 0, N, 0, 0 ^*/
  U8                   si_periodicity;
/*^ M, 0, H, 0, 6 ^*/ /* rrm_si_periodicity_et */

}sheduling_info_t;


typedef struct
{
  sib_mapping_info_t   sib_mapping_info; /*^ M, 0, N, 0, 0 ^*/
  U8                   si_periodicity;
/*^ M, 0, H, 0, 6 ^*/ /* rrm_si_periodicity_et */
  U8			si_index;	/*^M, 0, N, 0, 10 ^*/

}new_sheduling_info_t;

typedef struct
{
  U8                count;              /*^ M, 0, B, 1, 10 ^*/
  new_sheduling_info_t  sheduling_info[MAX_SI_MESSAGE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}new_sheduling_info_list_t;




typedef struct
{
  U8                count;              /*^ M, 0, B, 1, 10 ^*/
  sheduling_info_t  sheduling_info[MAX_SI_MESSAGE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}sheduling_info_list_t;

typedef enum
{
sa_0, 
sa_1, 
sa_2, 
sa_3, 
sa_4, 
sa_5, 
sa_6
}rrm_sub_frame_assignment_et;


typedef enum 
{
ssp_0, 
ssp_1,
ssp_2, 
ssp_3, 
ssp_4,
ssp_5, 
ssp_6, 
ssp_7,
ssp_8
}rrm_spacial_sub_frame_pattern_et;

typedef struct
{
  U8 sub_frame_assignment;
/*^ M, 0, H, 0, 6 ^*/  /* rrm_sub_frame_assignment_et */
  U8 spacial_sub_frame_pattern;
/*^ M, 0, H, 0 , 8 ^*/  /* rrm_spacial_sub_frame_pattern_et */
}tdd_config_t;

#define SIB_TYPE_1_P_MAX_PRESENCE_FLAG     0x01
#define SIB_TYPE_1_TDD_CONFIG_PRESENT_FLAG 0x02

typedef struct
{
  U16                           presence_bitmask;         /*^ BITMASK ^*/
  cell_access_related_info_t    cell_access_related_info; /*^ M, 0, N, 0, 0 ^*/
  cell_selection_Info_t         cell_selection_Info;      /*^ M, 0, N, 0, 0 ^*/
  S8                            p_max;                    /*^ O, 1, N, 0, 0 ^*/
  U8                            freq_band_indicator;      /*^ M, 0, B, 1, 64 ^*/
  U8                            si_window_length;
/*^ M, 0, H, 1, 6 ^*/ /* rrm_si_window_length_et */

  U8                            si_value_tag;             /*^ M, 0, H, 0, 31 ^*/
  sheduling_info_list_t         sheduling_info_list;      /*^ M, 0, N, 0, 0 ^*/
  
  tdd_config_t                  tdd_config; /*^ O, 2, N, 0, 0 ^*/

}sib_type_1_Info_t;


typedef enum
{
  RRM_RRC_AC_BARRING_FACTOR_P00,
  RRM_RRC_AC_BARRING_FACTOR_P05,
  RRM_RRC_AC_BARRING_FACTOR_P10,
  RRM_RRC_AC_BARRING_FACTOR_P15,
  RRM_RRC_AC_BARRING_FACTOR_P20,
  RRM_RRC_AC_BARRING_FACTOR_P25,
  RRM_RRC_AC_BARRING_FACTOR_P30,
  RRM_RRC_AC_BARRING_FACTOR_P40,
  RRM_RRC_AC_BARRING_FACTOR_P50,
  RRM_RRC_AC_BARRING_FACTOR_P60,
  RRM_RRC_AC_BARRING_FACTOR_P70,
  RRM_RRC_AC_BARRING_FACTOR_P75,
  RRM_RRC_AC_BARRING_FACTOR_P80,
  RRM_RRC_AC_BARRING_FACTOR_P85,
  RRM_RRC_AC_BARRING_FACTOR_P90,
  RRM_RRC_AC_BARRING_FACTOR_P95
}rrm_ac_barring_factor_et;


typedef enum
{
  RRM_RRC_AC_BARRING_TIME_S4,
  RRM_RRC_AC_BARRING_TIME_S8,
  RRM_RRC_AC_BARRING_TIME_S16,
  RRM_RRC_AC_BARRING_TIME_S32,
  RRM_RRC_AC_BARRING_TIME_S64,
  RRM_RRC_AC_BARRING_TIME_S128,
  RRM_RRC_AC_BARRING_TIME_S256,
  RRM_RRC_AC_BARRING_TIME_S512
}rrm_ac_barring_time_et;



typedef struct
{
  U8        ac_barring_factor;
/*^ M, 0, H, 1, 15 ^*/   /* rrm_ac_barring_factor_et */

  U8        ac_barring_time;
/*^ M, 0, H, 1, 7 ^*/    /* rrm_ac_barring_time_et */

  U8        ac_barring_for_special_ac;
/*^ M, 0, H, 0, 248 ^*/ /* only 5 last bits are used 7..3 */

}access_class_barring_Info_t;




#define AC_BARR_INFO_MO_SIG_PRESENCE_FLAG       0x01
#define AC_BARR_INFO_MO_DATA_PRESENCE_FLAG      0x02

typedef struct
{
  U16                           presence_bitmask;               /*^ BITMASK ^*/
  U8                            acBarringForEmergency;
/*^ M, 0, H, 0, 1 ^*/  /* rrc_bool_et */

  access_class_barring_Info_t   ac_barring_for_mo_signalling;
/*^ O, 1, N, 0, 0 ^*/

  access_class_barring_Info_t   ac_barring_for_mo_data;
/*^ O, 2, N, 0, 0 ^*/

}access_barring_info_t;



typedef enum
{
  RRM_RRC_RA_PREAMBLE_COUNT_N4,
  RRM_RRC_RA_PREAMBLE_COUNT_N8,
  RRM_RRC_RA_PREAMBLE_COUNT_N12,
  RRM_RRC_RA_PREAMBLE_COUNT_N16,
  RRM_RRC_RA_PREAMBLE_COUNT_N20,
  RRM_RRC_RA_PREAMBLE_COUNT_N24,
  RRM_RRC_RA_PREAMBLE_COUNT_N28,
  RRM_RRC_RA_PREAMBLE_COUNT_N32,
  RRM_RRC_RA_PREAMBLE_COUNT_N36,
  RRM_RRC_RA_PREAMBLE_COUNT_N40,
  RRM_RRC_RA_PREAMBLE_COUNT_N44,
  RRM_RRC_RA_PREAMBLE_COUNT_N48,
  RRM_RRC_RA_PREAMBLE_COUNT_N52,
  RRM_RRC_RA_PREAMBLE_COUNT_N56,
  RRM_RRC_RA_PREAMBLE_COUNT_N60,
  RRM_RRC_RA_PREAMBLE_COUNT_N64
}rrm_ra_preamble_count_et;


typedef enum
{
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N4,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N8,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N12,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N16,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N20,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N24,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N28,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N32,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N36,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N40,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N44,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N48,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N52,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N56,
  RRM_RRC_RA_PREAMBLE_GROUP_A_SIZE_N60
}rrm_ra_preambles_group_a_size_et;


typedef enum
{
  RRM_RRC_GROUP_A_MSG_SIZE_B56,
  RRM_RRC_GROUP_A_MSG_SIZE_B144,
  RRM_RRC_GROUP_A_MSG_SIZE_B208,
  RRM_RRC_GROUP_A_MSG_SIZE_B256
}rrm_group_a_msg_size_et;


typedef enum
{
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_MINUSINFINITY,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB0,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB5,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB8,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB10,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB12,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB15,
  RRM_RRC_GROUP_B_MSG_POWER_OFFSET_DB18
}rrm_group_b_msg_power_offset_et;



typedef struct
{
  U8        ra_preambles_group_a_size;
/*^ M, 0, H, 1, 14 ^*/       /* rrm_ra_preambles_group_a_size_et */

  U8        group_a_msg_size;
/*^ M, 0, H, 1, 3 ^*/       /* rrm_group_a_msg_size_et */

  U8        group_b_msg_power_offset;
/*^ M, 0, H, 1, 7 ^*/       /* rrm_group_b_msg_power_offset_et */

}preambles_group_a_config_t;




#define PREAMBLE_INFO_GROUP_A_CONFIG_PRESENCE_FLAG      0x01

typedef struct
{
    U16                         presence_bitmask;       /*^ BITMASK ^*/
    U8                          ra_preamble_count;
/*^ M, 0, H, 1, 15 ^*/  /* rrm_ra_preamble_count_et */

    preambles_group_a_config_t  preambles_group_a_config; /*^ O, 1, N, 0, 0 ^*/
}preamble_info_t;


typedef enum
{
  RRM_RRC_POWER_RAMP_STEP_DB0,
  RRM_RRC_POWER_RAMP_STEP_DB2,
  RRM_RRC_POWER_RAMP_STEP_DB4,
  RRM_RRC_POWER_RAMP_STEP_DB6
}rrm_power_ramping_step_et;


typedef enum
{
  RRM_RRC_PREAMBLE_POWER_DBM_120,
  RRM_RRC_PREAMBLE_POWER_DBM_118,
  RRM_RRC_PREAMBLE_POWER_DBM_116,
  RRM_RRC_PREAMBLE_POWER_DBM_114,
  RRM_RRC_PREAMBLE_POWER_DBM_112,
  RRM_RRC_PREAMBLE_POWER_DBM_110,
  RRM_RRC_PREAMBLE_POWER_DBM_108,
  RRM_RRC_PREAMBLE_POWER_DBM_106,
  RRM_RRC_PREAMBLE_POWER_DBM_104,
  RRM_RRC_PREAMBLE_POWER_DBM_102,
  RRM_RRC_PREAMBLE_POWER_DBM_100,
  RRM_RRC_PREAMBLE_POWER_DBM_98,
  RRM_RRC_PREAMBLE_POWER_DBM_96,
  RRM_RRC_PREAMBLE_POWER_DBM_94,
  RRM_RRC_PREAMBLE_POWER_DBM_92,
  RRM_RRC_PREAMBLE_POWER_DBM_90
}rrm_preamble_init_rec_target_pow_et;




typedef struct
{
   U8       power_ramping_step;
/*^ M, 0, H, 0, 3 ^*/ /* rrm_power_ramping_step_et */

   U8       preamble_init_rec_target_pow;
/*^ M, 0, H, 0, 15 ^*/ /* rrm_preamble_init_rec_target_pow_et */

}power_ramping_params_t;




typedef enum
{
  RRM_RRC_PREAMBLE_TRANS_MAX_N3,
  RRM_RRC_PREAMBLE_TRANS_MAX_N4,
  RRM_RRC_PREAMBLE_TRANS_MAX_N5,
  RRM_RRC_PREAMBLE_TRANS_MAX_N6,
  RRM_RRC_PREAMBLE_TRANS_MAX_N7,
  RRM_RRC_PREAMBLE_TRANS_MAX_N8,
  RRM_RRC_PREAMBLE_TRANS_MAX_N10,
  RRM_RRC_PREAMBLE_TRANS_MAX_N20,
  RRM_RRC_PREAMBLE_TRANS_MAX_N50,
  RRM_RRC_PREAMBLE_TRANS_MAX_N100,
  RRM_RRC_PREAMBLE_TRANS_MAX_N200
}rrm_preamble_trans_max_et;


typedef enum
{
  RRM_RRC_RA_RESP_WIN_SIZE_SF2,
  RRM_RRC_RA_RESP_WIN_SIZE_SF3,
  RRM_RRC_RA_RESP_WIN_SIZE_SF4,
  RRM_RRC_RA_RESP_WIN_SIZE_SF5,
  RRM_RRC_RA_RESP_WIN_SIZE_SF6,
  RRM_RRC_RA_RESP_WIN_SIZE_SF7,
  RRM_RRC_RA_RESP_WIN_SIZE_SF8,
  RRM_RRC_RA_RESP_WIN_SIZE_SF10
}rrm_ra_resp_win_size_et;



typedef enum
{
  RRM_RRC_MAC_CONT_RES_TIMER_SF8,
  RRM_RRC_MAC_CONT_RES_TIMER_SF16,
  RRM_RRC_MAC_CONT_RES_TIMER_SF24,
  RRM_RRC_MAC_CONT_RES_TIMER_SF32,
  RRM_RRC_MAC_CONT_RES_TIMER_SF40,
  RRM_RRC_MAC_CONT_RES_TIMER_SF48,
  RRM_RRC_MAC_CONT_RES_TIMER_SF56,
  RRM_RRC_MAC_CONT_RES_TIMER_SF64
}rrm_mac_cont_resol_timer_et;



typedef struct
{
  U8        preamble_trans_max;
/*^ M, 0, H, 1, 10 ^*/ /* rrm_preamble_trans_max_et */

  U8        ra_resp_win_size;
/*^ M, 0, H, 1, 7 ^*/  /* rrm_ra_resp_win_size_et */

  U8        mac_cont_resol_timer;
/*^ M, 0, H, 1, 7 ^*/  /* rrm_mac_cont_resol_timer_et */

}ra_supervision_info_t;


typedef struct
{
    preamble_info_t             preamble_info;          /*^ M, 0, N, 0, 0 ^*/
    power_ramping_params_t      power_ramping_params;   /*^ M, 0, N, 0, 0 ^*/
    ra_supervision_info_t       ra_supervision_info;    /*^ M, 1, N, 0, 0 ^*/
    U8                          max_harq_msg_3_tx;      /*^ M, 0, B, 1, 8 ^*/
}rach_config_common_t;



typedef enum
{
  RRM_RRC_MOD_PERIOD_COEFF_N2,
  RRM_RRC_MOD_PERIOD_COEFF_N4,
  RRM_RRC_MOD_PERIOD_COEFF_N8,
  RRM_RRC_MOD_PERIOD_COEFF_N16
}rrm_mod_period_coeff_et;


typedef struct
{
  U8        mod_period_coeff;
/*^ M, 0, H, 1, 3 ^*/   /* rrm_modif_period_coeff_et */

}bcch_config_t;



typedef enum
{
  RRM_RRC_DEF_PAG_CYCLE_RF32,
  RRM_RRC_DEF_PAG_CYCLE_RF64,
  RRM_RRC_DEF_PAG_CYCLE_RF128,
  RRM_RRC_DEF_PAG_CYCLE_RF256
}rrm_default_paging_cycle_et;


typedef enum
{
  RRM_RRC_NB_FOUR_T,
  RRM_RRC_NB_TWO_T,
  RRM_RRC_NB_ONE_T,
  RRM_RRC_NB_HALF_T,
  RRM_RRC_NB_QUARTER_T,
  RRM_RRC_NB_ONE_EIGHTH_T,
  RRM_RRC_NB_ONE_SIXTEENTH_T,
  RRM_RRC_NB_ONE_THIRTY_SECOND_T
}rrm_nb_et;


typedef struct
{
  U8    default_paging_cycle;
/*^ M, 0, H, 1, 3 ^*/   /* rrm_default_paging_cycle_et */

  U8    nb;                     /*^ M, 0, H, 1, 8 ^*/   /* rrm_nb_et */
}pcch_config_t;


typedef struct
{
  U8        prach_config_index;     /*^ M, 0, H, 1, 63 ^*/
  U8        high_speed_flag;    /*^ M, 0, H, 0, 1 ^*/  /* rrc_bool_et */
/*FALSE for unrestricted*/

  U8        zero_cor_zone_config;   /*^ M, 0, H, 1, 15 ^*/
  U8        prach_freq_offset;      /*^ M, 0, H, 1, 94 ^*/
}prach_config_info_t;


typedef struct
{
  U16                   root_seq_index;     /*^ M, 0, H, 1, 837 ^*/
  prach_config_info_t   prach_config_info;  /*^ M, 0, N, 0, 0 ^*/
}prach_config_sib_t;






typedef enum
{
    RRM_RRC_HM_INTER_SF,
    RRM_RRC_HM_INTRA_AND_INTER_SF
}rrm_hopping_mode_et;



typedef struct
{
  U8        nsb;                  /*^ M, 0, B, 1, 4 ^*/
  U8        hopping_mode;
/*^ M, 0, H, 1, 1 ^*/     /* rrm_hopping_mode_et */

  U8        pusch_hopping_offset; /*^ M, 0, H, 0, 98 ^*/
  U8        enable_64_qam;        /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
}pusch_config_basic_t;

typedef struct
{
  pusch_config_basic_t      pusch_config_basic;     /*^ M, 0, N, 0, 0 ^*/
  ul_ref_signals_pusch_t    ul_ref_signals_pusch;   /*^ M, 0, N, 0, 0 ^*/
}pusch_config_common_t;



typedef enum
{
  RRM_RRC_DS1,
  RRM_RRC_DS2,
  RRM_RRC_DS3
}rrm_delta_pucch_shift_et;



typedef struct
{
  U8        delta_pucch_shift;
/*^ M, 0, H, 1, 2 ^*/   /* rrm_delta_pucch_shift_et */

  U8        n_rb_cqi;               /*^ M, 0, H, 0, 98 ^*/
  U8        n_cs_an;                /*^ M, 0, H, 1, 7 ^*/
  U16       n_one_pucch_an;         /*^ M, 0, H, 1, 2047 ^*/
}pucch_config_common_t;



typedef enum
{
  RRM_RRC_SRS_BW_CONFIG_BW0,
  RRM_RRC_SRS_BW_CONFIG_BW1,
  RRM_RRC_SRS_BW_CONFIG_BW2,
  RRM_RRC_SRS_BW_CONFIG_BW3,
  RRM_RRC_SRS_BW_CONFIG_BW4,
  RRM_RRC_SRS_BW_CONFIG_BW5,
  RRM_RRC_SRS_BW_CONFIG_BW6,
  RRM_RRC_SRS_BW_CONFIG_BW7
}rrm_srs_bw_config_et;

typedef enum
{
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC0,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC1,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC2,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC3,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC4,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC5,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC6,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC7,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC8,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC9,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC10,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC11,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC12,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC13,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC14,
  RRM_RRC_SRS_SUBFRAME_CONFIG_SC15
}rrm_srs_subframe_config_et;

typedef enum
{
  RRM_SRS_MAX_UP_PTS_TRUE = 0
}rrm_srs_max_up_pts_et;


typedef enum
{
  RRM_RRC_DELTAF_NEG_TWO,
  RRM_RRC_DELTAF_ZERO,
  RRM_RRC_DELTAF_POS_TWO
}rrm_delta_f_pucch_format_one_et;


typedef enum
{
  RRM_RRC_DELTA_F1,
  RRM_RRC_DELTA_F3,
  RRM_RRC_DELTA_F5
}rrm_delta_f_pucch_format_one_b_et;


typedef struct
{
  U8    delta_f_pucch_format_one;
/*^ M, 0, H, 1, 2 ^*/  /* rrm_delta_f_pucch_format_one_et */

  U8    delta_f_pucch_format_one_b;
/*^ M, 0, H, 1, 2 ^*/  /* rrm_delta_f_pucch_format_one_b_et */

}delta_f_list_pucch_t;


typedef enum
{
  RRM_RRC_FORMAT2_DELTA_NEG_TWO,
  RRM_RRC_FORMAT2_DELTA_ZERO,
  RRM_RRC_FORMAT2_DELTA_POS_ONE,
  RRM_RRC_FORMAT2_DELTA_POS_TWO
}rrm_delta_f_pucch_format_two_et;


typedef enum
{
  RRM_RRC_DELTA_NEG_TWO,
  RRM_RRC_DELTA_ZERO,
  RRM_RRC_DELTA_POS_TWO
}rrm_delta_f_pucch_format_two_ab_et;



typedef struct
{
  U8    delta_f_pucch_format_two;
/*^ M, 0, H, 1, 3 ^*/ /* rrm_delta_f_pucch_format_two_et */

  U8    delta_f_pucch_format_two_a;
/*^ M, 0, H, 1, 2 ^*/ /* rrm_delta_f_pucch_format_two_ab_et */

  U8    delta_f_pucch_format_two_b;
/*^ M, 0, H, 1, 2 ^*/ /* rrm_delta_f_pucch_format_two_ab_et */

}delta_f_pucch_format_two_t;


typedef enum
{

  RRM_RRC_AL_0,
  RRM_RRC_AL_0_4,
  RRM_RRC_AL_0_5,
  RRM_RRC_AL_0_6,
  RRM_RRC_AL_0_7,
  RRM_RRC_AL_0_8,
  RRM_RRC_AL_0_9,
  RRM_RRC_AL_1
}rrm_alpha_et;


typedef struct
{
  S8                           p_zero_nominal_Pusch;
/*^ M, 0, B, -126, 24 ^*/

  U8                           alpha;
/*^ M, 0, H, 1, 7 ^*/  /* rrm_alpha_et */

  S8                           p_zero_nominal_pucch;
/*^ M, 0, B, -127, -96 ^*/

  delta_f_list_pucch_t         delta_f_list_pucch;      /*^ M, 0, N, 0, 0 ^*/
  delta_f_pucch_format_two_t   delta_f_pucch_format_two;/*^ M, 0, N, 0, 0 ^*/
  S8                           delta_preamble_msg_three;/*^ M, 0, B, -1, 6 ^*/
}uplink_power_control_common_t;



typedef enum
{
  RRM_RRC_UL_CYC_PREFIX_LEN_1,
  RRM_RRC_UL_CYC_PREFIX_LEN_2
}rrm_ul_cyclic_prefix_len_et;


typedef struct
{
  rach_config_common_t            rach_config_common; /*^ M, 0, N, 0, 0 ^*/
  bcch_config_t                   bcch_config;        /*^ M, 0, N, 0, 0 ^*/
  pcch_config_t                   pcch_config;        /*^ M, 0, N, 0, 0 ^*/
  prach_config_sib_t              prach_config_sib;   /*^ M, 0, N, 0, 0 ^*/
  U8                              ul_cyc_prefix_len;
/*^ M, 0, H, 1, 1 ^*/  /* rrm_ul_cyclic_prefix_len_et */

  pdsch_config_common_t           pdsch_config_common;
/*^ M, 0, N, 0, 0 ^*/

  pusch_config_common_t           pusch_config_common;
/*^ M, 0, N, 0, 0 ^*/

  pucch_config_common_t           pucch_config_common;
/*^ M, 0, N, 0, 0 ^*/

  sounding_rs_ul_config_common_t  sounding_rs_ul_config_common;
/*^ M, 0, N, 0, 0 ^*/ /* M since 331.860*/

  uplink_power_control_common_t   uplink_power_control_common;
/*^ M, 0, N, 0, 0 ^*/

}radio_resource_config_common_sib_t;

typedef enum
{
  RRM_RRC_TIMER_300_301_MS100,
  RRM_RRC_TIMER_300_301_MS200,
  RRM_RRC_TIMER_300_301_MS300,
  RRM_RRC_TIMER_300_301_MS400,
  RRM_RRC_TIMER_300_301_MS600,
  RRM_RRC_TIMER_300_301_MS1000,
  RRM_RRC_TIMER_300_301_MS1500,
  RRM_RRC_TIMER_300_301_MS2000
}rrm_timer_300_301_et;


typedef enum
{
  RRM_RRC_TIMER_310_MS0,
  RRM_RRC_TIMER_310_MS50,
  RRM_RRC_TIMER_310_MS100,
  RRM_RRC_TIMER_310_MS200,
  RRM_RRC_TIMER_310_MS500,
  RRM_RRC_TIMER_310_MS1000,
  RRM_RRC_TIMER_310_MS2000
}rrm_timer_310_et;

typedef enum
{
  RRM_RRC_TIMER_N310_N1,
  RRM_RRC_TIMER_N310_N2,
  RRM_RRC_TIMER_N310_N3,
  RRM_RRC_TIMER_N310_N4,
  RRM_RRC_TIMER_N310_N6,
  RRM_RRC_TIMER_N310_N8,
  RRM_RRC_TIMER_N310_N10,
  RRM_RRC_TIMER_N310_N20
}rrm_timer_n310_et;

typedef enum
{
  RRM_RRC_TIMER_311_MS1000,
  RRM_RRC_TIMER_311_MS3000,
  RRM_RRC_TIMER_311_MS5000,
  RRM_RRC_TIMER_311_MS10000,
  RRM_RRC_TIMER_311_MS15000,
  RRM_RRC_TIMER_311_MS20000,
  RRM_RRC_TIMER_311_MS30000
}rrm_timer_311_et;

typedef enum
{
  RRM_RRC_TIMER_N311_N1,
  RRM_RRC_TIMER_N311_N2,
  RRM_RRC_TIMER_N311_N3,
  RRM_RRC_TIMER_N311_N4,
  RRM_RRC_TIMER_N311_N5,
  RRM_RRC_TIMER_N311_N6,
  RRM_RRC_TIMER_N311_N8,
  RRM_RRC_TIMER_N311_N10
}rrm_timer_n311_et;

typedef struct
{
  U8      timer_300;    /*^ M, 0, H, 1, 7 ^*/ /* rrm_timer_300_301_et */
  U8      timer_301;    /*^ M, 0, H, 1, 7 ^*/ /* rrm_timer_300_301_et */
  U8      timer_310;    /*^ M, 0, H, 1, 6 ^*/ /* rrm_timer_310_et */
  U8      timer_n310;    /*^ M, 0, H, 0, 7 ^*/ /* rrm_timer_n310_et */
  U8      timer_311;    /*^ M, 0, H, 1, 6 ^*/ /* rrm_timer_311_et */
  U8      timer_n311;    /*^ M, 0, H, 0, 7 ^*/ /* rrm_timer_n311_et */
}ue_timers_and_constants_t;


typedef enum
{
  RRM_RRC_UL_BW_6RB,
  RRM_RRC_UL_BW_15RB,
  RRM_RRC_UL_BW_25RB,
  RRM_RRC_UL_BW_50RB,
  RRM_RRC_UL_BW_75RB,
  RRM_RRC_UL_BW_100RB
}rrm_ul_bandwidth_et;



#define FREQ_INFO_UL_CARRER_FREQ_PRESENCE_FLAG      0x01
#define FREQ_INFO_UL_BW_PRESENCE_FLAG               0x02

typedef struct
{
  U16       presence_bitmask;       /*^ BITMASK ^*/
  U16       ul_carrier_freq;        /*^ O, 1 ^*/
  U8        ul_bandwidth;
/*^ O, 2, H, 1, 5 ^*/   /* rrm_ul_bandwidth_et */

  U8        add_spectrum_emission;  /*^ M, 0, B, 1, 32 ^*/
}freq_info_t;

#define SUBFRAME_ALLOCATION_ONE_FRAME                0X01
#define SUBFRAME_ALLOCATION_FOUR_FRAMES              0X02

typedef struct
{
  U16       presence_bitmask;                                   /*^ BITMASK ^*/
  U8        one_frame[SUB_FRAME_ALLOC_ONE_FRAME_OCTET_SIZE];
/*^ O, 1, OCTET_STRING, FIXED ^*/

  U8        four_frames[SUB_FRAME_ALLOC_FOUR_FRAME_OCTET_SIZE];
/*^ O, 2, OCTET_STRING, FIXED ^*/

}subframe_allocation_t;


typedef enum
{
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_1,
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_2,
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_4,
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_8,
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_16,
  RRM_RRC_RADIO_FRAME_ALLOC_PERIOD_32
}rrm_radio_frame_alloc_period_et;


typedef struct
{
  U8      radio_frame_alloc_period;
/*^ M, 0, H, 1, 5 ^*/ /* rrm_radio_frame_alloc_period_et */

  U8      radio_frame_alloc_offset;     /*^ M, 0, H, 1, 7 ^*/
  subframe_allocation_t      subframe_allocation;  /*^ M, 0, N, 0, 0 ^*/
}mbsfn_subframe_config_t;



typedef struct
{
  U8                        count;                  /*^ M, 0, H, 1, 8 ^*/
  mbsfn_subframe_config_t   mbsfn_subframe_config[MAX_MBSFN_SUBFRAME_CONFIG];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}mbsfn_subframe_config_list_t;



typedef enum
{
  RRM_RRC_TIME_ALLIGN_TIMER_SF_500,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_750,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_1280,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_1920,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_2560,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_5120,
  RRM_RRC_TIME_ALLIGN_TIMER_SF_10240,
  RRM_RRC_TIME_ALLIGN_TIMER_INFINITY
}rrm_time_align_timer_et;


#define SIB2_ACCESS_BARR_INFO_PRESENCE_FLAG                         0x01
#define SIB2_MBSFN_SUBFRAME_CONF_LIST_PRESENCE_FLAG                 0x02

typedef struct
{
  U16                                 presence_bitmask;
/*^ BITMASK ^*/

  access_barring_info_t               access_barring_info;
/*^ O, 1, N, 0, 0 ^*/

  radio_resource_config_common_sib_t  radio_resource_config_common_sib;
/*^ M, 0, N, 0, 0 ^*/

  ue_timers_and_constants_t           ue_timers_and_constants;
/*^ M, 0, N, 0, 0 ^*/

  freq_info_t                         freq_info;
/*^ M, 0, N, 0, 0 ^*/

  mbsfn_subframe_config_list_t        mbsfn_subframe_config_list;
/*^ O, 2, N, 0, 0 ^*/

  U8                                  time_align_timer;
/*^ M, 0, H, 1, 7 ^*/ /* rrm_time_align_timer_et */

}sib_type_2_Info_t;
typedef enum
{
  RRM_RRC_Q_HYST_DB0,
  RRM_RRC_Q_HYST_DB1,
  RRM_RRC_Q_HYST_DB2,
  RRM_RRC_Q_HYST_DB3,
  RRM_RRC_Q_HYST_DB4,
  RRM_RRC_Q_HYST_DB5,
  RRM_RRC_Q_HYST_DB6,
  RRM_RRC_Q_HYST_DB8,
  RRM_RRC_Q_HYST_DB10,
  RRM_RRC_Q_HYST_DB12,
  RRM_RRC_Q_HYST_DB14,
  RRM_RRC_Q_HYST_DB16,
  RRM_RRC_Q_HYST_DB18,
  RRM_RRC_Q_HYST_DB20,
  RRM_RRC_Q_HYST_DB22,
  RRM_RRC_Q_HYST_DB24
}rrm_q_hyst_et;

typedef enum
{
  RRM_RRC_T_EVAL_S_30,
  RRM_RRC_T_EVAL_S_60,
  RRM_RRC_T_EVAL_S_120,
  RRM_RRC_T_EVAL_S_180,
  RRM_RRC_T_EVAL_S_240
}rrm_t_evaluation_et;


typedef enum
{
  RRM_RRC_T_HYST_NORMAL_S_30,
  RRM_RRC_T_HYST_NORMAL_S_60,
  RRM_RRC_T_HYST_NORMAL_S_120,
  RRM_RRC_T_HYST_NORMAL_S_180,
  RRM_RRC_T_HYST_NORMAL_S_240
}rrm_t_hyst_normal_et;



typedef struct
{
  U8        t_evaluation;
/*^ M, 0, H, 1, 4 ^*/   /* rrm_t_evaluation_et */

  U8        t_hyst_normal;
/*^ M, 0, H, 1, 4 ^*/   /* rrm_t_hyst_normal_et */

  U8        n_cell_change_medium;   /*^ M, 0, B, 1, 16 ^*/
  U8        n_cell_change_high;     /*^ M, 0, B, 1, 16 ^*/
}mobility_state_params_t;




typedef enum
{
  RRM_RRC_Q_HYST_NEG_SIX,
  RRM_RRC_Q_HYST_NEG_FOUR,
  RRM_RRC_Q_HYST_NEG_TWO,
  RRM_RRC_Q_HYST_ZERO
}rrm_q_hyst_sf_et;



typedef struct
{
  U8        q_hyst_sf_medium;  /*^ M, 0, H, 1, 6 ^*/ /* rrm_q_hyst_sf_et */
  U8        q_hyst_sf_high;    /*^ M, 0, H, 1, 6 ^*/ /* rrm_q_hyst_sf_et */
}speed_depend_scaling_param_hyst_t;


typedef struct
{
  mobility_state_params_t           mobility_state_params;
/*^ M, 0, N, 0, 0 ^*/

  speed_depend_scaling_param_hyst_t speed_depend_scaling_param_hyst;
/*^ M, 0, N, 0, 0 ^*/

}speed_depend_reselect_t;


#define CELL_RESELECT_SPEED_DEPEND_RESELECT_PRESENCE_FLAG       0x01

typedef struct
{
  U16                      presence_bitmask;        /*^ BITMASK ^*/
  U8                       q_hyst;
/*^ M, 0, H, 1, 15 ^*/ /* rrm_q_hyst_et */

  speed_depend_reselect_t  speed_depend_reselect;   /*^ O, 1, N, 0, 0 ^*/
}cell_reselect_info_comm_t;


#define CELL_RESELECT_NON_INTRA_SEARCH_PRESENCE_FLAG            0x01

typedef struct
{
  U16       presence_bitmask;       /*^ BITMASK ^*/
  U8        s_non_intra_search;     /*^ O, 1, H, 1, 31 ^*/
  U8        thresh_serving_low;     /*^ M, 0, H, 1, 31 ^*/
  U8        cell_reselect_priority; /*^ M, 0, H, 1, 7 ^*/
}cell_reselect_serv_freq_info_t;

typedef U8 cell_resel_priority_t;

typedef U8 resel_threshold_t;

typedef U8 t_reselection_t;

typedef enum
{
  RRM_RRC_M_BW_6,
  RRM_RRC_M_BW_15,
  RRM_RRC_M_BW_25,
  RRM_RRC_M_BW_50,
  RRM_RRC_M_BW_75,
  RRM_RRC_M_BW_100
}rrm_measure_bw_et;

typedef enum
{
    RRM_RRC_O_DOT_25,
    RRM_RRC_O_DOT_5,
    RRM_RRC_O_DOT_75,
    RRM_RRC_l_DOT_0
} rrm_speed_state_scale_factors_et;

typedef struct
{
    U8  sf_medium; /*^ M, 0, H, 0, 3 ^*/  /* rrm_speed_state_scale_factors_et */
    U8  sf_high;   /*^ M, 0, H, 0, 3 ^*/  /* rrm_speed_state_scale_factors_et */
} speed_state_scale_factors_t;



#define INTRA_FREQ_CELL_RESELECT_P_MAX_PRESENCE_FLAG            0x01
#define INTRA_FREQ_CELL_RESELECT_INTRA_SEARCH_PRESENCE_FLAG     0x02
#define INTRA_FREQ_CELL_RESELECT_MEAS_BW_PRESENCE_FLAG          0x04
#define INTRA_FREQ_CELL_RESELECT_EUTRAN_SF_PRESENCE_FLAG        0x08

typedef struct
{
  U16       presence_bitmask;           /*^ BITMASK ^*/
  S8        q_rx_lev_min;               /*^ M, 0, B, -70, -22 ^*/
  S8        p_max;                      /*^ O, 1, B, -30, 33 ^*/
  U8        s_intra_search;             /*^ O, 2, H, 1, 31 ^*/
  U8        measure_bw;
/*^ O, 4, H, 1, 5 ^*/   /* rrm_measure_bw_et */

  U8        presence_antenna_port_1;    /*^ M, 0, H, 0, 1 ^*/
  U8        neigh_cell_config;          /*^ M, 0, N, 0, 0 ^*/
  U8        t_reselec_eutra;            /*^ M, 0, H, 1, 7 ^*/
  speed_state_scale_factors_t  t_reselect_eutra_sf; /*^ O, 8, N, 0, 0 ^*/
}intra_freq_cell_reselect_info_t;


typedef struct
{
  cell_reselect_info_comm_t       timecell_reselect_info_comm;
/*^ M, 0, N, 0, 0 ^*/

  cell_reselect_serv_freq_info_t  cell_reselect_serv_freq_info;
/*^ M, 0, N, 0, 0 ^*/

  intra_freq_cell_reselect_info_t intra_freq_cell_reselect_info;
/*^ M, 0, N, 0, 0 ^*/

}sib_type_3_Info_t;


typedef enum
{
  RRM_RRC_Q_OFFESET_RANGE_DB_24,
  RRM_RRC_Q_OFFESET_RANGE_DB_22,
  RRM_RRC_Q_OFFESET_RANGE_DB_20,
  RRM_RRC_Q_OFFESET_RANGE_DB_18,
  RRM_RRC_Q_OFFESET_RANGE_DB_16,
  RRM_RRC_Q_OFFESET_RANGE_DB_14,
  RRM_RRC_Q_OFFESET_RANGE_DB_12,
  RRM_RRC_Q_OFFESET_RANGE_DB_10,
  RRM_RRC_Q_OFFESET_RANGE_DB_8,
  RRM_RRC_Q_OFFESET_RANGE_DB_6,
  RRM_RRC_Q_OFFESET_RANGE_DB_5,
  RRM_RRC_Q_OFFESET_RANGE_DB_4,
  RRM_RRC_Q_OFFESET_RANGE_DB_3,
  RRM_RRC_Q_OFFESET_RANGE_DB_2,
  RRM_RRC_Q_OFFESET_RANGE_DB_1,
  RRM_RRC_Q_OFFESET_RANGE_DB0,
  RRM_RRC_Q_OFFESET_RANGE_DB1,
  RRM_RRC_Q_OFFESET_RANGE_DB2,
  RRM_RRC_Q_OFFESET_RANGE_DB3,
  RRM_RRC_Q_OFFESET_RANGE_DB4,
  RRM_RRC_Q_OFFESET_RANGE_DB5,
  RRM_RRC_Q_OFFESET_RANGE_DB6,
  RRM_RRC_Q_OFFESET_RANGE_DB8,
  RRM_RRC_Q_OFFESET_RANGE_DB10,
  RRM_RRC_Q_OFFESET_RANGE_DB12,
  RRM_RRC_Q_OFFESET_RANGE_DB14,
  RRM_RRC_Q_OFFESET_RANGE_DB16,
  RRM_RRC_Q_OFFESET_RANGE_DB18,
  RRM_RRC_Q_OFFESET_RANGE_DB20,
  RRM_RRC_Q_OFFESET_RANGE_DB22,
  RRM_RRC_Q_OFFESET_RANGE_DB24
}rrm_q_offset_range_et;


typedef struct
{
  rrc_phys_cell_id_t phys_cell_id;    /*^ M, 0, H, 0, 503 ^*/
  U8 q_offset_cell;
/*^ M, 0, H, 0, 30 ^*/   /* rrm_q_offset_range_et */

}neigh_cell_t;


typedef struct
{
  U8            count;                      /*^ M, 0, H, 1, 16 ^*/
  neigh_cell_t  neigh_cell[MAX_CELL_INTRA]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}neigh_cell_list_t;


typedef enum
{
  RRM_RRC_RANGE_PCI_N_4,
  RRM_RRC_RANGE_PCI_N_8,
  RRM_RRC_RANGE_PCI_N_12,
  RRM_RRC_RANGE_PCI_N_16,
  RRM_RRC_RANGE_PCI_N_24,
  RRM_RRC_RANGE_PCI_N_32,
  RRM_RRC_RANGE_PCI_N_48,
  RRM_RRC_RANGE_PCI_N_64,
  RRM_RRC_RANGE_PCI_N_84,
  RRM_RRC_RANGE_PCI_N_96,
  RRM_RRC_RANGE_PCI_N_128,
  RRM_RRC_RANGE_PCI_N_168,
  RRM_RRC_RANGE_PCI_N_252,
  RRM_RRC_RANGE_PCI_N_504
}rrm_phy_cell_id_range_et;


#define PHY_CELL_ID_RANGE    0x01

typedef struct
{
  U16                 presence_bitmask; /*^ BITMASK ^*/
  rrc_phys_cell_id_t  start;            /*^ M, 0, H, 0, 503 ^*/
  U8                  range;
/*^ O, PHY_CELL_ID_RANGE, H, 0, 13 ^*/ /* rrm_phy_cell_id_range_et */

}phy_cell_id_range_t;



typedef struct
{
  U8                    count;            /*^ M, 0, H, 1, 16 ^*/
  phy_cell_id_range_t   black_listed_cell[MAX_CELL_BLACK_LIST];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}black_listed_cell_list_t;



#define SIB_4_NEIGH_CELL_LIST_PRESENCE_FLAG         0x01
#define SIB_4_BLACK_LIST_LIST_PRESENCE_FLAG         0x02
#define SIB_4_PHY_CELL_ID_PRESENCE_FLAG             0x04


typedef struct
{
  U16                       presence_bitmask;                  /*^ BITMASK ^*/
  neigh_cell_list_t         intra_freq_neigh_cell_list;
/*^ O, 1, N, 0, 0 ^*/

  black_listed_cell_list_t  intra_freq_black_listed_cell_list;
/*^ O, 2, N, 0, 0 ^*/

  phy_cell_id_range_t       csg_phy_cell_id_range;
/*^ O, 4, N, 0, 0 ^*/

}sib_type_4_Info_t;



#define INTER_FREQ_CARR_P_MAX_PRESENCE_FLAG                     0x01
#define INTER_FREQ_CARR_SCALE_PARAM_PRESENCE_FLAG               0x02
#define INTER_FREQ_CARR_CELL_RESELCT_PRIOR_PRESENCE_FLAG        0x04
#define INTER_FREQ_CARR_NEIGH_CELL_LIST_PRESENCE_FLAG           0x08
#define INTER_FREQ_CARR_BLACK_LIST_CELL_LIST_PRESENCE_FLAG      0x10


typedef struct
{
  U16                             presence_bitmask;         /*^ BITMASK ^*/
  U16                             eutra_dl_carrier_freq;    /*^ M, 0 ^*/
  S8                              qrx_lev_min;
/*^ M, 0, B, -70, -22 ^*/

  S8                              p_max;
/*^ O, 1, B, -30, 33 ^*/

  U8                              t_reselection_eutran;
/*^ M, 0, H, 1, 7 ^*/

  speed_state_scale_factors_t     speed_depend_scal_params;
/*^ O, 2, N, 0, 0 ^*/

  U8                              thresh_x_high;
/*^ M, 0, H, 1, 31 ^*/

  U8                              thresh_x_low;
/*^ M, 0, H, 1, 31 ^*/

  U8                              measurement_bandwidth;
/*^ M, 0, H, 1, 5 ^*/ /* rrm_band_width_et */

  U8                              presence_antenna_port_1;
/*^ M, 0, H, 0, 1 ^*/ /* OM: new field added according to TS 36.331-860 */

  U8                              cell_reselect_priority;
/*^ O, 4, H, 1, 7 ^*/

  U8                              neigh_cell_config;
/*^ M, 0, H, 0, 192 ^*/

  U8                              q_offset_freq;
/*^ M, 0, H, 0, 30 ^*/  /* rrm_q_offset_range_et */

  neigh_cell_list_t               inter_freq_neigh_cell_list;
/*^ O, 8, N, 0, 0 ^*/

  black_listed_cell_list_t        inter_freq_black_listed_cell_list;
/*^ O, 16, N, 0, 0 ^*/

}inter_freq_carrier_freq_t;


typedef struct
{
  U8                              count;  /*^ M, 0, H, 1, 8 ^*/
  inter_freq_carrier_freq_t
      inter_freq_carrier_freq_list[MAX_EUTRA_CARRIER_FREQ];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}inter_freq_carrier_freq_list_list_t;


typedef struct
{
  inter_freq_carrier_freq_list_list_t   inter_freq_carrier_freq_list_list;
/*^ M, 0, N, 0, 0 ^*/

}sib_type_5_Info_t;



typedef U16  arfcn_value_utra_t;

#define CR_FREQ_UTRA_FDD_CELL_RESEL_PRI_PRESENCE_FLAG             0x01

typedef struct
{
    U16                       presence_bitmask;          /*^ BITMASK ^*/
    arfcn_value_utra_t        carrier_freq;
/*^ M, 0, H, 0, 16383 ^*/

    cell_resel_priority_t     cell_reselection_priority;
/*^ O, CR_FREQ_UTRA_FDD_CELL_RESEL_PRI_PRESENCE_FLAG, H, 0, 7 ^*/

    resel_threshold_t         thresh_x_high;             /*^ M, 0, H, 0, 31 ^*/
    resel_threshold_t         thresh_x_low;              /*^ M, 0, H, 0, 31 ^*/
    S8                        q_rx_lev_min;
/*^ M, 0, B, -60, -13 ^*/

    S8                        p_max_utra;
/*^ M, 0, B, -50, 33 ^*/

    S8                        q_qual_min;                /*^ M, 0, B, -24, 0 ^*/
} carrier_freq_utra_fdd_t;

typedef struct
{
    U8                       count;                      /*^ M, 0, B, 1, 16 ^*/
    carrier_freq_utra_fdd_t  data[MAX_UTRA_FDD_CARRIER];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/  /*maxUTRA-FDD-Carrier*/

} carrier_freq_list_utra_fdd_t;

#define CR_FREQ_UTRA_TDD_CELL_RESEL_PRI_PRESENCE_FLAG    0x01

typedef struct
{
    U16                       presence_bitmask;          /*^ BITMASK ^*/
    arfcn_value_utra_t        carrier_freq;
/*^ M, 0, H, 0, 16383 ^*/

    cell_resel_priority_t     cell_reselection_priority;
/*^ O, CR_FREQ_UTRA_TDD_CELL_RESEL_PRI_PRESENCE_FLAG, H, 0, 7 ^*/

    resel_threshold_t         thresh_x_high;             /*^ M, 0, H, 0, 31 ^*/
    resel_threshold_t         thresh_x_low;              /*^ M, 0, H, 0, 31 ^*/
    S8                        q_rx_lev_min;
/*^ M, 0, B, -60, -13 ^*/

    S8                        p_max_utra;
/*^ M, 0, B, -50, 33 ^*/

} carrier_freq_utra_tdd_t;

typedef struct
{
    U8                       count;                      /*^ M, 0, B, 1, 16 ^*/
    carrier_freq_utra_tdd_t  data[MAX_UTRA_TDD_CARRIER];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/  /*maxUTRA-TDD-Carrier*/

} carrier_freq_list_utra_tdd_t;

#define SIB_6_CARRIER_FREQ_LIST_UTRA_FDD_PRESENCE_FLAG    0x01
#define SIB_6_CARRIER_FREQ_LIST_UTRA_TDD_PRESENCE_FLAG    0x02
#define SIB_6_T_RESELECTION_UTRA_SF_PRESENCE_FLAG         0x04

typedef struct
{
    U16                          presence_bitmask;           /*^ BITMASK ^*/
    carrier_freq_list_utra_fdd_t carrier_freq_list_utra_fdd;
/*^ O, SIB_6_CARRIER_FREQ_LIST_UTRA_FDD_PRESENCE_FLAG, N, 0, 0 ^*/

    carrier_freq_list_utra_tdd_t carrier_freq_list_utra_tdd;
/*^ O, SIB_6_CARRIER_FREQ_LIST_UTRA_TDD_PRESENCE_FLAG, N, 0, 0 ^*/

    t_reselection_t              t_resel_utra;
/*^ M, 0, H, 0, 7 ^*/

    speed_state_scale_factors_t  t_resel_utra_sf;
/*^ O, SIB_6_T_RESELECTION_UTRA_SF_PRESENCE_FLAG, N, 0, 0 ^*/

}sib_type_6_Info_t;


typedef  U16 arfcn_value_geran_t;

typedef enum
{
    RRM_RRC_DCS_1800,
    RRM_RRC_PCS_1900
} rrm_band_indicator_geran_et;

typedef struct
{
    U8                  count;                 /*^ M, 0, H, 0, 31 ^*/
    arfcn_value_geran_t data[MAX_EXPL_ARFCNS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} explicit_list_arfcns_t;

typedef struct
{
    U8  arfcn_spacing;          /*^ M, 0, B, 1, 8 ^*/
    U8  num_of_following_arfcns;/*^ M, 0, H, 0, 31 ^*/
} equally_spaced_arfcns_t;

typedef struct
{
    U8        count;                          /*^ M, 0, B, 1, 16 ^*/
    U8        data[MAX_VAR_BITMAP_OF_ARFCNS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} var_bitmap_of_arfcns_t;

#define GERAN_EXPL_LIST_OF_ARFCNS_PRESENCE_FLAG    0x01
#define GERAN_EQ_SPACED_ARFCNS_PRESENCE_FLAG       0x02
#define GERAN_VAR_BITMAP_ARFCNS_PRESENCE_FLAG      0x04

/*CHOICE*/
typedef struct
{
    U16                      presence_bitmask;       /*^ BITMASK ^*/
    explicit_list_arfcns_t   explicit_list_of_arfcns;
/*^ O, GERAN_EXPL_LIST_OF_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/

    equally_spaced_arfcns_t  equally_spaced_arfcns;
/*^ O, GERAN_EQ_SPACED_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/

    var_bitmap_of_arfcns_t   var_bitmap_of_arfcns;
/*^ O, GERAN_VAR_BITMAP_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/

} geran_following_arfcns_t;

typedef struct
{
    arfcn_value_geran_t       starting_arfcn; /*^ M, 0, H, 0, 1023 ^*/
    U8                        band_indicator;
/*^ M, 0, H, 0, 1 ^*/ /*rrm_band_indicator_geran_et*/

    geran_following_arfcns_t  following_arfcns;
} carrier_freqs_geran_t;




#define CRFI_GERAN_CELL_RESEL_PRI_PRESENCE_FLAG 0x01
#define CRFI_GERAN_P_MAX_GERAN_PRESENCE_FLAG    0x02

typedef struct
{
    U16                   presence_bitmask;          /*^ BITMASK ^*/
    cell_resel_priority_t cell_reselection_priority;
/*^ O, CRFI_GERAN_CELL_RESEL_PRI_PRESENCE_FLAG, H, 0, 7 ^*/

    U8                    ncc_permitted[NCC_PERMITTED_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U8                    q_rx_lev_min;              /*^ M, 0, H, 0, 45 ^*/
    U8                    p_max_geran;
/*^ O, CRFI_GERAN_P_MAX_GERAN_PRESENCE_FLAG, H, 0, 39 ^*/

    resel_threshold_t     thresh_x_high;             /*^ M, 0, H, 0, 31 ^*/
    resel_threshold_t     thresh_x_low;              /*^ M, 0, H, 0, 31 ^*/
} crfi_geran_common_info_t;

typedef struct
{
    carrier_freqs_geran_t     carrier_freqs;
    crfi_geran_common_info_t  common_info;
} carrier_freqs_info_geran_t;

typedef struct
{
    U8                         count;                  /*^ M, 0, H, 0, 16 ^*/
    carrier_freqs_info_geran_t cr_freq_info[MAX_GNFG];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/  /*ASN1V_maxGNFG*/

} carrier_freqs_info_list_geran_t;


#define SIB_7_T_RESEL_GERAN_SF_PRESENCE_FLAG  0x01
#define SIB_7_CR_FREQS_INFO_LST_PRESENCE_FLAG 0x02

typedef struct
{
    U16                              presence_bitmask;      /*^ BITMASK ^*/
    U8                               t_reselection_geran;
/*^ M, 0, H, 0, 7 ^*/

    speed_state_scale_factors_t      t_reselect_geran_sf;
/*^ O, SIB_7_T_RESEL_GERAN_SF_PRESENCE_FLAG, N, 0, 0 ^*/

    carrier_freqs_info_list_geran_t  carrier_freqs_info_lst;
/*^ O, SIB_7_CR_FREQS_INFO_LST_PRESENCE_FLAG, N, 0, 0 ^*/

}sib_type_7_Info_t;


typedef enum
{
    RRM_RRC_BAND_CLASS_BC_0,
    RRM_RRC_BAND_CLASS_BC_1,
    RRM_RRC_BAND_CLASS_BC_2,
    RRM_RRC_BAND_CLASS_BC_3,
    RRM_RRC_BAND_CLASS_BC_4,
    RRM_RRC_BAND_CLASS_BC_5,
    RRM_RRC_BAND_CLASS_BC_6,
    RRM_RRC_BAND_CLASS_BC_7,
    RRM_RRC_BAND_CLASS_BC_8,
    RRM_RRC_BAND_CLASS_BC_9,
    RRM_RRC_BAND_CLASS_BC_10,
    RRM_RRC_BAND_CLASS_BC_11,
    RRM_RRC_BAND_CLASS_BC_12,
    RRM_RRC_BAND_CLASS_BC_13,
    RRM_RRC_BAND_CLASS_BC_14,
    RRM_RRC_BAND_CLASS_BC_15,
    RRM_RRC_BAND_CLASS_BC_16,
    RRM_RRC_BAND_CLASS_BC_17
}rrm_bandclass_cdma2000_et;

#define SYS_TIME_INFO_CDMA2000_SYNC_SYS_TIME_PRESENCE_FLAG   0x01
#define SYS_TIME_INFO_CDMA2000_ASYNC_SYS_TIME_PRESENCE_FLAG  0x02

typedef struct
{
    U16 presence_bitmask;                         /*^ BITMASK ^*/
    U8  cdma_eutra_sync;
/*^ M, 0, H, 0, 1 ^*/    /* rrc_bool_et */

    U8  sync_sys_time[SYNC_SYS_TIME_OCTET_SIZE];
/*^ O,SYS_TIME_INFO_CDMA2000_SYNC_SYS_TIME_PRESENCE_FLAG,OCTET_STRING,FIXED ^*/

    U8  async_sys_time[ASYNC_SYS_TIME_OCTET_SIZE];
/*^ O,SYS_TIME_INFO_CDMA2000_ASYNC_SYS_TIME_PRESENCE_FLAG,OCTET_STRING,FIXED ^*/

}sys_time_info_cdma2000_t;

typedef U16 phys_cell_id_cdma2000_t; /*0,511*/

typedef struct
{
    U8                        count;
/*^ M, 0, B, 1, 16 ^*/

    phys_cell_id_cdma2000_t
        phys_cell_id_cdma2000[MAX_PHYS_CELL_ID_LIST_CDMA2000];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}phys_cell_id_list_cdma2000_t;

typedef U16 arfcn_value_cdma2000_t;

typedef struct
{
    arfcn_value_cdma2000_t         arfcn;         /*^ M, 0, H, 0, 2047 ^*/
    phys_cell_id_list_cdma2000_t   phys_cell_id_list;
}neigh_cells_per_bandclass_cdma2000_t;

typedef struct
{
    U8                                     count;     /*^ M, 0, B, 1, 16 ^*/
    neigh_cells_per_bandclass_cdma2000_t
        neigh_cells_per_bandclass_cdma2000[MAX_NCELLS_PER_BS_LIST_CDMA2000];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}neigh_cells_per_bandclass_list_cdma2000_t;

typedef struct
{
    U8                                         band_class;
/*^ M, 0, H, 0, 31 ^*/   /* rrm_bandclass_cdma2000_et */

    neigh_cells_per_bandclass_list_cdma2000_t  neigh_cells_per_freq_list;
}neigh_cell_cdma2000_t;

typedef struct
{
    U8                       count;        /*^ M, 0, B, 1, 16 ^*/
    neigh_cell_cdma2000_t    neigh_cell_cdma2000[MAX_NEIGH_CELL_LIST_CDMA2000];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}neigh_cell_list_cdma2000_t;

#define BAND_CLASS_INFO_CDMA2000_CELL_RESELECT_PRI_PRESENCE_FLAG  0x01

typedef struct
{
    U16    presence_bitmask;          /*^ BITMASK ^*/
    U8     band_class;
/*^ M, 0, H, 0, 31 ^*/   /* rrm_bandclass_cdma2000_et */

    U8     cell_reselection_priority;
/*^ O, BAND_CLASS_INFO_CDMA2000_CELL_RESELECT_PRI_PRESENCE_FLAG, H, 1, 7 ^*/

    U8     thresh_x_high;             /*^ M, 0, H, 0, 63 ^*/
    U8     thresh_x_low;              /*^ M, 0, H, 0, 63 ^*/
}band_class_info_cdma2000_t;

typedef struct
{
    U8                          count;                  /*^ M, 0, H, 1, 32 ^*/
    band_class_info_cdma2000_t  band_class_info_cdma2000[MAX_CDMA_BAND_CLASS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}band_class_list_cdma2000_t;



#define CELL_RESELECT_CDMA2000_SF_PRESENCE_FLAG 0x01

typedef struct
{
    U16                         presence_bitmask;       /*^ BITMASK ^*/
    band_class_list_cdma2000_t  band_class_list;
    neigh_cell_list_cdma2000_t  neigh_cell_list;
    U8                          t_reselection_cdma2000;    /*^ M, 0, H, 0, 7 ^*/
    speed_state_scale_factors_t t_reselection_cdma2000_sf;
/*^ O, CELL_RESELECT_CDMA2000_SF_PRESENCE_FLAG, N, 0, 0 ^*/

}cell_reselection_params_cdma2000_t;

typedef struct
{
    U8  sid[XRTT_SID_OCTET_SIZE]; /*^ M, 0, OCTET_STRING, FIXED ^*/
    U8  nid[XRTT_NID_OCTET_SIZE]; /*^ M, 0, OCTET_STRING, FIXED ^*/
    U8  multiple_sid;             /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  multiple_nid;             /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  home_reg;                 /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  foreign_sid_reg;          /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  foreign_nid_reg;          /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  parame_reg;               /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  power_up_reg;             /*^ M, 0, H, 0, 1 ^*/     /* rrc_bool_et */
    U8  reg_period[XRTT_REG_PERIOD_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U8  reg_zone[XRTT_REG_ZONE_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U8  total_zone[XRTT_TOTAL_ZONE_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U8  zone_timer[XRTT_ZONE_TIMER_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

}csfb_reg_param_1_xrtt_t;

typedef struct
{
    U8 count;              /*^ M, 0, B, 1, 2 ^*/
    U8 pre_reg_zone_id[2]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}secondary_pre_reg_zone_id_list_hrpd_t;

#define PRE_REG_INFO_HRPD_ZONE_ID_PRESENCE_FLAG         0x01
#define PRE_REG_INFO_HRPD_SECONDARY_LST_PRESENCE_FLAG   0x02

typedef struct
{
    U16                                   presence_bitmask; /*^ BITMASK ^*/
    U8                                    pre_reg_allowed;
/*^ M, 0, H, 0, 1 ^*/    /* rrc_bool_et */

    U8                                    pre_reg_zone_id;
/*^ O, PRE_REG_INFO_HRPD_ZONE_ID_PRESENCE_FLAG, N, 0, 255 ^*/

    secondary_pre_reg_zone_id_list_hrpd_t secondary_list;
/*^ O, PRE_REG_INFO_HRPD_SECONDARY_LST_PRESENCE_FLAG, N, 0, 0 ^*/

}pre_reg_info_hrpd_t;

#define PARAMS_HRPD_CELL_RESELECTION_PARAMS_PRESENCE_FLAG 0x01

typedef struct
{
    U16                                 presence_bitmask;
/*^ BITMASK ^*/

    pre_reg_info_hrpd_t                 pre_reg_info_hrpd;
/*^ M, 0, N, 0, 0 ^*/

    cell_reselection_params_cdma2000_t  cell_reselection_params_hrpd;
/*^ O, PARAMS_HRPD_CELL_RESELECTION_PARAMS_PRESENCE_FLAG, N, 0, 0 ^*/

}params_hrpd_t;

#define CFSB_REG_PARAM_1_XRTT_PRESENCE_FLAG         0x01
#define LONG_CODE_STATE_1_XRTT_PRESENCE_FLAG        0x02
#define CELL_RESELECTION_PARAM_1_XRTT_PRESENCE_FLAG 0x04

typedef struct
{
    U16                                presence_bitmask;
/*^ BITMASK ^*/

    csfb_reg_param_1_xrtt_t            csfb_reg_param_1_xrtt;
/*^ O, CFSB_REG_PARAM_1_XRTT_PRESENCE_FLAG, N, 0, 0 ^*/

    U8                long_code_state_1_xrtt[LONG_CODE_STATE_1_XRTT_OCTET_SIZE];
/*^ O, LONG_CODE_STATE_1_XRTT_PRESENCE_FLAG, OCTET_STRING, FIXED ^*/

    cell_reselection_params_cdma2000_t cell_reselection_params_1_xrtt;
/*^ O, CELL_RESELECTION_PARAM_1_XRTT_PRESENCE_FLAG, N, 0, 0 ^*/

}params_1_xrtt_t;

#define SIB_8_SYS_TIME_INFO_PRESENCE_FLAG     0x01
#define SIB_8_SEARCH_WIN_SIZE_PRESENCE_FLAG   0x02
#define SIB_8_PARAMS_HRPD_PRESENCE_FLAG       0x04
#define SIB_8_PARAMS_1_XRTT_PRESENCE_FLAG     0x08

typedef struct
{
    U16                       presence_bitmask;    /*^ BITMASK ^*/
    sys_time_info_cdma2000_t  sys_time_info;
/*^ O, SIB_8_SYS_TIME_INFO_PRESENCE_FLAG, N, 0, 0 ^*/

    U8                        search_window_size;
/*^ O, SIB_8_SEARCH_WIN_SIZE_PRESENCE_FLAG, H, 0, 15 ^*/

    params_hrpd_t             params_hrpd;
/*^ O, SIB_8_PARAMS_HRPD_PRESENCE_FLAG, N, 0, 0 ^*/

    params_1_xrtt_t           params_1_xrtt;
/*^ O, SIB_8_PARAMS_1_XRTT_PRESENCE_FLAG, N, 0, 0 ^*/

}sib_type_8_Info_t;



#define SIB_9_HNB_ID_PRESENCE_FLAG      0x01

typedef struct /*OM. changed since 331.860*/
{
  U16       presence_bitmask;              /*^ BITMASK ^*/
  U8        size_of_hnb_id;
/*^ O, SIB_9_HNB_ID_PRESENCE_FLAG, H, 1, 48 ^*/

  U8        hnb_id[MAX_HNB_ID_OCTET_SIZE];
/*^ O, SIB_9_HNB_ID_PRESENCE_FLAG, OCTET_STRING, VARIABLE ^*/

}sib_type_9_Info_t;



#define SIB_10_WARN_SEC_INFO_PRESENCE_FLAG      0x01

typedef struct
{
  U16       presence_bitmask;                          /*^ BITMASK ^*/
  U8        msg_id[MSG_ID_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

  U8        serial_number[SERIAL_NUMBER_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

  U8        warning_type[WARNING_TYPE_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

  U8        warning_security_info[SECURITY_INFORMATION_OCTET_SIZE];
/*^ O, 1, OCTET_STRING, FIXED ^*/

}sib_type_10_Info_t;


typedef enum
{
  RRM_RRC_NOT_LAST_SEGMENT,
  RRM_RRC_LAST_SEGMENT

}rrm_warning_msg_segment_type_et;


#define SIB_11_DATA_COD_SCHEME_PRESENCE_FLAG      0x01

typedef struct
{
  U16       presence_bitmask;              /*^ BITMASK ^*/
  U8        msg_id[MSG_ID_OCTET_SIZE];     /*^ M, 0, OCTET_STRING, FIXED ^*/
  U8        serial_number[SERIAL_NUMBER_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

  U8        warning_msg_segment_type;
/*^ M, 0, H, 1, 1 ^*/ /* rrm_warning_msg_segment_type_et */

  U8        warning_msg_segment_num;       /*^ M, 0, H, 1, 63 ^*/
  U8        warning_msg_segment_size;      /*^ M, 0, H, 1, 84 ^*/
  U8        warning_msg_segment[WARNING_MSG_SEGMENT_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

  U8        data_coding_scheme[DATA_CODING_SCHEME_OCTET_SIZE];
/*^ O, SIB_11_DATA_COD_SCHEME_PRESENCE_FLAG, OCTET_STRING, FIXED ^*/

}sib_type_11_Info_t;

typedef enum
{
  RRM_RRC_SSP_0,
  RRM_RRC_SSP_1,
  RRM_RRC_SSP_2,
  RRM_RRC_SSP_3,
  RRM_RRC_SSP_4,
  RRM_RRC_SSP_5,
  RRM_RRC_SSP_6,
  RRM_RRC_SSP_7,
  RRM_RRC_SSP_8
}rrm_ssp_et;
/******************************************************************************
        RRC_RRM_CELL_SETUP_RESP
******************************************************************************/
typedef enum
{
    RRM_RRC_INTERNAL_FAILURE,
    RRM_RRC_LL_CONFIG_FAILURE,
    RRM_RRC_LL_DEL_FAILURE,
    RRM_RRC_UNKNOWN_FAILURE
} rrm_fail_cause_et;


#define CELL_SETUP_RESP_API_FAIL_CAUSE_PRESENCE_FLAG        0x01

typedef struct
{
    U16               presence_bitmask;   /*^ BITMASK ^*/
    rrc_cell_index_t  cell_index;
/*^ M, 0, H, 0, 0 ^*/    /* MAX_NUM_CELLS - 1 */

    U8                response;
/*^ M, 0, H, 0, 1 ^*/    /* rrc_return_et */

    U8                fail_cause;
/*^ O, CELL_SETUP_RESP_API_FAIL_CAUSE_PRESENCE_FLAG, H, 0, 3 ^*/
/* rrm_fail_cause_et */

} rrc_rrm_cell_setup_resp_t;/*^ API,  RRC_RRM_CELL_SETUP_RESP ^*/


/******************************************************************************
 *             RRC_RRM_CELL_RECONFIG_REQ
 ******************************************************************************/

/* BROADCAST INFO PARAM */
typedef struct
{
#define CELL_RECONFIG_REQ_API_MIB_INFO_PRESENCE_FLAG			    0x01
#define CELL_RECONFIG_REQ_API_SIB_1_INFO_PRESENCE_FLAG			    0x02
#define CELL_RECONFIG_REQ_API_SIB_2_INFO_PRESENCE_FLAG			    0x04
#define CELL_RECONFIG_REQ_API_SIB_3_INFO_PRESENCE_FLAG			    0x08
#define CELL_RECONFIG_REQ_API_SIB_4_INFO_PRESENCE_FLAG			    0x10
#define CELL_RECONFIG_REQ_API_SIB_5_INFO_PRESENCE_FLAG          	0x20
#define CELL_RECONFIG_REQ_API_SIB_6_INFO_PRESENCE_FLAG          	0x40
#define CELL_RECONFIG_REQ_API_SIB_7_INFO_PRESENCE_FLAG          	0x80
#define CELL_RECONFIG_REQ_API_SIB_8_INFO_PRESENCE_FLAG          	0x100
#define CELL_RECONFIG_REQ_API_SIB_9_INFO_PRESENCE_FLAG          	0x200
#define CELL_RECONFIG_REQ_API_SIB_10_INFO_PRESENCE_FLAG         	0x400
#define CELL_RECONFIG_REQ_API_SIB_11_INFO_PRESENCE_FLAG         	0x800
  U16 				            presence_bitmask;	/*^ BITMASK ^*/
  mib_info_t			        mib_info;                 	/*^ O, 1, N, 0, 0 ^*/
  sib_type_1_Info_t           	sib_type_1_Info;          	/*^ O, 2, N, 0, 0 ^*/
  sib_type_2_Info_t           	sib_type_2_Info;          	/*^ O, 4, N, 0, 0 ^*/
  sib_type_3_Info_t           	sib_type_3_Info;          	/*^ O, 8, N, 0, 0 ^*/
  sib_type_4_Info_t           	sib_type_4_Info;          	/*^ O, 16, N, 0, 0 ^*/
  sib_type_5_Info_t           	sib_type_5_Info;          	/*^ O, 32, N, 0, 0 ^*/
  sib_type_6_Info_t           	sib_type_6_Info;          	/*^ O, 64, N, 0, 0 ^*/
  sib_type_7_Info_t           	sib_type_7_Info;          	/*^ O, 128, N, 0, 0 ^*/
  sib_type_8_Info_t           	sib_type_8_Info;          	/*^ O, 256, N, 0, 0 ^*/
  sib_type_9_Info_t           	sib_type_9_Info;          	/*^ O, 512, N, 0, 0 ^*/
  sib_type_10_Info_t          	sib_type_10_Info;         	/*^ O, 1024, N, 0, 0 ^*/
  sib_type_11_Info_t          	sib_type_11_Info;         	/*^ O, 2048, N, 0, 0 ^*/
}broadcast_config_info_t;

/*NON BROAD CAST INFO PARAM */
typedef struct
{
#define CELL_RECONFIG_REQ_API_CELL_PARAMETER_INFO_PRESENCE_FLAG			0x01
#define CELL_RECONFIG_REQ_API_SYNC_SIGNAL_INFO_PRESENCE_FLAG			0x02

  U16 				presence_bitmask;	/*^ BITMASK ^*/ 
  rrc_recfg_phy_cell_parameters_t   	cell_parameters;          	/*^ O, 1, N, 0, 0 ^*/
  rrc_phy_sync_signals_t      	sync_signals;             	/*^ O, 2, N, 0, 0 ^*/
}non_broadcast_config_info_t;


#define CELL_RECONFIG_REQ_API_BROADCAST_INFO_PRESENCE_FLAG		0x01
#define CELL_RECONFIG_REQ_API_NON_BROADCAST_INFO_PRESENCE_FLAG	0x02
#define CELL_RECONFIG_REQ_API_SFN_PRESENCE_FLAG		            0x04
typedef struct
{
  U16				                presence_bitmask;       /*^ BITMASK ^*/
  rrc_cell_index_t            	    cell_index;		/*^ M, 0, H, 0, 0 ^*/  /* MAX_NUM_CELLS - 1 */
  broadcast_config_info_t		    broadcast_info;		/*^ O, 1, N , 0 ,0 ^*/
  non_broadcast_config_info_t		non_broadcast_info;	/*^ O, 2, N, 0, 0 ^*/
}rrc_rrm_cell_reconfig_req_t; /*^ API, RRC_RRM_CELL_RECONFIGURE_REQ ^*/


/******************************************************************************
        RRC_RRM_CELL_RECONFIG_RESP
******************************************************************************/

#define CELL_RECONFIG_RESP_API_FAIL_CAUSE_PRESENCE_FLAG        0x01

typedef struct
{
    U16               presence_bitmask;   /*^ BITMASK ^*/
    rrc_cell_index_t  cell_index;
/*^ M, 0, H, 0, 0 ^*/    /* MAX_NUM_CELLS - 1 */

    U8                response;
/*^ M, 0, H, 0, 1 ^*/    /* rrc_return_et */

    U8                fail_cause;
/*^ O, CELL_RECONFIG_RESP_API_FAIL_CAUSE_PRESENCE_FLAG, H, 0, 3 ^*/
/* rrm_fail_cause_et */

} rrc_rrm_cell_reconfig_resp_t;/*^ API,  RRC_RRM_CELL_RECONFIG_RESP ^*/

/******************************************************************************
 *
 *  *             RRC_RRM_CELL_SETUP_REQ
 *
 *   ******************************************************************************/

#define CELL_SETUP_REQ_API_SIB_3_INFO_PRESENCE_FLAG             0x01
#define CELL_SETUP_REQ_API_SIB_4_INFO_PRESENCE_FLAG             0x02
#define CELL_SETUP_REQ_API_SIB_5_INFO_PRESENCE_FLAG             0x04
#define CELL_SETUP_REQ_API_SIB_6_INFO_PRESENCE_FLAG             0x08
#define CELL_SETUP_REQ_API_SIB_7_INFO_PRESENCE_FLAG             0x10
#define CELL_SETUP_REQ_API_SIB_8_INFO_PRESENCE_FLAG             0x20
#define CELL_SETUP_REQ_API_SIB_9_INFO_PRESENCE_FLAG             0x40
#define CELL_SETUP_REQ_API_SIB_10_INFO_PRESENCE_FLAG            0x80
#define CELL_SETUP_REQ_API_SIB_11_INFO_PRESENCE_FLAG            0x100


typedef struct
{
  U16                         presence_bitmask;         /*^ BITMASK ^*/
  rrc_cell_index_t            cell_index;
/*^ M, 0, H, 0, 0 ^*/  /* MAX_NUM_CELLS - 1 */

  mib_info_t                  mib_info;                 /*^ M, 0, N, 0, 0 ^*/
  sib_type_1_Info_t           sib_type_1_Info;          /*^ M, 0, N, 0, 0 ^*/
  sib_type_2_Info_t           sib_type_2_Info;          /*^ M, 0, N, 0, 0 ^*/
  sib_type_3_Info_t           sib_type_3_Info;          /*^ O, 1, N, 0, 0 ^*/
  sib_type_4_Info_t           sib_type_4_Info;          /*^ O, 2, N, 0, 0 ^*/
  sib_type_5_Info_t           sib_type_5_Info;          /*^ O, 4, N, 0, 0 ^*/
  sib_type_6_Info_t           sib_type_6_Info;          /*^ O, 8, N, 0, 0 ^*/
  sib_type_7_Info_t           sib_type_7_Info;          /*^ O, 16, N, 0, 0 ^*/
  sib_type_8_Info_t           sib_type_8_Info;          /*^ O, 32, N, 0, 0 ^*/
  sib_type_9_Info_t           sib_type_9_Info;          /*^ O, 64, N, 0, 0 ^*/
  sib_type_10_Info_t          sib_type_10_Info;         /*^ O, 128, N, 0, 0 ^*/
  sib_type_11_Info_t          sib_type_11_Info;         /*^ O, 256, N, 0, 0 ^*/
  rrc_rrm_cell_config_t       cell_config_param;        /*^ M, 0, N, 0, 0 ^*/
}rrc_rrm_cell_setup_req_t; /*^ API, RRC_RRM_CELL_SETUP_REQ ^*/

/******************************************************************************
            RRC_RRM_UE_ADMISSION_REQ
******************************************************************************/
/* TS 36.331 - 6.3.6 S-TMSI IE*/
typedef struct
{
  U8        mmec[MME_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

  U8        m_tmsi[M_TMSI_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

} rrc_s_tmsi_t;

/* TS 36.331 - 6.2.2 RRCConnectionrequest message InitialUE-Identity IE*/
typedef struct
{

    U16           bitmask;       /*^ BITMASK ^*/
#define RRC_INITIAL_UE_IDENTITY_S_TMSI_PRESENT        0x01
#define RRC_INITIAL_UE_IDENTITY_RANDOM_VALUE_PRESENT  0x02

    rrc_s_tmsi_t    s_tmsi;
/*^ O, RRC_INITIAL_UE_IDENTITY_S_TMSI_PRESENT ^*/

    U8        random_value[STMSI_RANDOM_VALUE_OCTET_SIZE];
/*^ O, RRC_INITIAL_UE_IDENTITY_RANDOM_VALUE_PRESENT, OCTET_STRING, FIXED ^*/

} rrc_initial_ue_identity_t;

/* TS 36.331 - 6.2.2 RRCConnectionrequest message EstablishmentCause IE*/
typedef enum
{
  RRC_ESTAB_CAUSE_EMERGENCY,
  RRC_ESTAB_CAUSE_HIGHPRIORITY_ACCESS,
  RRC_ESTAB_CAUSE_MT_ACCESS,
  RRC_ESTAB_CAUSE_MO_SIGNALLING,
  RRC_ESTAB_CAUSE_MO_DATA
} rrc_establishment_cause_et;

typedef struct
{
  U16                           ue_index;
  rrc_initial_ue_identity_t     ue_identity;  /*^ M, 0, N, 0, 0 ^*/
  U8                            establishment_cause;
/*^ M, 0, H, 1, 4 ^*/ /* rrc_establishment_cause_et */

} rrc_rrm_ue_admission_req_t; /*^ API, RRC_RRM_UE_ADMISSION_REQ ^*/

/******************************************************************************
    TS 36.331 - 6.3.2 RLC-Config IE
******************************************************************************/
typedef enum
{
  RRC_POLL_RETRAS_MS_5,
  RRC_POLL_RETRAS_MS_10,
  RRC_POLL_RETRAS_MS_15,
  RRC_POLL_RETRAS_MS_20,
  RRC_POLL_RETRAS_MS_25,
  RRC_POLL_RETRAS_MS_30,
  RRC_POLL_RETRAS_MS_35,
  RRC_POLL_RETRAS_MS_40,
  RRC_POLL_RETRAS_MS_45,
  RRC_POLL_RETRAS_MS_50,
  RRC_POLL_RETRAS_MS_55,
  RRC_POLL_RETRAS_MS_60,
  RRC_POLL_RETRAS_MS_65,
  RRC_POLL_RETRAS_MS_70,
  RRC_POLL_RETRAS_MS_75,
  RRC_POLL_RETRAS_MS_80,
  RRC_POLL_RETRAS_MS_85,
  RRC_POLL_RETRAS_MS_90,
  RRC_POLL_RETRAS_MS_95,
  RRC_POLL_RETRAS_MS_100,
  RRC_POLL_RETRAS_MS_105,
  RRC_POLL_RETRAS_MS_110,
  RRC_POLL_RETRAS_MS_115,
  RRC_POLL_RETRAS_MS_120,
  RRC_POLL_RETRAS_MS_125,
  RRC_POLL_RETRAS_MS_130,
  RRC_POLL_RETRAS_MS_135,
  RRC_POLL_RETRAS_MS_140,
  RRC_POLL_RETRAS_MS_145,
  RRC_POLL_RETRAS_MS_150,
  RRC_POLL_RETRAS_MS_155,
  RRC_POLL_RETRAS_MS_160,
  RRC_POLL_RETRAS_MS_165,
  RRC_POLL_RETRAS_MS_170,
  RRC_POLL_RETRAS_MS_175,
  RRC_POLL_RETRAS_MS_180,
  RRC_POLL_RETRAS_MS_185,
  RRC_POLL_RETRAS_MS_190,
  RRC_POLL_RETRAS_MS_195,
  RRC_POLL_RETRAS_MS_200,
  RRC_POLL_RETRAS_MS_205,
  RRC_POLL_RETRAS_MS_210,
  RRC_POLL_RETRAS_MS_215,
  RRC_POLL_RETRAS_MS_220,
  RRC_POLL_RETRAS_MS_225,
  RRC_POLL_RETRAS_MS_230,
  RRC_POLL_RETRAS_MS_235,
  RRC_POLL_RETRAS_MS_240,
  RRC_POLL_RETRAS_MS_245,
  RRC_POLL_RETRAS_MS_250,
  RRC_POLL_RETRAS_MS_300,
  RRC_POLL_RETRAS_MS_350,
  RRC_POLL_RETRAS_MS_400,
  RRC_POLL_RETRAS_MS_450,
  RRC_POLL_RETRAS_MS_500
}rrc_t_poll_retransmit_et;

typedef enum
{
  RRC_POLL_PDU_4,
  RRC_POLL_PDU_8,
  RRC_POLL_PDU_16,
  RRC_POLL_PDU_32,
  RRC_POLL_PDU_64,
  RRC_POLL_PDU_128,
  RRC_POLL_PDU_256,
  RRC_POLL_PDU_INFINITY
}rrc_poll_pdu_et;

typedef enum
{
  RRC_POLL_BYTE_KB_25,
  RRC_POLL_BYTE_KB_50,
  RRC_POLL_BYTE_KB_75,
  RRC_POLL_BYTE_KB_100,
  RRC_POLL_BYTE_KB_125,
  RRC_POLL_BYTE_KB_250,
  RRC_POLL_BYTE_KB_375,
  RRC_POLL_BYTE_KB_500,
  RRC_POLL_BYTE_KB_750,
  RRC_POLL_BYTE_KB_1000,
  RRC_POLL_BYTE_KB_1250,
  RRC_POLL_BYTE_KB_1500,
  RRC_POLL_BYTE_KB_2000,
  RRC_POLL_BYTE_KB_3000,
  RRC_POLL_BYTE_KB_INFINITY
}rrc_poll_byte_et;

typedef enum
{
  RRC_MAX_RETRANS_THRESH_1,
  RRC_MAX_RETRANS_THRESH_2,
  RRC_MAX_RETRANS_THRESH_3,
  RRC_MAX_RETRANS_THRESH_4,
  RRC_MAX_RETRANS_THRESH_6,
  RRC_MAX_RETRANS_THRESH_8,
  RRC_MAX_RETRANS_THRESH_16,
  RRC_MAX_RETRANS_THRESH_32
}rrc_max_retx_threshold_et;

typedef struct
{
  U8        t_poll_retransmit;
/*^ M, 0, H, 1, 54 ^*/      /* rrc_t_poll_retransmit_et */

  U8        poll_pdu;
/*^ M, 0, H, 1, 7 ^*/       /* rrc_poll_pdu_et */

  U8        poll_byte;
/*^ M, 0, H, 1, 14 ^*/      /* rrc_poll_byte_et */

  U8        max_retx_threshold;
/*^ M, 0, H, 1, 7 ^*/       /* rrc_max_retx_threshold_et */

} rrc_uplink_am_rlc_t;

typedef enum
{
  RRC_T_REORDER_MS_0,
  RRC_T_REORDER_MS_5,
  RRC_T_REORDER_MS_10,
  RRC_T_REORDER_MS_15,
  RRC_T_REORDER_MS_20,
  RRC_T_REORDER_MS_25,
  RRC_T_REORDER_MS_30,
  RRC_T_REORDER_MS_35,
  RRC_T_REORDER_MS_40,
  RRC_T_REORDER_MS_45,
  RRC_T_REORDER_MS_50,
  RRC_T_REORDER_MS_55,
  RRC_T_REORDER_MS_60,
  RRC_T_REORDER_MS_65,
  RRC_T_REORDER_MS_70,
  RRC_T_REORDER_MS_75,
  RRC_T_REORDER_MS_80,
  RRC_T_REORDER_MS_85,
  RRC_T_REORDER_MS_90,
  RRC_T_REORDER_MS_95,
  RRC_T_REORDER_MS_100,
  RRC_T_REORDER_MS_110,
  RRC_T_REORDER_MS_120,
  RRC_T_REORDER_MS_130,
  RRC_T_REORDER_MS_140,
  RRC_T_REORDER_MS_150,
  RRC_T_REORDER_MS_160,
  RRC_T_REORDER_MS_170,
  RRC_T_REORDER_MS_180,
  RRC_T_REORDER_MS_190,
  RRC_T_REORDER_MS_200
}rrc_t_reordering_et;

typedef enum
{
  RRC_T_STATUS_PROHB_MS_0,
  RRC_T_STATUS_PROHB_MS_5,
  RRC_T_STATUS_PROHB_MS_10,
  RRC_T_STATUS_PROHB_MS_15,
  RRC_T_STATUS_PROHB_MS_20,
  RRC_T_STATUS_PROHB_MS_25,
  RRC_T_STATUS_PROHB_MS_30,
  RRC_T_STATUS_PROHB_MS_35,
  RRC_T_STATUS_PROHB_MS_40,
  RRC_T_STATUS_PROHB_MS_45,
  RRC_T_STATUS_PROHB_MS_50,
  RRC_T_STATUS_PROHB_MS_55,
  RRC_T_STATUS_PROHB_MS_60,
  RRC_T_STATUS_PROHB_MS_65,
  RRC_T_STATUS_PROHB_MS_70,
  RRC_T_STATUS_PROHB_MS_75,
  RRC_T_STATUS_PROHB_MS_80,
  RRC_T_STATUS_PROHB_MS_85,
  RRC_T_STATUS_PROHB_MS_90,
  RRC_T_STATUS_PROHB_MS_95,
  RRC_T_STATUS_PROHB_MS_100,
  RRC_T_STATUS_PROHB_MS_105,
  RRC_T_STATUS_PROHB_MS_110,
  RRC_T_STATUS_PROHB_MS_115,
  RRC_T_STATUS_PROHB_MS_120,
  RRC_T_STATUS_PROHB_MS_125,
  RRC_T_STATUS_PROHB_MS_130,
  RRC_T_STATUS_PROHB_MS_135,
  RRC_T_STATUS_PROHB_MS_140,
  RRC_T_STATUS_PROHB_MS_145,
  RRC_T_STATUS_PROHB_MS_150,
  RRC_T_STATUS_PROHB_MS_155,
  RRC_T_STATUS_PROHB_MS_160,
  RRC_T_STATUS_PROHB_MS_165,
  RRC_T_STATUS_PROHB_MS_170,
  RRC_T_STATUS_PROHB_MS_175,
  RRC_T_STATUS_PROHB_MS_180,
  RRC_T_STATUS_PROHB_MS_185,
  RRC_T_STATUS_PROHB_MS_190,
  RRC_T_STATUS_PROHB_MS_195,
  RRC_T_STATUS_PROHB_MS_200,
  RRC_T_STATUS_PROHB_MS_205,
  RRC_T_STATUS_PROHB_MS_210,
  RRC_T_STATUS_PROHB_MS_215,
  RRC_T_STATUS_PROHB_MS_220,
  RRC_T_STATUS_PROHB_MS_225,
  RRC_T_STATUS_PROHB_MS_230,
  RRC_T_STATUS_PROHB_MS_235,
  RRC_T_STATUS_PROHB_MS_240,
  RRC_T_STATUS_PROHB_MS_245,
  RRC_T_STATUS_PROHB_MS_250,
  RRC_T_STATUS_PROHB_MS_300,
  RRC_T_STATUS_PROHB_MS_350,
  RRC_T_STATUS_PROHB_MS_400,
  RRC_T_STATUS_PROHB_MS_450,
  RRC_T_STATUS_PROHB_MS_500
} rrc_t_status_prohibit_et;

typedef struct
{
  U8        t_reordering;
/*^ M, 0, H, 1, 30 ^*/  /* rrc_t_reordering_et */

  U8        t_status_prohibit;
/*^ M, 0, H, 1, 55 ^*/  /* rrc_t_status_prohibit_et */

} rrc_downlink_am_rlc_t;

typedef struct
{
    rrc_uplink_am_rlc_t        ul_am_rlc;
    rrc_downlink_am_rlc_t      dl_am_rlc;
} rrc_am_config_t;

typedef enum
{
  RRC_SN_FIELD_LEN_5,
  RRC_SN_FIELD_LEN_10
} rrc_sn_field_length_et;

typedef struct
{
    U8        sn_field_length;
/*^ M, 0, H, 0, 1 ^*/  /* rrc_sn_field_length_et */

    U8        t_reordering;    /*^ M, 0, H, 1, 30 ^*/ /* rrc_t_reordering_et */
} rrc_downlink_um_rlc_t;

typedef struct
{
    U8        sn_field_length;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_sn_field_length_et */

} rrc_uplink_um_rlc_t;

typedef struct
{
    rrc_uplink_um_rlc_t        ul_um_rlc;
    rrc_downlink_um_rlc_t      dl_um_rlc;
} rrc_um_bi_directional_config_t;

typedef struct
{
    rrc_uplink_um_rlc_t        ul_um_rlc;
} rrc_um_uni_directional_ul_config_t;

typedef struct
{
    rrc_downlink_um_rlc_t      dl_um_rlc;
} rrc_um_uni_directional_dl_config_t;

typedef struct
{
  U16                 bitmask;   /*^ BITMASK ^*/
#define RRC_RLC_CONFIG_AM_CONFIG_PRESENT                        0x01
#define RRC_RLC_CONFIG_UM_BI_DIRECTIONAL_CONFIG_PRESENT         0x02
#define RRC_RLC_CONFIG_UM_UNI_DIRECTIONAL_CONFIG_UL_PRESENT     0x04
#define RRC_RLC_CONFIG_UM_UNI_DIRECTIONAL_CONFIG_DL_PRESENT     0x08

  rrc_am_config_t                       am_config;
/*^ O, RRC_RLC_CONFIG_AM_CONFIG_PRESENT ^*/

  rrc_um_bi_directional_config_t        um_bi_directional_config;
/*^ O, RRC_RLC_CONFIG_UM_BI_DIRECTIONAL_CONFIG_PRESENT ^*/

  rrc_um_uni_directional_ul_config_t    um_uni_directional_ul_config;
/*^ O, RRC_RLC_CONFIG_UM_UNI_DIRECTIONAL_CONFIG_UL_PRESENT ^*/

  rrc_um_uni_directional_dl_config_t    um_uni_directional_dl_config;
/*^ O, RRC_RLC_CONFIG_UM_UNI_DIRECTIONAL_CONFIG_DL_PRESENT ^*/

} rrc_rlc_config_t;

/******************************************************************************
    TS 36.331 - 6.3.2 LogicalChannelConfig IE
******************************************************************************/
typedef enum
{
  RRC_BIT_RATE_KBPS_0,
  RRC_BIT_RATE_KBPS_8,
  RRC_BIT_RATE_KBPS_16,
  RRC_BIT_RATE_KBPS_32,
  RRC_BIT_RATE_KBPS_64,
  RRC_BIT_RATE_KBPS_128,
  RRC_BIT_RATE_KBPS_256,
  RRC_BIT_RATE_INFINITY
}rrc_prioritized_bit_rate_et;

typedef enum
{
  RRC_BUCKET_SIZE_MS_50,
  RRC_BUCKET_SIZE_MS_100,
  RRC_BUCKET_SIZE_MS_150,
  RRC_BUCKET_SIZE_MS_300,
  RRC_BUCKET_SIZE_MS_500,
  RRC_BUCKET_SIZE_MS_1000
}rrc_bucket_size_duration_et;

typedef struct
{
  U16           bitmask;       /*^ BITMASK ^*/
#define RRC_UL_SPECIFIC_PARAMETERS_LOGICAL_CH_GROUP_PRESENT        0x01

  U8            priority;               /*^ M, 0, H, 1, 16 ^*/
  U8            prioritized_bit_rate;
/*^ M, 0, H, 1, 7 ^*/  /* rrc_prioritized_bit_rate_et */

  U8            bucket_size_duration;
/*^ M, 0, H, 1, 5 ^*/  /* rrc_bucket_size_duration_et */

  U8            logical_channel_group;
/*^ O, RRC_UL_SPECIFIC_PARAMETERS_LOGICAL_CH_GROUP_PRESENT, H, 1, 3 ^*/

} rrc_ul_specific_parameters_t;

/******************************************************************************
    TS 36.331 - 6.3.2 MAC-MainConfig IE
******************************************************************************/
typedef enum
{
  RRC_MAX_HARQ_TX_N_1,
  RRC_MAX_HARQ_TX_N_2,
  RRC_MAX_HARQ_TX_N_3,
  RRC_MAX_HARQ_TX_N_4,
  RRC_MAX_HARQ_TX_N_5,
  RRC_MAX_HARQ_TX_N_6,
  RRC_MAX_HARQ_TX_N_7,
  RRC_MAX_HARQ_TX_N_8,
  RRC_MAX_HARQ_TX_N_10,
  RRC_MAX_HARQ_TX_N_12,
  RRC_MAX_HARQ_TX_N_16,
  RRC_MAX_HARQ_TX_N_20,
  RRC_MAX_HARQ_TX_N_24,
  RRC_MAX_HARQ_TX_N_28
} rrc_max_harq_tx_et;

typedef enum
{
  RRC_PERIODIC_BSR_TIMER_SF_5,
  RRC_PERIODIC_BSR_TIMER_SF_10,
  RRC_PERIODIC_BSR_TIMER_SF_16,
  RRC_PERIODIC_BSR_TIMER_SF_20,
  RRC_PERIODIC_BSR_TIMER_SF_32,
  RRC_PERIODIC_BSR_TIMER_SF_40,
  RRC_PERIODIC_BSR_TIMER_SF_64,
  RRC_PERIODIC_BSR_TIMER_SF_80,
  RRC_PERIODIC_BSR_TIMER_SF_128,
  RRC_PERIODIC_BSR_TIMER_SF_160,
  RRC_PERIODIC_BSR_TIMER_SF_320,
  RRC_PERIODIC_BSR_TIMER_SF_640,
  RRC_PERIODIC_BSR_TIMER_SF_1280,
  RRC_PERIODIC_BSR_TIMER_SF_2560,
  RRC_PERIODIC_BSR_TIMER_INFINITY
}rrc_periodic_bsr_timer_et;

typedef enum
{
  RRC_RETX_BSR_TIMER_SF_320,
  RRC_RETX_BSR_TIMER_SF_640,
  RRC_RETX_BSR_TIMER_SF_1280,
  RRC_RETX_BSR_TIMER_SF_2560,
  RRC_RETX_BSR_TIMER_SF_5120,
  RRC_RETX_BSR_TIMER_SF_10240
}rrc_retx_bsr_timer_et;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/
#define RRC_UL_SCH_CONFIG_MAX_HARQ_TX_PRESENT          0x01
#define RRC_UL_SCH_CONFIG_PERIODIC_BSR_TIMER_PRESENT   0x02

  U8                    max_harq_tx;
/*^ O, RRC_UL_SCH_CONFIG_MAX_HARQ_TX_PRESENT, H, 1, 13 ^*/
/* rrc_max_harq_tx_et */

  U8                    periodic_bsr_timer;
/*^ O, RRC_UL_SCH_CONFIG_PERIODIC_BSR_TIMER_PRESENT, H, 1, 14 ^*/
/* rrc_periodic_bsr_timer_et */

  U8                    retx_bsr_timer;
/*^ M, 0, H, 1, 7 ^*/ /* rrc_retx_bsr_timer_et */

  U8                    tti_bounding;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_bool_et */

}rrc_ul_sch_config_t;

typedef enum
{
   RRC_ON_DURATION_TIMER_PSF_1,
   RRC_ON_DURATION_TIMER_PSF_2,
   RRC_ON_DURATION_TIMER_PSF_3,
   RRC_ON_DURATION_TIMER_PSF_4,
   RRC_ON_DURATION_TIMER_PSF_5,
   RRC_ON_DURATION_TIMER_PSF_6,
   RRC_ON_DURATION_TIMER_PSF_8,
   RRC_ON_DURATION_TIMER_PSF_10,
   RRC_ON_DURATION_TIMER_PSF_20,
   RRC_ON_DURATION_TIMER_PSF_30,
   RRC_ON_DURATION_TIMER_PSF_40,
   RRC_ON_DURATION_TIMER_PSF_50,
   RRC_ON_DURATION_TIMER_PSF_60,
   RRC_ON_DURATION_TIMER_PSF_80,
   RRC_ON_DURATION_TIMER_PSF_100,
   RRC_ON_DURATION_TIMER_PSF_200
}rrc_on_duration_timer_et;

typedef enum
{
   RRC_DRX_INACTIVITY_TIMER_PSF_1,
   RRC_DRX_INACTIVITY_TIMER_PSF_2,
   RRC_DRX_INACTIVITY_TIMER_PSF_3,
   RRC_DRX_INACTIVITY_TIMER_PSF_4,
   RRC_DRX_INACTIVITY_TIMER_PSF_5,
   RRC_DRX_INACTIVITY_TIMER_PSF_6,
   RRC_DRX_INACTIVITY_TIMER_PSF_8,
   RRC_DRX_INACTIVITY_TIMER_PSF_10,
   RRC_DRX_INACTIVITY_TIMER_PSF_20,
   RRC_DRX_INACTIVITY_TIMER_PSF_30,
   RRC_DRX_INACTIVITY_TIMER_PSF_40,
   RRC_DRX_INACTIVITY_TIMER_PSF_50,
   RRC_DRX_INACTIVITY_TIMER_PSF_60,
   RRC_DRX_INACTIVITY_TIMER_PSF_80,
   RRC_DRX_INACTIVITY_TIMER_PSF_100,
   RRC_DRX_INACTIVITY_TIMER_PSF_200,
   RRC_DRX_INACTIVITY_TIMER_PSF_300,
   RRC_DRX_INACTIVITY_TIMER_PSF_500,
   RRC_DRX_INACTIVITY_TIMER_PSF_750,
   RRC_DRX_INACTIVITY_TIMER_PSF_1280,
   RRC_DRX_INACTIVITY_TIMER_PSF_1920,
   RRC_DRX_INACTIVITY_TIMER_PSF_2560
}rrc_drx_inactivity_timer_et;

typedef enum
{
   RRC_DRX_RETRANS_TIMER_PSF_1,
   RRC_DRX_RETRANS_TIMER_PSF_2,
   RRC_DRX_RETRANS_TIMER_PSF_4,
   RRC_DRX_RETRANS_TIMER_PSF_6,
   RRC_DRX_RETRANS_TIMER_PSF_8,
   RRC_DRX_RETRANS_TIMER_PSF_16,
   RRC_DRX_RETRANS_TIMER_PSF_24,
   RRC_DRX_RETRANS_TIMER_PSF_33
}rrc_drx_retransmission_timer_et;

typedef struct
{
  U16           bitmask;    /*^ BITMASK ^*/
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_10_PRESENT         0x01
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_20_PRESENT         0x02
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_32_PRESENT         0x04
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_40_PRESENT         0x08
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_64_PRESENT         0x10
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_80_PRESENT         0x20
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_128_PRESENT        0x40
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_160_PRESENT        0x80
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_256_PRESENT        0x100
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_320_PRESENT        0x200
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_512_PRESENT        0x400
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_640_PRESENT        0x800
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_1024_PRESENT       0x1000
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_1280_PRESENT       0x2000
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_2048_PRESENT       0x4000
#define RRC_LONG_DRX_CYCLE_START_OFFSET_SF_2560_PRESENT       0x8000
  U8            sf_10;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_10_PRESENT, H, 1, 9 ^*/

  U8            sf_20;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_20_PRESENT, H, 1, 19 ^*/

  U8            sf_32;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_32_PRESENT, H, 1, 31 ^*/

  U8            sf_40;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_40_PRESENT, H, 1, 39 ^*/

  U8            sf_64;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_64_PRESENT, H, 1, 63 ^*/

  U8            sf_80;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_80_PRESENT, H, 1, 79 ^*/

  U8            sf_128;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_128_PRESENT, H, 1, 127 ^*/

  U8            sf_160;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_160_PRESENT, H, 1, 159 ^*/

  U8            sf_256;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_256_PRESENT, N, 0, 0 ^*/

  U16           sf_320;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_320_PRESENT, H, 1, 319 ^*/

  U16           sf_512;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_512_PRESENT, H, 1, 511 ^*/

  U16           sf_640;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_640_PRESENT, H, 1, 639 ^*/

  U16           sf_1024;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_1024_PRESENT, H, 1, 1023 ^*/

  U16           sf_1280;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_1280_PRESENT, H, 1, 1279 ^*/

  U16           sf_2048;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_2048_PRESENT, H, 1, 2047 ^*/

  U16           sf_2560;
/*^ O, RRC_LONG_DRX_CYCLE_START_OFFSET_SF_2560_PRESENT, H, 1, 2559 ^*/

}rrc_long_drx_cycle_start_offset_t;

typedef enum
{
  RRC_SHORT_DRX_CYCLE_SF_2,
  RRC_SHORT_DRX_CYCLE_SF_5,
  RRC_SHORT_DRX_CYCLE_SF_8,
  RRC_SHORT_DRX_CYCLE_SF_10,
  RRC_SHORT_DRX_CYCLE_SF_16,
  RRC_SHORT_DRX_CYCLE_SF_20,
  RRC_SHORT_DRX_CYCLE_SF_32,
  RRC_SHORT_DRX_CYCLE_SF_40,
  RRC_SHORT_DRX_CYCLE_SF_64,
  RRC_SHORT_DRX_CYCLE_SF_80,
  RRC_SHORT_DRX_CYCLE_SF_128,
  RRC_SHORT_DRX_CYCLE_SF_160,
  RRC_SHORT_DRX_CYCLE_SF_256,
  RRC_SHORT_DRX_CYCLE_SF_320,
  RRC_SHORT_DRX_CYCLE_SF_512,
  RRC_SHORT_DRX_CYCLE_SF_640
} rrc_short_drx_cycle_et;

typedef struct
{
  U8        short_drx_cycle;
/*^ M, 0, H, 1, 15 ^*/  /* rrc_short_drx_cycle_et */

  U8        short_drx_cycle_timer;  /*^ M, 0, B, 1, 16 ^*/
}rrc_short_drx_t;

typedef struct
{
  rrc_bitmask_t               bitmask;      /*^ BITMASK ^*/
#define RRC_DRX_CONFIG_SHORT_DRX_PRESENT            0x01

  U8                on_duration_timer;
/*^ M, 0, H, 1, 15 ^*/    /* rrc_on_duration_timer_et */

  U8                drx_inactivity_timer;
/*^ M, 0, H, 1, 21 ^*/   /* rrc_drx_inactivity_timer_et */

  U8                drx_retransmission_timer;
/*^ M, 0, H, 1, 7 ^*/   /* rrc_drx_retransmission_timer_et */

  rrc_long_drx_cycle_start_offset_t        long_drx_cycle_start_offset;

  rrc_short_drx_t   short_drx;
/*^ O, RRC_DRX_CONFIG_SHORT_DRX_PRESENT ^*/

} rrc_drx_config_param_t;

/* The Release action should be supported for DRX-Config IE*/
typedef struct
{
  rrc_bitmask_t bitmask;    /*^ BITMASK ^*/
#define RRC_DRX_CONFIG_PARAM_PRESENT    0x01

  rrc_drx_config_param_t    drx_config_param;
/*^ O, RRC_DRX_CONFIG_PARAM_PRESENT ^*/

} rrc_drx_config_t;

typedef enum
{
  RRC_PERIOD_PHR_TIMER_SF_10,
  RRC_PERIOD_PHR_TIMER_SF_20,
  RRC_PERIOD_PHR_TIMER_SF_50,
  RRC_PERIOD_PHR_TIMER_SF_100,
  RRC_PERIOD_PHR_TIMER_SF_200,
  RRC_PERIOD_PHR_TIMER_SF_500,
  RRC_PERIOD_PHR_TIMER_SF_1000,
  RRC_PERIOD_PHR_TIMER_INFINITY
} rrc_periodic_phr_timer_et;

typedef enum
{
  RRC_PROHB_PHR_TIMER_SF_0,
  RRC_PROHB_PHR_TIMER_SF_10,
  RRC_PROHB_PHR_TIMER_SF_20,
  RRC_PROHB_PHR_TIMER_SF_50,
  RRC_PROHB_PHR_TIMER_SF_100,
  RRC_PROHB_PHR_TIMER_SF_200,
  RRC_PROHB_PHR_TIMER_SF_500,
  RRC_PROHB_PHR_TIMER_SF_1000
} rrc_prohibit_phr_timer_et;

typedef enum
{
  RRC_DL_PATHLOSS_CHANGE_DB_1,
  RRC_DL_PATHLOSS_CHANGE_DB_3,
  RRC_DL_PATHLOSS_CHANGE_DB_6,
  RRC_DL_PATHLOSS_CHANGE_INFINITY
} rrc_dl_pathloss_change_et;

typedef struct
{
  U8        periodic_phr_timer;
/*^ M, 0, H, 1, 7 ^*/      /* rrc_periodic_phr_timer_et */

  U8        prohibit_phr_timer;
/*^ M, 0, H, 1, 7 ^*/      /* rrc_prohibit_phr_timer_et */

  U8        dl_pathloss_change;
/*^ M, 0, H, 1, 3 ^*/      /* rrc_dl_pathloss_change_et */

} rrc_phr_config_param_t;

/* The Release action should be supported for phr-Config IE*/
typedef struct
{
  rrc_bitmask_t bitmask;    /*^ BITMASK ^*/
#define RRC_PHR_CONFIG_PARAM_PRESENT    0x01

  rrc_phr_config_param_t phr_config_param;
/*^ O, RRC_PHR_CONFIG_PARAM_PRESENT ^*/

} rrc_phr_config_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/
#define RRC_MAC_MAIN_CONFIG_UL_SCH_CONFIG_PRESENT        0x01
#define RRC_MAC_MAIN_CONFIG_DRX_CONFIG_PRESENT           0x02
#define RRC_MAC_MAIN_CONFIG_PHR_CONFIG_PRESENT           0x04

  rrc_ul_sch_config_t   ul_sch_config;
/*^ O, RRC_MAC_MAIN_CONFIG_UL_SCH_CONFIG_PRESENT ^*/

  rrc_drx_config_t      drx_config;
/*^ O, RRC_MAC_MAIN_CONFIG_DRX_CONFIG_PRESENT ^*/

  U8                    time_alignment_timer_dedicated;
/*^ M, 0, H, 1, 7 ^*/ /* rrm_time_align_timer_et */

  rrc_phr_config_t      phr_config;
/*^ O, RRC_MAC_MAIN_CONFIG_PHR_CONFIG_PRESENT ^*/

} rrc_mac_main_config_t;

/******************************************************************************
    TS 36.331 - 6.3.2 SPS-Config IE
******************************************************************************/

typedef enum
{

  RRC_SEMI_PERSIST_INT_SF_10,
  RRC_SEMI_PERSIST_INT_SF_20,
  RRC_SEMI_PERSIST_INT_SF_32,
  RRC_SEMI_PERSIST_INT_SF_40,
  RRC_SEMI_PERSIST_INT_SF_64,
  RRC_SEMI_PERSIST_INT_SF_80,
  RRC_SEMI_PERSIST_INT_SF_128,
  RRC_SEMI_PERSIST_INT_SF_160,
  RRC_SEMI_PERSIST_INT_SF_320,
  RRC_SEMI_PERSIST_INT_SF_640
} rrc_semi_persist_sched_interval_et;

typedef enum
{
  RRC_IMPLICIT_RELEASE_E_2,
  RRC_IMPLICIT_RELEASE_E_3,
  RRC_IMPLICIT_RELEASE_E_4,
  RRC_IMPLICIT_RELEASE_E_8
} rrc_implicit_release_after_et;

typedef struct
{
  U8                    count;      /*^ M, 0, B, 1, 4 ^*/
  U16 n1_pucch_an_persist[MAX_N1_PUCCH_AN_PERSIST_SIZE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}rrc_n1_pucch_an_persist_list_t;

typedef struct
{
  U8        semi_persist_sched_interval_dl;
/*^ M, 0, H, 0, 9 ^*/  /* rrc_semi_persist_sched_interval_et */

  U8        number_of_conf_sps_processes;       /*^ M, 0, B, 1, 8 ^*/
  rrc_n1_pucch_an_persist_list_t  n1_pucch_an_persist_list;
}rrc_sps_config_dl_param_t;

typedef struct
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_SPS_CONFIG_DL_PARAM_PRESENT 0x01

    rrc_sps_config_dl_param_t     sps_config_dl_param;
/*^ O, RRC_SPS_CONFIG_DL_PARAM_PRESENT ^*/

} rrc_sps_config_dl_t;

typedef struct
{
  S8        p_zero_nominal_pusch_persistent;    /*^ M, 0, B, -126, 24 ^*/
  S8        p_zero_ue_pusch_persistent;         /*^ M, 0, B, -8, 7 ^*/
} rrc_p_zero_persistent_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/
#define RRC_SPS_CONFIG_UL_P_0_PERSISTENT_PRESENT                0x01
#define RRC_SPS_CONFIG_UL_TWO_INTERVALS_CONFIG_PRESENT          0x02

  U8          semi_persist_sched_interval_ul;
/*^ M, 0, H, 0, 9 ^*/  /* rrc_semi_persist_sched_interval_et */

  U8          implicit_release_after;
/*^ M, 0, H, 0, 3 ^*/  /* rrc_implicit_release_after_et */

  rrc_p_zero_persistent_t   p_zero_persistent;
/*^ O, RRC_SPS_CONFIG_UL_P_0_PERSISTENT_PRESENT ^*/

  U8          two_intervals_config;
/*^ O, RRC_SPS_CONFIG_UL_TWO_INTERVALS_CONFIG_PRESENT ^*/
/* TODO:
   This is just a flag and it's value is not used, only bitmask matters.
   In future version we can use only bitmask
   RRC_SPS_CONFIG_UL_TWO_INTERVALS_CONFIG_PRESENT without two_intervals_config
   field */

} rrc_sps_config_ul_param_t;

typedef struct
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_SPS_CONFIG_UL_PARAM_PRESENT 0x01

    rrc_sps_config_ul_param_t     sps_config_ul_param;
/*^ O, RRC_SPS_CONFIG_UL_PARAM_PRESENT ^*/

} rrc_sps_config_ul_t;

typedef struct
{
  U16               bitmask;           /*^ BITMASK ^*/
#define RRC_SPS_CONFIG_C_RNTI_PRESENT             0x01
#define RRC_SPS_CONFIG_SPS_CONFIG_DL_PRESENT      0x02
#define RRC_SPS_CONFIG_SPS_CONFIG_UL_PRESENT      0x04

  U8                semi_presist_sched_c_rnti[C_RNTI_OCTET_SIZE];
/*^ O, RRC_SPS_CONFIG_C_RNTI_PRESENT, OCTET_STRING, FIXED ^*/

  rrc_sps_config_dl_t   sps_config_dl;
/*^ O, RRC_SPS_CONFIG_SPS_CONFIG_DL_PRESENT ^*/

  rrc_sps_config_ul_t   sps_config_ul;
/*^ O, RRC_SPS_CONFIG_SPS_CONFIG_UL_PRESENT ^*/

} rrc_sps_config_t;


/******************************************************************************
    TS 36.331 - 6.3.5 Measurement information elements
******************************************************************************/

typedef struct
{
  U8    count;          /*^ M, 0, H, 0, 32 ^*/
  U8    meas_object_id[MAX_MEAS_OBJECT_ID];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_object_to_remove_list_t;

typedef struct
{
  U8    count;          /*^ M, 0, H, 0, 32 ^*/
  U8    cell_index[MAX_CELL_MEAS]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}cell_index_list_t;

typedef struct
{
  U8    cell_index;         /*^ M, 0, H, 0, 32 ^*/
  U16   phys_cell_id;       /*^ M, 0, H, 0, 503 ^*/
  U8    cell_individual_offset; /*^ M, 0, H, 0, 30 ^*/
}cells_to_add_mod_t;

typedef struct
{
  U8                    count;  /*^ M, 0, H, 0, 32 ^*/
  cells_to_add_mod_t    cells_to_add_mod[MAX_CELL_MEAS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}cells_to_add_mod_list_t;

typedef struct
{
  U8    cell_index;         /*^ M, 0, H, 0, 32 ^*/
  phy_cell_id_range_t   phys_cell_id_range;
}black_cells_to_add_mod_t;

typedef struct
{
  U8                    count;  /*^ M, 0, H, 0, 32 ^*/
  black_cells_to_add_mod_t  black_cells_to_add_mod[MAX_CELL_MEAS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}black_cells_to_add_mod_list_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_EUTRA_CELLS_TO_REMOVE_LIST_PRESENT              0x01
#define MEAS_OBJECT_EUTRA_CELLS_TO_ADD_MOD_LIST_PRESENT             0x02
#define MEAS_OBJECT_EUTRA_BLACK_CELLS_TO_REMOVE_LIST_PRESENT        0x04
#define MEAS_OBJECT_EUTRA_BLACK_CELLS_TO_ADD_MOD_LIST_PRESENT       0x08
#define MEAS_OBJECT_EUTRA_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT      0x10

  U16   carrier_freq;
  U8    allowed_meas_bandwidth;
/*^ M, 0, H, 0, 5 ^*/ /*ENUMERATED {mbw6, mbw15, mbw25, mbw50, mbw75, mbw100}*/

  U8    presence_antenna_port1; /*^ M, 0, H, 0, 1 ^*/ /* rrc_bool_et */
  U8    neigh_cell_config;              /* BIT STRING (SIZE (2)) */
  U8    offset_freq;            /*^ M, 0, H, 0, 30 ^*/ /* rrm_q_offset_range_et */
  cell_index_list_t         cells_to_remove_list;
/*^ O, MEAS_OBJECT_EUTRA_CELLS_TO_REMOVE_LIST_PRESENT ^*/

  cells_to_add_mod_list_t   cells_to_add_mod_list;
/*^ O, MEAS_OBJECT_EUTRA_CELLS_TO_ADD_MOD_LIST_PRESENT ^*/

  cell_index_list_t black_cells_to_remove_list;
/*^ O, MEAS_OBJECT_EUTRA_BLACK_CELLS_TO_REMOVE_LIST_PRESENT ^*/

  black_cells_to_add_mod_list_t black_cells_to_add_mod_list;
/*^ O, MEAS_OBJECT_EUTRA_BLACK_CELLS_TO_ADD_MOD_LIST_PRESENT ^*/

  U16   cell_for_which_to_report_cgi;
/*^ O, MEAS_OBJECT_EUTRA_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT, H, 0, 503 ^*/

}meas_object_eutra_t;

typedef struct
{
  U8    cell_index;         /*^ M, 0, H, 0, 32 ^*/
  U16   phys_cell_id;       /*^ M, 0, H, 0, 511 ^*/
}cells_to_add_mod_utra_fdd_t;

typedef struct
{
  U8                    count;  /*^ M, 0, H, 0, 32 ^*/
  cells_to_add_mod_utra_fdd_t   cells_to_add_mod_utra_fdd[MAX_CELL_MEAS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}cells_to_add_mod_list_utra_fdd_t;

typedef struct
{
  U8    cell_index;         /*^ M, 0, H, 0, 32 ^*/
  U8    phys_cell_id;       /*^ M, 0, H, 0, 127 ^*/
}cells_to_add_mod_utra_tdd_t;

typedef struct
{
  U8                    count;  /*^ M, 0, H, 0, 32 ^*/
  cells_to_add_mod_utra_tdd_t   cells_to_add_mod_utra_tdd[MAX_CELL_MEAS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}cells_to_add_mod_list_utra_tdd_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_FDD_PRESENT          0x01
#define MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_TDD_PRESENT          0x02

  cells_to_add_mod_list_utra_fdd_t cells_to_add_mod_list_utra_fdd;
/*^ O, MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_FDD_PRESENT ^*/

  cells_to_add_mod_list_utra_tdd_t cells_to_add_mod_list_utra_tdd;
/*^ O, MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_TDD_PRESENT ^*/

}meas_object_utra_cells_to_add_mod_list_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/
#define MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_UTRA_FDD_PRESENT  0x01
#define MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_UTRA_TDD_PRESENT  0x02

  U16 utra_fdd;
/*^ O,MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_UTRA_FDD_PRESENT,H,0,511 ^*/

  U8 utra_tdd;
/*^ O,MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_UTRA_TDD_PRESENT,H,0,127 ^*/

}meas_object_utra_cell_for_which_to_report_cgi_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_UTRA_CELLS_TO_REMOVE_LIST_PRESENT               0x01
#define MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_PRESENT              0x02
#define MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT       0x04

  U16   carrier_freq;   /*^ M, 0, H, 0, 16383 ^*/
  S8    offset_freq;    /*^ M, 0, B, -15, 15 ^*/
  cell_index_list_t         cells_to_remove_list;
/*^ O, MEAS_OBJECT_UTRA_CELLS_TO_REMOVE_LIST_PRESENT ^*/

  meas_object_utra_cells_to_add_mod_list_t  cells_to_add_mod_list;
/*^ O, MEAS_OBJECT_UTRA_CELLS_TO_ADD_MOD_LIST_PRESENT ^*/

  meas_object_utra_cell_for_which_to_report_cgi_t  cell_for_which_to_report_cgi;
/*^ O, MEAS_OBJECT_UTRA_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT ^*/

}meas_object_utra_t;

typedef struct
{
 U8     network_colour_code; /*BIT STRING (SIZE (3))*/
 U8     base_station_colour_code; /*BIT STRING (SIZE (3))*/
}phys_cell_id_geran_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_GERAN_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT      0x01

  carrier_freqs_geran_t carrier_freqs;
  S8    offset_freq;    /*^ M, 0, B, -15, 15 ^*/    /*Default value is 0*/
  U8    ncc_Permitted;  /*BIT STRING(SIZE (8)), DEFAULT '11111111'B*/
  phys_cell_id_geran_t  cell_for_which_to_report_cgi;
/*^ O, MEAS_OBJECT_GERAN_CELL_FOR_WHICH_TO_REPORT_CGI_PRESENT ^*/

}meas_object_geran_t;

typedef enum
{
  RRM_RRC_TYPE1_XRTT,
  RRM_RRC_TYPE_HRPD
}rrm_meas_object_cdma2000_type_et;

typedef enum
{
  RRM_RRC_BC_0,
  RRM_RRC_BC_1,
  RRM_RRC_BC_2,
  RRM_RRC_BC_3,
  RRM_RRC_BC_4,
  RRM_RRC_BC_5,
  RRM_RRC_BC_6,
  RRM_RRC_BC_7,
  RRM_RRC_BC_8,
  RRM_RRC_BC_9,
  RRM_RRC_BC_10,
  RRM_RRC_BC_11,
  RRM_RRC_BC_12,
  RRM_RRC_BC_13,
  RRM_RRC_BC_14,
  RRM_RRC_BC_15,
  RRM_RRC_BC_16,
  RRM_RRC_BC_17
} rrm_band_class_cdma2000_et;

typedef struct
{
  U8   band_class;     /*^ M, 0, H, 0, 31 ^*/ /* rrm_band_class_cdma2000_et */
  U16   arfcn;          /*^ M, 0, H, 0, 2047 ^*/
}carrier_freq_cdma2000_t;

typedef struct
{
  U8    cell_index;         /*^ M, 0, H, 0, 32 ^*/
  U16   phys_cell_id;       /*^ M, 0, H, 0, 511 ^*/
}cells_to_add_mod_cdma2000_t;

typedef struct
{
  U8                            count;  /*^ M, 0, H, 0, 32 ^*/
  cells_to_add_mod_cdma2000_t   cells_to_add_mod_cdma2000[MAX_CELL_MEAS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}cells_to_add_mod_list_cdma2000_list_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_CDMA2000_SEARCH_WINDOW_SIZE_PRESENT             0x01
#define MEAS_OBJECT_CDMA2000_CELLS_TO_REMOVE_LIST_PRESENT           0x02
#define MEAS_OBJECT_CDMA2000_CELLS_TO_ADD_MOD_LIST_PRESENT          0x04
#define MEAS_OBJECT_CDMA2000_CELL_FOR_WHICH_TO_REPEORT_CGI_PRESENT  0x08

  U8                                    cdma2000_type;
/*^ M, 0, H, 0, 1 ^*/  /* rrm_meas_object_cdma2000_type_et */

  carrier_freq_cdma2000_t               carrier_freq_cdma2000;
  U8                                    search_window_size;
/*^ O, MEAS_OBJECT_CDMA2000_SEARCH_WINDOW_SIZE_PRESENT, H, 0, 15 ^*/

  S8                                    offset_freq;
/*^ M, 0, B, -15, 15 ^*/

  cell_index_list_t                     cells_to_remove_list;
/*^ O, MEAS_OBJECT_CDMA2000_CELLS_TO_REMOVE_LIST_PRESENT ^*/

  cells_to_add_mod_list_cdma2000_list_t cells_to_add_mod_list;
/*^ O, MEAS_OBJECT_CDMA2000_CELLS_TO_ADD_MOD_LIST_PRESENT ^*/

  U16                                   cells_for_which_to_report_cgi;
/*^ O, MEAS_OBJECT_CDMA2000_CELL_FOR_WHICH_TO_REPEORT_CGI_PRESENT, H, 0, 511 ^*/

}meas_object_cdma2000_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_OBJECT_TO_ADD_EUTRA_PRESENT            0x01
#define MEAS_OBJECT_TO_ADD_UTRA_PRESENT             0x02
#define MEAS_OBJECT_TO_ADD_GERAN_PRESENT            0x04
#define MEAS_OBJECT_TO_ADD_CDMA2000_PRESENT         0x08

  meas_object_eutra_t       meas_object_eutra;
/*^ O, MEAS_OBJECT_TO_ADD_EUTRA_PRESENT ^*/

  meas_object_utra_t        meas_object_utra;
/*^ O, MEAS_OBJECT_TO_ADD_UTRA_PRESENT ^*/

  meas_object_geran_t       meas_object_geran;
/*^ O, MEAS_OBJECT_TO_ADD_GERAN_PRESENT ^*/

  meas_object_cdma2000_t    meas_object_cdma2000;
/*^ O, MEAS_OBJECT_TO_ADD_CDMA2000_PRESENT ^*/

}meas_object_to_add_mod_meas_object_t;

typedef struct
{
  U8                                    meas_object_id; /*^ M, 0, B, 1, 32 ^*/
  meas_object_to_add_mod_meas_object_t  meas_object;
}meas_object_to_add_mod_t;

typedef struct
{
  U8                        count;          /*^ M, 0, H, 0, 32 ^*/
  meas_object_to_add_mod_t  meas_object_to_add_mod[MAX_MEAS_OBJECT_ID];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_object_to_add_mod_list_t;

typedef struct
{
  U8    count;  /*^ M, 0, H, 0, 32 ^*/
  U8    report_config_id[MAX_REPORT_CONFIG_ID];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}report_config_to_remove_list_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define THRESHOLD_EUTRA_RSRP_PRESENT            0x01
#define THRESHOLD_EUTRA_RSRQ_PRESENT            0x02

  U8    threshold_rsrp;     /*^ O, THRESHOLD_EUTRA_RSRP_PRESENT, H, 0, 97 ^*/
  U8    threshold_rsrq;     /*^ O, THRESHOLD_EUTRA_RSRQ_PRESENT, H, 0, 34 ^*/
}threshold_eutra_t;

typedef struct
{
  threshold_eutra_t a1_threshold;
}report_config_eutra_trigger_type_event_eventid_event_a1_t;

typedef struct
{
  threshold_eutra_t a2_threshold;
}report_config_eutra_trigger_type_event_eventid_event_a2_t;

typedef struct
{
  S8    a3_offset;          /*^ M, 0, B, -30, 30 ^*/
  U8    report_on_leave;    /*^ M, 0, H, 0, 1 ^*/
}report_config_eutra_trigger_type_event_eventid_event_a3_t;

typedef struct
{
  threshold_eutra_t a4_threshold;
}report_config_eutra_trigger_type_event_eventid_event_a4_t;

typedef struct
{
  threshold_eutra_t a5_threshold1;
  threshold_eutra_t a5_threshold2;
}report_config_eutra_trigger_type_event_eventid_event_a5_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A1_PRESENT       0x01
#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A2_PRESENT       0x02
#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A3_PRESENT       0x04
#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A4_PRESENT       0x08
#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A5_PRESENT       0x10

  report_config_eutra_trigger_type_event_eventid_event_a1_t event_a1;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A1_PRESENT ^*/

  report_config_eutra_trigger_type_event_eventid_event_a2_t event_a2;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A2_PRESENT ^*/

  report_config_eutra_trigger_type_event_eventid_event_a3_t event_a3;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A3_PRESENT ^*/

  report_config_eutra_trigger_type_event_eventid_event_a4_t event_a4;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A4_PRESENT ^*/

  report_config_eutra_trigger_type_event_eventid_event_a5_t event_a5;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_EVENTID_A5_PRESENT ^*/

}report_config_eutra_trigger_type_event_eventid_t;

typedef enum
{
    RRM_RRC_TIME_TO_TRIGGER_MS_0,
    RRM_RRC_TIME_TO_TRIGGER_MS_40,
    RRM_RRC_TIME_TO_TRIGGER_MS_64,
    RRM_RRC_TIME_TO_TRIGGER_MS_80,
    RRM_RRC_TIME_TO_TRIGGER_MS_100,
    RRM_RRC_TIME_TO_TRIGGER_MS_128,
    RRM_RRC_TIME_TO_TRIGGER_MS_160,
    RRM_RRC_TIME_TO_TRIGGER_MS_256,
    RRM_RRC_TIME_TO_TRIGGER_MS_320,
    RRM_RRC_TIME_TO_TRIGGER_MS_480,
    RRM_RRC_TIME_TO_TRIGGER_MS_512,
    RRM_RRC_TIME_TO_TRIGGER_MS_640,
    RRM_RRC_TIME_TO_TRIGGER_MS_1024,
    RRM_RRC_TIME_TO_TRIGGER_MS_1280,
    RRM_RRC_TIME_TO_TRIGGER_MS_2560,
    RRM_RRC_TIME_TO_TRIGGER_MS_5120
}rrm_time_to_trigger_et;

typedef struct
{
  report_config_eutra_trigger_type_event_eventid_t  event_id;
  U8                                                hysteresis;
/*^ M, 0, H, 0, 30 ^*/

  U8                                                time_to_trigger;
/*^ M, 0, H, 0, 15 ^*/ /* rrm_time_to_trigger_et */

}report_config_eutra_trigger_type_event_t;

typedef enum
{
    RRM_RRC_REPORT_STRONGEST_CELLS,
    RRM_RRC_REPORT_CGI
}rrm_trigger_type_periodical_purpose_et;

typedef struct
{
  U8    purpose;
/*^ M, 0, H, 0, 1 ^*/ /* rrm_trigger_type_periodical_purpose_et */

}report_config_eutra_trigger_type_periodical_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_PRESENT      0x01
#define REPORT_CONFIG_EUTRA_TRIGGER_TYPE_PERIODICAL_PRESENT 0x02

  report_config_eutra_trigger_type_event_t      event;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_EVENT_PRESENT ^*/

  report_config_eutra_trigger_type_periodical_t periodical;
/*^ O, REPORT_CONFIG_EUTRA_TRIGGER_TYPE_PERIODICAL_PRESENT ^*/

}report_config_eutra_trigger_type_t;

typedef enum
{
  RRM_RRC_RSRP,
  RRM_RRC_RSRQ
}rrm_trigger_quantity_et;

typedef enum
{
  RRM_RRC_SAME_AS_TRIGGER_QUANTITY,
  RRM_RRC_BOTH
}rrm_report_quantity_et;

typedef enum
{
    RRM_RRC_REPORT_INTERVAL_MS_120,
    RRM_RRC_REPORT_INTERVAL_MS_240,
    RRM_RRC_REPORT_INTERVAL_MS_480,
    RRM_RRC_REPORT_INTERVAL_MS_640,
    RRM_RRC_REPORT_INTERVAL_MS_1024,
    RRM_RRC_REPORT_INTERVAL_MS_2048,
    RRM_RRC_REPORT_INTERVAL_MS_5120,
    RRM_RRC_REPORT_INTERVAL_MS_10240,
    RRM_RRC_REPORT_INTERVAL_MIN_1,
    RRM_RRC_REPORT_INTERVAL_MIN_6,
    RRM_RRC_REPORT_INTERVAL_MIN_12,
    RRM_RRC_REPORT_INTERVAL_MIN_30,
    RRM_RRC_REPORT_INTERVAL_MIN_60
}rrm_report_interval_et;

typedef enum
{
  RRM_RRC_REPORT_AMOUNT_1,
  RRM_RRC_REPORT_AMOUNT_2,
  RRM_RRC_REPORT_AMOUNT_4,
  RRM_RRC_REPORT_AMOUNT_8,
  RRM_RRC_REPORT_AMOUNT_16,
  RRM_RRC_REPORT_AMOUNT_32,
  RRM_RRC_REPORT_AMOUNT_64,
  RRM_RRC_REPORT_AMOUNT_INFINITY
} rrm_report_amount_et;

typedef struct
{
  report_config_eutra_trigger_type_t    trigger_type;
  U8                                    trigger_quantity;
/*^ M, 0, H, 0, 1 ^*/  /* rrm_trigger_quantity_et */

  U8                                    report_quantity;
/*^ M, 0, H, 0, 1 ^*/  /* rrm_report_quantity_et */

  U8                                    max_report_cells;
/*^ M, 0, B, 1, 8 ^*/

  U8                                    report_interval;
/*^ M, 0, H, 0, 15 ^*/  /* rrm_report_interval_et */

  U8                                    report_amount;
/*^ M, 0, H, 0, 7 ^*/  /* rrm_report_amount_et */

}report_config_eutra_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define THRESHOLD_UTRA_RSCP_PRESENT             0x01
#define THRESHOLD_UTRA_ECN0_PRESENT             0x02

  S8    threshold_rscp;     /*^ O, THRESHOLD_UTRA_RSCP_PRESENT, B, -5, 91 ^*/
  U8    threshold_ecn0;     /*^ O, THRESHOLD_UTRA_ECN0_PRESENT, H, 0, 49 ^*/
}threshold_utra_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_UTRA_PRESENT     0x01
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_GERAN_PRESENT    0x02
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_CDMA2000_PRESENT 0x04

  threshold_utra_t  b1_threshold_utra;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_UTRA_PRESENT ^*/

  U8    b1_threshold_geran;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_GERAN_PRESENT,H,0,63 ^*/

  U8    b1_threshold_cdma2000;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_THRESHOLD_CDMA2000_PRESENT,H,0,63 ^*/

}report_config_interrat_trigger_type_event_eventid_event_b1_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_UTRA_PRESENT     0x01
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_GERAN_PRESENT    0x02
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_CDMA2000_PRESENT 0x04

  threshold_eutra_t b2_threshold_eutra;
  threshold_utra_t  b2_threshold_utra;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_UTRA_PRESENT ^*/

  U8    b2_threshold_geran;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_GERAN_PRESENT,H,0,63 ^*/

  U8    b2_threshold_cdma2000;
/*^ O,REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_THRESHOLD_CDMA2000_PRESENT,H,0,63 ^*/

}report_config_interrat_trigger_type_event_eventid_event_b2_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_PRESENT        0x01
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_PRESENT        0x02

  report_config_interrat_trigger_type_event_eventid_event_b1_t  event_b1;
/*^ O, REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B1_PRESENT ^*/

  report_config_interrat_trigger_type_event_eventid_event_b2_t  event_b2;
/*^ O, REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_EVENTID_B2_PRESENT ^*/

}report_config_interrat_trigger_type_event_eventid_t;

typedef struct
{
  report_config_interrat_trigger_type_event_eventid_t   event_id;
  U8                                                hysteresis;
/*^ M, 0, H, 0, 30 ^*/

  U8                                                time_to_trigger;
/*^ M, 0, H, 0, 15 ^*/ /* rrm_time_to_trigger_et */

}report_config_interrat_trigger_type_event_t;

typedef struct
{
  U8    purpose;            /*^ M, 0, H, 0, 2 ^*/
  /* ENUMERATED {reportStrongestCells, reportStrongestCellsForSON, reportCGI}*/
}report_config_interrat_trigger_type_periodical_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_PRESENT       0x01
#define REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_PERIODICAL_PRESENT  0x02

  report_config_interrat_trigger_type_event_t       event;
/*^ O, REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_EVENT_PRESENT ^*/

  report_config_interrat_trigger_type_periodical_t  periodical;
/*^ O, REPORT_CONFIG_INTERRAT_TRIGGER_TYPE_PERIODICAL_PRESENT ^*/

}report_config_interrat_trigger_type_t;

typedef struct
{
  report_config_interrat_trigger_type_t trigger_type;
  U8                                    max_report_cells;
/*^ M, 0, B, 1, 8 ^*/

  U8                                    report_interval;
/*^ M, 0, H, 0, 15 ^*/  /* rrm_report_interval_et */

  U8                                    report_amount;
/*^ M, 0, H, 0, 7 ^*/  /* rrm_report_amount_et */

}report_config_interrat_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define REPORT_CONFIG_EUTRA_PRESENT     0x01
#define REPORT_CONFIG_INTERRAT_PRESENT  0x02

  report_config_eutra_t     report_config_eutra;
/*^ O, REPORT_CONFIG_EUTRA_PRESENT ^*/

  report_config_interrat_t  report_config_interrat;
/*^ O, REPORT_CONFIG_INTERRAT_PRESENT ^*/

}report_config_to_add_mod_report_config_t;

typedef struct
{
  U8                                            report_config_id;
/*^ M, 0, B, 1, 32 ^*/

  report_config_to_add_mod_report_config_t      report_config;
}report_config_to_add_mod_t;

typedef struct
{
  U8                            count;          /*^ M, 0, H, 0, 32 ^*/
  report_config_to_add_mod_t    report_config_to_add_mod[MAX_REPORT_CONFIG_ID];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}report_config_to_add_mod_list_t;

typedef struct
{
  U8    count;                  /*^ M, 0, H, 0, 32 ^*/
  U8    meas_id[MAX_MEAS_ID]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}meas_id_to_remove_list_t;

typedef struct
{
  U8    meas_id;            /*^ M, 0, B, 1, 32 ^*/
  U8    meas_object_id;     /*^ M, 0, B, 1, 32 ^*/
  U8    report_config_id;   /*^ M, 0, B, 1, 32 ^*/
}meas_id_to_add_mod_t;

typedef struct
{
  U8                    count;  /*^ M, 0, H, 0, 32 ^*/
  meas_id_to_add_mod_t  meas_id_to_add_mod[MAX_MEAS_ID];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_id_to_add_mod_list_t;

typedef struct
{
  U8    filter_coefficient_rsrp;
/*^ M, 0, H, 0, 14 ^*/  /* rrc_filter_coefficient_et */

  U8    filter_coefficient_rsrq;
/*^ M, 0, H, 0, 14 ^*/  /* rrc_filter_coefficient_et */

}quantity_config_eutra_t;

typedef enum
{
  RRM_RRC_CPICH_RSCP,
  RRM_RRC_CPICH_ECN0
}quantity_config_utra_meas_fdd_et;

typedef enum
{
  RRM_RRC_PCCPCH_RSCP
}quantity_config_utra_meas_tdd_et;

typedef struct
{
  U8    meas_quantity_utra_fdd;
/*^ M, 0, H, 0, 1 ^*/  /* quantity_config_utra_meas_fdd_et */

  U8    meas_quantity_utra_tdd;
/*^ M, 0, H, 0, 0 ^*/  /* quantity_config_utra_meas_tdd_et */

  U8    filter_coefficient;
/*^ M, 0, H, 0, 14 ^*/  /* rrc_filter_coefficient_et */

}quantity_config_utra_t;

typedef enum
{
  RRM_RRC_RSSI
}quantity_config_utra_meas_geran_et;

typedef struct
{
  U8    meas_quantity_geran;
/*^ M, 0, H, 0, 0 ^*/  /* quantity_config_utra_meas_geran_et */

  U8    filter_coefficient;
/*^ M, 0, H, 0, 14 ^*/  /* rrc_filter_coefficient_et */

}quantity_config_geran_t;

typedef enum
{
  RRM_RRC_PILOT_STRENGTH,
  RRM_RRC_PILOT_PN_PHASE_AND_PILOT_STRENGTH
}quantity_config_utra_meas_cdma2000_et;

typedef struct
{
  U8    meas_quantity_cdma2000;
/*^ M, 0, H, 0, 1 ^*/  /* quantity_config_utra_meas_cdma2000_et */

}quantity_config_cdma2000_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define QUANTITY_CONFIG_EUTRA_PRESENT           0x01
#define QUANTITY_CONFIG_UTRA_PRESENT            0x02
#define QUANTITY_CONFIG_GERAN_PRESENT           0x04
#define QUANTITY_CONFIG_CDMA2000_PRESENT        0x08

  quantity_config_eutra_t       quantity_config_eutra;
/*^ O, QUANTITY_CONFIG_EUTRA_PRESENT ^*/

  quantity_config_utra_t        quantity_config_utra;
/*^ O, QUANTITY_CONFIG_UTRA_PRESENT ^*/

  quantity_config_geran_t       quantity_config_geran;
/*^ O, QUANTITY_CONFIG_GERAN_PRESENT ^*/

  quantity_config_cdma2000_t    quantity_config_cdma2000;
/*^ O, QUANTITY_CONFIG_CDMA2000_PRESENT ^*/

}quantity_config_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_GAP_CONFIG_GP0_PRESENT             0x01
#define MEAS_GAP_CONFIG_GP1_PRESENT             0x02

  U8    gp0;            /*^ O, MEAS_GAP_CONFIG_GP0_PRESENT, H, 0, 39 ^*/
  U8    gp1;            /*^ O, MEAS_GAP_CONFIG_GP1_PRESENT, H, 0, 79 ^*/
}meas_gap_config_t;

typedef struct
{
  U8    count;  /*^ M, 0, B, 1, 2 ^*/
  U8    pre_registration_zone_id_hrpd[2];  /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}secondary_pre_registration_zone_id_list_hrpd_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define PRE_REGISTRATION_ZONE_ID_PRESENT                0x01
#define PRE_REGISTRATION_SECONDARY_ZONE_ID_LIST_PRESENT 0x02

  U8                                                pre_registration_allowed;
/*^ M, 0, H, 0, 1 ^*/

  U8                                                pre_registration_zone_id;
/*^ O, PRE_REGISTRATION_ZONE_ID_PRESENT, N, 0, 0 ^*/

  secondary_pre_registration_zone_id_list_hrpd_t
      secondary_pre_registration_zone_id_list;
/*^ O, PRE_REGISTRATION_SECONDARY_ZONE_ID_LIST_PRESENT ^*/

}pre_registration_info_hrpd_t;

typedef enum
{
  RRM_RRC_EV_S30,
  RRM_RRC_EV_S60,
  RRM_RRC_EV_S120,
  RRM_RRC_EV_S180,
  RRM_RRC_EV_S240
}mobility_state_parameters_t_evaluation_et;

typedef enum
{
  RRM_RRC_HN_S30,
  RRM_RRC_HN_S60,
  RRM_RRC_HN_S120,
  RRM_RRC_HN_S180,
  RRM_RRC_HN_S240
}mobility_state_parameters_t_hyst_normal_et;

typedef struct
{
  U8    t_evaluation;
/*^ M, 0, H, 0, 7 ^*/  /* mobility_state_parameters_t_evaluation_et */

  U8    t_hyst_normal;
/*^ M, 0, H, 0, 7 ^*/  /* mobility_state_parameters_t_hyst_normal_et */

  U8    m_cell_charge_medium;   /*^ M, 0, B, 1, 16 ^*/
  U8    m_cell_charge_high;     /*^ M, 0, B, 1, 16 ^*/
}mobility_state_parameters_t;

typedef struct
{
  mobility_state_parameters_t   mobility_state_parameters;
  speed_state_scale_factors_t   time_to_trigger_sf;
}meas_config_speed_state_pars_setup_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define MEAS_CONFIG_SPEED_STATE_SETUP_PRESENT     0x01

  meas_config_speed_state_pars_setup_t  setup;
/*^ O, MEAS_CONFIG_SPEED_STATE_SETUP_PRESENT ^*/

}meas_config_speed_state_pars_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/

#define UE_ADM_MEAS_OBJECT_TO_REMOVE_LIST_PRESENT           0x01
#define UE_ADM_MEAS_OBJECT_TO_ADD_MOD_LIST_PRESENT          0x02
#define UE_ADM_MEAS_REPORT_CONFIG_TO_REMOVE_LIST_PRESENT    0x04
#define UE_ADM_MEAS_REPORT_CONFIG_TO_ADD_MOD_LIST_PRESENT   0x08
#define UE_ADM_MEAS_ID_TO_REMOVE_LIST_PRESENT               0x10
#define UE_ADM_MEAS_ID_TO_ADD_MOD_LIST_PRESENT              0x20
#define UE_ADM_MEAS_QUANTITY_CONFIG_PRESENT                 0x40
#define UE_ADM_MEAS_GAP_CONFIG_PRESENT                      0x80
#define UE_ADM_MEAS_S_MEASURE_PRESENT                       0x100
#define UE_ADM_MEAS_PRE_REGISTRATION_INFO_PRESENT           0x200
#define UE_ADM_MEAS_SPEED_STATE_PARS_PRESENT                0x400

  meas_object_to_remove_list_t      meas_object_to_remove_list;
/*^ O, UE_ADM_MEAS_OBJECT_TO_REMOVE_LIST_PRESENT ^*/

  meas_object_to_add_mod_list_t     meas_object_to_add_mod_list;
/*^ O, UE_ADM_MEAS_OBJECT_TO_ADD_MOD_LIST_PRESENT ^*/


  report_config_to_remove_list_t    report_config_to_remove_list;
/*^ O, UE_ADM_MEAS_REPORT_CONFIG_TO_REMOVE_LIST_PRESENT ^*/

  report_config_to_add_mod_list_t   report_config_to_add_mod_list;
/*^ O, UE_ADM_MEAS_REPORT_CONFIG_TO_ADD_MOD_LIST_PRESENT ^*/


  meas_id_to_remove_list_t          meas_id_to_remove_list;
/*^ O, UE_ADM_MEAS_ID_TO_REMOVE_LIST_PRESENT ^*/

  meas_id_to_add_mod_list_t         meas_id_to_add_mod_list;
/*^ O, UE_ADM_MEAS_ID_TO_ADD_MOD_LIST_PRESENT ^*/


  quantity_config_t                 quantity_config;
/*^ O, UE_ADM_MEAS_QUANTITY_CONFIG_PRESENT ^*/

  meas_gap_config_t                 meas_gap_config;
/*^ O, UE_ADM_MEAS_GAP_CONFIG_PRESENT ^*/


  U8                                s_measure;
/*^ O, UE_ADM_MEAS_S_MEASURE_PRESENT, H, 0, 97 ^*/


  pre_registration_info_hrpd_t      pre_registration_info_hrpd;
/*^ O, UE_ADM_MEAS_PRE_REGISTRATION_INFO_PRESENT ^*/

  meas_config_speed_state_pars_t    meas_config_speed_state_pars;
/*^ O, UE_ADM_MEAS_SPEED_STATE_PARS_PRESENT ^*/

} rrm_meas_config_t;

/******************************************************************************
 * MAC LC Parameters - See DL_LC_CREATE_REQ and
 *                     UL_LC_CREATE_REQ TLVs description in MAC API document.
 ******************************************************************************/
typedef struct
{
    rrc_bitmask_t       bitmask;       /*^ BITMASK ^*/
#define RRM_MAC_LC_CONFIG_UL_LC_G_ID_PRESENT   0x01
#define RRM_MAC_LC_CONFIG_DL_PRIORITY_PRESENT  0x02

    U8  ul_lc_g_id;
/*^ O, RRM_MAC_LC_CONFIG_UL_LC_G_ID_PRESENT, H, 0, 3 ^*/

    U8  dl_lch_priority;
/*^ O, RRM_MAC_LC_CONFIG_DL_PRIORITY_PRESENT, H, 1, 16 ^*/

} rrm_mac_lc_config_t;

/******************************************************************************
            RRC_RRM_UE_ADMISSION_RESP
******************************************************************************/

/* TS 36.331 - 6.3.2 RadioResourceConfigDedicated IE SRB-ToAddMod IE.
 *             The rlc-Config IE is optional and defaultValues should be
 *             supported for it */
typedef struct
{
    rrc_bitmask_t         bitmask;   /*^ BITMASK ^*/
#define RRM_SRB_AM_CONFIG_EXPLICIT_PRESENT              0x01

    rrc_am_config_t       am_config_explicit;
/*^ O, RRM_SRB_AM_CONFIG_EXPLICIT_PRESENT ^*/

} rrm_srb_am_config_t;

/* TS 36.331 - 6.3.2 RadioResourceConfigDedicated IE SRB-ToAddMod IE.
 *             The logicalChannelConfig IE is optional and defaultValues
 *             should be supported for it  */
typedef struct
{
    rrc_bitmask_t         bitmask;   /*^ BITMASK ^*/
#define RRM_SRB_UL_SPECIFIC_PARAMETERS_EXPLICIT_PRESENT    0x01

    rrc_ul_specific_parameters_t  ul_specific_parameters_explicit;
/*^ O, RRM_SRB_UL_SPECIFIC_PARAMETERS_EXPLICIT_PRESENT ^*/

} rrm_srb_ul_specific_parameters_t;

/* TS 36.331 - 6.3.2 RadioResourceConfigDedicated IE SRB-ToAddMod IE.
 *             The srb-Identity IE isn't used because SRB configuration
 *             provided in different named fields for each SRB
 *             in srb_config_t structure */
typedef struct
{
    rrc_bitmask_t         bitmask;   /*^ BITMASK ^*/
#define RRM_SRB_CONFIG_AM_CONFIG_PRESENT                0x01
#define RRM_SRB_CONFIG_UL_SPECIFIC_PARAMETERS_PRESENT   0x02
#define RRM_SRB_CONFIG_MAC_LC_CONFIG_ENB_PRESENT        0x04

    rrm_srb_am_config_t    srb_am_config;
/*^ O, RRM_SRB_CONFIG_AM_CONFIG_PRESENT ^*/

    rrm_srb_ul_specific_parameters_t  ul_specific_parameters;
/*^ O, RRM_SRB_CONFIG_UL_SPECIFIC_PARAMETERS_PRESENT ^*/

    rrm_mac_lc_config_t    mac_lc_config_enb;
/*^ O, RRM_SRB_CONFIG_MAC_LC_CONFIG_ENB_PRESENT ^*/

} rrm_srb_config_t;

/* SRBs configuration - if absent the default configuration should be used */
typedef struct
{
    rrc_bitmask_t    bitmask;     /*^ BITMASK ^*/
#define RRM_SRB_INFO_SRB1_CONFIG_PRESENT         0x01
#define RRM_SRB_INFO_SRB2_CONFIG_PRESENT         0x02

    rrm_srb_config_t     srb1_config;
/*^ O, RRM_SRB_INFO_SRB1_CONFIG_PRESENT ^*/

    rrm_srb_config_t     srb2_config;
/*^ O, RRM_SRB_INFO_SRB2_CONFIG_PRESENT ^*/

} rrm_srb_info_t;

/* MAC-MainConfig Extensions - It contains MAC parameters which are not
 * defined in TS 36.331  */
typedef enum
{
  RRM_RRC_MODE_SCHEME_QPSK = 2,
  RRM_RRC_MODE_SCHEME_16_QAM = 4,
  RRM_RRC_MODE_SCHEME_64_QAM = 6
} rrm_mode_scheme_et;

typedef struct
{
  rrc_bitmask_t         bitmask;
/*^ BITMASK ^*/ /*todo:for future use*/


  U8                ue_priority;            /*^ M, 0, H, 0, 3 ^*/
  U8                dl_num_harq_process;    /*^ M, 0, B, 6, 8 ^*/
  U8                dl_modulation_scheme;
/*^ M, 0, B, 2, 6 ^*/     /* rrm_mode_scheme_et*/

  U32               dl_coding_rate;         /*^ M, 0, N, 0, 0 ^*/
  U8                dl_max_rb;              /*^ M, 0, B, 1, 100 ^*/
  U8                ul_max_rb;              /*^ M, 0, B, 1, 100 ^*/
  U8                ul_modulation_scheme;
/*^ M, 0, B, 2, 6 ^*/     /* rrm_mode_scheme_et*/

  U32               ul_coding_rate;
  U8                num_of_layer;           /*^ M, 0, B, 1, 2 ^*/
  U8                code_book_index;        /*^ M, 0, H, 0, 3 ^*/
} rrm_mac_main_config_extensions_t;

/* RRM MAC Main Configuration IE */
/* TS 36.331 - 6.3.2 RadioResourceConfigDedicated IE mac-MainConfig IE.
 *             The mac-MainConfig is optional and defaultValues
 *             should be supported for it  */
typedef struct
{
    rrc_bitmask_t             bitmask;     /*^ BITMASK ^*/
#define RRM_MAC_CONFIG_MAC_MAIN_CONFIG_PRESENT         0x01

    rrc_mac_main_config_t             mac_main_config;
/*^ O, RRM_MAC_CONFIG_MAC_MAIN_CONFIG_PRESENT ^*/

    rrm_mac_main_config_extensions_t  mac_main_config_extensions;
} rrm_mac_config_t;

/* RRM Radio Resource Configuration for UE - this IE should be presented in
 * case of successful UE admission */
typedef struct
{
    rrc_bitmask_t             bitmask;     /*^ BITMASK ^*/
#define RRM_UE_ADM_RADIO_RESP_SRB_INFO_PRESENT           0x01
#define RRM_UE_ADM_RADIO_RESP_MAC_CONFIG_PRESENT         0x02
#define RRM_UE_ADM_RADIO_RESP_SPS_CONFIG_PRESENT         0x04
#define RRM_UE_ADM_RADIO_RESP_PHY_CONFIG_DED_PRESENT     0x08
#define RRM_UE_ADM_RADIO_RESP_MEAS_CONFIG_PRESENT        0x10

  rrm_srb_info_t              srb_info;
/*^ O, RRM_UE_ADM_RADIO_RESP_SRB_INFO_PRESENT ^*/

  rrm_mac_config_t            mac_config;
/*^ O, RRM_UE_ADM_RADIO_RESP_MAC_CONFIG_PRESENT ^*/

  rrc_sps_config_t            sps_config;
/*^ O, RRM_UE_ADM_RADIO_RESP_SPS_CONFIG_PRESENT ^*/

  rrc_phy_physical_config_dedicated_t      physical_config_dedicated;
/*^ O, RRM_UE_ADM_RADIO_RESP_PHY_CONFIG_DED_PRESENT ^*/

  rrm_meas_config_t           meas_config;
/*^ O, RRM_UE_ADM_RADIO_RESP_MEAS_CONFIG_PRESENT ^*/

} rrm_ue_adm_radio_res_config_t;

typedef struct
{
    rrc_bitmask_t             bitmask;      /*^ BITMASK ^*/
#define RRM_UE_ADM_RESP_API_UE_ADM_RADIO_RESP_PRESENT   0x01

  U16                         ue_index;
  U8                          wait_time;    /*^ M, 0, B, 1, 16 ^*/
  U8                          response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

  rrm_ue_adm_radio_res_config_t   radio_res_config;
/*^ O, RRM_UE_ADM_RESP_API_UE_ADM_RADIO_RESP_PRESENT ^*/

} rrc_rrm_ue_admission_resp_t; /*^ API, RRC_RRM_UE_ADMISSION_RESP ^*/

/******************************************************************************
            RRC_RRM_UE_ADMISSION_CNF
******************************************************************************/

typedef struct
{
  U16           ue_index;
  U8            response;  /*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */
} rrc_rrm_ue_admission_cnf_t; /*^ API, RRC_RRM_UE_ADMISSION_CNF ^*/


/******************************************************************************
            RRC_RRM_ERB_SETUP_REQ
******************************************************************************/

/* TS 36.413 - E-RAB Level QoS Parameters 9.2.1.60*/
typedef enum
{
  RRC_RRM_SHALL_NOT_TRIGGER_PRE_EMPTION,
  RRC_RRM_MAY_TRIGGER_PRE_EMPTION
}rrm_preemp_cap_et;

typedef enum
{
  RRC_RRM_NOT_PRE_EMPTABLE,
  RRC_RRM_PRE_EMPTABLE
} rrm_preemp_vul_et;

typedef struct
{
  U8        priority_level;           /*^ M, 0, H, 1, 15 ^*/
  U8        preemption_capability;
/*^ M, 0, H, 0, 1 ^*/ /*rrm_preemp_cap_et*/

  U8        preemption_vulnerability;
/*^ M, 0, H, 0, 1 ^*/ /*rrm_preemp_vul_et*/

} rrm_allocation_and_retention_priority_t;

/* TS 36.413 - E-RAB Level QoS Parameters 9.2.1.18*/
typedef struct
{
  U32      erab_max_bit_rate_dl;   /*^ M, 0, N, 0, 0 ^*/
  U32      erab_max_bit_rate_ul;   /*^ M, 0, N, 0, 0 ^*/
  U32      erab_guar_bit_rate_dl;  /*^ M, 0, N, 0, 0 ^*/
  U32      erab_guar_bit_rate_ul;  /*^ M, 0, N, 0, 0 ^*/
} rrm_qbr_qos_info_t;

/* TS 36.413 - E-RAB Level QoS Parameters 9.2.1.15*/
typedef struct
{
    rrc_bitmask_t               bitmask;       /*^ BITMASK ^*/
#define ERAB_LEVEL_QOS_PARAM_GBR_QOS_INFO_PRESENT     0x01
  U8                            qci;                    /*^ M, 0, N, 0, 0 ^*/
  rrm_allocation_and_retention_priority_t       alloc_and_reten_prior;
/*^ M, 0, N, 0, 0  ^*/

  rrm_qbr_qos_info_t            qbr_qos_info;           /*^ O, 1, N, 0, 0  ^*/
} rrm_erab_level_qos_params_t;

/* TS 36.413 - E-RAB to be Setup Item 9.1.4.1*/
typedef struct
{
  U8                            erab_id;
/*^ M, 0, H, 1, 15 ^*/

  rrm_erab_level_qos_params_t   erab_level_qos_params;     /*^ M, 0, N, 0, 0 ^*/
} rrm_erab_to_be_setup_item_t;

/* TS 36.413 - E-RAB to be Setup Item list 9.1.4.1*/
typedef struct
{
  U16                      num_of_list;   /*^ M, 0, H, 1, 16 ^*/
  rrm_erab_to_be_setup_item_t  erab_to_be_setup_item[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_erab_to_be_setup_item_list_t;

/* TS 36.413 - UE Aggregate Maximum bit rate 9.2.1.20*/
typedef struct
{
  U64       ue_agg_max_bit_rate_ul;  /*^ M, 0, N, 0, 0 ^*/
  U64       ue_agg_max_bit_rate_dl;  /*^ M, 0, N, 0, 0 ^*/
} rrm_ue_agg_max_bit_rate_t;

typedef struct
{
  rrc_bitmask_t               bitmask;       /*^ BITMASK ^*/
#define RRM_ERB_SETUP_REQ_UE_AGG_MAX_BIT_RATE_PRESENT     0x01

  U16                               ue_index;
  rrm_ue_agg_max_bit_rate_t         ue_agg_max_bit_rate;
/*^ O, RRM_ERB_SETUP_REQ_UE_AGG_MAX_BIT_RATE_PRESENT, N, 0, 0 ^*/

  rrm_erab_to_be_setup_item_list_t  erab_to_be_setup_item_list;
/*^ M, 0, N, 0, 0 ^*/

}rrc_rrm_erb_setup_req_t; /*^ API, RRC_RRM_ERB_SETUP_REQ ^*/

/******************************************************************************
    TS 36.331 - 6.3.2 PDCP-Config IE
******************************************************************************/

typedef enum
{
  RRC_PDCP_SN_SIZE_7_BITS,
  RRC_PDCP_SN_SIZE_12_BITS
} rrc_pdcp_sn_size_et;

typedef enum
{
  RRC_PDCP_DISCARD_TIMER_MS_50,
  RRC_PDCP_DISCARD_TIMER_MS_100,
  RRC_PDCP_DISCARD_TIMER_MS_150,
  RRC_PDCP_DISCARD_TIMER_MS_300,
  RRC_PDCP_DISCARD_TIMER_MS_500,
  RRC_PDCP_DISCARD_TIMER_MS_750,
  RRC_PDCP_DISCARD_TIMER_MS_1500,
  RRC_PDCP_DISCARD_TIMER_INFINITY
} rrc_pdcp_discard_timer_et;

typedef struct
{
  U8            profile0x0001;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0002;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0003;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0004;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0006;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0101;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0102;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0103;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
  U8            profile0x0104;   /*^ M, 0, H, 0, 1 ^*/      /* rrc_bool_et */
} rrc_pdcp_rohc_profile_t;

typedef struct
{
  U16                        max_cid;        /*^ M, 0, B, 1, 16383 ^*/
  rrc_pdcp_rohc_profile_t    rohc_profile;   /*^ M, 0, N, 0, 0 ^*/
} rrc_pdcp_rohc_config_t;

/*PDCP-Config, see headerCompression IE (notUsed)*/
typedef struct
{
    rrc_bitmask_t         bitmask;                 /*^ BITMASK ^*/
#define RRC_PDCP_HEADER_COMPRESSION_ROHC_CONFIG_PRESENT  0x01

    rrc_pdcp_rohc_config_t  rohc_config;
/*^ O, RRC_PDCP_HEADER_COMPRESSION_ROHC_CONFIG_PRESENT ^*/

} rrc_pdcp_header_compression_config_t;

typedef struct
{
    rrc_bitmask_t         bitmask;                 /*^ BITMASK ^*/
#define RRC_PDCP_CONFIG_DISCARD_TIMER_PRESENT               0x01
#define RRC_PDCP_CONFIG_RLC_AM_STATUS_REPORT_REQ_PRESENT    0x02
#define RRC_PDCP_CONFIG_RLC_UM_PDCP_SN_SIZE_PRESENT         0x04

  U8                      discard_timer;
/*^ O, RRC_PDCP_CONFIG_DISCARD_TIMER_PRESENT, H, 1, 7 ^*/
/* rrc_pdcp_discard_timer_et */

  U8                      rlc_am_status_report_required;
/*^ O, RRC_PDCP_CONFIG_RLC_AM_STATUS_REPORT_REQ_PRESENT, H, 0, 1 ^*/
/* rrc_bool_et */

  U8                      rlc_um_pdcp_sn_size;
/*^ O, RRC_PDCP_CONFIG_RLC_UM_PDCP_SN_SIZE_PRESENT, H, 1, 1 ^*/
/* rrc_pdcp_sn_size_et */

  rrc_pdcp_header_compression_config_t   header_compression;
} rrc_pdcp_config_t;

/******************************************************************************
            RRC_RRM_ERB_SETUP_RESP
******************************************************************************/

typedef struct
{
    U8 allocation_retention_priority;
    U8 qos_profile_data_size;
/*^ M, 0, B, 3, 254 ^*/

    U8 qos_profile_data[MAX_S1U_QOS_PROFILE_DATA_OCTET_SIZE];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_s1u_qos_profile_t;

typedef struct
{
    U32 qos_id;
    U8  sap_flags;
    rrm_s1u_qos_profile_t qos_profile;
    U8  seq_flag;   /*^ M, 0, H, 0, 1 ^*/ /* rrc_bool_et */
    U8  reordering_reqd;    /*^ M, 0, H, 0, 1 ^*/ /* rrc_bool_et */
} rrm_s1u_config_t;

/* TS 36.331 - 6.3.2 RadioResourceConfigDedicated IE DRB-ToAddMod IE. */
typedef struct
{
    rrc_bitmask_t      bitmask;       /*^ BITMASK ^*/
#define RRM_DRB_CONFIG_BEARED_ID_PRESENT                0x01
#define RRM_DRB_CONFIG_LOGICAL_CHANNEL_IDENTITY_PRESENT 0x02
#define RRM_DRB_CONFIG_PDCP_CONFIG_PRESENT              0x04
#define RRM_DRB_CONFIG_RLC_CONFIG_PRESENT               0x08
#define RRM_DRB_CONFIG_UL_SPECIFIC_PARAMETERS_PRESENT   0x10
#define RRM_DRB_CONFIG_S1U_CONFIG_PRESENT               0x20
#define RRM_DRB_CONFIG_MAC_LC_CONFIG_ENB_PRESENT        0x40
#define RRM_DRB_CONFIG_RLC_CONFIG_UE_PRESENT            0x80


  U8                    erab_id;                /*^ M, 0, H, 1, 15 ^*/

  U8                    drb_id;                 /*^ M, 0, B, 1, 32 ^*/

  U8                    logical_channel_identity;
/*^ O, RRM_DRB_CONFIG_LOGICAL_CHANNEL_IDENTITY_PRESENT, B, 3, 10 ^*/

  rrc_pdcp_config_t     pdcp_config;
/*^ O, RRM_DRB_CONFIG_PDCP_CONFIG_PRESENT ^*/

  rrc_rlc_config_t      rlc_config;
/*^ O, RRM_DRB_CONFIG_RLC_CONFIG_PRESENT ^*/

  rrc_ul_specific_parameters_t  ul_specific_parameters;
/*^ O, RRM_SRB_CONFIG_UL_SPECIFIC_PARAMETERS_PRESENT ^*/

  rrm_s1u_config_t      s1u_config;
/*^ O, RRM_DRB_CONFIG_S1U_CONFIG_PRESENT ^*/

  rrm_mac_lc_config_t   mac_lc_config_enb;
/*^ O, RRM_DRB_CONFIG_MAC_LC_CONFIG_ENB_PRESENT ^*/

  rrc_rlc_config_t      rlc_config_ue;
/*^ O, RRM_DRB_CONFIG_RLC_CONFIG_UE_PRESENT ^*/

} rrm_drb_config_t;

typedef struct
{
  U8                     drb_count; /*^ M, 0, H, 1, 15 ^*/
  rrm_drb_config_t       drb_config[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_drb_to_add_info_list_t;

typedef struct
{
  U8                    erab_id; /*^ M, 0, H, 0,15 ^*/
  rrm_cause_t           cause;
} rrm_drb_failed_to_add_item_t;

typedef struct
{
  U8                            count; /*^ M, 0, H, 1, 15 ^*/
  rrm_drb_failed_to_add_item_t  drb_failed_to_add[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_drb_failed_to_add_info_list_t;

typedef struct
{
    rrc_bitmask_t              bitmask;     /*^ BITMASK ^*/
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_DRB_TO_ADD_LIST_PRESENT           0x01
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_MAC_CONFIG_PRESENT                0x02
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_SPS_CONFIG_PRESENT                0x04
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_PHY_CONFIG_DED_PRESENT            0x08
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_MEAS_CONFIG_PRESENT               0x10
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_DRB_FAILED_TO_ADD_LIST_PRESENT    0x20
#define RRM_ERAB_SETUP_RADIO_RES_CONFIG_SRB_INFO_PRESENT                  0x40

    rrm_drb_to_add_info_list_t  drb_to_add_list;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_DRB_TO_ADD_LIST_PRESENT ^*/

    rrm_mac_config_t            mac_config;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_MAC_CONFIG_PRESENT ^*/

    rrc_sps_config_t            sps_config;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_SPS_CONFIG_PRESENT ^*/

    rrc_phy_physical_config_dedicated_t      physical_config_dedicated;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_PHY_CONFIG_DED_PRESENT ^*/

    rrm_meas_config_t           meas_config;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_MEAS_CONFIG_PRESENT ^*/

    rrm_drb_failed_to_add_info_list_t  drb_failed_to_add_list;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_DRB_FAILED_TO_ADD_LIST_PRESENT ^*/
   rrm_srb_info_t              srb_info;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_SRB_INFO_PRESENT ^*/

} rrm_erab_setup_radio_res_config_t;

typedef struct _rrc_rrm_erb_setup_resp_t
{
    rrc_bitmask_t             bitmask;    /*^ BITMASK ^*/
#define RRM_ERB_SETUP_RESP_API_ADM_RADIO_RES_PRESENT   0x01

    U16                       ue_index;
    U8                        response; /*^ M, 0, H, 0, 2 ^*/ 

    rrm_erab_setup_radio_res_config_t    radio_rsource_config;
/*^ O, RRM_ERB_SETUP_RESP_API_ADM_RADIO_RES_PRESENT ^*/

}rrc_rrm_erb_setup_resp_t; /*^ API, RRC_RRM_ERB_SETUP_RESP ^*/

/******************************************************************************
            RRC_RRM_ERB_SETUP_CNF
******************************************************************************/
typedef struct
{
     U8      erab_id;   /*^ M, 0, H, 1, 15 ^*/
}rrm_erab_item_t;

typedef struct
{
    U8       erab_id;        /*^ M, 0, H, 1, 15 ^*/
    U32      error_code;     /*^ M, 0, L, 0, 15 ^*/
} rrm_erab_error_info_t;


typedef struct
{

    rrc_counter_t       erab_count; /*^ M, 0, H, 0, 16 ^*/
    rrm_erab_item_t     erab_cnf_info[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_erab_cnf_list_t;

typedef struct
{
    rrc_counter_t          erab_count; /*^ M, 0, H, 0, 16 ^*/
    rrm_erab_error_info_t  erab_error_info[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_erab_error_list_t;

typedef struct
{
    rrc_bitmask_t   bitmask;                 /*^ BITMASK ^*/
#define RRC_RRM_ERB_SETUP_CNF_ERAB_CNF_LIST_PRESENT    0x01
#define RRC_RRM_ERB_SETUP_CNF_ERAB_ERROR_LIST_PRESENT  0x02
    U16                  ue_index;
    U16                  response_code; /*^ M, 0, H, 0, 2 ^*/

    rrm_erab_cnf_list_t    erab_cnf_list;
/*^ O, RRC_RRM_ERB_SETUP_CNF_ERAB_CNF_LIST_PRESENT ^*/

    rrm_erab_error_list_t  erab_error_list;
/*^ O, RRC_RRM_ERB_SETUP_CNF_ERAB_ERROR_LIST_PRESENT ^*/
} rrc_rrm_erb_setup_cnf_t; /*^ API, RRC_RRM_ERB_SETUP_CNF ^*/


/******************************************************************************
            RRC_RRM_ERB_MODIFY_REQ
******************************************************************************/
typedef struct
{
  U16                               ue_index;
  rrm_ue_agg_max_bit_rate_t         ue_agg_max_bit_rate;
/*^ M, 0, N, 0, 0 ^*/

  rrm_erab_to_be_setup_item_list_t  erab_to_be_modified_item_list;
/*^ M, 0, N, 0, 0 ^*/

}rrc_rrm_erab_modify_req_t; /*^ API, RRC_RRM_ERB_MODIFY_REQ ^*/

/******************************************************************************
            RRC_RRM_ERB_MODIFY_RESP
******************************************************************************/
typedef struct
{
    rrc_bitmask_t              bitmask;     /*^ BITMASK ^*/
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_DRB_TO_MODIFY_LIST_PRESENT        0x01
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_MAC_CONFIG_PRESENT                0x02
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_SPS_CONFIG_PRESENT                0x04
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_PHY_CONFIG_DED_PRESENT            0x08
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_MEAS_CONFIG_PRESENT               0x10
#define RRM_ERAB_MODIFY_RADIO_RES_CONFIG_DRB_FAILED_TO_MODIFY_LIST_PRESENT 0x20

    rrm_drb_to_add_info_list_t  drb_to_modify_list;
/*^ O, RRM_ERAB_MODIFY_RADIO_RES_CONFIG_DRB_TO_MODIFY_LIST_PRESENT ^*/

    rrm_mac_config_t            mac_config;
/*^ O, RRM_ERAB_MODIFY_RADIO_RES_CONFIG_MAC_CONFIG_PRESENT ^*/

    rrc_sps_config_t            sps_config;
/*^ O, RRM_ERAB_MODIFY_RADIO_RES_CONFIG_SPS_CONFIG_PRESENT ^*/

    rrm_meas_config_t           meas_config;
/*^ O, RRM_ERAB_SETUP_RADIO_RES_CONFIG_MEAS_CONFIG_PRESENT ^*/

    rrm_drb_failed_to_add_info_list_t  drb_failed_to_modify_list;
/*^ O, RRM_ERAB_MODIFY_RADIO_RES_CONFIG_DRB_FAILED_TO_MODIFY_LIST_PRESENT ^*/

} rrm_erab_modify_radio_res_config_t;


typedef struct
{
    rrc_bitmask_t             bitmask;    /*^ BITMASK ^*/
#define RRM_ERB_MODIFY_RESP_API_ADM_RADIO_RES_PRESENT   0x01

    U16                       ue_index;
    U16                       response; /*^ M, 0, H, 0, 2 ^*/

    rrm_erab_modify_radio_res_config_t    radio_rsource_config;
/*^ O, RRM_ERB_MODIFY_RESP_API_ADM_RADIO_RES_PRESENT ^*/

}rrc_rrm_erab_modify_resp_t; /*^ API, RRC_RRM_ERB_MODIFY_RESP ^*/

/******************************************************************************
            RRC_RRM_ERB_MODIFY_CNF
******************************************************************************/

typedef struct
{
    rrc_bitmask_t   bitmask;                 /*^ BITMASK ^*/
#define RRM_ERB_MODIFY_CNF_CONFIRM_LIST_PRESENT    0x01
#define RRM_ERB_MODIFY_CNF_ERROR_LIST_PRESENT      0x02

    U16                  ue_index;
    U16                  response;/*^ M, 0, H, 0, 2 ^*/

    rrm_erab_cnf_list_t    erab_cnf_list;
/*^ O, RRM_ERB_MODIFY_CNF_CONFIRM_LIST_PRESENT ^*/
    rrm_erab_error_list_t  erab_error_list;
/*^ O, RRM_ERB_MODIFY_CNF_ERROR_LIST_PRESENT ^*/
} rrc_rrm_erb_modify_cnf_t; /*^ API, RRC_RRM_ERB_MODIFY_CNF ^*/

/******************************************************************************
            RRC_RRM_UE_CONNECTION_RELEASE_IND
******************************************************************************/

typedef struct
{
    rrc_bitmask_t             bitmask;    /*^ BITMASK ^*/
/*Choice - set only one bit*/
#define RRM_REDIRECTED_CARRIER_INFO_EUTRA_PRESENT           0x01
#define RRM_REDIRECTED_CARRIER_INFO_GERAN_PRESENT           0x02
#define RRM_REDIRECTED_CARRIER_INFO_UTRA_FDD_PRESENT        0x04
#define RRM_REDIRECTED_CARRIER_INFO_UTRA_TDD_PRESENT        0x08
#define RRM_REDIRECTED_CARRIER_INFO_CDMA2000_HRPD_PRESENT   0x10
#define RRM_REDIRECTED_CARRIER_INFO_CDMA2000_1XRTT_PRESENT  0x20

    U16 eutra;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_EUTRA_PRESENT ^*/ /*0..65535*/

    carrier_freqs_geran_t geran;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_GERAN_PRESENT ^*/

    U16 utra_fdd;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_UTRA_FDD_PRESENT, H, 0, 16383 ^*/

    U16 utra_tdd;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_UTRA_TDD_PRESENT, H, 0, 16383 ^*/

    carrier_freq_cdma2000_t cdma2000_hrpd;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_CDMA2000_HRPD_PRESENT ^*/

    carrier_freq_cdma2000_t cdma2000_1xrtt;
/*^ O, RRM_REDIRECTED_CARRIER_INFO_CDMA2000_1XRTT_PRESENT ^*/
} rrm_redirected_carrier_info_t;

typedef struct
{
    U16 carrier_freq; /*0..65535*/
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_freq_priority_eutra_t;

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 8 ^*/
    rrm_freq_priority_eutra_t freq_priority_eutra[MAX_FREQ];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_freq_priority_list_eutra_t;

typedef struct
{
    carrier_freqs_geran_t carrier_freq;
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_freqs_priority_geran_t;

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 16 ^*/
    rrm_freqs_priority_geran_t freqs_priority_geran[MAX_GNFG];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_freqs_priority_list_geran_t;

typedef struct
{
    U16 carrier_freq; /*^ M, 0, H, 0, 16383 ^*/
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_freq_priority_utra_fdd_t;

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 16 ^*/
    rrm_freq_priority_utra_fdd_t freq_priority_utra_fdd[MAX_UTRA_FDD_CARRIER];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_freq_priority_list_utra_fdd_t;

typedef struct
{
    U16 carrier_freq; /*^ M, 0, H, 0, 16383 ^*/
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_freq_priority_utra_tdd_t;

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 16 ^*/
    rrm_freq_priority_utra_tdd_t freq_priority_utra_tdd[MAX_UTRA_TDD_CARRIER];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_freq_priority_list_utra_tdd_t;

typedef struct
{
    U8 band_class; /*^ M, 0, H, 0, 31 ^*/ /*rrm_bandclass_cdma2000_et*/
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_band_class_priority_hrpd_t;

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 32 ^*/
    rrm_band_class_priority_hrpd_t band_class_priority[MAX_CDMA_BAND_CLASS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_band_class_priority_list_hrpd_t;

typedef struct
{
    U8 band_class; /*^ M, 0, H, 0, 31 ^*/ /*rrm_bandclass_cdma2000_et*/
    U8 cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
} rrm_band_class_priority_1xrtt_t; /*same as rrm_band_class_priority_hrpd_t*/

typedef struct
{
    U8           count;                 /*^ M, 0, B, 1, 32 ^*/
    rrm_band_class_priority_1xrtt_t band_class_priority[MAX_CDMA_BAND_CLASS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
} rrm_band_class_priority_list_1xrtt_t;

typedef struct
{
    rrc_bitmask_t             bitmask;    /*^ BITMASK ^*/
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_EUTRA_PRESENT 0x01
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_GERAN_PRESENT 0x02
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_UTRA_FDD_PRESENT 0x04
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_UTRA_TDD_PRESENT 0x08
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_BAND_CLASS_PRIORITY_LIST_HRPD_PRESENT 0x10
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_BAND_CLASS_PRIORITY_LIST_1XRTT_PRESENT 0x20
#define RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_T320_PRESENT 0x40

    rrm_freq_priority_list_eutra_t freq_priority_list_eutra;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_EUTRA_PRESENT ^*/

    rrm_freqs_priority_list_geran_t freq_priority_list_geran;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_GERAN_PRESENT ^*/

    rrm_freq_priority_list_utra_fdd_t freq_priority_list_utra_fdd;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_UTRA_FDD_PRESENT ^*/

    rrm_freq_priority_list_utra_tdd_t freq_priority_list_utra_tdd;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_FREQ_PRIORITY_LIST_UTRA_TDD_PRESENT ^*/

    rrm_band_class_priority_list_hrpd_t band_class_priority_list_hrpd;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_BAND_CLASS_PRIORITY_LIST_HRPD_PRESENT ^*/

    rrm_band_class_priority_list_1xrtt_t band_class_priority_list_1xrtt;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_BAND_CLASS_PRIORITY_LIST_1XRTT_PRESENT ^*/

    U8 t320;
/*^ O, RRM_IDLE_MODE_MOBILITY_CONTROL_INFO_T320_PRESENT, H, 0, 6 ^*/
/*t320 ENUMERATED {min5, min10, min20, min30, min60, min120, min180}*/

} rrm_idle_mode_mobility_control_info_t;

typedef struct
{
    rrc_bitmask_t             bitmask;    /*^ BITMASK ^*/
#define RRC_RRM_UE_CONNECTION_RELEASE_IND_REDIRECTED_CARRIER_INFO_PRESENT   0x01
#define RRC_RRM_UE_CONNECTION_RELEASE_IND_IDLE_MODE_MOBILITY_CONTROL_PRESENT 0x02

    U16                  ue_index;
    rrm_cause_t          release_cause;
    rrm_redirected_carrier_info_t redirected_carrier_info;
/*^ O, RRC_RRM_UE_CONNECTION_RELEASE_IND_REDIRECTED_CARRIER_INFO_PRESENT ^*/

    rrm_idle_mode_mobility_control_info_t idle_mode_mobility_control;
/*^ O, RRC_RRM_UE_CONNECTION_RELEASE_IND_IDLE_MODE_MOBILITY_CONTROL_PRESENT ^*/

} rrc_rrm_ue_connection_release_ind_t;
/*^ API, RRC_RRM_UE_CONNECTION_RELEASE_IND ^*/

/******************************************************************************
            RRC_RRM_MEASURMENT_RESULTS_IND
******************************************************************************/
typedef struct
{
  U8    rsrp_result;    /*^ M, 0, H, 0, 97 ^*/
  U8    rsrq_result;    /*^ M, 0, H, 0, 34 ^*/
}rrc_meas_result_serv_cell_t;

typedef struct
{
  plmn_identity_t plmn_identity;
  U8    cell_identity[4];
/*^ M, 0, OCTET_STRING, FIXED ^*/ /* BIT STRING (SIZE (28)) */

}cell_global_id_eutra_t;

typedef struct
{
  U8    count;  /*^ M, 0, H, 0, 5 ^*/
  plmn_identity_t   cell_identity[5];   /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}plmn_identity_list2_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_EUTRA_CGI_INFO_PLMN_IDENTITY_LIST_PRESENT   0x01

  cell_global_id_eutra_t    cell_global_id;
  U8    tracking_area_code[2];
/*^ M, 0, OCTET_STRING, FIXED ^*/    /* BIT STRING (SIZE (16)) */

  plmn_identity_list2_t   plmn_identity_list;
/*^ O, MEAS_RESULT_EUTRA_CGI_INFO_PLMN_IDENTITY_LIST_PRESENT ^*/

}meas_result_eutra_cgi_info_t;

typedef struct
{
  rrc_bitmask_t bitmask;                                /*^ BITMASK ^*/

#define MEAS_RESULT_EUTRA_MEAS_RESULT_RSRP_PRESENT      0x01
#define MEAS_RESULT_EUTRA_MEAS_RESULT_RSRQ_PRESENT      0x02

  U8    rsrp_result;
/*^ O, MEAS_RESULT_EUTRA_MEAS_RESULT_RSRP_PRESENT, H, 0, 97 ^*/

  U8    rsrq_result;
/*^ O, MEAS_RESULT_EUTRA_MEAS_RESULT_RSRQ_PRESENT, H, 0, 34 ^*/

}meas_result_eutra_meas_result_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_EUTRA_CGI_INFO_PRESENT  0x01

  U16                               phys_cell_id;   /*^ M, 0, H, 0, 503 ^*/
  meas_result_eutra_cgi_info_t      cgi_info;
/*^ O, MEAS_RESULT_EUTRA_CGI_INFO_PRESENT ^*/

  meas_result_eutra_meas_result_t   meas_result;
}meas_result_eutra_t;

typedef struct
{
  U8                    count;
/*^ M, 0, H, 0, 8 ^*/

  meas_result_eutra_t   meas_result_eutra[MAX_CELL_REPORT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_result_list_eutra_t;

typedef struct
{
  rrc_bitmask_t         bitmask;                /*^ BITMASK ^*/
#define MEAS_RESULT_UTRA_PHYS_CELL_ID_FDD_PRESENT   0x01
#define MEAS_RESULT_UTRA_PHYS_CELL_ID_TDD_PRESENT   0x02

  U16 fdd;  /*^ O, MEAS_RESULT_UTRA_PHYS_CELL_ID_FDD_PRESENT, H, 0, 511 ^*/
  U8 tdd;   /*^ O, MEAS_RESULT_UTRA_PHYS_CELL_ID_TDD_PRESENT, H, 0, 127 ^*/
}meas_result_utra_phys_cell_id_t;

typedef struct
{
  plmn_identity_t plmn_identity;
  U8    cell_identity[4];
/*^ M, 0, OCTET_STRING, FIXED ^*/   /* BIT STRING (SIZE (28)) */

}cell_global_id_utra_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_UTRA_CGI_INFO_PLMN_IDENTITY_LIST_PRESENT    0x01
#define MEAS_RESULT_UTRA_CGI_INFO_LOCATION_AREA_CODE_PRESENT    0x02
#define MEAS_RESULT_UTRA_CGI_INFO_ROUTING_AREA_CODE_PRESENT     0x03
  cell_global_id_utra_t    cell_global_id;
  U8    location_area_code[2];
/*^ M, 0, OCTET_STRING, FIXED ^*/  /* BIT STRING (SIZE (16)) */

  U8    routing_area_code;      /* BIT STRING (SIZE (8)) */
  plmn_identity_list2_t   plmn_identity_list;
/*^ O, MEAS_RESULT_UTRA_CGI_INFO_PLMN_IDENTITY_LIST_PRESENT ^*/

}meas_result_utra_cgi_info_t;

typedef struct
{
  rrc_bitmask_t bitmask;                                /*^ BITMASK ^*/

#define MEAS_RESULT_UTRA_MEAS_RESULT_RSCP_PRESENT      0x01
#define MEAS_RESULT_UTRA_MEAS_RESULT_ECN0_PRESENT      0x02

  S8    utra_rscp;
/*^ O, MEAS_RESULT_UTRA_MEAS_RESULT_RSCP_PRESENT, B, -5, 91 ^*/

  U8    utra_ecn0;
/*^ O, MEAS_RESULT_UTRA_MEAS_RESULT_ECN0_PRESENT, H, 0, 49 ^*/

}meas_result_utra_meas_result_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_UTRA_CGI_INFO_PRESENT   0x01

  meas_result_utra_phys_cell_id_t   phys_cell_id;
  meas_result_utra_cgi_info_t       cgi_info;
/*^ O, MEAS_RESULT_UTRA_CGI_INFO_PRESENT ^*/

  meas_result_utra_meas_result_t    meas_result;
}meas_result_utra_t;

typedef struct
{
  U8                    count;
/*^ M, 0, H, 0, 8 ^*/

  meas_result_utra_t    meas_result_utra[MAX_CELL_REPORT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_result_list_utra_t;

typedef struct
{
  U16   arfcn;  /*^ M, 0, H, 0, 1023 ^*/
  U8    band_indicator;  /*^ M, 0, H, 0, 1 ^*/ /*ENUMERATED {dcs1800, pcs1900}*/
} carrier_freq_geran_t;

typedef struct
{
  plmn_identity_t plmn_identity;
  U8    location_area_code[2];
/*^ M, 0, OCTET_STRING, FIXED ^*/  /* BIT STRING (SIZE (16)) */

  U8    cell_identity[2];
/*^ M, 0, OCTET_STRING, FIXED ^*/  /* BIT STRING (SIZE (16)) */

}cell_global_id_geran_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_GERAN_CGI_INFO_ROUTING_AREA_CODE_PRESENT    0x01

  cell_global_id_geran_t    cell_global_id;
  U8    routing_area_code;
/*^ O, MEAS_RESULT_GERAN_CGI_INFO_ROUTING_AREA_CODE_PRESENT ^*/
/* BIT STRING (SIZE (8)) */

}meas_result_geran_cgi_info_t;

typedef struct
{
  U8    rssi;   /*^ M, MEAS_RESULT_UTRA_MEAS_RESULT_ECN0_PRESENT, H, 0, 63 ^*/
}meas_result_geran_meas_result_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_GERAN_CGI_INFO_PRESENT  0x01

  carrier_freq_geran_t  carrier_freq;
  phys_cell_id_geran_t  phys_cell_id;
  meas_result_geran_cgi_info_t      cgi_info;
/*^ O, MEAS_RESULT_GERAN_CGI_INFO_PRESENT ^*/

  meas_result_geran_meas_result_t   meas_result;
}meas_result_geran_t;

typedef struct
{
  U8                    count;
/*^ M, 0, H, 0, 8 ^*/

  meas_result_geran_t   meas_result_geran[MAX_CELL_REPORT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_result_list_geran_t;

typedef struct
{
  rrc_bitmask_t bitmask;                                /*^ BITMASK ^*/

#define CELL_GLOBAL_ID_CDMA2000_1XRTT_PRESENT       0x01
#define CELL_GLOBAL_ID_CDMA2000_HRPD_PRESENT        0x02

  U8    cell_global_id_1xrtt[6];
/*^ O, CELL_GLOBAL_ID_CDMA2000_1XRTT_PRESENT, OCTET_STRING, FIXED ^*/
/*BIT STRING (SIZE (47))*/

  U8    cell_global_id_hrpd[16];
/*^ O, CELL_GLOBAL_ID_CDMA2000_HRPD_PRESENT, OCTET_STRING, FIXED ^*/
/*BIT STRING (SIZE (128))*/

}cell_global_id_cdma2000_t;

typedef struct
{
  rrc_bitmask_t bitmask;                                /*^ BITMASK ^*/

#define MEAS_RESULT_CDMA2000_PILOT_PN_PHASE_PRESENT     0x01

  U16           pilot_pn_phase;
/*^ O, MEAS_RESULT_CDMA2000_PILOT_PN_PHASE_PRESENT, H, 0, 32767 ^*/

  U8            pilot_strength;                         /*^ M, 0, H, 0, 63 ^*/
}meas_result_cdma2000_meas_result_t;

typedef struct
{
  rrc_bitmask_t   bitmask;                              /*^ BITMASK ^*/

#define MEAS_RESULT_CDMA2000_CGI_INFO_PRESENT   0x01

  U16                                   phy_cell_id;    /*^ M, 0, H, 0, 511 ^*/
  cell_global_id_cdma2000_t             cgi_info;
/*^ O, MEAS_RESULT_CDMA2000_CGI_INFO_PRESENT ^*/

  meas_result_cdma2000_meas_result_t    meas_result;
}meas_result_cdma2000_t;

typedef struct
{
  U8                        count;
/*^ M, 0, H, 0, 8 ^*/

  meas_result_cdma2000_t    meas_result_cdma2000[MAX_CELL_REPORT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

}meas_result_list_cdma2000_t;

typedef struct
{
  U8                            pre_registration_status_hrpd;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_bool_et */

  meas_result_list_cdma2000_t   meas_result_list_cdma2000;
}meas_results_cdma2000_t;

typedef struct
{
  rrc_bitmask_t                 bitmask;                    /*^ BITMASK ^*/

#define RRM_MEAS_RESULT_LIST_EUTRA_PRESENT  0x01
#define RRM_MEAS_RESULT_LIST_UTRA_PRESENT   0x02
#define RRM_MEAS_RESULT_LIST_GERAN_PRESENT  0x04
#define RRM_MEAS_RESULTS_CDMA2000_PRESENT   0x08

  meas_result_list_eutra_t      meas_result_list_eutra;
/*^ O, RRM_MEAS_RESULT_LIST_EUTRA_PRESENT ^*/

  meas_result_list_utra_t       meas_result_list_utra;
/*^ O, RRM_MEAS_RESULT_LIST_UTRA_PRESENT ^*/

  meas_result_list_geran_t      meas_result_list_geran;
/*^ O, RRM_MEAS_RESULT_LIST_GERAN_PRESENT ^*/

  meas_results_cdma2000_t       meas_result_cdma2000;
/*^ O, RRM_MEAS_RESULTS_CDMA2000_PRESENT ^*/
}rrc_meas_result_neigh_cells_t;

typedef struct
{
    rrc_bitmask_t                   bitmask;                    /*^ BITMASK ^*/

#define RRM_MEASURMENT_RESULTS_NEIGH_CELLS_PRESENT    0x01

    U16                             ue_index;
    U8                              meas_id;
/*^ M, 0, H, 1, 32 ^*/

    rrc_meas_result_serv_cell_t     meas_result_serv_cell;
    rrc_meas_result_neigh_cells_t   meas_result_neigh_cells;
/*^ O, RRM_MEASURMENT_RESULTS_NEIGH_CELLS_PRESENT ^*/
} rrc_rrm_measurment_results_ind_t; /*^ API, RRC_RRM_MEASURMENT_RESULTS_IND ^*/

/*****************************************************************************
      RRC_RRM_CELL_DEL_RESP
 ******************************************************************************/

#define CELL_DEL_RESP_API_FAIL_CAUSE_PRESENCE_FLAG        0x01
typedef struct
{
   U16               presence_bitmask;   /*^ BITMASK ^*/
   rrc_cell_index_t  cell_index;
            /*^ M, 0, H, 0, 0 ^*/    /* MAX_NUM_CELLS - 1 */

    U8                response;
                /*^ M, 0, H, 0, 1 ^*/    /* rrc_return_et */

    U8                fail_cause;
                    /*^ O, CELL_DEL_RESP_API_FAIL_CAUSE_PRESENCE_FLAG, H, 0, 1 ^*/
                    /* rrm_fail_cause_et */

} rrm_rrc_cell_del_resp_t;/*^ API,  RRC_RRM_CELL_DELETE_RESP ^*/
/******************************************************************************
	RRC_RRM_UE_CAPABILITY_ENQUIRY_REQ
******************************************************************************/

typedef enum
{
	RRC_RAT_TYPE_EUTRA,
	RRC_RAT_TYPE_UTRA,
	RRC_RAT_TYPE_GERAN_CS,
	RRC_RAT_TYPE_GERAN_PS,
	RRC_RAT_TYPE_CDMA2000_1XRTT,
	RRC_RAT_TYPE_SPARE3,
	RRC_RAT_TYPE_SPARE2,
	RRC_RAT_TYPE_SPARE1
}rrc_rat_type_et;

typedef struct
{
	U8							rat_type_count; 				/*^ M, 0, H, 0, 8 ^*/
	U8				rat_type[MAX_RAT_CAPABILITY];	/*^ M, 0, OCTET_STRING, VARIABLE ^*/	   /* rrc_rat_type_et */
}rat_type_info_t;


/*****************************************************************************
      RRC_RRM_CELL_DEL_REQ
******************************************************************************/
typedef struct
{
  rrc_cell_index_t cell_index; /*^ M, 0, H, 0, 0 ^*/    /* MAX_NUM_CELLS - 1 */
}rrc_rrm_cell_del_req_t;/*^ API,  RRC_RRM_CELL_DELETE_REQ ^*/
typedef struct
{
	U16                  					bitmask;                    /*^ BITMASK ^*/

	#define RAT_TYPE_INFO_PRESENT	0x01

	U16                        	ue_Index; 
	rat_type_info_t    			rat_type_info;	/*^ O, RAT_TYPE_INFO_PRESENT,N,0,0 ^*/
}rrc_rrm_ue_capability_enquiry_req_t;
/*^ API, RRC_RRM_UE_CAPABILITY_ENQUIRY_REQ ^*/

/* ERB RELEASE COMMAND START */

/******************************************************************************
            RRC_RRM_ERB_RELEASE_REQ
******************************************************************************/
typedef struct
{
     U8                            erab_id;   
/*^ M, 0, H, 1, 15 ^*/ 
     rrm_cause_t   		cause;    
} rrm_erab_to_be_release_item_t;

typedef struct
{
     U16                      num_of_list;    
/*^ M, 0, H, 1, 16 ^*/ 
     rrm_erab_to_be_release_item_t  erab_to_be_release_item[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_erab_to_be_released_item_list_t;
typedef struct
{
    rrc_bitmask_t   bitmask;                 /*^ BITMASK ^*/
#define RRC_RRM_ERB_RELEASE_REQ_UE_AGG_MAX_BIT_RATE_PRESENT    0x01
    
     U16                               ue_index;
     rrm_ue_agg_max_bit_rate_t         ue_agg_max_bit_rate;
/*^ O, RRC_RRM_ERB_RELEASE_REQ_UE_AGG_MAX_BIT_RATE_PRESENT, N, 0, 0 ^*/

     rrm_erab_to_be_released_item_list_t  erab_to_be_released_item_list;
/*^ M, 0, N, 0, 0 ^*/

} rrc_rrm_erb_release_req_t; /*^ API, RRC_RRM_ERB_RELEASE_REQ ^*/

/******************************************************************************
            RRC_RRM_ERB_RELEASE_RESP
******************************************************************************/
typedef struct
{
     U16             num_of_list;    
/*^ M, 0, H, 1, 16 ^*/
     rrm_erab_item_t  drb_release_item[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_erab_release_item_list_t;
typedef struct
{
     U8                            erab_id;    /*^ M, 0, H, 1, 15 ^*/
     rrm_cause_t                   cause;
}rrm_erab_failed_to_release_item_t;

typedef struct
{
     U16                                num_of_list; 
/*^ M, 0, H, 1, 16 ^*/
     rrm_erab_failed_to_release_item_t  drb_failed_to_release_item[MAX_ERAB_COUNT];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_erab_failed_to_release_item_list_t; 

typedef struct
{
    rrc_bitmask_t   bitmask;                 /*^ BITMASK ^*/
#define RRC_RRM_DRB_RELEASE_ITEM_LIST_PRESENT            0x01
#define RRC_RRM_DRB_FAILED_TO_RELEASE_ITEM_LIST_PRESENT  0x02

    U16                               ue_index;
    rrc_response_t                    response;
    
    rrm_erab_release_item_list_t       drb_release_item_list;
    /*^ O, RRC_RRM_DRB_RELEASE_ITEM_LIST_PRESENT ^*/
    rrm_erab_failed_to_release_item_list_t  drb_failed_to_release_item_list;
    /*^ O, RRC_RRM_DRB_FAILED_TO_RELEASE_ITEM_LIST_PRESENT ^*/ 
}rrc_rrm_erb_release_resp_t; /*^ API, RRC_RRM_ERB_RELEASE_RESP ^*/

/******************************************************************************
            RRC_RRM_ERB_RELEASE_CNF
******************************************************************************/

typedef struct
{
    rrc_bitmask_t   bitmask;                 /*^ BITMASK ^*/
#define RRM_ERB_RELEASE_CNF_CONFIRM_LIST_PRESENT    0x01
#define RRM_ERB_RELEASE_CNF_ERROR_LIST_PRESENT      0x02
    U16                  ue_index;
    U16                  response;

    rrm_erab_cnf_list_t    erab_cnf_list;
/*^ O, RRM_ERB_RELEASE_CNF_CONFIRM_LIST_PRESENT ^*/
    rrm_erab_error_list_t  erab_error_list;
/*^ O, RRM_ERB_RELEASE_CNF_ERROR_LIST_PRESENT ^*/
} rrc_rrm_erb_release_cnf_t; /*^ API, RRC_RRM_ERB_RELEASE_CNF ^*/


/******************************************************************************
            RRC_RRM_ERB_RELEASE_IND
******************************************************************************/
typedef struct
{
    U16           ue_index;

     rrm_erab_to_be_released_item_list_t  erab_to_be_released_item_list;
 /*^ M, 0, N, 0, 0 ^*/
} rrc_rrm_erb_release_ind_t; /*^ API, RRC_RRM_ERB_RELEASE_IND ^*/ 

/******************************************************************************
	RRC_RRM_UE_CAPABILITY_ENQUIRY_RESP
******************************************************************************/


typedef enum
{
	rrm_rel8,
	rrm_relspare7,
	rrm_relspare6,
	rrm_relspare5,
	rrm_relspare4,
	rrm_relspare3,
	rrm_relspare2,
	rrm_relspare1
}rrc_access_stratum_release_et;

typedef enum
{
	rrm_cs2,
	rrm_cs4,
	rrm_cs8,
	rrm_cs12,
	rrm_cs16,
	rrm_cs24,
	rrm_cs32,
	rrm_cs48,
	rrm_cs64,
	rrm_cs128,
	rrm_cs256,
	rrm_cs512,
	rrm_cs1024,
	rrm_cs16384,
	rrm_spare2,
	rrm_spare1
}rrc_max_num_rohc_context_session_et;

typedef struct
{
	rrc_pdcp_rohc_profile_t    				rohc_profile;   /*^ M, 0, N, 0, 0 ^*/	
	rrc_max_num_rohc_context_session_et		max_num_rohc_context_session;	/*^ M, 0, H, 1, 15 ^*/   /* rrc_max_num_rohc_context_session_et */
}pdcp_parameters_t;

typedef struct
{
	U8		ue_TxAntennaSelectionSupported;	/*^ M, 0, H, 1, 1 ^*/      /* rrc_bool_et */
	U8 		ue_SpecificRefSigsSupported;	/*^ M, 0, H, 1, 1 ^*/      /* rrc_bool_et */
}physical_layer_params_t;

typedef struct
{
	U8		band_eutra;		/*^ M, 0, B, 1, 64 ^*/
	U8		half_duplex;	/*^ M, 0, H, 1, 1 ^*/	/* rrc_bool_et */
}supported_band_eutra_t;

typedef struct
{
	U8          count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	supported_band_eutra_t supported_band_eutra[MAX_BAND_EUTRA]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/	
}supported_band_list_eutra_t;

typedef struct
{
	supported_band_list_eutra_t		supported_band_list_eutra;	/*^ M, 0, H, 1, 64 ^*/
}rf_parameters_t;

typedef struct
{
	U8		inter_freq_need_for_gaps;	/*^ M, 0, H, 1, 1 ^*/	/* rrc_bool_et */
}inter_freq_band_info_t;

typedef struct
{
	U8          			count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	inter_freq_band_info_t 	inter_freq_band_info[MAX_BAND_EUTRA]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/	
}inter_freq_band_list_t;

typedef struct
{
	U8		inter_rat_need_for_gaps;	/*^ M, 0, H, 1, 1 ^*/	/* rrc_bool_et */
}inter_rat_band_info_t;

typedef struct
{
	U8          			count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	inter_rat_band_info_t 	inter_rat_band_info[MAX_BAND_EUTRA]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/	
}inter_rat_band_list_t;

typedef struct
{
	U16                  	bitmask;                    /*^ BITMASK ^*/
	#define EUTRA_INTER_RAT_BAND_LIST_PRESENT		0x01
	inter_freq_band_list_t	inter_freq_band_list;
	inter_rat_band_list_t	inter_rat_band_list;
	/*^ O, EUTRA_INTER_RAT_BAND_LIST_PRESENT,N,0,0 ^*/
}band_info_eutra_t;

typedef struct
{
	U8          		count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	band_info_eutra_t 	band_info_eutra[MAX_BAND_EUTRA]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/	
}band_list_eutra_t;

typedef struct
{
	band_list_eutra_t		band_list_eutra;
}meas_pameters_t;

typedef enum
{
	utra_fdd_bandI,
	utra_fdd_bandII,
	utra_fdd_bandIII,
	utra_fdd_bandIV,
	utra_fdd_bandV,
	utra_fdd_bandVI,
	utra_fdd_bandVII,
	utra_fdd_bandVIII,
	utra_fdd_bandIX,
	utra_fdd_bandX,
	utra_fdd_bandXI,
	utra_fdd_bandXII,
	utra_fdd_bandXIII,
	utra_fdd_bandXIV,
	utra_fdd_bandXV,
	utra_fdd_bandXVI
}supported_band_utra_fdd_et;

typedef struct
{
	U8          				count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	U8 	supported_band_utra_fdd[MAX_BAND_EUTRA];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* supported_band_utra_fdd_et */
}utra_fdd_t;

typedef enum
{
	tdd128_a,
	tdd128_b,
	tdd128_c,
	tdd128_d,
	tdd128_e,
	tdd128_f,
	tdd128_g,
	tdd128_h,
	tdd128_i,
	tdd128_j,
	tdd128_k,
	tdd128_l,
	tdd128_m,
	tdd128_n,
	tdd128_o,
	tdd128_p
}supported_band_utra_tdd128_et;

typedef struct
{
	U8          				count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	U8 	supported_band_utra_tdd128[MAX_BAND_EUTRA];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* supported_band_utra_tdd128_et */
}utra_tdd128_t;

typedef enum
{
	tdd384_a,
	tdd384_b,
	tdd384_c,
	tdd384_d,
	tdd384_e,
	tdd384_f,
	tdd384_g,
	tdd384_h,
	tdd384_i,
	tdd384_j,
	tdd384_k,
	tdd384_l,
	tdd384_m,
	tdd384_n,
	tdd384_o,
	tdd384_p
}supported_band_utra_tdd384_et;

typedef struct
{
	U8          				count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	U8 	supported_band_utra_tdd384[MAX_BAND_EUTRA];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* supported_band_utra_tdd384_et */
}utra_tdd384_t;

typedef enum
{
	tdd768_a,
	tdd768_b,
	tdd768_c,
	tdd768_d,
	tdd768_e,
	tdd768_f,
	tdd768_g,
	tdd768_h,
	tdd768_i,
	tdd768_j,
	tdd768_k,
	tdd768_l,
	tdd768_m,
	tdd768_n,
	tdd768_o,
	tdd768_p
}supported_band_utra_tdd768_et;

typedef struct
{
	U8		          				count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	U8 	supported_band_utra_tdd768[MAX_BAND_EUTRA];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* supported_band_utra_tdd768_et */
}utra_tdd768_t;

typedef enum
{
	geran_gsm450,
	geran_gsm480,
	geran_gsm710,
	geran_gsm750, 
	geran_gsm810, 
	geran_gsm850,
	geran_gsm900P,
	geran_gsm900E, 
	geran_gsm900R, 
	geran_gsm1800, 
	geran_gsm1900,
	geran_spare5, 
	geran_spare4, 
	geran_spare3, 
	geran_spare2, 
	geran_spare1
}supported_band_geran_et;

typedef struct
{
	U8		          			count;		/*^ M, 0, B, 1, 64 ^*/     /* MAX_BAND_EUTRA  */
	U8 	supported_band_geran[MAX_BAND_EUTRA];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* supported_band_geran_et */
}supported_band_list_geran_t;

typedef struct
{
	supported_band_list_geran_t		supported_band_list_geran;
	U8								inter_rat_ps_ho_to_geran;	/*^ M, 0, H, 1, 1 ^*/	/* rrc_bool_et */
}geran_t;

typedef struct
{
	U8		          			count;		/*^ M, 0, B, 1, 32 ^*/     /* MAX_CDMA_BAND_CLASS  */
	U8 	band_class_cdma2000[MAX_CDMA_BAND_CLASS];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* rrm_bandclass_cdma2000_et */
}supported_band_list_hrpd_t;

typedef enum
{
	tx_rx_single,
	tx_rx_dual
}tx_rx_config_hrpd_1xrtt;

typedef struct
{
	supported_band_list_hrpd_t		supported_band_list_hrpd;
	U8			tx_confiig_hrpd;	/*^ M, 0, H, 0, 16 ^*/   /* tx_rx_config_hrpd_1xrtt */
	U8			rx_confiig_hrpd;	/*^ M, 0, H, 0, 16 ^*/   /* tx_rx_config_hrpd_1xrtt */
}cdma2000_hrpd_t;

typedef struct
{
	U8		          			count;		/*^ M, 0, B, 1, 32 ^*/     /* MAX_CDMA_BAND_CLASS  */
	U8 	band_class_cdma2000[MAX_CDMA_BAND_CLASS];
		/*^ M,0,OCTET_STRING,VARIABLE ^*/   /* rrm_bandclass_cdma2000_et */
}supported_band_list_1xrtt_t;

typedef struct
{
	supported_band_list_1xrtt_t		supported_band_list_1xrtt;
	U8			tx_confiig_1xrtt;	/*^ M, 0, H, 0, 16 ^*/   /* tx_rx_config_hrpd_1xrtt */
	U8			rx_confiig_1xrtt;	/*^ M, 0, H, 0, 16 ^*/   /* tx_rx_config_hrpd_1xrtt */
}cdma2000_1x_rtt_t;

typedef struct
{
	U16                   bitmask;                    /*^ BITMASK ^*/
	
	#define INTER_RAT_UTRA_FDD_PRESENT				0x01
	#define INTER_RAT_UTRA_TDD128_PRESENT			0x02
	#define INTER_RAT_UTRA_TDD384_PRESENT			0x04	
	#define INTER_RAT_UTRA_TDD768_PRESENT			0x08
	#define INTER_RAT_UTRA_GERAN_PRESENT			0x10	
	#define INTER_RAT_UTRA_CDMA2000_HRPD_PRESENT	0x20	
	#define INTER_RAT_UTRA_CDMA2000_1XRTT_PRESENT	0x40		

	utra_fdd_t			utra_fdd;		/*^ O, INTER_RAT_UTRA_FDD_PRESENT,N,0,0 ^*/
	utra_tdd128_t		utra_tdd128;	/*^ O, INTER_RAT_UTRA_TDD128_PRESENT,N,0,0 ^*/
	utra_tdd384_t		utra_tdd384;	/*^ O, INTER_RAT_UTRA_TDD384_PRESENT,N,0,0 ^*/
	utra_tdd768_t		utra_tdd768;	/*^ O, INTER_RAT_UTRA_TDD768_PRESENT,N,0,0 ^*/
	geran_t				geran;			/*^ O, INTER_RAT_UTRA_GERAN_PRESENT,N,0,0 ^*/
	cdma2000_hrpd_t		cdma2000_hrpd;	/*^ O, INTER_RAT_UTRA_CDMA2000_HRPD_PRESENT,N,0,0 ^*/
	cdma2000_1x_rtt_t	cdma2000_1x_rtt;	/*^ O, INTER_RAT_UTRA_CDMA2000_1XRTT_PRESENT,N,0,0 ^*/
}inter_rat_Parameters_t;

typedef struct
{
	U16                   bitmask;                    /*^ BITMASK ^*/
	
	#define EUTRA_FEATURE_GROUP_INDICATORS_PRESENT		0x01
	
	rrc_access_stratum_release_et		access_stratum_release;	/*^ M, 0, H, 1, 7 ^*/   /* rrc_access_stratum_release_et */
	U8 									ue_category;	/*^ M, 0, B, 1, 5 ^*/
	pdcp_parameters_t					pdcp_parameters;
	physical_layer_params_t				physical_layer_params;
	rf_parameters_t						rf_parameters;
	meas_pameters_t						meas_prameters;
	U8									feature_group_indicators[4];
	/*^ O, EUTRA_FEATURE_GROUP_INDICATORS_PRESENT, OCTET_STRING, FIXED ^*/
/*BIT STRING (SIZE (32))*/
	inter_rat_Parameters_t				inter_rat_Parameters;
}eutra_radio_capability_info_def_t;

typedef struct
{
	U8 temp;	/*^ M, 0, B, 1, 5 ^*/
}non_critical_extensions_present_t;

typedef struct
{
	U16                   bitmask;                    /*^ BITMASK ^*/

	#define EUTRA_NON_CRITICAL_EXTENSIONS_PRESENT		0x01
	eutra_radio_capability_info_def_t	eutra_radio_capability_info_def;
	non_critical_extensions_present_t	non_critical_extensions_present;/*^ O, EUTRA_NON_CRITICAL_EXTENSIONS_PRESENT,N,0,0 ^*/
	
}eutra_radio_capability_info_t;

typedef struct
{
	U32			 len_utra_radio_capability_info ; /*^ M,0,H,0,256 ^*/  
	U8           utra_radio_capability_asn_buff[MAX_ASN_BUFFER]; /*^ M,0,OCTET_STRING,VARIABLE ^*/  	
}utra_radio_capability_info_t;

typedef struct
{
	U32			 len_cdma2000_radio_capability_info ; /*^ M,0,H,0,256 ^*/  
	U8           cdma2000_radio_capability_asn_buff[MAX_ASN_BUFFER]; /*^ M,0,OCTET_STRING,VARIABLE ^*/  	
}cdma2000_radio_capability_info_t;

typedef struct
{
	U32			 len_geran_cs_radio_capability_info ; /*^ M,0,H,0,256 ^*/  
	U8           geran_cs_radio_capability_asn_buff[MAX_ASN_BUFFER]; /*^ M,0,OCTET_STRING,VARIABLE ^*/  	
}geran_cs_radio_capability_info_t;

typedef struct
{
	U32			 len_geran_ps_radio_capability_info ; /*^ M,0,H,0,256 ^*/  
	U8           geran_ps_radio_capability_asn_buff[MAX_ASN_BUFFER]; /*^ M,0,OCTET_STRING,VARIABLE ^*/  	
}geran_ps_radio_capability_info_t;

typedef struct
{
	U16                   bitmask;                    /*^ BITMASK ^*/

	#define EUTRA_RADIO_CAPABILITY_PRESENT		0x01
	#define UTRA_RADIO_CAPABILITY_PRESENT   	0x02
	#define CDMA2000_RADIO_CAPABILITY_PRESENT  	0x04
	#define GERAN_CS_RADIO_CAPABILITY_PRESENT   0x08
	#define GERAN_PS_RADIO_CAPABILITY_PRESENT   0x10

	eutra_radio_capability_info_t eutra_radio_capability_info;
	/*^ O, EUTRA_RADIO_CAPABILITY_PRESENT,N,0,0 ^*/
	utra_radio_capability_info_t 		utra_radio_capability_info; /*^ O, UTRA_RADIO_CAPABILITY_PRESENT,N,0,0 ^*/
	cdma2000_radio_capability_info_t 	cdma2000_radio_capability_info;	/*^ O, CDMA2000_RADIO_CAPABILITY_PRESENT,N,0,0 ^*/
	geran_cs_radio_capability_info_t	geran_cs_radio_capability_info;	/*^ O, GERAN_CS_RADIO_CAPABILITY_PRESENT,N,0,0 ^*/
	geran_ps_radio_capability_info_t	geran_ps_radio_capability_info;	/*^ O, GERAN_PS_RADIO_CAPABILITY_PRESENT,N,0,0 ^*/
	
}rrc_radio_capability_info_t;

typedef struct
{
	U16                  					bitmask;                    /*^ BITMASK ^*/

	#define RADIO_CAPABILITY_INFO_PRESENT	0x01
	U16                        				ue_Index;
	U8        								result;       /*^ M, 0, H, 0, 1 ^*/   /* rrc_return_et */
	rrc_radio_capability_info_t    			radio_capability_info;	/*^ O, RADIO_CAPABILITY_INFO_PRESENT,N,0,0 ^*/
}rrc_rrm_ue_capability_enquiry_resp_t;
/*^ API, RRC_RRM_UE_CAPABILITY_ENQUIRY_RESP ^*/


typedef struct
{
	U16                        				ue_Index;
	rrc_radio_capability_info_t    			radio_capability_info;	/*^ M, RADIO_CAPABILITY_INFO_PRESENT,N,0,0 ^*/
}rrc_rrm_ue_capability_ind_t;
/*^ API, RRC_RRM_UE_CAPABILITY_IND ^*/

typedef struct
{
    #define RRC_RRM_UE_CONTXT_MOD_AMBR_PRESENT 0x01
    #define RRC_RRM_UE_CONTXT_MOD_CS_FALLBACK_PRESENT 0x02
    #define RRC_RRM_UE_CONTXT_MOD_SPID_PRESENT 0x04
    
    U16                                     bitmask;/*^ BITMASK ^*/
    U16                                     ue_index;
    U16                               SPID; /*^ O, RRC_RRM_UE_CONTXT_MOD_SPID_PRESENT, N, 0, 0 ^*/
    rrm_ue_agg_max_bit_rate_t         ue_agg_max_bit_rate; /*^ O, RRC_RRM_UE_CONTXT_MOD_AMBR_PRESENT, N, 0, 0 ^*/
    U32                               CS_Fallback_Indicator; /*^ O, RRC_RRM_UE_CONTXT_MOD_CS_FALLBACK_PRESENT, N, 0, 0 ^*/  
}rrc_rrm_ue_contxt_mod_req_t;
/*^ API, RRC_RRM_UE_CONTEXT_MOD_REQ ^*/
    
typedef struct
{
    rrc_bitmask_t         bitmask;   /*^ BITMASK ^*/
    #define UE_CONTEXT_MOD_RESP_API_FAIL_CAUSE_PRESENCE_FLAG        0x01
    U16                                     ue_index;
    U8                                      response;       /*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */
    rrm_cause_t           cause; /*^ O, UE_CONTEXT_MOD_RESP_API_FAIL_CAUSE_PRESENCE_FLAG ^*/
}rrc_rrm_ue_contxt_mod_resp_t;
/*^ API, RRC_RRM_UE_CONTEXT_MOD_RESP ^*/

typedef struct
{
    U16                                     ue_index;
    U8                                      response;       /*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */
}rrc_rrm_ue_contxt_mod_cnf_t;
/*^ API, RRC_RRM_UE_CONTEXT_MOD_CNF ^*/


#pragma pack(pop)

#endif
