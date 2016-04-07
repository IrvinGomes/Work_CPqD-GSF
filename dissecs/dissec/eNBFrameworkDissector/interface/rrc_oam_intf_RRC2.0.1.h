/*********************************************************************
 *
 *  FILE NAME   : rrc_oam_intf.h
 *
 *  DESCRIPTION : File contains the OAM interface API structures.
 *
 *  REVISION HISTORY :
 *
 *  DATE                Name            Reference        Comments
 *  may 11, 2009        Pankaj A        ---------        --------
 *
 *
 *  Copyright (c) 2009, Aricent Inc.
 *
 *******************************************************************/
#ifndef __RRC_OAM_INTF__
#define __RRC_OAM_INTF__

#include "rrc_defines.h"

#define MAC_IP_ADDRESS_LENGTH                   4
#define MAX_EXT_MODULES                         9 
#define MAX_FILE_NAME_SIZE                      256
#define MAX_LLIM_TIMER_INFO                     7
#define MAX_UECC_TIMER_INFO                     13
#define MAX_CSC_TIMER_INFO                      3
#define RRC_NUM_ESTABLISHMENT_CAUSE             8
#define RRC_NUM_RELEASE_CAUSE                   4
#define RRC_MAX_NUM_UE_STATUS                   100

typedef enum
{
    OAM_TRANSPORT_MODE_TCP,
    OAM_TRANSPORT_MODE_UDP
} rrc_oam_transport_mode_et;

typedef enum
{
    RRC_OAM_NOT_CONNECTED,
    RRC_OAM_CONNECTED
} rrc_oam_connection_status_et;

typedef enum
{
    OAM_LOG_LEVEL_FATAL,
    OAM_LOG_LEVEL_ERROR,
    OAM_LOG_LEVEL_WARNING,
    OAM_LOG_LEVEL_INFO,
    OAM_LOG_LEVEL_BRIEF,
    OAM_LOG_LEVEL_DETAILED
} rrc_oam_log_level_et;

typedef enum
{
    OAM_LOG_OFF,
    OAM_LOG_ON
} rrc_oam_log_on_off_et;


typedef enum
{
    CSC_CELL_SETUP_TIMER,               /* 0 */
    LLIM_CELL_SETUP_TIMER,              /* 1 */
    UECC_RRC_CONN_SETUP_TIMER,          /* 2 */
    LLIM_CREATE_UE_ENTITY_TIMER,        /* 3 */
    UECC_RRC_CONN_RECONFIG_TIMER,       /* 4 */
    LLIM_RECONFIG_UE_ENTITY_TIMER,      /* 5 */
    UECC_RRC_CONN_RELEASE_TIMER,        /* 6 */
    LLIM_DELETE_UE_ENTITY_TIMER,        /* 7 */
    LLIM_CONFIG_UE_SECURITY_TIMER,      /* 8 */
    UECC_RRC_MME_GUARD_TIMER,           /* 9 */
    UECC_RRM_UE_CAPABILITY_ENQ_TIMER,   /* 10 */
    CSC_CELL_RECONFIG_TIMER,            /* 11 */
    LLIM_CELL_RECONFIG_TIMER,           /* 12 */
    CSC_CELL_DELETE_TIMER,              /* 13 */
    UECC_UE_CONTXT_MODIFY_TIMER,       /* 14 */
    UECC_ERAB_SETUP_TIMER,        /* 15 */
    UECC_ERAB_MODIFY_TIMER,       /* 16 */
    UECC_ERAB_RELEASE_CMD_TIMER,  /* 17 */
    UECC_ERAB_RELEASE_IND_TIMER,  /* 18 */
    UECC_RLF_WAIT_FOR_REEST_TIMER,      /* 19 */
    UECC_RLF_UE_SUSPEND_TIMER,          /* 20 */
    UECC_HO_PREP_TIMER,                /* 21 */
    LLIM_SUSPEND_UE_ENTITY_TIMER,      /* 22 */
    RRC_OAM_TIMER_ID_LAST
} rrc_oam_timer_id_et;

#pragma pack(push, 1)

/******************************************************************************
*   RRC_OAM_COMMUNICATION_INFO_REQ
******************************************************************************/
#define RRC_OAM_IP_ADDR_PRESENT         0x01

typedef struct _rrc_oam_ext_comm_info_t
{
    U16             bitmask;                        /*^ BITMASK ^*/

    U8              ext_module_id;
/*^ M, 0, B, 1, 9 ^*/ /*  rrc_oam_ext_module_id_et */

    U8              transport_mode;
/*^ M, 0, H, 0, 1 ^*/  /* rrc_oam_transport_mode_et */

    U8              ip_addr[MAC_IP_ADDRESS_LENGTH];
/*^ O, RRC_OAM_IP_ADDR_PRESENT, OCTET_STRING, FIXED ^*/

    U16             port;                           /*^ M, 0, N, 0, 0 ^*/
} rrc_oam_ext_comm_info_t;

typedef struct _rrc_oam_communication_info_req_t
{
    rrc_oam_ext_comm_info_t ext_comm_info[MAX_EXT_MODULES];
/*^ M, 0, OCTET_STRING, FIXED ^*/

} rrc_oam_communication_info_req_t; /*^ API, RRC_OAM_COMMUNICATION_INFO_REQ ^*/

/******************************************************************************
*   RRC_OAM_COMMUNICATION_INFO_RESP
******************************************************************************/
typedef struct _rrc_oam_ext_connection_status_t
{
    U8              ext_module_id;
/*^ M, 0, B, 1, 9 ^*/ /* rrc_oam_ext_module_id_et */

    U8              connection_status;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_oam_connection_status_et */

} rrc_oam_ext_connection_status_t;

typedef struct _rrc_oam_communication_info_resp_t
{
    rrc_oam_ext_connection_status_t ext_connection_status[MAX_EXT_MODULES];
/*^ M, 0, OCTET_STRING, FIXED ^*/

} rrc_oam_communication_info_resp_t;
/*^ API, RRC_OAM_COMMUNICATION_INFO_RESP ^*/


/******************************************************************************
*   RRC_OAM_PROVISION_REQ
******************************************************************************/
typedef struct _rrc_oam_integrity_algorithms_t
{
    U8                                  num_algorithms; /*^ M, 0, B, 1, 2 ^*/
    U8  algorithms[RRC_MAX_INTEGRITY_ALGORITHMS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/ /* rrc_int_algorithm_et */

} rrc_oam_integrity_algorithms_t;

typedef struct _rrc_oam_ciphering_algorithms_t
{
    U8                                  num_algorithms; /*^ M, 0, B, 1, 3 ^*/
    U8  algorithms[RRC_MAX_CIPHERING_ALGORITHMS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/ /* rrc_ciph_algorithm_et */

} rrc_oam_ciphering_algorithms_t;

typedef struct _rrc_oam_supported_security_algorithms_t
{
    rrc_oam_integrity_algorithms_t      integrity_algorithms;
/*^ M, 0, N, 0, 0 ^*/

    rrc_oam_ciphering_algorithms_t      ciphering_algorithms;
/*^ M, 0, N, 0, 0 ^*/

} rrc_oam_supported_security_algorithms_t;

typedef struct _rrc_oam_timer_info_t
{
    U8              timer_id;
/*^ M, 0, H, 0, 23 ^*/ /* rrc_oam_timer_id_et */

    U16             timer_val;          /*^ M, 0, N, 0, 0 ^*/
} rrc_oam_timer_info_t;

typedef struct _rrc_oam_llim_timer_info_t
{
    U8                      num_of_timers;
/*^ M, 0, H, 0, 7 ^*/

    rrc_oam_timer_info_t    timer_info[MAX_LLIM_TIMER_INFO];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrc_oam_llim_timer_info_t;

typedef struct _rrc_oam_csc_timer_info_t
{
    U8                      num_of_timers;
/*^ M, 0, H, 0, 3 ^*/

    rrc_oam_timer_info_t    timer_info[MAX_CSC_TIMER_INFO];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrc_oam_csc_timer_info_t;

typedef struct _rrc_oam_uecc_timer_info_t
{
    U8                      num_of_timers;
/*^ M, 0, H, 0, 13  ^*/

    rrc_oam_timer_info_t    timer_info[MAX_UECC_TIMER_INFO];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrc_oam_uecc_timer_info_t;

#define RRC_OAM_LOG_FILE_NAME_PRESENT       0x01

typedef struct _rrc_oam_provision_req_t
{
    U16                         bitmask;                    /*^ BITMASK ^*/

    U8                          log_level;
/*^ M, 0, H, 0, 5 ^*/  /* rrc_oam_log_level_et */

    S8                          log_file_name[MAX_FILE_NAME_SIZE];
/*^ O, RRC_OAM_LOG_FILE_NAME_PRESENT, OCTET_STRING, FIXED ^*/

    U8                          phy_sync_mode;
/*^ M, 0, N, 0, 0 ^*/

    U16                         max_num_supported_ue;
/*^ M, 0, B, 1, 600 ^*/


    U8                          len_enb_gsn_address;
/*^ M, 0, B, 4, 20 ^*/

    U8                          enb_gsn_address[RRC_S1U_MAX_GSN_ADDR];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/


    rrc_oam_supported_security_algorithms_t supported_security_algorithms;
/*^ M, 0, N, 0, 0 ^*/


    rrc_oam_llim_timer_info_t   llim_timer_info;
/*^ M, 0, N, 0, 0 ^*/

    rrc_oam_csc_timer_info_t    csc_timer_info;
/*^ M, 0, N, 0, 0 ^*/

    rrc_oam_uecc_timer_info_t   uecc_timer_info;
/*^ M, 0, N, 0, 0 ^*/

    rrc_sfn_t                   non_broadcast_sfn_offset;
/*^ M, 0, B, 0,1023 ^*/

} rrc_oam_provision_req_t; /*^ API, RRC_OAM_PROVISION_REQ ^*/

/******************************************************************************
*   RRC_OAM_PROVISION_RESP
******************************************************************************/
typedef struct _rrc_oam_provision_resp_t
{
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_oam_provision_resp_t; /*^ API, RRC_OAM_PROVISION_RESP ^*/

/******************************************************************************
*   RRC_OAM_SET_LOG_LEVEL_REQ
******************************************************************************/
typedef struct _rrc_oam_set_log_level_req_t
{
    U8                  log_level;
/*^ M, 0, H, 0, 5 ^*/ /* rrc_oam_log_level_et */

} rrc_oam_set_log_level_req_t; /*^ API, RRC_OAM_SET_LOG_LEVEL_REQ ^*/

/******************************************************************************
*   RRC_OAM_SET_LOG_LEVEL_RESP
******************************************************************************/
typedef struct _rrc_oam_set_log_level_resp_t
{
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_oam_set_log_level_resp_t; /*^ API, RRC_OAM_SET_LOG_LEVEL_RESP ^*/

/******************************************************************************
*   RRC_OAM_LOG_ENABLE_REQ
******************************************************************************/
typedef struct _rrc_oam_log_enable_req_t
{
    U8                  log_on_off;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_oam_log_on_off_et */

} rrc_oam_log_enable_req_t; /*^ API, RRC_OAM_LOG_ENABLE_REQ ^*/

/******************************************************************************
*   RRC_OAM_LOG_ENABLE_RESP
******************************************************************************/
typedef struct _rrc_oam_log_enable_resp_t
{
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_oam_log_enable_resp_t; /*^ API, RRC_OAM_LOG_ENABLE_RESP ^*/

/******************************************************************************
*   RRC_OAM_GET_CELL_STATS_REQ
******************************************************************************/
typedef struct _rrc_oam_get_cell_stats_req_t
{
    rrc_cell_index_t    cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

} rrc_oam_get_cell_stats_req_t; /*^ API, RRC_OAM_GET_CELL_STATS_REQ ^*/

/******************************************************************************
*   RRC_OAM_GET_CELL_STATS_RESP
******************************************************************************/
typedef struct _rrc_oam_cell_stats_t
{
    U32                 num_conn_req[RRC_NUM_ESTABLISHMENT_CAUSE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U32                 num_conn_rej;           /*^ M, 0, N, 0, 0 ^*/
    U32                 num_conn_establ;        /*^ M, 0, N, 0, 0 ^*/
    U32                 num_conn_rel[RRC_NUM_RELEASE_CAUSE];
/*^ M, 0, OCTET_STRING, FIXED ^*/

    U32                 num_conn_reconf_msg;    /*^ M, 0, N, 0, 0 ^*/
} rrc_oam_cell_stats_t;

#define RRC_OAM_CELL_STATS_PRESENT          0x01

typedef struct _rrc_oam_get_cell_stats_resp_t
{
    U16                     bitmask;    /*^ BITMASK ^*/

    rrc_cell_index_t        cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

    U8                      response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

    rrc_oam_cell_stats_t    cell_stats;
/*^ O, RRC_OAM_CELL_STATS_PRESENT, N, 0, 0 ^*/

} rrc_oam_get_cell_stats_resp_t; /*^ API, RRC_OAM_GET_CELL_STATS_RESP ^*/

/******************************************************************************
*   RRC_OAM_GET_CELL_STATUS_REQ
******************************************************************************/
typedef struct _rrc_oam_get_cell_status_req_t
{
    rrc_cell_index_t    cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

} rrc_oam_get_cell_status_req_t; /*^ API, RRC_OAM_GET_CELL_STATUS_REQ ^*/

/******************************************************************************
*   RRC_OAM_GET_CELL_STATUS_RESP
******************************************************************************/
typedef struct _rrc_oam_cell_status_t
{
    U32                 num_ue;         /*^ M, 0, N, 0, 0 ^*/
    U32                 num_srb1;       /*^ M, 0, N, 0, 0 ^*/
    U32                 num_srb2;       /*^ M, 0, N, 0, 0 ^*/
    U32                 num_drb;        /*^ M, 0, N, 0, 0 ^*/
} rrc_oam_cell_status_t;

#define RRC_OAM_CELL_STATUS_PRESENT 0x01

typedef struct _rrc_oam_get_cell_status_resp_t
{
    U16                     bitmask;    /*^ BITMASK ^*/

    rrc_cell_index_t        cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

    U8                      response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

    rrc_oam_cell_status_t   cell_status;
/*^ O, RRC_OAM_CELL_STATUS_PRESENT, N, 0, 0 ^*/

} rrc_oam_get_cell_status_resp_t; /*^ API, RRC_OAM_GET_CELL_STATUS_RESP ^*/

/******************************************************************************
*   RRC_OAM_GET_UE_STATUS_REQ
******************************************************************************/
#define RRC_OAM_UE_INDEX_PRESENT            0x01

typedef struct _rrc_oam_get_ue_status_req_t
{
    U16                     bitmask;    /*^ BITMASK ^*/

    rrc_cell_index_t        cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

    rrc_ue_index_t          ue_index;
/*^ O, RRC_OAM_UE_INDEX_PRESENT, N, 0, 0 ^*/

} rrc_oam_get_ue_status_req_t; /*^ API, RRC_OAM_GET_UE_STATUS_REQ ^*/

/******************************************************************************
*   RRC_OAM_GET_UE_STATUS_RESP
******************************************************************************/
#define RRC_OAM_UE_STATUS_MME_UE_S1AP_ID_PRESENT   0x01

typedef struct _rrc_oam_ue_status_t
{
    U16                     bitmask;    /*^ BITMASK ^*/
    rrc_ue_index_t          ue_index;   /*^ M, 0, N, 0, 0 ^*/
    U16                     crnti;      /*^ M, 0, N, 0, 0 ^*/
    U8                      ue_state;   /*^ M, 0, N, 0, 0 ^*/
    U8                      ue_category;/*^ M, 0, N, 0, 0 ^*/
    U8                      num_srb;
/*^ M, 0, B, 1, 3 ^*/ /* RRC_MAX_NUM_SRB */

    U8                      num_drb;
/*^ M, 0, H, 0, 11 ^*/ /* RRC_MAX_NUM_DRB */

    U32                     enb_ue_s1ap_id; /*^ M, 0, H, 0, 16777215 ^*/
    U32                     mme_ue_s1ap_id;
/*^ O, RRC_OAM_UE_STATUS_MME_UE_S1AP_ID_PRESENT, N, 0, 0 ^*/

} rrc_oam_ue_status_t;

typedef struct _rrc_oam_ue_status_list_t
{
    U16                     num_ue_status;
/*^ M, 0, H, 0, 100 ^*/ /* RRC_MAX_NUM_UE_STATUS */

    rrc_oam_ue_status_t     ue_status[RRC_MAX_NUM_UE_STATUS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrc_oam_ue_status_list_t;

#define RRC_OAM_UE_STATUS_PRESENT           0x01

typedef struct _rrc_oam_get_ue_status_resp_t
{
    U16                         bitmask;        /*^ BITMASK ^*/

    rrc_cell_index_t            cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

    U8                          response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

    rrc_oam_ue_status_list_t    ue_status_list;
/*^ O, RRC_OAM_UE_STATUS_PRESENT, N, 0, 0 ^*/

} rrc_oam_get_ue_status_resp_t; /*^ API, RRC_OAM_GET_UE_STATUS_RESP ^*/

/******************************************************************************
*   RRC_OAM_RESET_CELL_STATS_REQ
******************************************************************************/
typedef struct _rrc_oam_reset_cell_stats_req_t
{
    rrc_cell_index_t    cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

} rrc_oam_reset_cell_stats_req_t; /*^ API, RRC_OAM_RESET_CELL_STATS_REQ ^*/

/******************************************************************************
*   RRC_OAM_RESET_CELL_STATS_RESP
******************************************************************************/
typedef struct _rrc_oam_reset_cell_stats_resp_t
{
    rrc_cell_index_t    cell_index;
/*^ M, 0, H, 0, 0 ^*/ /* MAX_NUM_CELLS - 1 */

    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_oam_reset_cell_stats_resp_t; /*^ API, RRC_OAM_RESET_CELL_STATS_RESP ^*/

/******************************************************************************
*   RRC_OAM_CLEANUP_RESP
******************************************************************************/
typedef struct _rrc_oam_cleanup_resp_t
{
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_oam_cleanup_resp_t; /*^ API, RRC_OAM_CLEANUP_RESP ^*/

/******************************************************************************
*   RRC_OAM_INIT_IND
******************************************************************************/
typedef struct _rrc_oam_init_ind_t
{
    U8 dummy;
} rrc_oam_init_ind_t; /*^ API, EMPTY, RRC_OAM_INIT_IND ^*/

#pragma pack(pop)

#endif /* __RRC_OAM_INTF__ */

