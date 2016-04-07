
/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (C) 2009 Aricent Inc. All Rights Reserved.
 *
 ****************************************************************************
 *
 *  $Id: rrc_s1apOam_intf.h,v 1.3 2010/03/24 09:50:40 gur18569 Exp $
 *
 ****************************************************************************
 *
 *  File Description : This file contains the declarations of data types for
 *                     S1AP-OAM interface file.
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------
 *
 * $Log: rrc_s1apOam_intf.h,v $
 * Revision 1.3  2010/03/24 09:50:40  gur18569
 * Merged files from Rel 1.0 support branch
 *
 * Revision 1.2.2.3  2010/03/05 08:27:46  gur18569
 * removed guard timer
 *
 * Revision 1.2.2.2  2010/02/02 13:18:16  ukr15916
 * tabs->spaces expanded
 *
 * Revision 1.2.2.1  2010/01/25 09:04:50  gur18569
 * added reset_timer field
 *
 * Revision 1.2  2010/01/04 16:10:03  ukr15916
 * no message
 *
 * Revision 1.1.2.6  2009/11/26 18:33:42  ukr16018
 * Merge S1AP and RRC (from branch dev_rel_1_0).
 *
 * Revision 1.1.2.5  2009/11/19 05:34:37  gur20470
 * Modified MAX_IP_ADDRESS_LENGTH
 *
 * Revision 1.1.2.4  2009/11/11 04:36:39  gur18569
 * added max_reset_retries
 *
 * Revision 1.1.2.3  2009/10/29 13:19:17  gur18569
 * fixed errors
 *
 * Revision 1.1.2.2  2009/10/28 07:26:59  gur18569
 * changed TAC_OCTET_SIZE from 6 to 2
 *
 * Revision 1.1.2.1  2009/10/23 16:15:31  gur18569
 * Initial version
 *
 * Revision 1.1.2.1  2009/10/15 08:42:38  gur18569
 * Initial version
 *
 *
 *
 ****************************************************************************/

#ifndef _S1AP_OAM_INFT_H_
#define _S1AP_OAM_INFT_H_

/****************************************************************************
 * Project Includes
 ****************************************************************************/

#include "rrc_defines.h"
#include "s1ap_api.h"

/****************************************************************************
 * Exported Includes
 ****************************************************************************/



/****************************************************************************
 * Exported Definitions
 ****************************************************************************/
/* Hash Defined*/
#define MAX_NUM_MME                  3
#define MAX_NUM_IP_ADDR                     3
#define MAX_IP_ADDRESS_LENGTH           15
#define MAX_NUM_TAC                     256
#define MAX_CSG_ID_LIST                 256
#define MAX_PLMN_ID_BYTES               3
#define MAX_BC_PLMN                     6
#define TAC_OCTET_SIZE                  2
#define MACRO_ENB_ID_OCTET_SIZE         3
#define HOME_ENB_ID_OCTET_SIZE          4
#define CSG_ID_OCTET_SIZE               4
#define MAX_ENB_NAME_STR_SIZE           150

#define RRC_S1APOAM_MODULE_ID    RRC_OAM_MODULE_ID
/****************************************************************************
 * Exported Types
 ****************************************************************************/

#pragma pack(push, 1)


/******************************************************************************
                        S1AP_OAM_PROVISION_REQ
******************************************************************************/
typedef struct
{
    U8 ip_addr[MAX_IP_ADDRESS_LENGTH]; /*^ M,0,OCTET_STRING,FIXED ^*/
}ip_addr_t;

typedef struct
{
    /* number of ip addrs */
    U8           num_ip_addr; /*^ M,0,B,1,3 ^*/

    /* ip addresses of MMEs */
    ip_addr_t  ip_addr[MAX_NUM_IP_ADDR]; /*^ M,0,OCTET_STRING,VARIABLE ^*/

    /* port of MME with which SCTP association needs to be initiated */
    U16       port;    /*^ M,0,N,0,0 ^*/

    /* num of streams to be setup between MME and enb */
    U16          num_streams; /*^ M,0,B,2,10 ^*/

    /* timer for SCTP connection recovery */
    U16          heart_beat_timer; /*^ M,0,N,0,0 ^*/
}mme_comm_info_t;

typedef struct
{
    /* number of ip addr */
    U8           num_ip_addr; /*^ M,0,B,1,3 ^*/

    /* ip addresses of MMEs */
    ip_addr_t ip_addr[MAX_NUM_IP_ADDR];  /*^ M,0,OCTET_STRING,VARIABLE ^*/

    /* port of MME with which SCTP association needs to be initiated */
    U16       port;  /*^ M,0,N,0,0 ^*/
}enb_comm_info_t;

typedef struct
{
    U8 eNB_id[MACRO_ENB_ID_OCTET_SIZE]; /*^ M,0,OCTET_STRING,FIXED ^*/
}macro_enb_id_t;

typedef struct
{
    U8 eNB_id[HOME_ENB_ID_OCTET_SIZE]; /*^ M,0,OCTET_STRING,FIXED ^*/
}home_enb_id_t;

#define S1AP_OAM_MACRO_ENB_ID_PRESENT        0x01
#define S1AP_OAM_HOME_ENB_ID_PRESENT         0x02

typedef struct
{
    U8 presence_bitmask;    /*^ BITMASK ^*/

    macro_enb_id_t  macro_enb_id; /*^ O,1,N,0,0 ^*/

    home_enb_id_t   home_enb_id; /*^ O,2,N,0,0 ^*/
}enb_id_info_t;

typedef struct
{
    U8 plmn_id[MAX_PLMN_ID_BYTES]; /*^ M,0,OCTET_STRING,FIXED ^*/
}s1ap_plmn_identity_t;

typedef struct
{
    /*PLMN id */
    s1ap_plmn_identity_t plmn_identity; /*^ M,0,N,0,0 ^*/

    /* eNB id info */
    enb_id_info_t       enb_id; /*^ M,0,N,0,0 ^*/
}gb_enb_id_t;


typedef struct
{
    /* no of broadcast PLMN */
    U8           num_bplmn; /*^ M,0,B,1,6 ^*/

    s1ap_plmn_identity_t plmn_identity[MAX_BC_PLMN]; /*^ M,0,OCTET_STRING,VARIABLE ^*/
}bc_plmn_list_t;

typedef struct
{
    U8      tac[TAC_OCTET_SIZE]; /*^ M,0,OCTET_STRING,FIXED ^*/

    /* broadcast PLMN list info*/
    bc_plmn_list_t  bc_plmn_list; /*^ M,0,N,0,0 ^*/
}supp_ta_t;

typedef struct
{
    /* num of TAI supported */
    U16    num_supported_tais; /*^ M,0,B,1,256 ^*/

    supp_ta_t supp_tais[MAX_NUM_TAC]; /*^ M,0,OCTET_STRING,VARIABLE ^*/

}supp_ta_list_t;

typedef struct
{
    U8         csg_id[CSG_ID_OCTET_SIZE];   /*^ M,0,OCTET_STRING,FIXED ^*/
}csg_id_info_t;

typedef struct
{
    /* number of CSG Ids */
    U16   num_csg_ids; /*^ M,0,B,1,256 ^*/

    csg_id_info_t   csg_ids[MAX_CSG_ID_LIST]; /*^ M,0,OCTET_STRING,VARIABLE ^*/
}csg_id_list_t;

#define S1AP_OAM_ENB_NAME_PRESENT        0x01

typedef struct
{
    U16           bitmask;     /*^ BITMASK ^*/

    /* global enb id info */
    gb_enb_id_t     gb_enb_id; /*^ M,0,N,0,0 ^*/

    U8          enb_name[MAX_ENB_NAME_STR_SIZE]; /*^ O,1,OCTET_STRING,FIXED ^*/

    /* supported TAI info */
    supp_ta_list_t       supp_ta_list; /*^ M,0,N,0,0 ^*/

    /* CSG list info */
    csg_id_list_t      csg_id_list; /*^ M,0,N,0,0 ^*/

    U32          default_paging_drx;    /*^ M,0,L,32,0 ^*/
}s1_setup_req_t;

typedef struct
{
    /* number of MMEs supported */
    U8           num_mme;     /*^ M,0,H,1,3 ^*/

    /* Info needed to open an association with MME */
    mme_comm_info_t mme_comm_info[MAX_NUM_MME]; /*^ M,0,OCTET_STRING,VARIABLE ^*/

    /* SCTP connection info of enb */
    enb_comm_info_t enb_comm_info; /*^ M,0,N,0,0 ^*/

    /* Info needed to send an s1 setup request */
    s1_setup_req_t  s1_setup_req_parameters;  /*^ M,0,N,0,0 ^*/

    /* timer value that indicates waiting time after sending s1 setup request */
    U32          s1_setup_timer;    /*^ M,0,N,0,0 ^*/

    /* timer value that indicates waiting time after sending RESET request */
    U32          reset_ep_timer;    /*^ M,0,N,0,0 ^*/

    /* no of retries to be made when s1 setup req fails */
    U8           max_s1_setup_retries;    /*^ M,0,N,0,0 ^*/

    /* no of retries to be made when reset ack is not received */
    U8           max_reset_retries;    /*^ M,0,N,0,0 ^*/

    /* max no of UEs supported */
    U16           max_ue_supported;     /*^ M,0,B,1,600 ^*/
}s1apInfo_t;

typedef struct
{
  s1apInfo_t            s1apInfo;       /*^ M, 0, N, 0, 0 ^*/
}s1ap_oam_provision_req_t;              /*^ API, S1AP_OAM_PROVISION_REQ ^*/

/******************************************************************************
                        S1AP_OAM_PROVISION_RESP
******************************************************************************/
typedef struct
{
  U8            response;       /*^ M, 0, H, 1, 1 ^*/  /* rrc_return_et */
}s1ap_oam_provision_resp_t; /*^ API, S1AP_OAM_PROVISION_RESP ^*/


/******************************************************************************
                        S1AP_OAM_RESET_RESP
******************************************************************************/
typedef struct
{
  U8            response;       /*^ M, 0, H, 1, 1 ^*/  /* rrc_return_et */
}s1ap_oam_reset_resp_t; /*^ API, S1AP_OAM_RESET_RESP ^*/


/******************************************************************************
                        S1AP_OAM_STATS_RESP
******************************************************************************/

typedef struct
{
    /* Index of MME */
    U8 mme_id;      /*^ M, 0, N, 0, 0 ^*/

    /* Number of active UE associated logical S1
       connections handled by a MME */
    U16 count_of_ue;   /*^ M, 0, N, 0, 0 ^*/
}active_mme_ctx_t;

typedef struct
{
    /* Number of active MMEs */
    U8 active_mme_count;      /*^ M, 0, N, 0, 0 ^*/

    /* List of Stats information per MME*/
    active_mme_ctx_t active_mme_list[MAX_NUM_MME];  /*^ M,0,OCTET_STRING,VARIABLE ^*/
}s1ap_oam_stats_resp_t; /*^ API, S1AP_OAM_STATS_RESP ^*/

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




#endif /* _S1AP_OAM_INFT_H_ */
