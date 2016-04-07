/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (c) Aricent.
 *
 ****************************************************************************
 *
 *  $Id: lteOamSimulator.h,v 1.1.4.1 2010/05/11 03:25:38 gur19836 Exp $ 

 ****************************************************************************
 *
 *  File Description : This file contains declarations for the OAM Interface
 *                     of MAC & RLC and OAM simulator
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------

 *
 ****************************************************************************/

#ifndef LTE_OAM_SIM_H
#define LTE_OAM_SIM_H


#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif






/****************************************************************************
 * Exported Includes
 ****************************************************************************/

/****************************************************************************
 * Exported Definitions
 ****************************************************************************/

/****************************************************************************
 * Exported Types
 ****************************************************************************/

/****************************************************************************
 * Exported Constants
 ****************************************************************************/
#define MAC_SUCCESS 1

#define NUM_OF_UE 300

#define MAC_MODULE_ID 7
#define RLC_MODULE_ID 6
#define PDCP_MODULE_ID 5
#define OAM_MODULE_ID 1
#define RRC_MODULE_ID 3 

/* OAM Simulator constants*/
//#define RX_PORT_MAC 13457
#define TX_PORT_MAC 12345
//#define RX_PORT_RLC 13555
#define TX_PORT_RLC 12340
//#define RX_PORT_PDCP 34323
#define TX_PORT_PDCP 34324

#define RX_PORT_OAM 13444

#define MAX_LINE_SIZE 80
#define MIN_UE_ID 10
#define MAX_VALID_UE_ID 0xFFF2
#define BUFFERSIZE 65535
#define WAIT_TIME 1

#define FILE_NAME 20
#define USER_INPUT 16
#define NUM_PARAM 28
#define START_UE_ID 10
#define START_CRNTI_ID 1000
#define IDX 1
#define UE_STATUS 2
#define MAX_LC 11
#define AM_MODE 2 
#define UM_MODE 1
#define RX 0
#define TX 1

#define MAC_LAYER 1
#define RLC_LAYER 2
#define PDCP_LAYER 3


#define UE_MAX_RANGE 300
#define MAX_UE  299
#define MIN_UE  0
/* MAC OAM API Ids */
/* API Ids 51-100 are reserved for OAM */
#define MAC_MESSAGE_API_START       1
/* MAC OAM API Ids */
#define MAC_INIT_LAYER_REQ         (MAC_MESSAGE_API_START + 1)
#define MAC_INIT_LAYER_CNF         (MAC_MESSAGE_API_START +2)
#define MAC_CLEANUP_LAYER_REQ      (MAC_MESSAGE_API_START +3)
#define MAC_CLEANUP_LAYER_CNF      (MAC_MESSAGE_API_START +4)
#define MAC_SET_LOG_LEVEL_REQ      (MAC_MESSAGE_API_START + 7)
#define MAC_SET_LOG_LEVEL_CNF      (MAC_MESSAGE_API_START + 8)
#define MAC_GET_STATUS_REQ         (MAC_MESSAGE_API_START +9)
#define MAC_GET_STATUS_CNF         (MAC_MESSAGE_API_START +10)
#define MAC_RESET_STATS_REQ        (MAC_MESSAGE_API_START +11)
#define MAC_RESET_STATS_CNF        (MAC_MESSAGE_API_START +12)

#define MAC_GET_STATS_REQ          (MAC_MESSAGE_API_START +13)
#define MAC_GET_STATS_CNF          (MAC_MESSAGE_API_START +14)
#define MAC_ENABLE_DISABLE_LOG_REQ (MAC_MESSAGE_API_START +17 )
#define MAC_GET_KPI_REQ            (MAC_MESSAGE_API_START +18)
#define MAC_GET_KPI_CNF            (MAC_MESSAGE_API_START +19)

#define MAC_GET_LOG_LEVEL_REQ      (MAC_MESSAGE_API_START + 20)
#define MAC_GET_LOG_LEVEL_RESP     (MAC_MESSAGE_API_START + 21)
#define MAC_ENABLE_LOG_CATEGORY_REQ  (MAC_MESSAGE_API_START + 22)
#define MAC_DISABLE_LOG_CATEGORY_REQ  (MAC_MESSAGE_API_START + 23)
#define MAC_GET_LOG_CATEGORY_REQ   (MAC_MESSAGE_API_START + 24)
#define MAC_GET_LOG_CATEGORY_RESP  (MAC_MESSAGE_API_START + 25)

#define MAC_GET_BUILD_INFO_CNF     (MAC_MESSAGE_API_START + 56) 
#define MAC_ENABLE_DL_SCH_STATS_REQ (MAC_MESSAGE_API_START + 64)
#define MAC_ENABLE_UL_SCH_STATS_REQ (MAC_MESSAGE_API_START + 65)

#define MAC_DL_THROUGHPUT       (MAC_MESSAGE_API_START + 100)
#define MAC_MESSAGE_API_END        (MAC_MESSAGE_API_START   + 200)

/*

#define MAC_INIT_LAYER_REQ          51
#define MAC_INIT_LAYER_CNF          52
#define MAC_CLEANUP_LAYER_REQ       53
#define MAC_CLEANUP_LAYER_CNF       54
#define MAC_GET_BUILD_INFO_REQ      55
#define MAC_GET_BUILD_INFO_CNF      56
#define MAC_SET_LOG_LEVEL_REQ       57
#define MAC_ENABLE_LOG_REQ          58
#define MAC_GET_STATUS_REQ          59 
#define MAC_GET_STATUS_CNF          60
#define MAC_RESET_STATS_REQ         61
#define MAC_GET_STATS_REQ           62 
#define MAC_GET_STATS_CNF           63
#define MAC_ENABLE_DL_SCH_STATS_REQ 64
#define MAC_ENABLE_UL_SCH_STATS_REQ 65
#define MAC_ENABLE_DISABLE_LOG_REQ  66
*/
/* Tags */
#define GET_PER_UE_STATUS       1
#define MAC_UE_STATUS           2
#define MAC_DL_LOG_CH_STATUS    3
#define MAC_UL_LOG_CH_STATUS    4
/*#define MAC_DL_THROUGHPUT       5*/
#define MAC_UL_THROUGHPUT       6

#define FAILURE 0
#define SUCCESS 1
#define DOWNLINK 1
#define UPLINK 2
#define GET_PER_UE_STATUS_LENGTH 6


/* RLC OAM APIs */
/* API Ids 51-100 are reserved for OAM */
/*
#define RLC_INIT_LAYER_REQ      51
#define RLC_INIT_LAYER_CNF      52
#define RLC_CLEANUP_LAYER_REQ   53
#define RLC_CLEANUP_LAYER_CNF   54
#define RLC_GET_BUILD_INFO_REQ  55
#define RLC_GET_BUILD_INFO_CNF  56
#define RLC_RESET_STATS_REQ     57
#define RLC_GET_STATS_REQ       58
#define RLC_GET_STATS_CNF       59
#define RLC_GET_STATUS_REQ      60
#define RLC_GET_STATUS_CNF      61
#define RLC_RESET_STATS_CNF     69
#define RLC_SET_LOG_LEVEL_REQ   70
#define RLC_SET_LOG_LEVEL_CNF   71
#define RLC_ENABLE_DISABLE_LOG_REQ 66
*/

/* RLC OAM API Ids */
#define  RLC_MESSAGE_API_START     MAC_MESSAGE_API_END
#define  RLC_INIT_LAYER_REQ        (RLC_MESSAGE_API_START + 1)
#define  RLC_INIT_LAYER_CNF        (RLC_MESSAGE_API_START + 2)

#define  RLC_RESET_STATS_REQ       (RLC_MESSAGE_API_START + 3)
#define  RLC_RESET_STATS_CNF       (RLC_MESSAGE_API_START + 4)
#define  RLC_GET_STATS_REQ         (RLC_MESSAGE_API_START + 5)
#define  RLC_GET_STATS_CNF         (RLC_MESSAGE_API_START + 6)
#define  RLC_GET_STATUS_REQ        (RLC_MESSAGE_API_START + 7)
#define  RLC_GET_STATUS_CNF        (RLC_MESSAGE_API_START + 8)
#define  RLC_SET_LOG_LEVEL_REQ     (RLC_MESSAGE_API_START + 9)
#define  RLC_SET_LOG_LEVEL_RESP    (RLC_MESSAGE_API_START + 10)
#define  RLC_GET_LOG_LEVEL_REQ     (RLC_MESSAGE_API_START + 11)
#define  RLC_GET_LOG_LEVEL_RESP    (RLC_MESSAGE_API_START + 12)
#define  RLC_ENABLE_LOG_CATEGORY_REQ (RLC_MESSAGE_API_START + 13)
#define  RLC_DISABLE_LOG_CATEGORY_REQ (RLC_MESSAGE_API_START + 14)
#define  RLC_GET_LOG_CATEGORY_REQ  (RLC_MESSAGE_API_START + 15)
#define  RLC_GET_LOG_CATEGORY_RESP (RLC_MESSAGE_API_START + 16)
#define  RLC_PACKET_DROP_REQ       (RLC_MESSAGE_API_START + 29)
#define RLC_CLEANUP_LAYER_CNF   (RLC_MESSAGE_API_START +54)
#define RLC_GET_BUILD_INFO_CNF  (RLC_MESSAGE_API_START +56)
#define RLC_SET_LOG_LEVEL_CNF   (RLC_MESSAGE_API_START +71)
#define  RLC_MESSAGE_API_END        (RLC_MESSAGE_API_START   + 200)


/* Tags */
#define RLC_UE_STATS            1
#define RLC_UE_STATUS           2
#define GET_TM_STATS_REQ        3
#define GET_TM_STATS_CNF        4
#define GET_UM_STATS_REQ        5
#define GET_UM_STATS_CNF        6
#define GET_AM_STATS_REQ        7
#define GET_AM_STATS_CNF        8
#define GET_UE_STATS_REQ        9
#define GET_UE_STATS_CNF        10
#define RLC_TX_UM_ENTITY_STATUS 11
#define RLC_RX_UM_ENTITY_STATUS 12
#define GET_LOAD_STATS_REQ 	17
#define GET_LOAD_STATS_CNF	18

#define RLC_COMMON_CHANNEL_STATUS_REQ       72
#define RLC_COMMON_CHANNEL_STATUS_CNF       81

#define CCCH_TX_SET              1
#define CCCH_RX_SET              2
#define CCCH_BI_SET		 3

#define BCCH_TX_SET              1
#define PCCH_TX_SET              1



/* RLC Return Types */
#define RLC_SUCCESS             1 
#define RLC_FAILURE             0
#define RLC_PARTIAL_SUCCESS     2

/* Error Codes */
#define RLC_SYNTAX_ERROR                12
#define RLC_LAYER_NOT_INITIALIZED       14
#define RLC_LAYER_ALREADY_INITIALIZED   15
#define RLC_NO_ACTIVE_UE_IN_SYSTEM      16
#if 0
/* PDCP OAM APIs */
/* API Ids 51-100 are reserved for OAM */

#define PDCP_INIT_LAYER_REQ      51
#define PDCP_INIT_LAYER_CNF      52
#define PDCP_CLEANUP_LAYER_REQ   53
#define PDCP_CLEANUP_LAYER_CNF   54
#define PDCP_GET_STATS_REQ       55
#define PDCP_GET_STATS_CNF       56
#define PDCP_GET_INTEGRITY_STATS_REQ 57
#define PDCP_GET_INTEGRITY_STATS_CNF 58 
#define PDCP_GET_ROHC_STATS_REQ  59
#define PDCP_GET_ROHC_STATS_CNF  60
#define PDCP_GET_CIPHERING_STATS_REQ 61
#define PDCP_GET_CIPHERING_STATS_CNF 62 
#define PDCP_GET_UE_STATS_REQ    63
#define PDCP_GET_UE_STATS_CNF    64

#define PDCP_GET_BUILD_INFO_CNF 65     
#define PDCP_RESET_STATS_CNF    66    
#define PDCP_GET_STATUS_REQ     67   
#define PDCP_GET_STATUS_CNF     68  
#define PDCP_SET_LOG_CNF        69 
#define PDCP_SET_LOG_REQ        70

#endif

/* PDCP OAM API Ids */
#define    PDCP_MESSAGE_API_START     RLC_MESSAGE_API_END
#define    PDCP_INIT_LAYER_REQ        (PDCP_MESSAGE_API_START + 1)
#define    PDCP_INIT_LAYER_CNF        (PDCP_MESSAGE_API_START + 2)
#define    PDCP_CLEANUP_LAYER_REQ     (PDCP_MESSAGE_API_START + 3)
#define    PDCP_CLEANUP_LAYER_CNF     (PDCP_MESSAGE_API_START + 4)
#define    PDCP_GET_BUILD_INFO_REQ    (PDCP_MESSAGE_API_START + 5)
#define    PDCP_GET_BUILD_INFO_CNF    (PDCP_MESSAGE_API_START + 6)
#define    PDCP_RESET_STATS_REQ       (PDCP_MESSAGE_API_START + 7)
#define    PDCP_RESET_STATS_CNF       (PDCP_MESSAGE_API_START + 8)
#define    PDCP_GET_STATS_REQ         (PDCP_MESSAGE_API_START + 9)
#define    PDCP_GET_STATS_RESP        (PDCP_MESSAGE_API_START + 10)
#define    PDCP_GET_STATUS_REQ        (PDCP_MESSAGE_API_START + 11)
//#define    PDCP_GET_STATUS_RESP       (PDCP_MESSAGE_API_START + 12)
#define    PDCP_SET_LOG_LEVEL_REQ     (PDCP_MESSAGE_API_START + 13)
#define    PDCP_SET_LOG_LEVEL_RESP    (PDCP_MESSAGE_API_START + 14)
#define    PDCP_GET_LOG_LEVEL_REQ     (PDCP_MESSAGE_API_START + 15)
#define    PDCP_GET_LOG_LEVEL_RESP    (PDCP_MESSAGE_API_START + 16)
#define    PDCP_ENABLE_LOG_CATEGORY_REQ (PDCP_MESSAGE_API_START + 17)
#define    PDCP_DISABLE_LOG_CATEGORY_REQ (PDCP_MESSAGE_API_START + 18)
#define    PDCP_GET_LOG_CATEGORY_REQ  (PDCP_MESSAGE_API_START + 19)
#define    PDCP_GET_LOG_CATEGORY_RESP (PDCP_MESSAGE_API_START + 20)
#define    PDCP_GET_STATS_CNF       (PDCP_MESSAGE_API_START + 56)
#define    PDCP_GET_STATUS_CNF     (PDCP_MESSAGE_API_START + 12)
#define    PDCP_MESSAGE_API_END          (PDCP_MESSAGE_API_START + 200)

 
/* OAM API commands list */
#if 0
enum OamCmdListT
{
    PDCP_INIT_LAYER_REQ = 0,    /*0*/
    PDCP_CLEANUP_LAYER_REQ,     /*1*/
    PDCP_GET_BUILD_INFO_REQ,    /*2*/
    PDCP_RESET_STATS_REQ,       /*3*/
    PDCP_GET_STATS_REQ,         /*4*/
    PDCP_GET_STATUS_REQ,        /*5*/

    PDCP_OAM_LAST_REQ,
};

/* OAM API responses list */
enum OamResponseCmdListT
{
    PDCP_INIT_LAYER_CNF = 0,        /*0*/
    PDCP_CLEANUP_LAYER_CNF,         /*1*/
    PDCP_GET_BUILD_INFO_CNF,        /*2*/
    PDCP_RESET_STATS_CNF,           /*3*/
    PDCP_GET_STATS_CNF,             /*4*/
    PDCP_GET_STATUS_CNF,            /*5*/

    PDCP_OAM_LAST_CNF,
};
#endif
/* OAM API TAGs list for commands */
enum OamCmdTagsListT
{
    PDCP_GET_INTEGRITY_STATS_REQ = 0,        /*0*/
    PDCP_GET_ROHC_STATS_REQ,                 /*1*/
    PDCP_GET_CIPHERING_STATS_REQ,            /*2*/
    PDCP_GET_UE_STATS_REQ,                   /*3*/

    PDCP_OAM_CMD_TAG_LAST,
};

/* OAM API TAGs list for responses */
enum OamResponseTagsListT
{
    PDCP_GET_INTEGRITY_STATS_CNF = 0,        /*0*/
    PDCP_GET_ROHC_STATS_CNF,                 /*1*/
    PDCP_GET_CIPHERING_STATS_CNF,            /*2*/
    PDCP_GET_UE_STATS_CNF,                   /*3*/
    PDCP_UE_STATS,                          /*4*/
    SRB_PDCP_UE_STATS,                       /*5*/
    DRB_PDCP_UE_STATS,                       /*6*/
    PDCP_UE_STATUS,                          /*7*/
    PDCP_SRB_ENTITY_STATUS,                  /*8*/
    PDCP_DRB_ENTITY_STATUS,                  /*9*/

    PDCP_OAM_RESPONSE_TAG_LAST,
};

/* Header Length */
#define API_HEADER_LEN 10









/* If possible we can include pdcpErrors.h  then we can remove following error enums from this file*/ 
 /* General response codes */
  #define PDCP_FAIL               0
 #define PDCP_SUCCESS            1
 #define PDCP_PARTIAL_SUCCESS    2


 /* PDCP errors groups */
 #define PDCP_ERR_SYSTEM_GROUP       0x0100
 #define PDCP_ERR_CONTEXT_GROUP      0x0200
 #define PDCP_ERR_TLV_PARSING_GROUP  0x0300
 #define PDCP_ERR_DATA_TRANSFER      0x0400

#endif /* Included LTE_OAM_SIM_H */
