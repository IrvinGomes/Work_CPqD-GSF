/*!
 *   \file   	rrm_defines.h
 *   \brief   	This file contains basic RRM types definitions.
 *   \date   	14 FEB 2012
 *   \author  	gur26991
 */
 /*!
 *   \copyright	Copyright (c) 2009, Aricent Inc. All Rights Reserved
 */

#ifndef _RRM_DEFINES_H_
#define _RRM_DEFINES_H_

#ifdef HAVE_CONFIG_H
/*! \headerfile <> config.h
 */
#include "config.h"
#endif
/*! \headerfile <> types.h
 *	\brief		 Basic types 
 */
#include <sys/types.h>
/*!	\headerfile <> cspl.h
 *	\brief		 CSPL types 
 */
/*! \headerfile <> stacklayer.h 
 */
#include <stacklayer.h>
/*! \headerfile <> rrm_api_types.h
 */
#include "rrm_api_types.h"
/*! \headerfile <> rrm_api_defines.h
 */
#include "rrm_api_defines.h"
/*! \headerfile <> rrc_rrm_intf.h
 */
#ifdef ALM_FRWK
/*! \headerfile <> alarm.h 
 */
	#include <alarm.h>
#endif

#ifdef ALM_FRWK
/*! \def ALARM_MSG_RRM
 */
    #define ALARM_MSG_RRM    		ALARM_MSG
 /*! \def ALARM_FMT_MSG_RRM
 */   
 #define ALARM_FMT_MSG_RRM    	ALARM_FMT_MSG
#else
/*! \def ALARM_MSG_RRM
 */
    #define ALARM_MSG_RRM(src_module_id, alarm_id, criticality)
 /*! \def ALARM_FMT_MSG_RRM
 */   
 #define ALARM_FMT_MSG_RRM(src_module_id, alarm_id, criticality , ...)
#endif
/*! \def RRM_RRC_SEND_FAIL
 */
#define RRM_RRC_SEND_FAIL		1
/*! \def RRM_ZERO
 */
#define RRM_ZERO                0

/*! \def RRM_HIGH_NIBBLE
 */
#define RRM_HIGH_NIBBLE		0xF0

/*! \def RRM_LOW_NIBBLE
 */
#define RRM_LOW_NIBBLE		0x0F

/*added for compilation will be exposed by MAC*/
/*! \def RRM_L2_KPI_STATS_IND
 */
#define RRM_L2_KPI_STATS_IND 41
/*! \def RRM_L2_GET_SNR_REPORT
 */
#define RRM_L2_GET_SNR_REPORT 42
/*! \def RRM_L2_SNR_REPORT
 */
#define RRM_L2_SNR_REPORT    43

/*  DYNAMIC ICIC CHANGES START  */

/*cause of UE Location from CELLM to UEM*/
/*! \enum   rrm_location_update_action_et
 *  \brief Action on UE location from CC to CE and vice-versa
 */
typedef enum
{
    UE_LOCATION_UPDATE_CE_TO_CC,
    UE_LOCATION_UPDATE_CC_TO_CE,
    INVALID_REASON
}rrm_location_update_action_et;

/*cause of UE OLPC Action from CELLM to UEM*/
/*! \enum   rrm_location_update_action_et
 *  \brief Action on UE location from CC to CE and vice-versa
 */
typedef enum
{
    UE_OLPC_REDUCE_POWER_ACTION,
    UE_OLPC_INVALID_POWER_ACTION
}rrm_olpc_reduce_power_action_et;

/*failure cause of Action from UEM to CELLM*/
/*! \enum  rrm_icic_action_response_et 
 *  \brief Response Action from UEM
 */
typedef enum
{
    UE_OLPC_REDUCE_POWER_ACTION_SUCCESS,
    UE_LOCATION_INFO_ACTION_SUCCESS,
    UE_OLPC_REDUCE_POWER_ACTION_FAILURE,
    UE_LOCATION_INFO_ACTION_FAILURE,
    UE_PARTIAL_SUCCESS_WITH_OLPC_REDUCE_POWER_ACTION_FAILED,
    UE_PARTIAL_SUCCESS_WITH_LOCATION_INFO_ACTION_FAILED,
    UE_COMBINED_ACTION_FAILURE,
    UE_COMBINED_ACTION_SUCCESS
}rrm_icic_action_response_et;

/*  DYNAMIC ICIC CHANGES END  */

/*response cause of CELLM to MIF*/
/*! \enum   rrm_reponse_et
 *  \brief response cause of cellm and mif
 */
typedef enum
{
    RRM_CELL_PARSING_FAILED,
    RRM_CELL_TRANS_ID_UNMATCHED,
    RRM_CELL_SUCCESS_RESP
}rrm_reponse_et;

/*! \def NO_OF_MODULES
 */
#define NO_OF_MODULES                           5
/*! \def RRMRRC
 */
#define RRMRRC                                  1
/*! \def RRMITFMGR
 */
#define RRMITFMGR                               2
/*! \def RRM_API_HEADER_SIZE
 */
#define RRM_API_HEADER_SIZE 					16

/*! \def RRM_INTERFACE_API_HEADER_SIZE
 */
#define RRM_INTERFACE_API_HEADER_SIZE 			12

/*! \def RRM_INTERFACE_L2_API_HEADER_SIZE
 *   The RRM L2INTERFACE API HEADER SIZE includes cell_index to support
 *   multiple cells.
 */
/*BUG 585, MULTISECTOR FEATURE*/
#ifdef MULTISECTOR_ENABLE
#define RRM_INTERFACE_L2_API_HEADER_SIZE        12
#else
#define RRM_INTERFACE_L2_API_HEADER_SIZE        12
#endif

/*! \def L2_RRM_API_HEADER_LEN 
 */
/* Fix for MAC API 12 bytes */
#define L2_RRM_API_HEADER_LEN         12

/* Fix for MAC API 12 bytes */

/*! \def ENDIAN_INIT
 */
#define ENDIAN_INIT 							1
/*! \def IS_LITTLE_ENDIAN
 */
//#define IS_LITTLE_ENDIAN(endian_check) 			(*((U8*)&endian_check)?1:0)
/*! \def IS_BIG_ENDIAN
 */
#define IS_BIG_ENDIAN(endian_check) 			(*((U8*)&endian_check)?0:1)

/*! \def RRM_NULL
 */
#define RRM_NULL        						0
#ifndef _PNULL_
#define _PNULL_
/*! \def RRM_PNULL
 */
#define RRM_PNULL           					((void *)0)
#endif

/*! \def RRM_PNULL
 */
#define RRM_PNULL           					((void *)0)

/*! \def RRM_API_ID_INDEX
 */
#define RRM_API_ID_INDEX						6
/*! \def RRM_MSG_SIZE_INDEX
 */
#define RRM_MSG_SIZE_INDEX						8
/*! \def RRM_SRC_ID_INDEX
 */
#define	RRM_SRC_ID_INDEX						2

/*! \def RRM_CSPL_API_ID_INDEX
 */
#define RRM_CSPL_API_ID_INDEX                   5
/*! \def RRM_INTF_TRANS_ID_INDEX
 */
#define RRM_INTF_TRANS_ID_INDEX                 0
/*! \def RRM_INTF_MSG_ID_INDEX
 */
#define RRM_INTF_MSG_ID_INDEX                   8
#ifndef PNULL
/*! \def PNULL
 */
#define PNULL 									NULL
#endif

/*! \def RRM_APPS_MODULE_ID
 */
#define RRM_APPS_MODULE_ID						6
/*! \def UNKNOWN_MODULE_NAME
 */
#define UNKNOWN_MODULE_NAME						8
/*! \def RRM_MAX_MTU_SIZE
 */
#define RRM_MAX_MTU_SIZE               			64*1024
/*! \def SH_HDRSIZE
 */
#define SH_HDRSIZE                     			16
/*! \def MAX_RX_DATA_SIZE
 */
#define MAX_RX_DATA_SIZE               			65535
/*! \def MSG_API_HDR_SIZE
 */
#define MSG_API_HDR_SIZE						10
/*! \def IP_PORT_STR_MAX_LEN
 */
#define IP_PORT_STR_MAX_LEN						10
/*! \def NEXT_EXPIRY_TIMER
 */
#define NEXT_EXPIRY_TIMER  						500

/* Interface Heade rOffsets */
/*! \def EXT_MSG_API_HDR_SIZE
 */
#define EXT_MSG_API_HDR_SIZE            		12
#define L2_EXT_MSG_API_HDR_SIZE            		12
/*! \def EXT_MSG_TRANSACTION_ID_OFFSET
 */
#define EXT_MSG_TRANSACTION_ID_OFFSET  			0
/*! \def EXT_MSG_SRC_MODULE_ID_OFFSET
 */
#define EXT_MSG_SRC_MODULE_ID_OFFSET  			2
/*! \def EXT_MSG_DEST_MODULE_ID_OFFSET
 */
#define EXT_MSG_DEST_MODULE_ID_OFFSET  			4
/*! \def EXT_MSG_API_OFFSET
 */
#define EXT_MSG_API_OFFSET          			6
/*! \def EXT_MSG_BUF_LEN_OFFSET
 */
#define EXT_MSG_BUF_LEN_OFFSET      			8

/*! \def EXT_CELL_INDEX_OFFSET
 */
#define EXT_CELL_INDEX_OFFSET                   10


/* STACKAPI Header Offsets */
/*! \def STACK_API_SRC_MODULE_ID_OFFSET
 */
#define STACK_API_SRC_MODULE_ID_OFFSET          1
/*! \def STACK_API_DEST_MODULE_ID_OFFSET
 */
#define STACK_API_DEST_MODULE_ID_OFFSET         3
/*! \def STACK_API_API_OFFSET
 */
#define STACK_API_API_OFFSET                    5
/*! \def STACK_API_PARAM_LEN_OFFSET
 */
#define STACK_API_PARAM_LEN_OFFSET              7
/*! \def STACK_API_PAYLOAD_LEN_OFFSET
 */
#define STACK_API_PAYLOAD_LEN_OFFSET            11

/*! \def RRM_API_PRIORITY
 */
#define RRM_API_PRIORITY            			0
/*! \def RRM_VERSION_ID
 */
#define RRM_VERSION_ID              			0x01

/* OAM Agent Module Id - 1 */
#ifndef RRM_OAM_MODULE_ID
/*! \def RRM_MIN_EXT_MODULE_ID
 */
#define RRM_MIN_EXT_MODULE_ID   				1
/*! \def RRM_OAM_MODULE_ID
 */
#define RRM_OAM_MODULE_ID       				(RRM_MIN_EXT_MODULE_ID + 0)
/*! \def RRM_MAX_EXT_MODULE_ID
 */
#define RRM_MAX_EXT_MODULE_ID   				 RRM_OAM_MODULE_ID
#endif
/* RRM Module Id = 2 */
/*! \def RRM_MODULE_ID
 */
#ifndef RRM_MODULE_ID
/*! \def RRM_MODULE_ID
 */
#define RRM_MODULE_ID							    0x2
#endif

#ifndef RRC_MODULE_ID
/*! \def RRC_MODULE_ID
 */
#define RRC_MODULE_ID							    0x3
#endif

/*! \def RRM_L2_MODULE_ID
 */
#define RRM_L2_MODULE_ID                            0x7

#ifndef OAM_IPR
/*PDCP module id*/
/*! \def PDCP_MODULE_ID
 */
#define PDCP_MODULE_ID                              0x5
/*MAC module id*/
/*! \def MAC_MODULE_ID
 */
#define MAC_MODULE_ID                               0x7
#endif

/*! \def RRM_ONE_THOUSAND_MS
 */
#define RRM_ONE_THOUSAND_MS					1000
/*PLATFORM module id*/
/*! \def RRM_PLATFORM_MODULE_ID
 */
#define RRM_PLATFORM_MODULE_ID                      0x74
/* SON Module Id = 100 */
/*! \def RRM_SON_MODULE_ID
 */
#define RRM_SON_MODULE_ID       				0x64
/*! \def RRM_SON_APPS_MODULE_ID
 */
#define RRM_SON_APPS_MODULE_ID                                  0x6466 
/*! \def RRM_SON_ANR_MODULE_ID
 */
#define RRM_SON_ANR_MODULE_ID       				0x6467
/*! \def RRM_SON_ES_MODULE_ID
 */
#define RRM_SON_ES_MODULE_ID        				0x6468
/*! \def RRM_SON_NMM_MODULE_ID
 */
#define RRM_SON_NMM_MODULE_ID       				0x6469

/*! \def RRM_SON_MLB_MODULE_ID
 */
#define RRM_SON_MLB_MODULE_ID                                   0x646B

/*! \def RRM_SON_MRO_MODULE_ID
 */
#define RRM_SON_MRO_MODULE_ID                                   0x646A


/* Internal Module Ids MIF-21, CellM-22, UeM-23*/
/*! \def RRM_MIN_INT_MODULE_ID
 */
#define RRM_MIN_INT_MODULE_ID   				 RRM_MAX_EXT_MODULE_ID + 20
/*! \def RRM_MIF_MODULE_ID
 */
#define RRM_MIF_MODULE_ID                       (RRM_MIN_INT_MODULE_ID + 0)
/*! \def RRM_CM_MODULE_ID
 */
#define RRM_CM_MODULE_ID                        (RRM_MIN_INT_MODULE_ID + 1)
/*! \def RRM_UEM_MODULE_ID
 */
#define RRM_UEM_MODULE_ID   					(RRM_MIN_INT_MODULE_ID + 2)
/*! \def RRM_MAX_INT_MODULE_ID
 */
#define RRM_MAX_INT_MODULE_ID 					RRM_UEM_MODULE_ID
/*! \def RRM_FULL_INTERFACE_HEADERS_SIZE
 */
#define RRM_FULL_INTERFACE_HEADERS_SIZE \
        (RRM_API_HEADER_SIZE + RRM_INTERFACE_API_HEADER_SIZE)
/*! \def RRM_BUFFER_SHOULD_BE_RELEASED
 */
#define RRM_BUFFER_SHOULD_BE_RELEASED 			7
/*! \def RRM_MAX_UTRAN_NBRS
 */
#define RRM_MAX_UTRAN_NBRS                      16
#define RRM_MAX_GERAN_NBRS                      16

#ifdef SON_CDMA_COMPILE
#define RRM_MAX_CDMA_NBRS                       72
#define RRM_MAX_CDMA_1X_RTT_NBRS                36
#define RRM_MAX_CDMA_HRPD_NBRS                  36
#endif

/*! \def RRM_UTRAN_CELL_IDENTITY_OCTETS
*/
/*+ Fix for array bounds +*/
#define RRM_UTRAN_CELL_IDENTITY_OCTETS                   2
/*- Fix for array bounds -*/
/*! \def RRM_MAX_RNC_ID
*/
#define RRM_MAX_RNC_ID                                   4095


/*! \def MAX_UMTS_NCL_ROWS
 */
#define MAX_UMTS_NCL_ROWS 						32
/*! \def MAX_UMTS_NCL_COLS
 */
#define MAX_UMTS_NCL_COLS 						32
/*! \def MAX_EAID
 */
#define MAX_EAID								3
/*! \def MAX_QOS_CONFIG_PARAMS
 */
#define MAX_QOS_CONFIG_PARAMS					9
/*! \def MAX_NO_INTER_FREQ
 */
#define MAX_NO_INTER_FREQ 						8
/*! \def MAX_NO_EUTRAN_TO_UTRAN_FDD
 */
#define MAX_NO_EUTRAN_TO_UTRAN_FDD 				16
/*! \def MAX_NO_EUTRAN_TO_UTRAN_TDD
 */
#define MAX_NO_EUTRAN_TO_UTRAN_TDD              16
/*! \def MAX_NO_GERAN_FREQ_GROUUP
 */
#define MAX_NO_GERAN_FREQ_GROUUP 				16

#ifdef SON_CDMA_COMPILE
/*! \def MAX_NO_CDMA_FREQ_GROUUP
 *  */
#define MAX_NO_CDMA_FREQ_GROUUP                 16
#endif


/*! \def MAX_NO_DRX_PROFILE
 */
#define MAX_NO_DRX_PROFILE 						2 /* assuming DRX for two profiles only */
                                                /*  1 for SPS and other for non-SPS services */
/*! \def MAX_NO_SRB
 */
#define	MAX_NO_SRB 								2 /** Choice of default configuration**/
						   						/**	  or else parameters			    **/
/*! \def MAX_NO_INTER_FREQ_PARAM
 */
#define MAX_NO_INTER_FREQ_PARAM 				8
/*! \def MAX_MCC_DIGITS
 */
#define MAX_MCC_DIGITS 							3 /** also defined in rrm_cell_context.h    */
/*! \def MAX_MNC_DIGITS
 */
#define MAX_MNC_DIGITS 							3 /** also defined in rrm_cell_context.h    */
/*! \def MAX_CID_BYTES
 */
#define MAX_CID_BYTES 							16
/*! \def MAX_SUBFRAME_ALLOCATIONS
 */
#define MAX_SUBFRAME_ALLOCATIONS 				4
/*! \def MAX_MB_SFN_SUBFRAME_LIST
 */
#define MAX_MB_SFN_SUBFRAME_LIST 				8
/*! \def CELLM_RRMIM_BASE
 */
#define CELLM_RRMIM_BASE 						0

/*!< MACRO for filling functions for UEM */
/*! \def MAC_UE_PRIORITY
 */
#define MAC_UE_PRIORITY 						0
/*! \def CODE_BOOK_INDEX
 */
#define CODE_BOOK_INDEX 					    0 	
/*! \def MAX_NUM_SNR_VALUES
 */
#define MAX_NUM_SNR_VALUES 						20
/*! \def LOGICAL_CH_GRP_SRB1_DEFAULT_VAL
 */
#define LOGICAL_CH_GRP_SRB1_DEFAULT_VAL 		0
/*! \def PRIORITY_SRB1_DEFAULT_VAL
 */
#define PRIORITY_SRB1_DEFAULT_VAL 				1
/*! \def SRB1_PRIORITY
 */
#define SRB1_PRIORITY 							1
/*! \def LOGICAL_CH_GRP_SRB2_DEFAULT_VAL
 */
#define LOGICAL_CH_GRP_SRB2_DEFAULT_VAL 		0
/*! \def PRIORITY_SRB2_DEFAULT_VAL
 */
#define PRIORITY_SRB2_DEFAULT_VAL 				3
/*! \def SRB2_PRIORITY
 */
#define SRB2_PRIORITY 							1

#ifndef OAM_IPR
/*! \def NON_GBR
 */
#define NON_GBR 								0
/*! \def GBR
 */
#define GBR 									1
#endif

/*! \def NO_DRX_PROFILE
 */
#define NO_DRX_PROFILE                          255
/*! \def MAX_LC_ID_INDEX
 */
#define MAX_LC_ID_INDEX                         8
/*! \def MAX_DRB_ID_INDEX
 */
#define MAX_DRB_ID_INDEX                        32
/*! \def SAP_FLAGS
 */
#define SAP_FLAGS                               15
/*! \def MAX_OUTPUT_POWER
 */
#define MAX_OUTPUT_POWER                        23
/*! \def QOS_PROFILE_DATA_SIZE
 */
#define QOS_PROFILE_DATA_SIZE                   10
/*! \def NUM_TPC_ID_DCI_FRMT_3A
 */
#define NUM_TPC_ID_DCI_FRMT_3A                  31
/*! \def NUM_TPC_ID_DCI_FRMT_3
 */
#define NUM_TPC_ID_DCI_FRMT_3                       15
/*! \def AM_MODE
 */
#define AM_MODE                                 1
/*! \def UM_MODE
 */
#define UM_MODE                                 2
/*!< MACRO releated to configuration file
 *   reading functions
 */
/*! \def MAX_LABEL
 */
#define MAX_LABEL 								10
/*! \def IPADDR_PORT_MAX_LEN
 */
#define IPADDR_PORT_MAX_LEN 					300
/*! \def RRM_CONFIG_FILE
 */
#define RRM_CONFIG_FILE 						"../cfg/eNodeB_Configuration.cfg"
/*! \def MAX_KEY_SIZE
 */
#define MAX_KEY_SIZE  							128
/*! \def MAX_BUFF_SIZE
 */
#define MAX_BUFF_SIZE 							256
/*! \def RRM_PORT_INDEX
 */
#define RRM_PORT_INDEX 							0
/*! \def RRC_PORT_INDEX
 */
#define RRC_PORT_INDEX 							1
/*! \def OAM_PORT_INDEX
 */
#define OAM_PORT_INDEX 							2
/*! \def SON_PORT_INDEX
 */
#define SON_PORT_INDEX 							3
/*! \def L2_PORT_INDEX
 */
#define L2_PORT_INDEX 							4
/*! \def RRM_IP_ADDR_INDEX
 */
#define RRM_IP_ADDR_INDEX 						5
/*! \def RRC_IP_ADDR_INDEX
 */
#define RRC_IP_ADDR_INDEX 						6
/*! \def OAM_IP_ADDR_INDEX
 */
#define OAM_IP_ADDR_INDEX 						7
/*! \def SON_IP_ADDR_INDEX
 */
#define SON_IP_ADDR_INDEX 						8
/*! \def L2_IP_ADDR_INDEX
 */
#define L2_IP_ADDR_INDEX 						9
/*! \def MAX_IP_ADD_LEN_STR
 */
#define MAX_IP_ADD_LEN_STR                                              16
/*! \def RRM_254
 */
#define RRM_254                                 254
/*! \def RRM_255
 */
#define RRM_255                                 255
/*! \def RRM_256
 */
#define RRM_256                                 256
/*! \def INDEX_0
 */
#define INDEX_0                                 0
/*! \def RRM_INVALID_RETURN
*/
#define RRM_INVALID_RETURN			0xff
/*! \def RRM_TX_MODE_TABLE_SIZE
*/
#define RRM_TX_MODE_TABLE_SIZE		  	7	

/* Uplink power control starts */
#define RRM_OLPC_CATEGORY_TABLE_SIZE		8
/* Uplink power control end */

#define RRM_MAX_PSC   511

/* FGI Feature Start */
#define  L2_RRM_API_HEADER_LEN              12

#define RRM_ONE            1
#define RRM_TWO            2
#define RRM_THREE          3
#define RRM_FOUR           4
#define RRM_FIVE           5
#define RRM_SIX            6
#define RRM_SEVEN          7
#define RRM_EIGHT          8
#define RRM_NINE           9
#define RRM_TEN            10
#define RRM_ELEVEN         11
#define RRM_TWELVE         12
#define RRM_THIRTEEN       13
#define RRM_FOURTEEN       14
#define RRM_FIFTEEN        15
#define RRM_SIXTEEN        16
#define RRM_TWENTY         20
#define RRM_TWENTY_TWO     22
#define RRM_TWENTY_THREE   23
#define RRM_TWENTY_FOUR    24
#define RRM_TWENTY_FIVE    25
#define RRM_TWENTY_SIX     26
#define RRM_THIRTY_TWO     32
/*DYNAMIC SIB SCHEDULING START*/
#define RRM_FOURTY         40
/*DYNAMIC SIB SCHEDULING END*/
#define RRM_TWO_FIFTY_FIVE 255
/* FGI Feature End */

/*! \def  RRM_EVENT_HANDLER_MODULE_ID
*/
#define  RRM_EVENT_HANDLER_MODULE_ID             11 
/*! \def EVENT_HANDLER_PORT_INDEX
*/
#define  EVENT_HANDLER_PORT_INDEX                5
/*! \def RRM_EVENT_NOTIFICATION_HEADER_LEN
*/
#define  RRM_EVENT_NOTIFICATION_HEADER_LEN       10

/* RRM_MAC_RECONF_SCHEDULER_CHANGES_START */
/*! \def RRM_MAX_CQI_VAL
*/ 
#define RRM_MAX_CQI_VAL                          15    
/*! \def RRM_NUM_DCI_SIZE_CATEGORY
*/
/*! \def RRM_NUM_DCI_SIZE_CATEGORY
*/                       
#define RRM_NUM_DCI_SIZE_CATEGORY                     3
/*! \def RRM_MAX_AGGREGATION_LEVEL_POWER_OFFSET_COUNT
*/
#define RRM_MAX_AGGREGATION_LEVEL_POWER_OFFSET_COUNT  4
/*! \def RRM_MAX_NUM_TPC_FOR_PUCCH
*/
#define RRM_MAX_NUM_TPC_FOR_PUCCH             4
/*! \def RRM_MAX_NUM_TPC_FOR_PUSCH
*/
#define RRM_MAX_NUM_TPC_FOR_PUSCH             4
/*! \def RRM_MAX_NUM_ALPHA_COUNT
*/
#define RRM_MAX_NUM_ALPHA_COUNT               8
/*! \def RRM_MAX_NUM_PATHLOSS_TO_SINR_COUNT
*/
#define RRM_MAX_NUM_PATHLOSS_TO_SINR_COUNT   10
/* RRM_MAC_RECONF_SCHEDULER_CHANGES_ENDS */

typedef U8 rrm_cell_index_t;
typedef U16 rrm_ue_index_t;

/*Local Event Handling Feature Start*/
/*! \def RRM_INVALID_CORE_ID
*/
#define RRM_INVALID_CORE_ID   0xff
/*! \def RRM_INVALID_UE_ID
*/
#define RRM_INVALID_UE_ID     0xff
/*! \def RRM_INVALID_CELL_ID
*/
#define RRM_INVALID_CELL_ID   0xff
/*! \def RRM_INVALID_MOM_ID
*/
#define RRM_INVALID_MOM_ID    0xff
/*Local Event Handling Feature End*/
/*start supported_rat*/
/*! \def RRM_EUTRAN_RAT_SUPPORTED
*/
#define RRM_EUTRAN_RAT_SUPPORTED 0x01
/*! \def RRM_UTRAN_RAT_SUPPORTED
*/
#define RRM_UTRAN_RAT_SUPPORTED 0x02
/*! \def RRM_GERAN_RAT_SUPPORTED
*/
#define RRM_GERAN_RAT_SUPPORTED 0x04
/*! \def RRM_CDMA_1xRTT_RAT_SUPPORTED
*/
#define RRM_CDMA_1xRTT_RAT_SUPPORTED 0x08
/*! \def RRM_CDMA_HPRD_RAT_SUPPORTED
*/
#define RRM_CDMA_HPRD_RAT_SUPPORTED 0x10
/*! \def  RRM_GET_MIN( a, b ) ( ((a) < (b)) ? (a) : (b) )
*/
#define RRM_GET_MIN( a, b ) ( ((a) < (b)) ? (a) : (b) )
#define RRM_GET_MAX( a, b ) ( ((a) > (b)) ? (a) : (b) )
/*end supported_rat*/
/*start tgt cell ranking*/
#define RRM_LOWEST_RANK 0
/*end tgt cell ranking*/
#define MAX_BUFFER      	100
/*RIM changes start*/
#define RRM_MAX_RSN                   4294967296ULL /* 2^32   Maximum RSN allowed*/
#define RRM_MAX_RSN_BY_2              2147483648ULL /* 2^31   Maximum RSN allowed BY 2*/
#define RRM_INCREMENT_RSN(s) (((s + 1)) % (RRM_MAX_RSN))
/*RIM changes end*/
/*CCO changes start*/
#define RRM_NCC_MASK   0x700
#define RRM_BSCC_MASK  0x007
/*CCO changes end*/
/*CCO changes start*/
#define RRM_NCC_MASK   0x700
#define RRM_BSCC_MASK  0x007
#define RRM_MAX_PSC   511
/*CCO changes end*/
/* Start fix for bug 715 */
#define RRM_MAX_PCI_UTRAN_TDD   127
/* End fix for bug 715 */
#endif
