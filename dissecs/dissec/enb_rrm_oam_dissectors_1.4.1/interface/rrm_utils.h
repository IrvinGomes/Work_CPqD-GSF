/*! \file rrm_utils.h
 *  \brief This file contains the enums, struct, constants definitions for RRM APPS.
 *  \date January 20, 2012
 *  \author gur21481
  */
/*!

*  \copyright {Copyright (c) 2009, Aricent Inc. All Rights Reserved}

*/


#ifndef _RRM_UTILS_H_
#define _RRM_UTILS_H_
/*
* Header File Includes
*/

/*! \headerfile cspl.h <>
 */
#include <cspl.h>

/*! \headerfile stacklayer.h <>
 */
#include <stacklayer.h>

/*! \headerfile string.h <>
 */
#include <string.h>

/*! \headerfile mqueue.h <>
 */
#include    <mqueue.h>
 
/*! \headerfile rrm_defines.h <>
 */
#include <rrm_defines.h>

/*! \headerfile rrm_oam_defines.h <>
 */
#include <rrm_oam_defines.h>
/*! \fn rrm_void_t rrm_msg_mem_get(size_t size)
 *  \brief It returns memory buffer from memory pool.
 *  \param size     Size of buffer which will be allocated
 */
#include "rrm_mif_db.h"

rrm_void_t *
rrm_msg_mem_get
(
    size_t size    
);
/* Platform-dependent defines */
/*! \def RRM_MEMSET
*/
#define RRM_MEMSET 					memset
/* ! \def RRM_MEMCPY
*/
#define RRM_MEMCPY 					memcpy
/* ! \def RRM_MEMCMP
*/
#define RRM_MEMCMP 					memcmp
/* ! \def RRM_STRNCMP(X,Y,Z)
*/
#define RRM_STRNCMP(X,Y,Z)    		strncmp((const char*)X,(const char*)Y,Z)
/* ! \def RRM_STRCAT(X,Y)
*/
#define RRM_STRCAT(X,Y)       		strcat((char*)X,(char*)Y)
/* ! \def RRM_STRTOK(X,Y)
*/
#define RRM_STRTOK(X,Y)       		strtok((char*)X,(const char*)Y)
/* ! \def RRM_STRCPY(X,Y)
*/
#define RRM_STRCPY(X,Y)       		strcpy((char*)X,(const char*)Y)
/* ! \def RRM_STRLEN(X)
*/
#define RRM_STRLEN(X)         		strlen((const char*)X)
/* ! \def RRM_STRFTIME(A,B,C,D)
*/
#define RRM_STRFTIME(A,B,C,D) 		strftime((char*)A,B,C,D)
/* ! \def RRM_SPRINTF(X,Y,Z)
*/
#define RRM_SPRINTF(X,Y,Z)    		sprintf((char*)X,Y,Z)
/* ! \def RRM_SNPRINTF(A,B,C,D)
*/
#define RRM_SNPRINTF(A,B,C,D) 		snprintf((char*)A,B,C,D)
/* ! \def RRM_QVLOGVA(X,Y,Z)
*/
#define RRM_QVLOGVA(X,Y,Z)    		qvLogVa(X,(const char*)Y,Z)
/* ! \def  RRM_PUTS(X)
*/
#define RRM_PUTS(X)           		puts((const char*)X)
/* ! \def RRM_FOPEN(X,Y)
*/
#define RRM_FOPEN(X,Y)        		fopen((const char*)X,(const char*)Y)
/* ! \def RRM_STRCMP(X,Y)
*/
#define RRM_STRCMP(X,Y)    			strcmp((char*)X,(char*)Y)
/* ! \def RRM_FPRINTF
*/
#define RRM_FPRINTF         		fprintf
/* ! \def RRM_MEM_CPY
*/
#define RRM_MEM_CPY					memcpy

/** Added Macros for MIF */
#define RRM_MESSAGE_API_START       		6000
#define RRM_OAM_INIT_IND            		(RRM_MESSAGE_API_START + 1)
#define RRM_OAM_INIT_CNF            		(RRM_MESSAGE_API_START + 2)
#define RRM_OAM_SHUTDOWN_REQ        		(RRM_MESSAGE_API_START + 3)
#define RRM_OAM_LOG_ENABLE_DISABLE_REQ 		(RRM_MESSAGE_API_START + 4)
#define RRM_OAM_LOG_ENABLE_DISABLE_RESP 	(RRM_MESSAGE_API_START + 5)
#define RRM_OAM_SET_LOG_LEVEL_REQ   		(RRM_MESSAGE_API_START + 6)
#define RRM_OAM_SET_LOG_LEVEL_RESP  		(RRM_MESSAGE_API_START + 7)
#define RRM_OAM_CELL_CONFIG_REQ          	(RRM_MESSAGE_API_START + 8)
#define RRM_OAM_CELL_CONFIG_RESP       		(RRM_MESSAGE_API_START + 9)
#define RRM_OAM_CELL_RECONFIG_REQ   		(RRM_MESSAGE_API_START + 10)
#define RRM_OAM_CELL_RECONFIG_RESP     		(RRM_MESSAGE_API_START + 11)
#define RRM_OAM_CELL_DELETE_REQ     		(RRM_MESSAGE_API_START + 12)
#define RRM_OAM_CELL_DELETE_RESP    		(RRM_MESSAGE_API_START + 13)
#define RRM_OAM_GENERIC_RESP        		(RRM_MESSAGE_API_START + 14)
#define RRM_OAM_INIT_CONFIG_REQ     		(RRM_MESSAGE_API_START + 15)
#define RRM_OAM_INIT_CONFIG_RESP            (RRM_MESSAGE_API_START + 16)
#define RRM_OAM_CELL_START_REQ              (RRM_MESSAGE_API_START + 17)
#define RRM_OAM_CELL_STOP_REQ               (RRM_MESSAGE_API_START + 18)
#define RRM_OAM_RESUME_SERVICE_REQ          (RRM_MESSAGE_API_START + 19)
#define RRM_OAM_RESUME_SERVICE_RESP         (RRM_MESSAGE_API_START + 20)
#define RRM_OAM_START_RESP                  (RRM_MESSAGE_API_START + 21)
#define RRM_OAM_STOP_RESP                   (RRM_MESSAGE_API_START + 22)
#define RRM_OAM_DELETE_RESP                 (RRM_MESSAGE_API_START + 23)
#define RRM_OAM_RAC_ENABLE_DISABLE_REQ      (RRM_MESSAGE_API_START + 24)
#define RRM_OAM_RAC_ENABLE_DISABLE_RESP     (RRM_MESSAGE_API_START + 25)
#define RRM_OAM_SHUTDOWN_RESP               (RRM_MESSAGE_API_START + 26)
#define RRM_OAM_CELL_CONTEXT_PRINT_REQ      (RRM_MESSAGE_API_START + 27)
/*STATIC ICCI START*/
#define RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ    (RRM_MESSAGE_API_START + 28)
#define RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP   (RRM_MESSAGE_API_START + 29)
/*STATIC ICCI ENDS*/
/*UE RELEASE FROM OAM STRAT*/
#define RRM_OAM_UE_RELEASE_REQ       (RRM_MESSAGE_API_START + 30)
/* Soft Lock APIs Start */
#define RRM_OAM_CELL_BLOCK_REQ       (RRM_MESSAGE_API_START + 33)
#define RRM_OAM_CELL_BLOCK_RESP      (RRM_MESSAGE_API_START + 34)
#define RRM_OAM_CELL_UNBLOCK_CMD     (RRM_MESSAGE_API_START + 35)
#define RRM_OAM_READY_FOR_CELL_BLOCK_IND (RRM_MESSAGE_API_START + 36)
/* Soft Lock APIs End */

#define RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ (RRM_MESSAGE_API_START + 37) 
#define RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP (RRM_MESSAGE_API_START + 38)

/*#define RRM_OAM_PROC_SUPERVISION_RESP   (RRM_MESSAGE_API_START + 39)*/
/*UE RELEASE FROM OAM ENDS */

#define RRM_OAM_CELL_UPDATE_REQ             (RRM_MESSAGE_API_START + 40)
#define RRM_OAM_CELL_UPDATE_RESP            (RRM_MESSAGE_API_START + 41)
#define RRM_OAM_GET_VER_ID_REQ              (RRM_MESSAGE_API_START + 42)
#define RRM_OAM_GET_VER_ID_RESP             (RRM_MESSAGE_API_START + 43)
#define RRM_OAM_PROC_SUP_REQ                (RRM_MESSAGE_API_START + 44)
#define RRM_OAM_PROC_SUP_RESP               (RRM_MESSAGE_API_START + 45)
/* Event Notification API */
#define RRM_OAM_EVENT_NOTIFICATION          (RRM_MESSAGE_API_START + 46)
#define RRM_OAM_NR_ENB_UPDATE_REQ	    (RRM_MESSAGE_API_START + 47)
#define RRM_OAM_NR_ENB_UPDATE_RESP          (RRM_MESSAGE_API_START + 48)
#define RRM_OAM_LOAD_CONFIG_REQ             (RRM_MESSAGE_API_START + 49)
#define RRM_OAM_LOAD_CONFIG_RESP            (RRM_MESSAGE_API_START + 50)
#define RRM_OAM_LOAD_REPORT_IND             (RRM_MESSAGE_API_START + 51)
#define RRM_OAM_EVENT_CONFIG_REQ            (RRM_MESSAGE_API_START + 52)
#define RRM_OAM_EVENT_CONFIG_RESP           (RRM_MESSAGE_API_START + 53)
#define RRM_PLATFORM_LOAD_IND                (RRM_MESSAGE_API_START + 55)
#define RRM_OAM_CONFIG_KPI_REQ              (RRM_MESSAGE_API_START +56) 
#define RRM_OAM_CONFIG_KPI_RESP             (RRM_MESSAGE_API_START +57) 
#define RRM_OAM_GET_KPI_REQ                 (RRM_MESSAGE_API_START +58) 
#define RRM_OAM_GET_KPI_RESP                (RRM_MESSAGE_API_START +59) 
#define RRM_OAM_KPI_IND                     (RRM_MESSAGE_API_START +60) 
#define RRM_MESSAGE_API_END                 (RRM_MESSAGE_API_START + 100)


#define RRM_VER_ID            		      "LTE_RRM_VER_2.0.1" 
#define RRM_OAM_API_BASE            		RRM_MESSAGE_API_START
#define RRM_OAM_MAX_API             		RRM_MESSAGE_API_END
/********************************************************************
 * RMIF APIs
 *******************************************************************/
#define RMIF_CELL_API_REQ_BASE       		500
#define RMIF_CELL_API_RESP_BASE      		600
#define RMIF_UE_API_REQ_BASE         		700
#define RMIF_UE_API_RESP_BASE        		800
#define RMCM_UEM_API_REQ_BASE         		900
#define RMCM_UEM_API_RESP_BASE        		1000

/* UE MEAS CHANGES : STARTS */

/*! \def RRM_MIN_TRANSACTION_ID
 *  \brief Macro storing the value of minimum transaction Identifier
    generated by RRM
 */
#define RRM_MIN_TRANSACTION_ID  0

/*! \def RRM_MAX_TRANSACTION_ID
 *  \brief Macro storing the value of maximum transaction Identifier
    generated by RRM
 */
#define RRM_MAX_TRANSACTION_ID  0xFFFF

/* UE MEAS CHANGES : ENDS */

/*! \enum rrm_cm_uem_message_req_e
 *  \brief This enum contains rrm cm uem message request params
 */
typedef enum _rrm_cm_uem_message_req_e
{
     RRMUEM_CM_DELETE_ALL_UE_CONTEXT_REQ = RMCM_UEM_API_REQ_BASE,
     /*  DYNAMIC ICIC CHANGES START  */
     RRMUEM_CM_UPDATE_UE_INFO_REQ
     /*  DYNAMIC ICIC CHANGES END  */
}rrm_cm_uem_message_req_e;
/* ! \def enum rrm_mif_cellm_message_req_e
 *   \brief This enum contains the rrm mif celm message request params
*/
typedef enum _rrm_mif_cellm_message_req_e
{
	RRMCM_RMIF_LOG_ENABLE_DISABLE_REQ = RMIF_CELL_API_REQ_BASE,
	RRMCM_RMIF_SET_LOG_LEVEL_REQ,
	RRMCM_RMIF_INIT_CONFIG_REQ,
	RRMCM_RMIF_CELL_CONFIG_REQ,
	RRMCM_RMIF_CELL_RECONFIG_REQ,
	RRMCM_RMIF_CELL_DELETE_REQ,
	RRMCM_RMIF_CELL_START_REQ,
	RRMCM_RMIF_CELL_STOP_REQ,
    RRMCM_RMIF_CELL_UPDATE_REQ,
	RRMCM_RMIF_CELL_START_ADMISSION_REQ,
	RRMCM_RMIF_CELL_STOP_ADMISSION_REQ,
	RRMCM_RMIF_CELL_SET_ATTRIBUTE_FROM_ANR_REQ,
	RRMCM_RMIF_CELL_SET_ATTRIBUTE_FROM_ES_REQ,
	RRMCM_RMIF_CELL_REGISTER_FROM_ANR_REQ,
	RRMCM_RMIF_CELL_REGISTER_FROM_ES_REQ,
	RRMCM_RMIF_RAC_ENABLE_DISABLE_REQ,
	RRMCM_RMIF_CELL_DEREGISTER_FROM_ANR_REQ,
	RRMCM_RMIF_CELL_DEREGISTER_FROM_ES_REQ,
	RRMCM_RMIF_NMM_PREPARE_REQ,
	RRMCM_RMIF_NMM_COMPLETE_REQ,
	RRMCM_RMIF_CELL_CONTEXT_PRINT_REQ,
    RRMCM_RMIF_MEAS_CONFIG_FROM_ANR_REQ,
    RRMCM_RMIF_UPDATED_NRT_INFO_FROM_ANR_REQ,
    RRMCM_RMIF_TNL_DISCOVERY_FROM_ANR_REQ,
    RRMCM_RMIF_CELL_ECN_CAPACITY_REQ,
/* RRM_MAC_RECONF_SCHEDULER_CHANGES_START */
    RRMCM_RMIF_MAC_RECONF_SCHEDULE_IND,
/* RRM_MAC_RECONF_SCHEDULER_CHANGES_ENDS */
    /* Code for MLB start */
    RRMCM_RMIF_LOAD_CONFIG_REQ,
    RRMCM_RMIF_LOAD_CONFIG_RESP,
    RRMCM_RMIF_CELL_REGISTER_FROM_MLB_REQ,
    RRMCM_RMIF_CELL_DEREGISTER_FROM_MLB_REQ,
	RRMCM_RMIF_CELL_SET_ATTRIBUTE_FROM_MLB_REQ,
    RRMCM_RMIF_CELL_REGISTER_FROM_MRO_REQ,
    RRMCM_RMIF_CELL_DEREGISTER_FROM_MRO_REQ,
    /* MRO changes start */
    RRMCM_RMIF_CELL_SET_ATTRIBUTE_FROM_MRO_REQ,
    /* MRO changes end */
    RRMCM_RMIF_CELL_PLATFORM_IND,
    /* Code for MLB end */
    RRMCM_RMIF_TTT_UPDATE_IND_REQ,
    RRMCM_RMIF_CONFIG_KPI_REQ,
    RRMCM_RMIF_GET_KPI_REQ
}rrm_mif_cellm_message_req_e;
/* ! \def enum rrm_mif_cellm_message_resp_e
*   \brief This enum contains the rrm mif cellm message response params
*/
typedef enum _rrm_mif_cellm_message_resp_e
{
 	RRMCM_RMIF_LOG_ENABLE_DISABLE_RESP = RMIF_CELL_API_RESP_BASE,
 	RRMCM_RMIF_SET_LOG_LEVEL_RESP,
 	RRMCM_RMIF_INIT_CONFIG_RESP,
 	RRMCM_RMIF_CELL_CONFIG_RESP,   
 	RRMCM_RMIF_CELL_RECONFIG_RESP, 
 	RRMCM_RMIF_CELL_DELETE_RESP,   
 	RRMCM_RMIF_CELL_START_RESP,    
 	RRMCM_RMIF_CELL_STOP_RESP,   
    RRMCM_RMIF_CELL_UPDATE_RESP,  
 	RRMCM_RMIF_CELL_START_ADMISSION_RESP,
 	RRMCM_RMIF_CELL_STOP_ADMISSION_RESP,
 	RRMCM_RMIF_CELL_SET_ATTRIBUTE_RESP,
 	RRMCM_RMIF_CELL_REGISTER_RESP,
 	RRMCM_RMIF_CELL_DEREGISTER_RESP,
 	RRMCM_RMIF_GENERIC_RESP,
 	RRMCM_RMIF_CELL_STATE_CHANGE_FOR_ANR_IND,
 	RRMCM_RMIF_CELL_ACTIVE_UE_COUNT_REPORT_FOR_ANR_IND,
 	RRMCM_RMIF_CELL_ACTIVE_THRESHOLD_REACHED_REPORT_FOR_ANR_IND,
 	RRMCM_RMIF_CELL_STATE_CHANGE_FOR_ES_IND,
 	RRMCM_RMIF_CELL_ACTIVE_UE_COUNT_REPORT_FOR_ES_IND,
 	RRMCM_RMIF_CELL_ACTIVE_THRESHOLD_REACHED_REPORT_FOR_ES_IND,
	RRMCM_RMIF_RAC_ENABLE_DISABLE_RES,
 	RRMCM_RMIF_INIT_IND,
 	RRMCM_RMIF_NMM_PREPARE_RESP,
 	RRMCM_RMIF_NMM_COMPLETE_RESP,
 	RRMCM_RMIF_MEAS_CONFIG_RESP,
 	RRMCM_RMIF_UPDATED_NRT_INFO_FROM_ANR_RES,
    RRMCM_RMIF_TNL_DISCOVERY_FROM_ANR_RES,
    RRMCM_RMIF_CELL_ECN_CAPACITY_RESP,
    /* MLB Changes start */
    RRMCM_RMIF_CELL_STATE_CHANGE_FOR_MLB_IND,
    /* MLB Changes end */
    RRMCM_RMIF_CELL_STATE_CHANGE_FOR_MRO_IND,
    RRMCM_RMIF_CONFIG_KPI_RESP,
    RRMCM_RMIF_GET_KPI_RESP,
    RRMCM_RMIF_KPI_IND
}rrm_mif_cellm_message_resp_e;
/* ! \def enum rrm_mif_uem_message_resp_e
 *   \brief This enum contains the rrm mif uem message response params
*/
typedef enum _rrm_mif_uem_message_resp_e
{
    RRMUEM_RMIF_INIT_IND = RMIF_UE_API_RESP_BASE,
    RRMUEM_RMIF_INIT_CONFIG_RES,
    RRMUEM_RMIF_EMERGENCY_CALL_ACTIVE_RES,
    RRMUEM_RMIF_SET_LOG_LEVEL_RES,
    RRMUEM_RMIF_LOG_ENABLE_DISABLE_RES,
    RRMUEM_RMIF_MEAS_CONFIG_RES,
    RRMUEM_RMIF_SNR_REPORT,
    RRMUEM_RMIF_MEAS_RESULTS_IND,
    RRMUEM_RMIF_HO_REPORT,
    RRMUEM_RMIF_NO_ACTIVE_UE_IND,
    RRMUEM_RMIF_NON_EMRGNCY_ACTIVE_CALLS_HO_RESP,
    RRMUEM_RMIF_EVENT_NOTIFICATION_IND,
    /* MRO changes start */
    RRMUEM_RMIF_HO_ATTEMPT_IND,
    RRMUEM_RMIF_HO_FAILURE_REPORT,
    /* MRO changes end */
    RRMUEM_RMIF_EVENT_CONFIG_RESP
}rrm_mif_uem_message_resp_e;

/* ! \def rrm_mif_uem_message_req_e
*   \brief This enum contains the rrm mif uem message request params
*/
typedef enum _rrm_mif_uem_message_req_e
{
 	RRMUEM_RMIF_INIT_CONFIG_REQ = RMIF_UE_API_REQ_BASE,
 	RRMUEM_RMIF_EMERGENCY_CALL_ACTIVE_REQ,
 	RRMUEM_RMIF_SET_LOG_LEVEL_REQ,
	RRMUEM_RMIF_LOG_ENABLE_DISABLE_REQ,
    RRMUEM_RMIF_GET_SNR_REPORT,
    RRMUEM_RMIF_UE_REL_REQ,
    RRMUEM_RMIF_RELEASE_ALL_EXISTING_UE_FORCEFULLY_REQ,
    RRMUEM_RMIF_NON_EMRGNCY_ACTIVE_CALLS_HO_REQ,
    RRMUEM_RMIF_EVENT_CONFIG_REQ
}rrm_mif_uem_message_req_e;

/* ! \def rrm_cellm_uem_message_ind_e
*   \brief This enum contains the rrm celm uem message index 
*/
typedef enum _rrm_cellm_uem_message_ind_e
{
    RRMUEM_CM_SET_UNSET_ECN_IND,
    RRMUEM_CM_UNSET_ECN_FOR_ALL_UE_IND,
    RRMUEM_CM_REDIRECT_REL_IND,
    RRMUEM_CM_PRB_THRESHOLD_REACHED_IND
}rrm_cellm_uem_message_ind_e;
/* ! \def rrm_cm_uem_message_resp_e
 *   \brief This enum contains rrm cm uem message response params
*/
typedef enum _rrm_cm_uem_message_resp_e
{
    RRMUEM_CM_DELETE_ALL_UE_CONTEXT_RESP = RMCM_UEM_API_RESP_BASE,
    /*  DYNAMIC ICIC CHANGES START  */
    RRMUEM_CM_UPDATE_UE_INFO_RESP 
    /*  DYNAMIC ICIC CHANGES END  */
}rrm_cm_uem_message_resp_e;


/* ! \def RRMUEM_RMIF_SHUTDOWN_RESP
*/

#define RMIF_MAX_API RRMUEM_RMIF_SHUTDOWN_RESP
/* ! \def RRMCM_RRMUEM_API_BASE
*/
#define RRMCM_RRMUEM_API_BASE                   0x300
/* ! \def RRMCM_RRMUEM_MAX_API
*/
#define RRMCM_RRMUEM_MAX_API            		(RRMCM_RRMUEM_API_BASE + 100)
/* Measurment Re-config END */

/* Trace Procedure Code */
/* ! \def NORMAL
*/
#define NORMAL 									10 

#ifdef WIN32
/* ! \def RRM_STRDUP
*/
#define RRM_STRDUP _strdup
#else
/* ! \def RRM_STRDUP(X)
*/
#define RRM_STRDUP(X) strdup((char*)X)
#endif

/*
*   logging
*/

#define RRM										4
#define RRM_MODULE_ID_ARR 3
#ifdef RRM_ADV_LOGGER
    #define LOGGER_TYPE RRM_ADV_LOGGER
#endif

#ifdef RRM_INTERNAL_LOGGER
    #define LOGGER_TYPE RRM_INTERNAL_LOGGER
#endif

#define RRM_LOG_LEVEL_NONE  QVLOG_NONE

#define RRM_MIN_MODULE_ID_FOR_ADV_LOGGER 21
#define DEFAULT_LOG_FILE                "rrm_logs.log"
#define RRM_TRACE_FILE			"test.log"

#if (RRM_ADV_LOGGER == LOGGER_TYPE)
    /*
     *  Advanced logger
     */
    
    /*! \headerfile advlogging.h <>
     */
    #include <advlogging.h>

    /*! \fn rrm_void_t rrm_set_module_loglevel_limit(rrm_oam_log_level_et log_level)
     *  \brief This function sets the module log level to advance logger
     *  \param log_level    Log level to be used(RRM_ERROR, RRM_BRIEF etc.)
     */
    rrm_void_t
    rrm_set_module_loglevel_limit
    (
         rrm_oam_log_level_et log_level
    );
    extern AdvL_ContextIndex        g_advl_ctxt[RRM_MODULE_ID_ARR];//[RRM_MAX_INT_MODULE_ID];
    extern AdvL_ContextIndex        g_main_advl_ctxt;


    /*! \def SET_MODULE_LOG_LEVEL(log_level)
     *  \brief Macro defining the function to set module's log level
     */
    #define SET_MODULE_LOG_LEVEL(log_level)\
        rrm_set_module_loglevel_limit(log_level);
    
    /*! \def RRM_LOG_CTXT_CONSOLE
     *  \brief Macro to set the logs to appear on console
     */
    #define RRM_LOG_CTXT_CONSOLE    LogContext_Default

    /*! \def RRM_LOG_CTXT_FILE
     *  \brief Macro to set the logs to appear in a file
     */
    #define RRM_LOG_CTXT_FILE       LogTarget_File

    /*! \def RRM_ERROR
     *  \brief Macro defining log level for ERROR logs/traces
     */
    #define RRM_ERROR               LogError
    
    /*! \def RRM_WARNING
     *  \brief Macro defining log level for WARNING logs/traces
     */
    #define RRM_WARNING             LogWarning
    
    /*! \def RRM_BRIEF
     *  \brief Macro defining log level for BRIEF logs/traces
     */
    #define RRM_BRIEF               LogBrief
    
    /*! \def RRM_DETAILED
     *  \brief Macro defining log level for DETAILED logs/traces
     */
    #define RRM_DETAILED            LogDetailed

    /*! \def RRM_INIT_LOG(log_file_name) 
     *  \brief Macro to be used to initialize advance logging.
     */
	#define RRM_INIT_LOG(log_file_name) rrm_init_log(log_file_name) 
    
    /*! \def RRM_LOG(is_log_enable, facility_name, log_level, format, ...)
     *  \brief Macro to be used for logging. Its first argument tells if the 
     *      corresponding log is be printed or not. Second argument gives the 
     *      information about the facility using the log. Third argument gives
     *      the log level(INFO, WARNING etc.). Forth argument is used to give 
     *      any nformation related to the event using the log.
     */
    #define RRM_LOG(is_log_enable, facility_name, log_level, format, ...) \
        {\
            if ((U32)RRM_OAM_LOG_ON == (U32)is_log_enable)\
            {\
                U8 module_id = 0;\
                module_id = qvGetServiceName(qvSelf());\
                if (0 != module_id)\
                {\
                    write_log_message(g_advl_ctxt[module_id - \
                        RRM_MIN_MODULE_ID_FOR_ADV_LOGGER], log_level, __FILE__, \
                        __LINE__, __func__ , (char *)facility_name, format, \
                        ##__VA_ARGS__);\
                }\
            }\
        }        

    /*! \def RRM_PANIC(format, ...)
     *  \brief Macro to be used by the encapsulation code for aborting the 
     *      process in error situation. Its argument is used to give any 
     *      information related to the event using the log.
     */
    #define RRM_PANIC(format, ...) \
        {\
            write_log_message(g_main_advl_ctxt, RRM_ERROR, __FILE__, \
                __LINE__, __func__ , (char *)rrm_log_facility_name, format, \
                ##__VA_ARGS__);\
            rrm_abort();\
        }
    
    /*! \def RRM_ENCAPS_WARNING(format, ...)
     *  \brief Macro to be used by the encapsulation code to print some warning.
     *      Its argument is used to give any information related to the event 
     *      using the log.
     */
    #define RRM_ENCAPS_WARNING(format, ...) \
        {\
            write_log_message(g_main_advl_ctxt, RRM_ERROR, __FILE__, \
                __LINE__, __func__ , (char *)rrm_log_facility_name, format, \
                ##__VA_ARGS__);\
        }
    
    /*! \def RRM_TRACE(is_log_enable, log_level, format, ...)
     *  \brief Macro to be used for tracing. It is same as RRM_LOG macro 
     *      but with a default facility name(LTE_RRM).
     */
    #define RRM_TRACE(is_log_enable, facility_name, log_level, format, ...) \
        RRM_LOG(is_log_enable, rrm_log_facility_name, log_level, format, \
        ##__VA_ARGS__)

/* Advance logger
#if (LOGGER_TYPE == RRM_ADV_LOGGER)

    #include <advlogging.h>

    extern AdvL_ContextIndex        g_advl_ctxt;

    #define RRM_LOG_CTXT_CONSOLE    LogContext_Default
    #define RRM_LOG_CTXT_FILE       (LogContext_Default + 1)
   
    #define RRM_FATAL               LogFatal
    #define RRM_ERROR               LogError
    #define RRM_WARNING             LogWarning
    #define RRM_INFO                LogInfo
    #define RRM_BRIEF               LogBrief
    #define RRM_DETAILED            LogDetailed

    #define RRM_LOG(is_log_enable, facility_name, log_level, format, ...) \
        write_log_message(g_advl_ctxt, log_level, __FILE__, __LINE__, \
        __func__ , facility_name, format, ##__VA_ARGS__)
*/
#elif (LOGGER_TYPE == RRM_INTERNAL_LOGGER)
    /*
    *   Internal logger
    */
    

	#define RRM_INIT_LOG(log_file_name) 
    void rrm_trace_message(S32 log_level,const S8 *facility_name,
        const S8* format,...);
    void rrm_set_loglevel(U8 new_log_level);

    #define RRM_ERROR       	QVLOG_MAJOR
    #define RRM_WARNING     	QVLOG_MINOR
    #define RRM_BRIEF       	QVLOG_INFO
    #define RRM_DETAILED    	QVLOG_DETAIL

   /*! \def RRM_PANIC(format, ...)
    *  \brief Macro to be used by the encapsulation code for aborting the process
    *      in error situation. Its argument is used to give any information
    *      related to the event using the log.
    */

    #define RRM_PANIC(format, ...) qvPanic((const S8)format, ##__VA_ARGS__)

   /*! \def RRM_ENCAPS_WARNING (format, ...)
    *  \brief Macro to be used by the encapsulation code to print some warning.
    *         Its argument is used to give any information related to the event
    *         using the log.
    */
    #define RRM_ENCAPS_WARNING(format, ...) qvWarning((const S8*)format,\
                                                      ##__VA_ARGS__)
    
    #define RRM_LOG(is_log_enable, facility_name, log_level, format, ...) \
        if ((U32)RRM_TRUE == (U32)is_log_enable) rrm_trace_message \
           (log_level, facility_name, (const S8*)format, ##__VA_ARGS__)
    
    #define RRM_TRACE(is_log_enable, facility_name, log_level, format, ...) \
        RRM_LOG(is_log_enable, facility_name, log_level, format, ##__VA_ARGS__)

    #define SET_MODULE_LOG_LEVEL(log_level)\
        set_module_log_level(log_level);
    
#elif (LOGGER_TYPE > RRM_ADV_LOGGER)
    #error Wrong logger type specified!
#else
    #define RRM_LOG(is_log_enable, facility_name, log_level, format, ...)
#endif

#if (LOGGER_TYPE == RRM_INTERNAL_LOGGER)
/*! \fn set_module_log_level(rrm_oam_log_level_et log_level)
 *  \brief  Set the Module Log Level
 *  \param  log_level

*/
void
set_module_log_level
(
    rrm_oam_log_level_et log_level
);
#endif

extern const S8 *rrm_log_facility_name;
/*
*   UT Trace
*/
/* This will be used when debugging flag is ON. In this logging mode will
    be considered as enabled. */
/*! \def RRM_DEBUG_TRACE(log_level, format, ...)
 *  \brief Macro to be used for debugging purpose traces.
 */
#ifdef RRM_DEBUG
    #define RRM_DEBUG_TRACE(log_level, format, ...) \
        RRM_TRACE(RRM_TRUE, rrm_log_facility_name, log_level, format, \
        ##__VA_ARGS__)
    
        #define RRM_UT_TRACE_ENTER() \
     			RRM_DEBUG_TRACE(RRM_DETAILED, "FUNC_ENTER: LINE %d FUNCTION %s\n",__LINE__,__FUNCTION__)
    
        #define RRM_UT_TRACE_EXIT() \
           		RRM_DEBUG_TRACE(RRM_DETAILED, "FUNC_EXIT: LINE %d, FUNCTION %s \n",__LINE__,__FUNCTION__) 

    #define RRM_FSM_INIT_TRACE(fsm_name, state_name) \
        RRM_TRACE(RRM_BRIEF, "[%s] initialised, initial state [%s]", \
                fsm_name, state_name)

    #define RRM_FSM_SET_STATE_TRACE(fsm_name, state_name) \
        RRM_TRACE(RRM_BRIEF, "[%s] state changed to [%s]", \
                fsm_name, state_name)

    #define RRM_FSM_EVENT_TRACE(fsm_name, event_name, state_name) \
        RRM_TRACE(RRM_BRIEF, "[%s] event [%s] received in state [%s]", \
                fsm_name, event_name, state_name)
#else
    #define RRM_UT_TRACE_ENTER()
    #define RRM_UT_TRACE_EXIT()
    #define RRM_FSM_INIT_TRACE(fsm_name, state_name)

    #define RRM_FSM_SET_STATE_TRACE(fsm_name, state_name)

    #define RRM_FSM_EVENT_TRACE(fsm_name, event_name, state_name)
#endif /* RRM_DEBUG */
/*
*   ASSERT
*/
#ifdef RRM_DEBUG
void
rrm_assert
(
    void* file,
    U32 line,
    void* expression
);
#define RRM_ASSERT(exp) (void)((exp) || (rrm_assert(__FILE__,__LINE__,#exp),0))
#else
#define RRM_ASSERT(exp)
#endif /* RRM_DEBUG */

/* Bit Masks */
#define RRM_BIT0_MASK   0x00000001U
#define RRM_BIT1_MASK   0x00000002U
#define RRM_BIT2_MASK   0x00000004U
#define RRM_BIT3_MASK   0x00000008U
#define RRM_BIT4_MASK   0x00000010U
#define RRM_BIT5_MASK   0x00000020U
#define RRM_BIT6_MASK   0x00000040U
#define RRM_BIT7_MASK   0x00000080U
#define RRM_BIT8_MASK   0x00000100U
#define RRM_BIT9_MASK   0x00000200U
#define RRM_BIT10_MASK  0x00000400U
#define RRM_BIT11_MASK  0x00000800U
#define RRM_BIT12_MASK  0x00001000U
#define RRM_BIT13_MASK  0x00002000U
#define RRM_BIT14_MASK  0x00004000U
#define RRM_BIT15_MASK  0x00008000U
#define RRM_BIT16_MASK  0x00010000U
#define RRM_BIT17_MASK  0x00020000U
#define RRM_BIT18_MASK  0x00040000U
#define RRM_BIT19_MASK  0x00080000U
#define RRM_BIT20_MASK  0x00100000U
#define RRM_BIT21_MASK  0x00200000U
#define RRM_BIT22_MASK  0x00400000U
#define RRM_BIT23_MASK  0x00800000U
#define RRM_BIT24_MASK  0x01000000U
#define RRM_BIT25_MASK  0x02000000U
#define RRM_BIT26_MASK  0x04000000U
#define RRM_BIT27_MASK  0x08000000U
#define RRM_BIT28_MASK  0x10000000U
#define RRM_BIT29_MASK  0x20000000U
#define RRM_BIT30_MASK  0x40000000U
#define RRM_BIT31_MASK  0x80000000U

/* Bit Mask Map 0 -> 1, 2 -> 2, 3 -> 4, 4 -> 8 etc. */
extern U32 bit_masks_map[32];

/* Bit array operations */
#define RRM_BIT_SET(X, Y)      X |= bit_masks_map[Y]
#define RRM_BIT_UNSET(X, Y)    X &= ~bit_masks_map[Y]

#define MAX_NUM_OF_CELL_SUPPORTED_MQ     3
#define SET_PERMISSION                   0666
#define MAX_MSG_SZ                       6144
#define MAX_MSG_NO                       20

/******************************************************************************
*   Memory management functions
******************************************************************************/

extern const QSYSOP rrm_os;
extern const QWAIT rrm_waitstruct;
extern const QSHELL rrm_shell;

extern const QMANIFEST rrm_manifest_mgmt_if;
extern const QMANIFEST rrm_manifest_apps;
extern const QMANIFEST rrm_manifest_nmm;

/*! \typedef struct rrm_l2_msgq_intf_data
 *  \brief
 *  \param  mqd_send_to_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ]
 *  \param  mqd_recv_from_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ]
 */
typedef struct _rrm_l2_msgq_intf_data
{
    mqd_t  mqd_send_to_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    mqd_t  mqd_recv_from_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    struct mq_attr message_attributes;
}rrm_l2_msgq_intf_data;

typedef struct
{
    mqd_t  mqd_send_to_pdcp[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    mqd_t  mqd_recv_from_pdcp[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    struct mq_attr message_attributes;
}rrm_pdcp_msgq_intf_data;


/*! \typedef struct rrm_listener_t
 *  \brief
 *  \param sd_udp                                       UDP socket descriptor
 */
typedef struct _rrm_listener_t
{
    int   sd_udp_oam;
    int   sd_udp_rrc;
    int   sd_udp_son;
    int   sd_udp_rrm;
    mqd_t mqd_send_to_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ]; 
    mqd_t mqd_recv_from_mac[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    mqd_t mqd_send_to_pdcp[MAX_NUM_OF_CELL_SUPPORTED_MQ];
    mqd_t mqd_recv_from_pdcp[MAX_NUM_OF_CELL_SUPPORTED_MQ];

}rrm_listener_t;

#define RRM_MEM_FREE(p_buffer) \
        { \
            rrm_mem_free(p_buffer); \
           p_buffer = RRM_PNULL;\
        }

#define RRM_MSG_MEM_FREE(p_buffer) \
        { \
            rrm_msg_mem_free(p_buffer); \
           p_buffer = RRM_PNULL;\
        }
/*! \fn rrm_void_t rrm_init_log(const S8 * p_log_file_name);
*  \brief This function is used to initialize advance logger
*  \param p_log_file_name  Pointer to the log file name
*/
rrm_void_t
rrm_init_log
(
      const S8 * p_log_file_name
);

/*! \fn rrm_void_t rrm_send_msg(rrm_void_t  *p_msg, U16 dst_module_id)
 *  \brief It sends the message to the destination module using qvSend
 *  \param p_msg            Message that will be passed
 *  \param dst_module_id    Module id for which message will be passed
 */
rrm_void_t
rrm_send_msg
(
    rrm_void_t  *p_msg,      
    U16         dst_module_id 
);

/*! \fn rrm_void_t rrm_msg_mem_get(size_t size)
 *  \brief It returns memory buffer from memory pool.
 *  \param size     Size of buffer which will be allocated
 */
rrm_void_t *
rrm_msg_mem_get
(
    size_t size    
);

/*! \fn rrm_void_t rrm_msg_mem_free(rrm_void_t *p_buffer)
 *  \brief It frees memory buffer allocated to memory pool.
 *  \param p_buffer Pointer to buffer which will be freed
 */
rrm_void_t
rrm_msg_mem_free
(
    rrm_void_t *p_buffer
);

void*
rrm_sys_mem_get
(
    rrm_size_t size
);

void
rrm_sys_mem_free
(
    void *p_buffer
);

/*! \fn rrm_void_t rrm_register_modules(rrm_void_t)
 *  \brief It registers various RRM modules with CSPL.
*/

rrm_void_t
rrm_register_modules
(
    void
);

/*! \fn rrm_void_t rrm_construct_cspl_header(rrm_void_t *p_buf,U8 version,U16 from,U16 to,U16 api_id,U8 priority,U16 payloadlen)
 *  \brief It is used to create the CSPL Header of the message
 *  \param p_buf        Pointer to the buffer to which header is appended
 *  \param version      version of API
 *  \param from         Source module Id
 *  \param to           Destination module Id
 *  \param api_id       API Identifier
 *  \param priority     Priority of the message
 *  \param payloadlen   lenght of the payload
 */
rrm_void_t
rrm_construct_cspl_header
(
    rrm_void_t  *p_buf,
    U8          version,
    U16         from,
    U16         to,
    U16         api_id,
    U8          priority,
    U16         payloadlen
);
/*! \fn rrm_void_t rrm_parse_cspl_header(rrm_void_t  *p_buf, STACKAPIHDR *p_cspl_hdr)
 *  \brief It is used to parse the CSPL Header and populate the STACKAPIHDR structure
 *  \param p_buf        Pointer the CSPL header
 *  \param p_cspl_hdr   Pointer to the STACKAPIHDR structure to be populated
 */
rrm_void_t
rrm_parse_cspl_header
(
    rrm_void_t  *p_buf,
    STACKAPIHDR *p_cspl_hdr
);

void* rrm_mem_get(rrm_size_t size);
rrm_return_et rrm_check_cspl_header(U8 *p_api);

void
rrm_send_message
(
    void *p_msg,
    rrm_module_id_t dst_module
);

void*
rrm_mem_get
(
    rrm_size_t size
);

void
rrm_mem_free
(
    void *p_buffer
);


/******************************************************************************
*   Timer management functions
******************************************************************************/

extern rrm_timer_t
rrm_start_timer
(
    U32             timer_duration,
    void            *p_timer_data,
    U16             timer_data_size,
    rrm_bool_t      is_repeated
);

extern void
rrm_stop_timer
(
    rrm_timer_t timer
);

extern void*
rrm_get_timer_data
(
    rrm_timer_t timer
);

/******************************************************************************
*   File management functions
******************************************************************************/

void
rrm_free
(
    void * p_var
);

FILE *
rrm_fopen
(
    const S8* p_filename,
    const S8* p_mode
);


S32 
rrm_fread
(
    void *ptr, 
    U32 size, 
    U32 nmemb, 
    FILE *stream
);

S32 
rrm_fseek
(
    FILE *stream, 
    U32 offset, 
    U32 whence
);

S32 
rrm_ftell
(
    FILE *stream
);

S32 
rrm_fclose
(
    FILE *fp
);

void
rrm_construct_api_header
(
    U8                  *p_header,      /* RRM header */
    U8                  version_id,     /* API version Id */
    rrm_module_id_t     src_module_id,  /* Source module Id */
    rrm_module_id_t     dst_module_id,  /* Destination module Id */
    U16                 api_id,         /* API Id */
    U16                 api_buf_size    /* API buffer size */
);

void
rrm_construct_interface_api_header
(
 U8                  *p_header,      /* RRM interface header */
 U16                 transaction_id, /* Interface transaction identifier */
 rrm_module_id_t     src_module_id,  /* Source module identifier */
 rrm_module_id_t     dst_module_id,  /* Destination module identifier */
 U16                 api_id,         /* API identifier */
 U16                 api_buf_size    /* API buffer size */
 );

U16
rrm_get_api_buf_size
(
    U8 *p_header /* RRM header */
);

U16
rrm_get_api_id
(
    rrm_void_t *p_header
);


rrm_module_id_t
rrm_get_src_module_id
(
 void *p_header /* RRM header */
 );


U16
rrm_get_word_from_header
(
    U8 *p_header
);

/*! \fn U16 rrm_generate_txn_id()
 *  \brief It is used to generate the transaction Id
   
 */
U16
rrm_generate_txn_id
(
);

extern rrm_l2_msgq_intf_data      *p_rrm_l2_msgq_intf_glb_data;
void *rrm_malloc(unsigned int size);
extern rrm_pdcp_msgq_intf_data *p_rrm_pdcp_msgq_intf_glb_data; 

/**TBD */
#define RRM_RRC_MSG_PARSE_FAILURE 10
#define RRM_RRC_MSG_SEND_FAIL	   11
#define RRM_RRC_MSG_SUCCESS	 12

/* COMP_WARN_1_FEB:compilation warning removal */
void *rrm_malloc(unsigned int size);

#endif // _RRM_UTILS_H_
