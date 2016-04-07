
/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (c) Aricent.
 *
 ****************************************************************************
 *
 *  $Id: ueTags.h,v 1.1.4.1 2010/05/11 03:25:38 gur19836 Exp $ 

 ****************************************************************************
 *
 *  File Description : 
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------

 *
 ****************************************************************************/
#ifndef _UE_TAGS_H_
#define  _UE_TAGS_H_

#include "lteOamSimulator.h"
#include "rrc_ext_api.h"
#include "s1ap_api.h"

static const value_string tagType_oam_mac[]=
{ 
  {MAC_INIT_LAYER_REQ ,"MAC_INIT_LAYER_REQ"},			
  {MAC_INIT_LAYER_IND ,"MAC_INIT_LAYER_IND"},			
  {MAC_INIT_LAYER_CNF ,"MAC_INIT_LAYER_CNF"},			
  {MAC_CLEANUP_LAYER_REQ ,"MAC_CLEANUP_LAYER_REQ"},			
  {MAC_GET_BUILD_INFO_CNF ,"MAC_GET_BUILD_INFO_CNF"},			
  {MAC_SET_LOG_LEVEL_REQ ,"MAC_SET_LOG_LEVEL_REQ"},			
  {MAC_GET_STATUS_CNF ,"MAC_GET_STATUS_CNF"},			
  {MAC_GET_STATS_CNF ,"MAC_GET_STATS_CNF"},			
  {MAC_DL_THROUGHPUT ,"MAC_DL_THROUGHPUT"},			
  {MAC_UL_THROUGHPUT ,"MAC_UL_THROUGHPUT"},			
  {MAC_ENABLE_DL_SCH_STATS_REQ ,"MAC_ENABLE_DL_SCH_STATS_REQ"},			
  {MAC_ENABLE_UL_SCH_STATS_REQ ,"MAC_ENABLE_UL_SCH_STATS_REQ"},
  {MAC_MODIFY_LAYER_REQ,"MAC_MODIFY_LAYER_REQ"},
  {MAC_CONFIGURE_KPI_STATS_REQ ,"MAC_CONFIGURE_KPI_STATS_REQ"},
  {MAC_CONFIGURE_KPI_STATS_CNF ,"MAC_CONFIGURE_KPI_STATS_CNF"},
  {MAC_KPI_STATS_IND ,"MAC_KPI_STATS_IND"},
  {MAC_GET_KPI_STATS_REQ ,"MAC_GET_KPI_STATS_REQ"},
  {MAC_GET_KPI_STATS_CNF ,"MAC_GET_KPI_STATS_CNF"},
  {MAC_RECONFIG_SCHEDULER_PARAMS ,"MAC_RECONFIG_SCHEDULER_PARAMS"},
  {MAC_UE_SINR_TA_REQ ,"MAC_UE_SINR_TA_REQ"},
  {MAC_UE_SINR_TA_RESP ,"MAC_UE_SINR_TA_RESP"}
};
			
static const value_string tagType_oam_rlc[]=
{ 
  {RLC_INIT_LAYER_REQ ,"RLC_INIT_LAYER_REQ"},			
  {RLC_INIT_LAYER_IND ,"RLC_INIT_LAYER_IND"},			
  {RLC_INIT_LAYER_CNF ,"RLC_INIT_LAYER_CNF"},			
  {RLC_CLEANUP_LAYER_CNF ,"RLC_CLEANUP_LAYER_CNF"},			
  {RLC_GET_BUILD_INFO_CNF ,"RLC_GET_BUILD_INFO_CNF"},			
  {RLC_RESET_STATS_CNF ,"RLC_RESET_STATS_CNF"},			
  {RLC_GET_STATUS_CNF ,"RLC_GET_STATUS_CNF"},			
  {RLC_GET_STATS_CNF ,"RLC_GET_STATS_CNF"},			
  {RLC_SET_LOG_LEVEL_REQ ,"RLC_SET_LOG_LEVEL_REQ"},			
  {RLC_SET_LOG_LEVEL_CNF ,"RLC_SET_LOG_LEVEL_CNF"},			
  {GET_TM_STATS_CNF ,"GET_TM_STATS_CNF"},
  {RLC_CONFIGURE_KPI_STATS_REQ ,"RLC_CONFIGURE_KPI_STATS_REQ"},
  {RLC_CONFIGURE_KPI_STATS_CNF ,"RLC_CONFIGURE_KPI_STATS_CNF"},
  {RLC_KPI_STATS_IND ,"RLC_KPI_STATS_IND"},
  {RLC_GET_KPI_STATS_REQ ,"RLC_GET_KPI_STATS_REQ"},
  {RLC_GET_KPI_STATS_CNF ,"RLC_GET_KPI_STATS_CNF"}
};
			
static const value_string tagType_oam_pdcp_req[]=
{ 
  {PDCP_INIT_LAYER_REQ ,"PDCP_INIT_LAYER_REQ"},			
  {PDCP_GET_STATUS_REQ ,"PDCP_GET_STATUS_REQ"},			
//  {PDCP_CONFIGURE_KPI_STATS_REQ ,"PDCP_CONFIGURE_KPI_STATS_REQ"},
 // {PDCP_CONFIGURE_KPI_STATS_CNF ,"PDCP_CONFIGURE_KPI_STATS_CNF"},
 // {PDCP_KPI_STATS_IND ,"PDCP_KPI_STATS_IND"},
 // {PDCP_GET_KPI_STATS_REQ ,"PDCP_GET_KPI_STATS_REQ"},
 // {PDCP_GET_KPI_STATS_CNF ,"PDCP_GET_KPI_STATS_CNF"},
  {PDCP_NOTIFY_OAM_DEVICE_FAILURE ,"PDCP_NOTIFY_OAM_DEVICE_FAILURE"}
};

static const value_string tagType_oam_pdcp_cnf[]=
{ 
  {PDCP_INIT_LAYER_CNF ,"PDCP_INIT_LAYER_CNF"},			
  {PDCP_INIT_LAYER_IND ,"PDCP_INIT_LAYER_IND"},			
  {PDCP_CLEANUP_LAYER_CNF ,"PDCP_CLEANUP_LAYER_CNF"},			
  {PDCP_GET_BUILD_INFO_CNF ,"PDCP_GET_BUILD_INFO_CNF"},			
  {PDCP_RESET_STATS_CNF ,"PDCP_RESET_STATS_CNF"},			
  {PDCP_GET_STATS_CNF ,"PDCP_GET_STATS_CNF"},			
  {PDCP_GET_STATUS_CNF ,"PDCP_GET_STATUS_CNF"}			
};

static const value_string tagType_L3_phy[]=
{ 
  {RRC_PHY_CONFIG_CELL_REQ ,"RRC_PHY_CONFIG_CELL_REQ"},			
  {RRC_PHY_CONFIG_CELL_CNF ,"RRC_PHY_CONFIG_CELL_CNF"},			
  {RRC_PHY_RECONFIG_CELL_REQ ,"RRC_PHY_RECONFIG_CELL_REQ"},			
  {RRC_PHY_RECONFIG_CELL_CNF ,"RRC_PHY_RECONFIG_CELL_CNF"},			
  {RRC_PHY_DELETE_CELL_REQ ,"RRC_PHY_DELETE_CELL_REQ"},			
  {RRC_PHY_DELETE_CELL_CNF ,"RRC_PHY_DELETE_CELL_CNF"},			
  {RRC_PHY_CREATE_UE_ENTITY_REQ ,"RRC_PHY_CREATE_UE_ENTITY_REQ"},			
  {RRC_PHY_CREATE_UE_ENTITY_CNF ,"RRC_PHY_CREATE_UE_ENTITY_CNF"},			
  {RRC_PHY_DELETE_UE_ENTITY_REQ ,"RRC_PHY_DELETE_UE_ENTITY_REQ"},			
  {RRC_PHY_DELETE_UE_ENTITY_CNF ,"RRC_PHY_DELETE_UE_ENTITY_CNF"},			
  {RRC_PHY_RECONFIG_UE_ENTITY_REQ ,"RRC_PHY_RECONFIG_UE_ENTITY_REQ"},			
  {RRC_PHY_RECONFIG_UE_ENTITY_CNF ,"RRC_PHY_RECONFIG_UE_ENTITY_CNF"},
  {RRC_PHY_CHANGE_CRNTI_REQ ,"RRC_PHY_CHANGE_CRNTI_REQ"},			
  {RRC_PHY_CHANGE_CRNTI_CNF ,"RRC_PHY_CHANGE_CRNTI_CNF"},			
  {RRC_PHY_CELL_START_REQ,"RRC_PHY_CELL_START_REQ"},
  {RRC_PHY_CELL_START_CNF,"RRC_PHY_CELL_START_CNF"},
  {RRC_PHY_CELL_STOP_REQ,"RRC_PHY_CELL_STOP_REQ"},
  {RRC_PHY_CELL_STOP_CNF,"RRC_PHY_CELL_STOP_CNF"}
};

static const value_string tagType_L3_rrm[]=
{ 
  {RRC_RRM_UE_RELEASE_REQ ,"RRC_RRM_UE_RELEASE_REQ"},			
  {RRC_RRM_UE_RELEASE_RESP ,"RRC_RRM_UE_RELEASE_RESP"},			
  {RRC_RRM_CELL_SETUP_REQ ,"RRC_RRM_CELL_SETUP_REQ"},			
  {RRC_RRM_CELL_SETUP_RESP ,"RRC_RRM_CELL_SETUP_RESP"},			
  {RRC_RRM_CELL_DELETE_REQ ,"RRC_RRM_CELL_DELETE_REQ"},			
  {RRC_RRM_CELL_DELETE_RESP ,"RRC_RRM_CELL_DELETE_RESP"},			
  {RRC_RRM_UE_ADMISSION_REQ ,"RRC_RRM_UE_ADMISSION_REQ"},			
  {RRC_RRM_UE_ADMISSION_RESP ,"RRC_RRM_UE_ADMISSION_RESP"},			
  {RRC_RRM_UE_ADMISSION_CNF ,"RRC_RRM_UE_ADMISSION_CNF"},			
  {RRC_RRM_UE_CAPABILITY_IND ,"RRC_RRM_UE_CAPABILITY_IND"},			
  {RRC_RRM_ERB_SETUP_REQ ,"RRC_RRM_ERB_SETUP_REQ"},			
  {RRC_RRM_ERB_SETUP_RESP ,"RRC_RRM_ERB_SETUP_RESP"},			
  {RRC_RRM_ERB_SETUP_CNF ,"RRC_RRM_ERB_SETUP_CNF"},			
  {RRC_RRM_ERB_RELEASE_REQ ,"RRC_RRM_ERB_RELEASE_REQ"},			
  {RRC_RRM_ERB_RELEASE_RESP ,"RRC_RRM_ERB_RELEASE_RESP"},			
  {RRC_RRM_ERB_RELEASE_CNF ,"RRC_RRM_ERB_RELEASE_CNF"},
  {RRC_RRM_UE_CONNECTION_RELEASE_IND ,"RRC_RRM_UE_CONNECTION_RELEASE_IND"},			
  {RRC_RRM_INACTIVE_UES_IND ,"RRC_RRM_INACTIVE_UES_IND"},			
  {RRC_RRM_MEASURMENT_RESULTS_IND ,"RRC_RRM_MEASURMENT_RESULTS_IND"},			
  {RRC_RRM_UE_HO_ADM_REQ ,"RRC_RRM_UE_HO_ADM_REQ"},			
  {RRC_RRM_UE_HO_ADM_RESP ,"RRC_RRM_UE_HO_ADM_RESP"},			
  {RRC_RRM_UE_HO_CMD_RESP ,"RRC_RRM_UE_HO_CMD_RESP"},			
  {RRC_RRM_UE_HO_CMD_REQ ,"RRC_RRM_UE_HO_CMD_REQ"},			
  {RRC_RRM_HO_FAILURE ,"RRC_RRM_HO_FAILURE"},
  {RRC_RRM_HO_CANCEL_REQ ,"RRC_RRM_HO_CANCEL_REQ"},
  {RRC_RRM_HO_CANCEL_RESP ,"RRC_RRM_HO_CANCEL_RESP"},
  {RRC_RRM_MEAS_CONFIG_RESP ,"RRC_RRM_MEAS_CONFIG_RESP"},
  {RRC_RRM_MEAS_CONFIG_REQ,"RRC_RRM_MEAS_CONFIG_REQ"},
  {RRC_RRM_UE_HO_ADM_CNF ,"RRC_RRM_UE_HO_ADM_CNF"},
  {RRC_RRM_UE_HO_REQUIRED ,"RRC_RRM_UE_HO_REQUIRED"},
  {RRC_RRM_CELL_RECONFIGURE_REQ ,"RRC_RRM_CELL_RECONFIGURE_REQ"},			
  {RRC_RRM_CELL_RECONFIG_RESP ,"RRC_RRM_CELL_RECONFIG_RESP"},			
  {RRC_RRM_UE_HO_RESTRICTION_LIST_IND ,"RRC_RRM_UE_HO_RESTRICTION_LIST_IND"},
  {RRC_RRM_ERB_MODIFY_REQ ,"RRC_RRM_ERB_MODIFY_REQ"},
  {RRC_RRM_ERB_MODIFY_RESP ,"RRC_RRM_ERB_MODIFY_RESP"},
  {RRC_RRM_CELL_START_REQ ,"RRC_RRM_CELL_START_REQ "},	
  {RRC_RRM_CELL_START_RESP ,"RRC_RRM_CELL_START_RESP "},	
  {RRC_RRM_CELL_STOP_REQ ,"RRC_RRM_CELL_STOP_REQ "},	
  {RRC_RRM_CELL_STOP_RESP ,"RRC_RRM_CELL_STOP_RESP "},	
  {RRC_RRM_UE_CONTEXT_MOD_REQ ,"RRC_RRM_UE_CONTEXT_MOD_REQ "},	
  {RRC_RRM_UE_CONTEXT_MOD_RESP ,"RRC_RRM_UE_CONTEXT_MOD_RESP "},	
  {RRC_RRM_UE_CONTEXT_MOD_CNF ,"RRC_RRM_UE_CONTEXT_MOD_CNF "},	
  {X2AP_RRM_LINK_DOWN_IND,"X2AP_RRM_LINK_DOWN_IND"},
  {X2AP_RRM_LINK_UP_IND,"X2AP_RRM_LINK_UP_IND"},
  {S1AP_RRM_PWS_REQ,"S1AP_RRM_PWS_REQ"},
  {S1AP_RRM_PWS_RESP,"S1AP_RRM_PWS_RESP"},
  {S1AP_RRM_PWS_CNF,"S1AP_RRM_PWS_CNF"},
  {S1AP_RRM_KILL_REQ,"S1AP_RRM_KILL_REQ"},
  {S1AP_RRM_KILL_RESP,"S1AP_RRM_KILL_RESP"},
  {S1AP_RRM_KILL_CNF,"S1AP_RRM_KILL_CNF"},
  {RRC_RRM_UPDATED_PWS_SI_LIST_REQ,"RRC_RRM_UPDATED_PWS_SI_LIST_REQ"},
  {RRC_RRM_UPDATED_PWS_SI_LIST_RESP,"RRC_RRM_UPDATED_PWS_SI_LIST_RESP"},
  {RRC_RRM_UPDATED_PWS_SI_LIST_CNF,"RRC_RRM_UPDATED_PWS_SI_LIST_CNF"},
  {X2AP_RRM_LI_RRM_LOAD_INFORMATION_REQ,"X2AP_RRM_LI_RRM_LOAD_INFORMATION_REQ"},
  {X2AP_RRM_LI_RRM_LOAD_INFORMATION_RES,"X2AP_RRM_LI_RRM_LOAD_INFORMATION_RES"},
  {X2AP_RRM_LI_RRM_LOAD_INFORMATION_IND,"X2AP_RRM_LI_RRM_LOAD_INFORMATION_IND"},
  {X2AP_RRM_RSU_ENB_START_REQ,"X2AP_RRM_RSU_ENB_START_REQ"},
  {X2AP_RRM_RSU_RRM_START_REQ,"X2AP_RRM_RSU_RRM_START_REQ"},
  {X2AP_RRM_RSU_ENB_START_RES,"X2AP_RRM_RSU_ENB_START_RES"},
  {X2AP_RRM_RSU_RRM_START_RES,"X2AP_RRM_RSU_RRM_START_RES"},
  {X2AP_RRM_RSU_ENB_STOP_REQ,"X2AP_RRM_RSU_ENB_STOP_REQ"},
  {X2AP_RRM_RSU_RRM_STOP_REQ,"X2AP_RRM_RSU_RRM_STOP_REQ"},
  {X2AP_RRM_RSU_RRM_STOP_RES,"X2AP_RRM_RSU_RRM_STOP_RES"},
  {X2AP_RRM_RSU_ENB_STOP_RES,"X2AP_RRM_RSU_ENB_STOP_RES"},
  {X2AP_RRM_RSU_RRM_UPDATE,"X2AP_RRM_RSU_RRM_UPDATE"},
  {X2AP_RRM_RSU_RRM_UPDATE_IND,"X2AP_RRM_RSU_RRM_UPDATE_IND"},
  {X2AP_RRM_ENB_CONFIG_UPDATE_REQ,"X2AP_RRM_ENB_CONFIG_UPDATE_REQ"},
  {X2AP_RRM_ENB_CONFIG_UPDATE_IND,"X2AP_RRM_ENB_CONFIG_UPDATE_IND"},
  {X2AP_RRM_RESET_REQ,"X2AP_RRM_RESET_REQ"},
  {X2AP_RRM_ENB_CONFIG_UPDATE_RES,"X2AP_RRM_ENB_CONFIG_UPDATE_RES"},
  {X2AP_RRM_RESET_RES,"X2AP_RRM_RESET_RES"},
  {X2AP_RRM_RESET_IND,"X2AP_RRM_RESET_IND"},
  {X2AP_RRM_RLF_IND,"X2AP_RRM_RLF_IND"},
  {RRC_RRM_ERB_RELEASE_IND ,"RRC_RRM_ERB_RELEASE_IND "},	
  {RRC_RRM_PROXIMITY_IND ,"RRC_RRM_PROXIMITY_IND "},	
  {RRC_RRM_INTRA_ENB_HO_IND ,"RRC_RRM_INTRA_ENB_HO_IND "},	
  {RRC_RRM_UE_RECONFIG_REQ ,"RRC_RRM_UE_RECONFIG_REQ "},	
  {RRC_RRM_UE_RECONFIG_RESP ,"RRC_RRM_UE_RECONFIG_RESP "},	

};


static const value_string tagType_L3_oam[]=
{ 
  {RRC_OAM_INIT_IND ,"RRC_OAM_INIT_IND"},			
  {RRC_OAM_INIT_CNF ,"RRC_OAM_INIT_CNF"},			
  {RRC_OAM_COMMUNICATION_INFO_REQ ,"RRC_OAM_COMMUNICATION_INFO_REQ"},			
  {RRC_OAM_COMMUNICATION_INFO_RESP ,"RRC_OAM_COMMUNICATION_INFO_RESP"},			
  {RRC_OAM_PROVISION_REQ ,"RRC_OAM_PROVISION_REQ"},			
  {RRC_OAM_PROVISION_RESP ,"RRC_OAM_PROVISION_RESP"},			
  {RRC_OAM_S1AP_INFO_REQ ,"RRC_OAM_S1AP_INFO_REQ"},			
  {RRC_OAM_S1AP_INFO_RESP ,"RRC_OAM_S1AP_INFO_RESP"},			
  {RRC_OAM_SET_LOG_LEVEL_REQ ,"RRC_OAM_SET_LOG_LEVEL_REQ"},			
  {RRC_OAM_SET_LOG_LEVEL_RESP ,"RRC_OAM_SET_LOG_LEVEL_RESP"},			
  {RRC_OAM_LOG_ENABLE_REQ ,"RRC_OAM_LOG_ENABLE_REQ"},			
  {RRC_OAM_LOG_ENABLE_RESP,"RRC_OAM_LOG_ENABLE_RESP"},			
  {RRC_OAM_GET_CELL_STATS_REQ ,"RRC_OAM_GET_CELL_STATS_REQ"},			
  {RRC_OAM_GET_CELL_STATS_RESP ,"RRC_OAM_GET_CELL_STATS_RESP"},			
  {RRC_OAM_GET_CELL_STATUS_REQ ,"RRC_OAM_GET_CELL_STATUS_REQ"},			
  {RRC_OAM_GET_CELL_STATUS_RESP ,"RRC_OAM_GET_CELL_STATUS_RESP"},			
  {RRC_OAM_GET_UE_STATUS_REQ ,"RRC_OAM_GET_UE_STATUS_REQ"},			
  {RRC_OAM_GET_UE_STATUS_RESP ,"RRC_OAM_GET_UE_STATUS_RESP"},			
  {RRC_OAM_RESET_CELL_STATS_REQ ,"RRC_OAM_RESET_CELL_STATS_REQ"},			
  {RRC_OAM_RESET_CELL_STATS_RESP ,"RRC_OAM_RESET_CELL_STATS_RESP"},			
  {RRC_OAM_CLEANUP_REQ ,"RRC_OAM_CLEANUP_REQ"},			
  {RRC_OAM_CLEANUP_RESP ,"RRC_OAM_CLEANUP_RESP"},
  {RRC_OAM_CONFIG_STATS_REQ,"RRC_OAM_CONFIG_STATS_REQ"},
  {RRC_OAM_CONFIG_STATS_RESP,"RRC_OAM_CONFIG_STATS_RESP"},
  {S1AP_OAM_INIT_IND,"S1AP_OAM_INIT_IND"},
  {S1AP_OAM_INIT_CNF,"S1AP_OAM_INIT_CNF"},
  {S1AP_OAM_PROVISION_REQ,"S1AP_OAM_PROVISION_REQ"},
  {S1AP_OAM_PROVISION_RESP,"S1AP_OAM_PROVISION_RESP"},
  {S1AP_OAM_CLEANUP_REQ,"S1AP_OAM_CLEANUP_REQ"},
  {S1AP_OAM_CLEANUP_RESP,"S1AP_OAM_CLEANUP_RESP"},
  {S1AP_OAM_RESET_REQ,"S1AP_OAM_RESET_REQ"},
  {S1AP_OAM_RESET_RESP,"S1AP_OAM_RESET_RESP"},
  {S1AP_OAM_STATS_IND,"S1AP_OAM_STATS_IND"},
  {S1AP_OAM_STATS_RESP,"S1AP_OAM_STATS_RESP"},
  {S1AP_OAM_S1AP_LINK_STATUS_IND,"S1AP_OAM_S1AP_LINK_STATUS_IND"},
  {X2AP_OAM_INIT_IND,"X2AP_OAM_INIT_IND"},
  {X2AP_OAM_PROVISION_REQ,"X2AP_OAM_PROVISION_REQ"},
  {X2AP_OAM_PROVISION_RESP,"X2AP_OAM_PROVISION_RESP"},
  {X2AP_OAM_LINK_DOWN_IND,"X2AP_OAM_LINK_DOWN_IND"},
  {X2AP_OAM_LINK_UP_IND,"X2AP_OAM_LINK_UP_IND"},
  {X2AP_OAM_ADD_ENB_REQ,"X2AP_OAM_ADD_ENB_REQ"},
  {X2AP_OAM_ADD_ENB_RES,"X2AP_OAM_ADD_ENB_RES"},
  {S1AP_OAM_ADD_MME_REQ,"S1AP_OAM_ADD_MME_REQ"},
  {S1AP_OAM_ADD_MME_RES,"S1AP_OAM_ADD_MME_RES"},
  {S1AP_OAM_ENB_CONFIG_UPDATE,"S1AP_OAM_ENB_CONFIG_UPDATE"},
  {S1AP_OAM_ENB_CONFIG_UPDATE_RESPONSE,"S1AP_OAM_ENB_CONFIG_UPDATE_RESPONSE"},
};
/*
static const value_string tagType_s1ap_oam[]=
{ 
  {S1AP_OAM_INIT_IND,"S1AP_OAM_INIT_IND"},
  {S1AP_OAM_INIT_CNF,"S1AP_OAM_INIT_CNF"},
  {S1AP_OAM_PROVISION_REQ,"S1AP_OAM_PROVISION_REQ"},
  {S1AP_OAM_PROVISION_RESP,"S1AP_OAM_PROVISION_RESP"},
  {S1AP_OAM_CLEANUP_REQ,"S1AP_OAM_CLEANUP_REQ"},
  {S1AP_OAM_CLEANUP_RESP,"S1AP_OAM_CLEANUP_RESP"},
  {S1AP_OAM_RESET_REQ,"S1AP_OAM_RESET_REQ"},
  {S1AP_OAM_RESET_RESP,"S1AP_OAM_RESET_RESP"},
  {S1AP_OAM_STATS_IND,"S1AP_OAM_STATS_IND"},
  {S1AP_OAM_STATS_RESP,"S1AP_OAM_STATS_RESP"}
};
*/

static const value_string tagType_L3_mac[]=
{ 
  {RRC_MAC_CONFIG_CELL_REQ ,"RRC_MAC_CONFIG_CELL_REQ"},
  {RRC_MAC_SFN_REQ ,"RRC_MAC_SFN_REQ"},			
  {RRC_MAC_RECONFIG_CELL_REQ ,"RRC_MAC_RECONFIG_CELL_REQ"},			
  {RRC_MAC_CREATE_UE_ENTITY_REQ ,"RRC_MAC_CREATE_UE_ENTITY_REQ"},			
  {RRC_MAC_DELETE_UE_ENTITY_REQ ,"RRC_MAC_DELETE_UE_ENTITY_REQ"},			
  {RRC_MAC_RECONFIGURE_UE_ENTITY_REQ ,"RRC_MAC_RECONFIGURE_UE_ENTITY_REQ"},			
  {RRC_MAC_UE_DRX_CMD_REQ ,"RRC_MAC_UE_DRX_CMD_REQ"},			
  {RRC_MAC_BCCH_CONFIG_REQ ,"RRC_MAC_BCCH_CONFIG_REQ"},			
  {RRC_MAC_PCCH_MSG_REQ ,"RRC_MAC_PCCH_MSG_REQ"},			
  {RRC_MAC_CCCH_MSG_REQ ,"RRC_MAC_CCCH_MSG_REQ"},			
  {RRC_MAC_UE_CON_REJ_REQ ,"RRC_MAC_UE_CON_REJ_REQ"},
  {RRC_MAC_DELETE_CELL_REQ ,"RRC_MAC_DELETE_CELL_REQ"},
  {RRC_MAC_DELETE_CELL_CNF ,"RRC_MAC_DELETE_CELL_CNF"},
  {RRC_MAC_CONFIG_CELL_CNF ,"RRC_MAC_CONFIG_CELL_CNF"},
  {RRC_MAC_SFN_CNF,"RRC_MAC_SFN_CNF"},
  {RRC_MAC_RECONFIG_CELL_CNF,"RRC_MAC_RECONFIG_CELL_CNF"},
  {RRC_MAC_CREATE_UE_ENTITY_CNF,"RRC_MAC_CREATE_UE_ENTITY_CNF"},
  {RRC_MAC_DELETE_UE_ENTITY_CNF,"RRC_MAC_DELETE_UE_ENTITY_CNF"},
  {RRC_MAC_RECONFIGURE_UE_ENTITY_CNF,"RRC_MAC_RECONFIGURE_UE_ENTITY_CNF"},
  {RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND,"RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND"},
  {RRC_MAC_SFN_IND,"RRC_MAC_SFN_IND"},
  {RRC_MAC_CCCH_MSG_IND,"RRC_MAC_CCCH_MSG_IND"},
  {RRC_MAC_HO_RACH_RESOURCE_REQ,"RRC_MAC_HO_RACH_RESOURCE_REQ"},
  {RRC_MAC_HO_RACH_RESOURCE_RESP,"RRC_MAC_HO_RACH_RESOURCE_RESP"},
  {RRC_MAC_UE_INACTIVE_TIME_REQ,"RRC_MAC_UE_INACTIVE_TIME_REQ"},
  {RRC_MAC_UE_INACTIVE_TIME_RESP,"RRC_MAC_UE_INACTIVE_TIME_RESP"},
  {RRC_MAC_RESET_UE_ENTITY_REQ,"RRC_MAC_RESET_UE_ENTITY_REQ"},
  {RRC_MAC_RESET_UE_ENTITY_CNF,"RRC_MAC_RESET_UE_ENTITY_CNF"},
  {RRC_MAC_CHANGE_CRNTI_REQ,"RRC_MAC_CHANGE_CRNTI_REQ"},
  {RRC_MAC_CHANGE_CRNTI_CNF,"RRC_MAC_CHANGE_CRNTI_CNF"},
  {RRC_MAC_INACTIVE_UES_IND,"RRC_MAC_INACTIVE_UES_IND"},
  {RRC_MAC_HO_REL_RACH_RESOURCE_IND,"RRC_MAC_HO_REL_RACH_RESOURCE_IND"},
  {RRC_MAC_RLF_IND,"RRC_MAC_RLF_IND"},
  {RRC_MAC_SFN_ERR_IND,"RRC_MAC_SFN_ERR_IND"},
  {RRC_MAC_CELL_STOP_REQ,"RRC_MAC_CELL_STOP_REQ"},
  {RRC_MAC_CELL_START_CNF,"RRC_MAC_CELL_START_CNF"},
  {RRC_MAC_CELL_STOP_CNF,"RRC_MAC_CELL_STOP_CNF"},
  {RRC_MAC_CELL_START_REQ,"RRC_MAC_CELL_START_REQ"},
  {MAC_UE_SYNC_STATUS_IND,"MAC_UE_SYNC_STATUS_IND"},
};
			
static const value_string tagType_L3_rlc[]=
{ 
  {RRC_RLC_CREATE_UE_ENTITY_REQ ,"RRC_RLC_CREATE_UE_ENTITY_REQ"},			
  {RRC_RLC_CREATE_UE_ENTITY_CNF ,"RRC_RLC_CREATE_UE_ENTITY_CNF"},			
  {RRC_RLC_RECONFIG_UE_ENTITY_REQ ,"RRC_RLC_RECONFIG_UE_ENTITY_REQ"},			
  {RRC_RLC_RECONFIG_UE_ENTITY_CNF ,"RRC_RLC_RECONFIG_UE_ENTITY_CNF"},			
  {RRC_RLC_DELETE_UE_ENTITY_REQ ,"RRC_RLC_DELETE_UE_ENTITY_REQ"},			
  {RRC_RLC_DELETE_UE_ENTITY_CNF ,"RRC_RLC_DELETE_UE_ENTITY_CNF"},			
  {RRC_RLC_RE_ESTABLISH_UE_ENTITY_REQ ,"RRC_RLC_RE_ESTABLISH_UE_ENTITY_REQ"},			
  {RRC_RLC_RE_ESTABLISH_UE_ENTITY_CNF ,"RRC_RLC_RE_ESTABLISH_UE_ENTITY_CNF"},			
  {RRC_RLC_COMMON_CHANNEL_DATA_REQ ,"RRC_RLC_COMMON_CHANNEL_DATA_REQ"},			
  {RRC_RLC_COMMON_CHANNEL_DATA_IND ,"RRC_RLC_COMMON_CHANNEL_DATA_IND"},
  {RRC_RLC_CHANGE_CRNTI_REQ ,"RRC_RLC_CHANGE_CRNTI_REQ"},			
  {RRC_RLC_CHANGE_CRNTI_CNF ,"RRC_RLC_CHANGE_CRNTI_CNF"},			
  {RRC_RLC_UE_ENTITY_ERROR_IND ,"RRC_RLC_UE_ENTITY_ERROR_IND"},			
};
			
static const value_string tagType_L3_pdcp_req[]=
{ 
  {RRC_PDCP_CREATE_UE_ENTITY_REQ ,"RRC_PDCP_CREATE_UE_ENTITY_REQ"},			
  {RRC_PDCP_RECONFIG_UE_ENTITY_REQ ,"RRC_PDCP_RECONFIG_UE_ENTITY_REQ"},			
  {RRC_PDCP_RESUME_UE_ENTITY_REQ ,"RRC_PDCP_RESUME_UE_ENTITY_REQ"},			
  {RRC_PDCP_DELETE_UE_ENTITY_REQ ,"RRC_PDCP_DELETE_UE_ENTITY_REQ"},			
  {RRC_PDCP_SUSPEND_UE_ENTITY_REQ ,"RRC_PDCP_SUSPEND_UE_ENTITY_REQ"},			
  {RRC_PDCP_SRB_DATA_REQ ,"RRC_PDCP_SRB_DATA_REQ"},			
  {RRC_PDCP_MAC_I_REQ ,"RRC_PDCP_MAC_I_REQ"},			
  {RRC_PDCP_CHANGE_CRNTI_REQ ,"RRC_PDCP_CHANGE_CRNTI_REQ"},			
  {RRC_PDCP_REESTABLISHMENT_UE_ENTITY_REQ ,"RRC_PDCP_REESTABLISHMENT_UE_ENTITY_REQ"},			
  {RRC_PDCP_SN_HFN_STATUS_REQ ,"RRC_PDCP_SN_HFN_STATUS_REQ"},			
  {RRC_PDCP_DATA_BUFFER_STOP_IND ,"RRC_PDCP_DATA_BUFFER_STOP_IND"},			
};

static const value_string tagType_L3_pdcp_cnf[]=
{ 
  {RRC_PDCP_CREATE_UE_ENTITY_CNF ,"RRC_PDCP_CREATE_UE_ENTITY_CNF"},			
  {RRC_PDCP_RECONFIG_UE_ENTITY_CNF ,"RRC_PDCP_RECONFIG_UE_ENTITY_CNF"},			
  {RRC_PDCP_DELETE_UE_ENTITY_CNF ,"RRC_PDCP_DELETE_UE_ENTITY_CNF"},			
  {RRC_PDCP_RESUME_UE_ENTITY_CNF ,"RRC_PDCP_RESUME_UE_ENTITY_CNF"},			
  {RRC_PDCP_REESTABLISHMENT_UE_ENTITY_CNF ,"RRC_PDCP_REESTABLISHMENT_UE_ENTITY_CNF"},			
  {RRC_PDCP_CHANGE_CRNTI_CNF ,"RRC_PDCP_CHANGE_CRNTI_CNF"},			
  {RRC_PDCP_SUSPEND_UE_ENTITY_CNF ,"RRC_PDCP_SUSPEND_UE_ENTITY_CNF"},			
  {RRC_PDCP_SRB_DATA_IND ,"RRC_PDCP_SRB_DATA_IND"},			
  {RRC_PDCP_SN_HFN_STATUS_RESP ,"RRC_PDCP_SN_HFN_STATUS_RESP"},			
  {RRC_PDCP_SN_HFN_STATUS_IND ,"RRC_PDCP_SN_HFN_STATUS_IND"},			
  {RRC_PDCP_DATA_BUFFER_STOP_IND ,"RRC_PDCP_DATA_BUFFER_STOP_IND"},			
  {RRC_PDCP_MAC_I_RESP ,"RRC_PDCP_MAC_I_RESP"},			
  {RRC_PDCP_SRB_DATA_STATUS_IND ,"RRC_PDCP_SRB_DATA_STATUS_IND"},			
  {PDCP_COUNT_WRAPAROUND_IND ,"PDCP_COUNT_WRAPAROUND_IND"}			
};

static const value_string tagType_oam_rrm[]=
{
  {RRM_OAM_INIT_IND,"RRM_OAM_INIT_IND"},			
  {RRM_OAM_INIT_IND_RESP,"RRM_OAM_SET_CELL_SETUP_PARAM_RESP"},			
  {RRM_OAM_SET_TRANS_MODE_REQ,"RRM_OAM_SET_TRANS_MODE_REQ"},		
  {RRM_OAM_SET_TRANS_MODE_RESP,"RRM_OAM_SET_TRANS_MODE_RESP"},			
  {RRM_OAM_SET_ROHC_PROFILE_REQ,"RRM_OAM_SET_PDCP_PARAMS_REQ"},
  {RRM_OAM_SET_UE_SEMI_STATIC_PARAM_REQ,"RRM_OAM_SET_UE_SEMI_STATIC_PARAM_REQ"},		
  {RRM_OAM_SET_TDD_PARAM_REQ,"RRM_OAM_SET_TDD_PARAM_REQ"},		
  {RRM_OAM_SET_MAC_PARAM_REQ,"RRM_OAM_SET_MAC_PARAM_REQ"},		
  {RRM_OAM_SET_RLC_MODE_REQ,"RRM_OAM_SET_RLC_MODE_REQ"},		
  {RRM_OAM_SET_RLC_MODE_PARAM_REQ,"RRM_OAM_SET_RLC_MODE_PARAM_REQ"},	
  {RRM_OAM_SET_UE_SRS_PARAM_REQ,"RRM_OAM_SET_UE_SRS_PARAM_REQ"},	
  {RRM_OAM_INIT_REQ,"RRM_OAM_INIT_REQ"},		
  {RRM_OAM_CELL_DELETE_REQ,"RRM_OAM_DELETE_REQ"},		
  {RRM_OAM_CELL_DELETE_RESP,"RRM_OAM_DELETE_RESP"},		
  {RRM_OAM_CELL_SETUP_RESP,"RRM_OAM_SETUP_RESP"},		
  {RRM_OAM_SET_PHY_PARAM_REQ,"RRM_OAM_SET_PHY_PARAM_REQ"},		
  {RRM_OAM_SET_RLF_TIMERS_AND_CONSTANTS_PARAM_R9_REQ,"RRM_OAM_SET_RLF_TIMERS_AND_CONSTANTS_PARAM_R9_REQ"},
  {RRM_OAM_SET_LOGICAL_CHANNEL_CONFIG_PARAM_REQ,"RRM_OAM_SET_LOGICAL_CHANNEL_CONFIG_PARAM_REQ"}
};

static const value_string tagType_rrc_s1U[]=
{
  {RRC_S1U_CREATE_UE_ENTITY_REQ,"RRC_S1U_CREATE_UE_ENTITY_REQ"},			
  {RRC_S1U_CREATE_UE_ENTITY_CNF,"RRC_S1U_CREATE_UE_ENTITY_CNF"},			
  {RRC_S1U_DELETE_UE_ENTITY_REQ,"RRC_S1U_DELETE_UE_ENTITY_REQ"},
  {RRC_S1U_DELETE_UE_ENTITY_CNF,"RRC_S1U_DELETE_UE_ENTITY_CNF"},			
  {RRC_S1U_RECONFIGURE_UE_ENTITY_REQ,"RRC_S1U_RECONFIGURE_UE_ENTITY_REQ"},			
  {RRC_S1U_RECONFIGURE_UE_ENTITY_CNF,"RRC_S1U_RECONFIGURE_UE_ENTITY_CNF"},			
  {RRC_S1U_ERROR_IND,"RRC_S1U_ERROR_IND"},			
  {RRC_S1U_END_MARKER_IND,"RRC_S1U_END_MARKER_IND"},			
  {RRC_S1U_PATH_FAILURE_IND,"RRC_S1U_PATH_FAILURE_IND"}			
};


static const value_string tagType_oam_s1U[]=
{
  {EGTPU_OAM_INITDB_REQ,"EGTPU_OAM_INITDB_REQ"},
  {EGTPU_OAM_LM_INITDB_CNF,"EGTPU_OAM_LM_INITDB_CNF"}
};


static const value_string tagType_rrm_mac[]=
{
  {RRM_MAC_CELL_CONFIG_REQ,"RRM_MAC_CELL_CONFIG_REQ"},
  {RRM_MAC_RECONFIG_SCHEDULER_REQ,"RRM_MAC_RECONFIG_SCHEDULER_REQ"},
  {RRM_MAC_UE_RECONFIG_REQ,"RRM_MAC_UE_RECONFIG_REQ"},
  {RRM_MAC_CELL_CONFIG_CNF,"RRM_MAC_CELL_CONFIG_CNF"},
  {RRM_MAC_SCHEDULER_RECONFIG_CNF,"RRM_MAC_SCHEDULER_RECONFIG_CNF"},
  {RRM_MAC_UE_RECONFIG_CNF,"RRM_MAC_UE_RECONFIG_CNF"},
  {RRM_MAC_PERIODIC_REPORT_IND,"RRM_MAC_PERIODIC_REPORT_IND"},
};

#endif