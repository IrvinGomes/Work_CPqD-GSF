/********************************************************************
 *
 *  FILE NAME   : rrc_ext_api.h
 *
 *  DESCRIPTION : This file contains the interface message API
 *                IDs for all modules external to RRC.
 *
 *  REVISION HISTORY :
 *
 *  DATE          Name        Reference         Comments
 *  ----          ----        ---------         --------
 *  11 MAY 2009   Yusuf R     API no. 408500003 Initial
 *
 *  Copyright (c) 2009, Aricent Inc.
 *
 *******************************************************************/

#ifndef _RRC_EXT_API_H_
#define _RRC_EXT_API_H_

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

/********************************************************************
 * RRC - MAC APIs
 *******************************************************************/
#define RRC_MAC_API_BASE                     0x0000

#define RRC_MAC_CONFIG_CELL_REQ              (RRC_MAC_API_BASE + 0x01)
#define RRC_MAC_SFN_REQ                      (RRC_MAC_API_BASE + 0x02)
#define RRC_MAC_RECONFIG_CELL_REQ            (RRC_MAC_API_BASE + 0x03)
#define RRC_MAC_CREATE_UE_ENTITY_REQ         (RRC_MAC_API_BASE + 0x04)
#define RRC_MAC_DELETE_UE_ENTITY_REQ         (RRC_MAC_API_BASE + 0x05)
#define RRC_MAC_RECONFIGURE_UE_ENTITY_REQ    (RRC_MAC_API_BASE + 0x06)
#define RRC_MAC_UE_DRX_CMD_REQ               (RRC_MAC_API_BASE + 0x07)
#define RRC_MAC_BCCH_CONFIG_REQ              (RRC_MAC_API_BASE + 0x08)
#define RRC_MAC_PCCH_MSG_REQ                 (RRC_MAC_API_BASE + 0x09)
#define RRC_MAC_CCCH_MSG_REQ                 (RRC_MAC_API_BASE + 0x0A)
#define RRC_MAC_UE_CON_REJ_REQ               (RRC_MAC_API_BASE + 0x0B)

#define RRC_MAC_DELETE_CELL_REQ              (RRC_MAC_API_BASE + 0x0C)
#define RRC_MAC_DELETE_CELL_CNF              (RRC_MAC_API_BASE + 0x6B)

#define RRC_MAC_CONFIG_CELL_CNF              (RRC_MAC_API_BASE + 0x65)
#define RRC_MAC_SFN_CNF                      (RRC_MAC_API_BASE + 0x66)
#define RRC_MAC_RECONFIG_CELL_CNF            (RRC_MAC_API_BASE + 0x67)
#define RRC_MAC_CREATE_UE_ENTITY_CNF         (RRC_MAC_API_BASE + 0x68)
#define RRC_MAC_DELETE_UE_ENTITY_CNF         (RRC_MAC_API_BASE + 0x69)
#define RRC_MAC_RECONFIGURE_UE_ENTITY_CNF    (RRC_MAC_API_BASE + 0x6A)

#define RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND (RRC_MAC_API_BASE + 0xC9)
#define RRC_MAC_SFN_IND                      (RRC_MAC_API_BASE + 0xCA)
#define RRC_MAC_CCCH_MSG_IND                 (RRC_MAC_API_BASE + 0xCB)

#define RRC_MAC_MAX_API                      RRC_MAC_CCCH_MSG_IND

/******************************************************************************
 * RRC - MAC TAGs
 *****************************************************************************/
#define RRC_MAC_TAG_BASE                        0

#define RRC_MAC_RACH_CONFIG_INFO                (RRC_MAC_TAG_BASE + 0x01)
#define RRC_MAC_PHICH_CONFIG_INFO               (RRC_MAC_TAG_BASE + 0x02)
#define RRC_MAC_MIB_MSG_REQ                     (RRC_MAC_TAG_BASE + 0x03)
#define RRC_MAC_SIBTYPE1_MSG_REQ                (RRC_MAC_TAG_BASE + 0x04) /*TODO:RRC_MAC_SIBTYPE1_MSG_INFO ?*/
#define RRC_MAC_SI_MSG_INFO                     (RRC_MAC_TAG_BASE + 0x05)
#define RRC_MAC_SI_MSG_REQ                      (RRC_MAC_TAG_BASE + 0x06)
#define RRC_MAC_CONFIG_CELL_ERROR_CODE          (RRC_MAC_TAG_BASE + 0x07)
#define RRC_MAC_SFN_SF_INFO                     (RRC_MAC_TAG_BASE + 0x08)
#define RRC_MAC_ADD_UE_INFO                     (RRC_MAC_TAG_BASE + 0x09)
#define RRC_MAC_CREATE_LC_INFO                  (RRC_MAC_TAG_BASE + 0x0A)
#define RRC_MAC_SR_CONFIG_INFO                  (RRC_MAC_TAG_BASE + 0x0B)
#define RRC_MAC_CQI_INFO                        (RRC_MAC_TAG_BASE + 0x0C)
#define RRC_MAC_UL_LC_CREATE_REQ                (RRC_MAC_TAG_BASE + 0x0D)
#define RRC_MAC_DL_LC_CREATE_REQ                (RRC_MAC_TAG_BASE + 0x0E)
#define RRC_MAC_UL_LC_RECONFIGURE_REQ           (RRC_MAC_TAG_BASE + 0x0F)
#define RRC_MAC_DL_LC_RECONFIGURE_REQ           (RRC_MAC_TAG_BASE + 0x10)
#define RRC_MAC_SR_SETUP_INFO                   (RRC_MAC_TAG_BASE + 0x11)
#define RRC_MAC_CREATE_LC_ERROR                 (RRC_MAC_TAG_BASE + 0x12)
#define RRC_MAC_UL_LC_CONFIG_RESP               (RRC_MAC_TAG_BASE + 0x13)
#define RRC_MAC_DL_LC_CONFIG_RESP               (RRC_MAC_TAG_BASE + 0x14)
#define RRC_MAC_RECONFIG_UE_INFO                (RRC_MAC_TAG_BASE + 0x15)
#define RRC_MAC_RECONFIGURE_LC_REQ              (RRC_MAC_TAG_BASE + 0x16)
#define RRC_MAC_CREATE_LC_REQ                   (RRC_MAC_TAG_BASE + 0x17)
#define RRC_MAC_DELETE_LC_REQ                   (RRC_MAC_TAG_BASE + 0x18)
#define RRC_MAC_DL_MAX_RB_INFO                  (RRC_MAC_TAG_BASE + 0x19)
#define RRC_MAC_UL_MAX_RB_INFO                  (RRC_MAC_TAG_BASE + 0x1A)
#define RRC_MAC_TX_MODE_INFO                    (RRC_MAC_TAG_BASE + 0x1B)
#define RRC_MAC_NUM_OF_LAYER_INFO               (RRC_MAC_TAG_BASE + 0x1C)
#define RRC_MAC_CODE_BOOK_INDEX_INFO            (RRC_MAC_TAG_BASE + 0x1D)
#define RRC_MAC_SIMULTANEOUS_ACK_NACK_CQI_INFO  (RRC_MAC_TAG_BASE + 0x1E)
#define RRC_MAC_CQI_PMI_CONFIG_INDEX_INFO       (RRC_MAC_TAG_BASE + 0x1F)
#define RRC_MAC_RECONFIGURE_LC_ERROR            (RRC_MAC_TAG_BASE + 0x20)
#define RRC_MAC_DELETE_LC_ERROR                 (RRC_MAC_TAG_BASE + 0x21)
#define RRC_MAC_PUCCH_CONFIG_INFO               (RRC_MAC_TAG_BASE + 0x22)
#define RRC_MAC_SI_MSG_INFO_PARAM               (RRC_MAC_TAG_BASE + 0x23)

#define RRC_MAC_CQI_APERIODIC_CONFIG_INFO       (RRC_MAC_TAG_BASE + 0x32)
#define RRC_MAC_CQI_PERIODIC_CONFIG_INFO        (RRC_MAC_TAG_BASE + 0x33)
#define RRC_MAC_RI_CONFIG_INDEX_INFO            (RRC_MAC_TAG_BASE + 0x34)
#define RRC_MAC_RBS_FOR_DCI_1A                  (RRC_MAC_TAG_BASE + 0x81)

#define RRC_MAC_MAX_TAG                          RRC_MAC_RBS_FOR_DCI_1A 

/********************************************************************
 * RRC - RLC APIs
 *******************************************************************/
#define RRC_RLC_API_BASE                     0x0000

#define RRC_RLC_CREATE_UE_ENTITY_REQ         (RRC_RLC_API_BASE + 1)
#define RRC_RLC_CREATE_UE_ENTITY_CNF         (RRC_RLC_API_BASE + 2)
#define RRC_RLC_RECONFIG_UE_ENTITY_REQ       (RRC_RLC_API_BASE + 3)
#define RRC_RLC_RECONFIG_UE_ENTITY_CNF       (RRC_RLC_API_BASE + 4)
#define RRC_RLC_DELETE_UE_ENTITY_REQ         (RRC_RLC_API_BASE + 5)
#define RRC_RLC_DELETE_UE_ENTITY_CNF         (RRC_RLC_API_BASE + 6)
#define RRC_RLC_RE_ESTABLISH_UE_ENTITY_REQ   (RRC_RLC_API_BASE + 7)
#define RRC_RLC_RE_ESTABLISH_UE_ENTITY_CNF   (RRC_RLC_API_BASE + 8)
#define RRC_RLC_COMMON_CHANNEL_DATA_REQ      (RRC_RLC_API_BASE + 9)
#define RRC_RLC_COMMON_CHANNEL_DATA_IND      (RRC_RLC_API_BASE + 10)
#define RRC_RLC_MAX_API                      RRC_RLC_COMMON_CHANNEL_DATA_IND

/******************************************************************************
 * RRC - RLC TAGs
 *****************************************************************************/
#define RRC_RLC_TAG_BASE                        11

#define RRC_RLC_CREATE_TX_UM_RLC_ENTITY         (RRC_RLC_TAG_BASE + 0)
#define RRC_RLC_CREATE_RX_UM_RLC_ENTITY         (RRC_RLC_TAG_BASE + 1)
#define RRC_RLC_CREATE_TX_RX_UM_RLC_ENTITY      (RRC_RLC_TAG_BASE + 2)
#define RRC_RLC_CREATE_TX_RX_AM_RLC_ENTITY      (RRC_RLC_TAG_BASE + 3)

#define RRC_RLC_DELETE_TX_UM_RLC_ENTITY         (RRC_RLC_TAG_BASE + 6)
#define RRC_RLC_DELETE_RX_UM_RLC_ENTITY         (RRC_RLC_TAG_BASE + 7)
#define RRC_RLC_DELETE_TX_RX_UM_RLC_ENTITY      (RRC_RLC_TAG_BASE + 8)
#define RRC_RLC_DELETE_TX_RX_AM_RLC_ENTITY      (RRC_RLC_TAG_BASE + 9)

#define RRC_RLC_RECONFIG_TX_UM_RLC_ENTITY       (RRC_RLC_TAG_BASE + 10)
#define RRC_RLC_RECONFIG_RX_UM_RLC_ENTITY       (RRC_RLC_TAG_BASE + 11)
#define RRC_RLC_RECONFIG_TX_RX_UM_RLC_ENTITY    (RRC_RLC_TAG_BASE + 12)
#define RRC_RLC_RECONFIG_TX_RX_AM_RLC_ENTITY    (RRC_RLC_TAG_BASE + 13)

#define RRC_RLC_ENTITY_LCID                     (RRC_RLC_TAG_BASE + 17)

#define RRC_RLC_CREATE_ENTITY_ERROR             (RRC_RLC_TAG_BASE + 18)
#define RRC_RLC_DELETE_ENTITY_ERROR             (RRC_RLC_TAG_BASE + 19)
#define RRC_RLC_RECONFIG_ENTITY_ERROR           (RRC_RLC_TAG_BASE + 20)
#define RRC_RLC_RE_ESTABLISH_ENTITY_ERROR       (RRC_RLC_TAG_BASE + 21)

#define RRC_RLC_MAX_TAG                         RRC_RLC_RE_ESTABLISH_ENTITY_ERROR

/********************************************************************
 * RRC - PDCP APIs
 *******************************************************************/
#define RRC_PDCP_API_BASE                     0x0000

#define RRC_PDCP_CREATE_UE_ENTITY_REQ         (RRC_PDCP_API_BASE + 0)
#define RRC_PDCP_RECONFIG_UE_ENTITY_REQ       (RRC_PDCP_API_BASE + 1)
#define RRC_PDCP_DELETE_UE_ENTITY_REQ         (RRC_PDCP_API_BASE + 2)
#define RRC_PDCP_SRB_DATA_REQ                 (RRC_PDCP_API_BASE + 3)

#define RRC_PDCP_CREATE_UE_ENTITY_CNF         (RRC_PDCP_API_BASE + 0)
#define RRC_PDCP_RECONFIG_UE_ENTITY_CNF       (RRC_PDCP_API_BASE + 1)
#define RRC_PDCP_DELETE_UE_ENTITY_CNF         (RRC_PDCP_API_BASE + 2)
#define RRC_PDCP_SRB_DATA_IND                 (RRC_PDCP_API_BASE + 3)
#define RRC_PDCP_SRB_DATA_STATUS_IND          (RRC_PDCP_API_BASE + 4)
#define RRC_PDCP_MAX_API                      RRC_PDCP_SRB_DATA_STATUS_IND

/******************************************************************************
 * RRC - PDCP TAGs
 *****************************************************************************/
#define RRC_PDCP_TAG_BASE                           0

#define RRC_PDCP_CREATE_SRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 0)
#define RRC_PDCP_CREATE_DRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 1)
#define RRC_PDCP_CONFIGURE_INTEGRITY_PROTECTION_TAG (RRC_PDCP_TAG_BASE + 2)
#define RRC_PDCP_CONFIGURE_DISCARD_TIMER_TAG        (RRC_PDCP_TAG_BASE + 3)
#define RRC_PDCP_CONFIGURE_SN_SIZE_TAG              (RRC_PDCP_TAG_BASE + 4)
#define RRC_PDCP_CONFIGURE_ROHC_TAG                 (RRC_PDCP_TAG_BASE + 5)
#define RRC_PDCP_CONFIGURE_CIPHERING_TAG            (RRC_PDCP_TAG_BASE + 6)
#define RRC_PDCP_CONFIGURE_ST_REPORT_REQUIRED_TAG   (RRC_PDCP_TAG_BASE + 7)
#define RRC_PDCP_DELETE_SRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 8)
#define RRC_PDCP_DELETE_DRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 9)
#define RRC_PDCP_RECONFIG_SRB_ENTITY_TAG            (RRC_PDCP_TAG_BASE + 10)
#define RRC_PDCP_RECONFIG_DRB_ENTITY_TAG            (RRC_PDCP_TAG_BASE + 11)

#define RRC_PDCP_CREATE_SRB_ENTITY_ERROR_TAG        (RRC_PDCP_TAG_BASE + 0)
#define RRC_PDCP_CREATE_DRB_ENTITY_ERROR_TAG        (RRC_PDCP_TAG_BASE + 1)
#define RRC_PDCP_DELETE_SRB_ENTITY_ERROR_TAG        (RRC_PDCP_TAG_BASE + 2)
#define RRC_PDCP_DELETE_DRB_ENTITY_ERROR_TAG        (RRC_PDCP_TAG_BASE + 3)
#define RRC_PDCP_RECONFIG_SRB_ENTITY_ERROR_TAG      (RRC_PDCP_TAG_BASE + 4)
#define RRC_PDCP_RECONFIG_DRB_ENTITY_ERROR_TAG      (RRC_PDCP_TAG_BASE + 5)
#define RRC_PDCP_SRB_DATA_STATUS_ERROR_TAG          (RRC_PDCP_TAG_BASE + 6)

#define RRC_PDCP_MAX_TAG                            RRC_PDCP_RECONFIG_DRB_ENTITY_TAG

/********************************************************************
 * RRC - PHY APIs
 *******************************************************************/
#define RRC_PHY_API_BASE                      0x0000

#define RRC_PHY_CONFIG_CELL_REQ               (RRC_PHY_API_BASE + 1)
#define RRC_PHY_CONFIG_CELL_CNF               (RRC_PHY_API_BASE + 2)
#define RRC_PHY_DELETE_CELL_REQ               (RRC_PHY_API_BASE + 3)
#define RRC_PHY_DELETE_CELL_CNF               (RRC_PHY_API_BASE + 4)
#define RRC_PHY_CREATE_UE_ENTITY_REQ          (RRC_PHY_API_BASE + 5)
#define RRC_PHY_CREATE_UE_ENTITY_CNF          (RRC_PHY_API_BASE + 6)
#define RRC_PHY_DELETE_UE_ENTITY_REQ          (RRC_PHY_API_BASE + 7)
#define RRC_PHY_DELETE_UE_ENTITY_CNF          (RRC_PHY_API_BASE + 8)
#define RRC_PHY_RECONFIG_UE_ENTITY_REQ        (RRC_PHY_API_BASE + 9)
#define RRC_PHY_RECONFIG_UE_ENTITY_CNF        (RRC_PHY_API_BASE + 10)
#define RRC_PHY_MAX_API                       RRC_PHY_RECONFIG_UE_ENTITY_CNF


/********************************************************************
 * RRC - S1U APIs
 *******************************************************************/
#define RRC_S1U_API_BASE                    0x0000

#define RRC_S1U_CREATE_UE_ENTITY_REQ        (RRC_S1U_API_BASE + 1)
#define RRC_S1U_CREATE_UE_ENTITY_CNF        (RRC_S1U_API_BASE + 2)
#define RRC_S1U_DELETE_UE_ENTITY_REQ        (RRC_S1U_API_BASE + 3)
#define RRC_S1U_DELETE_UE_ENTITY_CNF        (RRC_S1U_API_BASE + 4)
#define RRC_S1U_RECONFIGURE_UE_ENTITY_REQ   (RRC_S1U_API_BASE + 5)
#define RRC_S1U_RECONFIGURE_UE_ENTITY_CNF   (RRC_S1U_API_BASE + 6)
#define RRC_S1U_ERROR_IND                   (RRC_S1U_API_BASE + 7)
#define RRC_S1U_PATH_FAILURE_IND            (RRC_S1U_API_BASE + 8)

#define RRC_S1U_MAX_API                     RRC_S1U_PATH_FAILURE_IND

/********************************************************************
 * RRC - S1U TAGs
 *******************************************************************/
#define RRC_S1U_TAG_BASE                    0

#define RRC_S1U_IE_SEQ_NUM_TAG              (RRC_S1U_TAG_BASE + 1)
#define RRC_S1U_IE_REORDERING_REQD_TAG      (RRC_S1U_TAG_BASE + 2)
#define RRC_S1U_IE_SEQ_DISABLE_TAG          (RRC_S1U_TAG_BASE + 3)
#define RRC_S1U_IE_TEID_DATA_I_TAG          (RRC_S1U_TAG_BASE + 4)
#define RRC_S1U_IE_GSN_ADDR_TAG             (RRC_S1U_TAG_BASE + 5)
#define RRC_S1U_IE_QOS_PROFILE_TAG          (RRC_S1U_TAG_BASE + 6)
#define RRC_S1U_IE_RELAY_SETUP_SAP_REQ_TAG  (RRC_S1U_TAG_BASE + 7)
#define RRC_S1U_IE_RELAY_SETUP_SAP_CNF_TAG  (RRC_S1U_TAG_BASE + 8)
#define RRC_S1U_IE_RELAY_REL_SAP_REQ_TAG    (RRC_S1U_TAG_BASE + 9)
#define RRC_S1U_IE_RELAY_REL_SAP_CNF_TAG    (RRC_S1U_TAG_BASE + 10)

#define RRC_S1U_MAX_TAG                     RRC_S1U_IE_RELAY_REL_SAP_CNF_TAG

/********************************************************************
 * RRC - RRM APIs
 *******************************************************************/
#define RRC_RRM_API_BASE                      0x0000

#define RRC_RRM_UE_RELEASE_REQ                (RRC_RRM_API_BASE + 1)
#define RRC_RRM_UE_RELEASE_RESP               (RRC_RRM_API_BASE + 2)
#define RRC_RRM_CELL_SETUP_REQ                (RRC_RRM_API_BASE + 3)
#define RRC_RRM_CELL_SETUP_RESP               (RRC_RRM_API_BASE + 4)
#define RRC_RRM_CELL_DELETE_REQ               (RRC_RRM_API_BASE + 5)
#define RRC_RRM_CELL_DELETE_RESP              (RRC_RRM_API_BASE + 6)
#define RRC_RRM_UE_ADMISSION_REQ              (RRC_RRM_API_BASE + 7)
#define RRC_RRM_UE_ADMISSION_RESP             (RRC_RRM_API_BASE + 8)
#define RRC_RRM_UE_ADMISSION_CNF              (RRC_RRM_API_BASE + 9)
#define RRC_RRM_ERB_SETUP_REQ                 (RRC_RRM_API_BASE + 10)
#define RRC_RRM_ERB_SETUP_RESP                (RRC_RRM_API_BASE + 11)
#define RRC_RRM_ERB_SETUP_CNF                 (RRC_RRM_API_BASE + 12)
#define RRC_RRM_ERB_RELEASE_REQ               (RRC_RRM_API_BASE + 13)
#define RRC_RRM_ERB_RELEASE_RESP              (RRC_RRM_API_BASE + 14)
#define RRC_RRM_UE_CONNECTION_RELEASE_IND     (RRC_RRM_API_BASE + 15)
#define RRC_RRM_MEASURMENT_RESULTS_IND        (RRC_RRM_API_BASE + 16)
#define RRC_RRM_CELL_STOP_RESP        (RRC_RRM_API_BASE + i49)
#define RRC_RRM_MAX_API                       RRC_RRM_CELL_STOP_RESP


/********************************************************************
 * RRC - OAM APIs
 *******************************************************************/
#define RRC_OAM_API_BASE                      0x0000

#define RRC_OAM_INIT_IND                      (RRC_OAM_API_BASE + 1)
#define RRC_OAM_INIT_CNF                      (RRC_OAM_API_BASE + 2)
#define RRC_OAM_COMMUNICATION_INFO_REQ        (RRC_OAM_API_BASE + 3)
#define RRC_OAM_COMMUNICATION_INFO_RESP       (RRC_OAM_API_BASE + 4)
#define RRC_OAM_PROVISION_REQ                 (RRC_OAM_API_BASE + 5)
#define RRC_OAM_PROVISION_RESP                (RRC_OAM_API_BASE + 6)
#define RRC_OAM_S1AP_INFO_REQ                 (RRC_OAM_API_BASE + 7)
#define RRC_OAM_S1AP_INFO_RESP                (RRC_OAM_API_BASE + 8)
#define RRC_OAM_SET_LOG_LEVEL_REQ             (RRC_OAM_API_BASE + 9)
#define RRC_OAM_SET_LOG_LEVEL_RESP            (RRC_OAM_API_BASE + 10)
#define RRC_OAM_LOG_ENABLE_REQ                (RRC_OAM_API_BASE + 11)
#define RRC_OAM_LOG_ENABLE_RESP               (RRC_OAM_API_BASE + 12)
#define RRC_OAM_GET_CELL_STATS_REQ            (RRC_OAM_API_BASE + 13)
#define RRC_OAM_GET_CELL_STATS_RESP           (RRC_OAM_API_BASE + 14)
#define RRC_OAM_GET_CELL_STATUS_REQ           (RRC_OAM_API_BASE + 15)
#define RRC_OAM_GET_CELL_STATUS_RESP          (RRC_OAM_API_BASE + 16)
#define RRC_OAM_GET_UE_STATUS_REQ             (RRC_OAM_API_BASE + 17)
#define RRC_OAM_GET_UE_STATUS_RESP            (RRC_OAM_API_BASE + 18)
#define RRC_OAM_RESET_CELL_STATS_REQ          (RRC_OAM_API_BASE + 19)
#define RRC_OAM_RESET_CELL_STATS_RESP         (RRC_OAM_API_BASE + 20)
#define RRC_OAM_CLEANUP_REQ                   (RRC_OAM_API_BASE + 21)
#define RRC_OAM_CLEANUP_RESP                  (RRC_OAM_API_BASE + 22)
#define RRC_OAM_MAX_API                       RRC_OAM_CLEANUP_RESP


#define RRM_OAM_API_BASE                      0x0000

#define RRM_OAM_INIT_IND		       (RRM_OAM_API_BASE + 1)
#define RRM_OAM_INIT_IND_RESP                  (RRM_OAM_API_BASE + 2)
#define RRM_OAM_SET_TRANS_MODE_REQ             (RRM_OAM_API_BASE + 3)
#define RRM_OAM_SET_TRANS_MODE_RESP            (RRM_OAM_API_BASE + 4)
#define RRM_OAM_SET_ROHC_PROFILE_REQ           (RRM_OAM_API_BASE + 5)
#define RRM_OAM_SET_UE_SEMI_STATIC_PARAM_REQ   (RRM_OAM_API_BASE + 6)
#define RRM_OAM_SET_TDD_PARAM_REQ              (RRM_OAM_API_BASE + 7)

#endif /* _RRC_EXT_API_H_ */
