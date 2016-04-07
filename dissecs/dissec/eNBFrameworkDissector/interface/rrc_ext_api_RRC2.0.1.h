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
 *  20 MAY 2010   TSinha      API no. <TODO>    Added Support for E-RAB 
 *                                              Management Procedure APIs
 *
 *  Copyright (c) 2009, Aricent Inc.
 *
 *******************************************************************/

#ifndef _RRC_EXT_API_H_
#define _RRC_EXT_API_H_

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#define RRC_S1U_MAX_TUNNELS_PER_LC 3

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
#define RRC_MAC_RESET_UE_ENTITY_REQ          (RRC_MAC_API_BASE + 0x0F)
#define RRC_MAC_DELETE_CELL_CNF              (RRC_MAC_API_BASE + 0x6B)

#define RRC_MAC_CONFIG_CELL_CNF              (RRC_MAC_API_BASE + 0x65)
#define RRC_MAC_SFN_CNF                      (RRC_MAC_API_BASE + 0x66)
#define RRC_MAC_RECONFIG_CELL_CNF            (RRC_MAC_API_BASE + 0x67)
#define RRC_MAC_CREATE_UE_ENTITY_CNF         (RRC_MAC_API_BASE + 0x68)
#define RRC_MAC_DELETE_UE_ENTITY_CNF         (RRC_MAC_API_BASE + 0x69)
#define RRC_MAC_RECONFIGURE_UE_ENTITY_CNF    (RRC_MAC_API_BASE + 0x6A)
#define RRC_MAC_RESET_UE_ENTITY_CNF          (RRC_MAC_API_BASE + 0x6E)
#define RRC_MAC_UE_ENTITY_POWER_HEADROOM_IND (RRC_MAC_API_BASE + 0xC9)
#define RRC_MAC_SFN_IND                      (RRC_MAC_API_BASE + 0xCA)
#define RRC_MAC_CCCH_MSG_IND                 (RRC_MAC_API_BASE + 0xCB)
#define RRC_MAC_HO_RACH_RESOURCE_REQ                 (RRC_MAC_API_BASE + 0x0D)
#define RRC_MAC_HO_RACH_RESOURCE_RESP                 (RRC_MAC_API_BASE + 0x6C)
#define RRC_MAC_UE_INACTIVE_TIME_REQ                 (RRC_MAC_API_BASE + 0x0E)
#define RRC_MAC_UE_INACTIVE_TIME_RESP                (RRC_MAC_API_BASE + 0x6D)
#define RRC_MAC_RESET_UE_ENTITY_REQ                (RRC_MAC_API_BASE + 0x0F)
#define RRC_MAC_RESET_UE_ENTITY_CNF                (RRC_MAC_API_BASE + 0x6E)
#define RRC_MAC_CHANGE_CRNTI_REQ                (RRC_MAC_API_BASE + 0x10)
#define RRC_MAC_CHANGE_CRNTI_CNF                (RRC_MAC_API_BASE + 0x6F)
#define RRC_MAC_INACTIVE_UES_IND                (RRC_MAC_API_BASE + 0xCE)
#define RRC_MAC_HO_REL_RACH_RESOURCE_IND                (RRC_MAC_API_BASE + 0xCC)
#define RRC_MAC_RLF_IND                (RRC_MAC_API_BASE + 0xCD)
#define MAC_UE_SYNC_STATUS_IND                (RRC_MAC_API_BASE + 0xD3)
//#define RRC_MAC_RADIO_LINK_FAILURE_IND       (RRC_MAC_API_BASE + 0xCD)
//#define RRC_MAC_MAX_API                       RRC_MAC_RADIO_LINK_FAILURE_IND

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
#define RRC_MAC_MOD_PERIOD_INFO                 (RRC_MAC_TAG_BASE + 0x35)
#define RRC_MAC_SFN_GAP_INFO                    (RRC_MAC_TAG_BASE + 0x36)
#define RRC_MAC_MAX_TAG                          RRC_MAC_SFN_GAP_INFO
#define RRC_MAC_SFN_ERR_IND			(RRC_MAC_TAG_BASE + 0xCA)
#define RRC_MAC_CELL_STOP_REQ			(RRC_MAC_TAG_BASE + 0xD1)
#define RRC_MAC_CELL_START_REQ			(RRC_MAC_TAG_BASE + 0xCF)
#define RRC_MAC_CELL_START_CNF			(RRC_MAC_TAG_BASE + 0xD0)
#define RRC_MAC_CELL_STOP_CNF			(RRC_MAC_TAG_BASE + 0xD2)
#define RRC_MAC_RBS_FOR_DCI_1A			(RRC_MAC_TAG_BASE + 0x81)
#define RRC_MAC_RBS_FOR_DCI_1C			(RRC_MAC_TAG_BASE + 0x82)
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
#define RRC_RLC_UE_ENTITY_ERROR_IND          (RRC_RLC_API_BASE + 12)
#define RRC_RLC_CHANGE_CRNTI_REQ             (RRC_RLC_API_BASE + 13)
#define RRC_RLC_CHANGE_CRNTI_CNF             (RRC_RLC_API_BASE + 14)
#define RRC_RLC_MAX_API                       RRC_RLC_CHANGE_CRNTI_CNF 

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
#define RRC_PDCP_SN_HFN_STATUS_REQ	      (RRC_PDCP_API_BASE + 5)
#define RRC_PDCP_SN_HFN_STATUS_RESP	      (RRC_PDCP_API_BASE + 6)
#define RRC_PDCP_SN_HFN_STATUS_IND	      (RRC_PDCP_API_BASE + 7)
#define RRC_PDCP_DATA_BUFFER_STOP_IND         (RRC_PDCP_API_BASE + 8)
#define RRC_PDCP_MAC_I_REQ                    (RRC_PDCP_API_BASE + 9)
#define RRC_PDCP_MAC_I_RESP                   (RRC_PDCP_API_BASE + 10)
#define RRC_PDCP_SUSPEND_UE_ENTITY_REQ        (RRC_PDCP_API_BASE + 11)
#define RRC_PDCP_SUSPEND_UE_ENTITY_CNF         (RRC_PDCP_API_BASE + 12)
#define RRC_PDCP_REESTABLISHMENT_UE_ENTITY_REQ         (RRC_PDCP_API_BASE + 13)
#define RRC_PDCP_REESTABLISHMENT_UE_ENTITY_CNF         (RRC_PDCP_API_BASE + 14)
#define RRC_PDCP_RESUME_UE_ENTITY_REQ         (RRC_PDCP_API_BASE + 15)
#define RRC_PDCP_RESUME_UE_ENTITY_CNF         (RRC_PDCP_API_BASE + 16)
#define RRC_PDCP_CHANGE_CRNTI_REQ             (RRC_PDCP_API_BASE + 17)
#define RRC_PDCP_CHANGE_CRNTI_CNF             (RRC_PDCP_API_BASE + 18)
#define PDCP_COUNT_WRAPAROUND_IND             19
#define RRC_PDCP_MAX_API                      RRC_PDCP_SUSPEND_UE_ENTITY_CNF

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
#define RRC_PDCP_CONFIGURE_SRB_CIPHERING_TAG        (RRC_PDCP_TAG_BASE + 6)
#define RRC_PDCP_CONFIGURE_ST_REPORT_REQUIRED_TAG   (RRC_PDCP_TAG_BASE + 7)
#define RRC_PDCP_DELETE_SRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 8)
#define RRC_PDCP_DELETE_DRB_ENTITY_TAG              (RRC_PDCP_TAG_BASE + 9)
#define RRC_PDCP_RECONFIG_SRB_ENTITY_TAG            (RRC_PDCP_TAG_BASE + 10)
#define RRC_PDCP_RECONFIG_DRB_ENTITY_TAG            (RRC_PDCP_TAG_BASE + 11)
#define RRC_PDCP_CONFIGURE_DRB_CIPHERING_TAG        (RRC_PDCP_TAG_BASE + 12)

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
#define RRC_PHY_RECONFIG_CELL_REQ             (RRC_PHY_API_BASE + 11)
#define RRC_PHY_RECONFIG_CELL_CNF             (RRC_PHY_API_BASE + 12)
#define RRC_PHY_CHANGE_CRNTI_REQ             (RRC_PHY_API_BASE + 13)
#define RRC_PHY_CHANGE_CRNTI_CNF             (RRC_PHY_API_BASE + 14)
#define RRC_PHY_CELL_START_REQ	             (RRC_PHY_API_BASE + 15)
#define RRC_PHY_CELL_START_CNF		     (RRC_PHY_API_BASE + 16)
#define RRC_PHY_CELL_STOP_REQ		     (RRC_PHY_API_BASE + 17)
#define RRC_PHY_CELL_STOP_CNF		     (RRC_PHY_API_BASE + 18)
#define RRC_PHY_MAX_API                       RRC_PHY_CELL_STOP_CNF


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
#define RRC_S1U_END_MARKER_IND              (RRC_S1U_API_BASE + 9)

#define RRC_S1U_MAX_API                     RRC_S1U_PATH_FAILURE_IND



/********************************************************************
 *  * EGTPU - OAM APIs
 *   *******************************************************************/
#define EGTPU_OAM_API_BASE           0x0000
#define EGTPU_OAM_INITDB_REQ         400
#define EGTPU_OAM_LM_INITDB_CNF      450

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
#define RRC_S1U_IE_TUNNEL_INFO_TAG          (RRC_S1U_TAG_BASE + 11)
#define RRC_S1U_IE_TEID_SELF_TAG            (RRC_S1U_TAG_BASE + 12)
#define RRC_S1U_IE_BUFFER_IND_TAG           (RRC_S1U_TAG_BASE + 13)
#define RRC_S1U_IE_TEID_PEER_TAG            (RRC_S1U_TAG_BASE + 14)
#define RRC_S1U_IE_RELEASE_TUNNEL_INFO_TAG  (RRC_S1U_TAG_BASE + 15)
#define RRC_S1U_IE_TUNNEL_INFO_CNF_TAG      (RRC_S1U_TAG_BASE + 16)

#define RRC_S1U_MAX_TAG                     RRC_S1U_IE_TEID_PEER_TAG

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
#define RRC_RRM_CELL_RECONFIGURE_REQ          (RRC_RRM_API_BASE + 17)
#define RRC_RRM_CELL_RECONFIG_RESP            (RRC_RRM_API_BASE + 18)
#define RRC_RRM_UE_CAPABILITY_ENQUIRY_REQ     (RRC_RRM_API_BASE + 19)
#define RRC_RRM_UE_CAPABILITY_ENQUIRY_RESP    (RRC_RRM_API_BASE + 20)
#define RRC_RRM_UE_CAPABILITY_IND	      (RRC_RRM_API_BASE + 21)
/* Start: E-RAB Modify API */
#define RRC_RRM_ERB_MODIFY_REQ                (RRC_RRM_API_BASE + 22)
#define RRC_RRM_ERB_MODIFY_RESP               (RRC_RRM_API_BASE + 23)
#define RRC_RRM_ERB_MODIFY_CNF                (RRC_RRM_API_BASE + 24)
/* End: E-RAB Modify API */
/* ERB RELEASE COMMAND START */
#define RRC_RRM_ERB_RELEASE_CNF               (RRC_RRM_API_BASE + 25)
#define RRC_RRM_UE_CONTEXT_MOD_REQ            (RRC_RRM_API_BASE + 26)
#define RRC_RRM_UE_CONTEXT_MOD_RESP           (RRC_RRM_API_BASE + 27)
#define RRC_RRM_ERB_RELEASE_IND               (RRC_RRM_API_BASE + 28)
#define RRC_RRM_UE_CONTEXT_MOD_CNF            (RRC_RRM_API_BASE + 29)
#define RRC_RRM_UE_HO_REQUIRED                (RRC_RRM_API_BASE + 30)
#define RRC_RRM_UE_HO_ADM_REQ                 (RRC_RRM_API_BASE + 31)
#define RRC_RRM_UE_HO_ADM_RESP                (RRC_RRM_API_BASE + 32)
#define RRC_RRM_UE_HO_ADM_CNF                 (RRC_RRM_API_BASE + 33)
#define RRC_RRM_UE_HO_RESTRICTION_LIST_IND    (RRC_RRM_API_BASE + 34)
#define RRC_RRM_UE_HO_CMD_REQ                 (RRC_RRM_API_BASE + 35)
#define RRC_RRM_UE_HO_CMD_RESP                (RRC_RRM_API_BASE + 36)
#define RRC_RRM_MEAS_CONFIG_REQ               (RRC_RRM_API_BASE + 37)
#define RRC_RRM_MEAS_CONFIG_RESP              (RRC_RRM_API_BASE + 38)
#define RRC_RRM_HO_FAILURE                    (RRC_RRM_API_BASE + 39)
#define RRC_RRM_HO_CANCEL_REQ                 (RRC_RRM_API_BASE + 40)
#define RRC_RRM_HO_CANCEL_RESP                (RRC_RRM_API_BASE + 41)
#define RRC_RRM_UPDATED_PWS_SI_LIST_REQ       (RRC_RRM_API_BASE + 42)
#define RRC_RRM_UPDATED_PWS_SI_LIST_RESP      (RRC_RRM_API_BASE + 43)
#define RRC_RRM_UPDATED_PWS_SI_LIST_CNF       (RRC_RRM_API_BASE + 44)
#define RRC_RRM_INACTIVE_UES_IND	      (RRC_RRM_API_BASE + 45)
#define RRC_RRM_CELL_START_REQ                (RRC_RRM_API_BASE + 46)
#define RRC_RRM_CELL_START_RESP               (RRC_RRM_API_BASE + 47)
#define RRC_RRM_CELL_STOP_REQ                 (RRC_RRM_API_BASE + 48)
#define RRC_RRM_CELL_STOP_RESP                (RRC_RRM_API_BASE + 49)
#define RRC_RRM_PROXIMITY_IND                (RRC_RRM_API_BASE + 50)
#define RRC_RRM_INTRA_ENB_HO_IND                (RRC_RRM_API_BASE + 51)
#define RRC_RRM_UE_RECONFIG_REQ                (RRC_RRM_API_BASE + 52)
#define RRC_RRM_UE_RECONFIG_RESP                (RRC_RRM_API_BASE + 53)
/***********X2ap apis **********/
#define X2AP_RRM_IF_API_BASE                   900
#define X2AP_RRM_LINK_DOWN_IND                 (X2AP_RRM_IF_API_BASE + 1)	
#define X2AP_RRM_LINK_UP_IND                   (X2AP_RRM_IF_API_BASE + 2)
#define X2AP_RRM_RSU_RRM_START_REQ             (X2AP_RRM_IF_API_BASE + 4)
#define X2AP_RRM_RSU_ENB_START_RES             (X2AP_RRM_IF_API_BASE + 5)
#define X2AP_RRM_RSU_RRM_STOP_REQ              (X2AP_RRM_IF_API_BASE + 6)
#define X2AP_RRM_RSU_ENB_STOP_RES              (X2AP_RRM_IF_API_BASE + 7)
#define X2AP_RRM_RSU_ENB_START_REQ             (X2AP_RRM_IF_API_BASE + 8)
#define X2AP_RRM_RSU_RRM_START_RES             (X2AP_RRM_IF_API_BASE + 9)
#define X2AP_RRM_RSU_ENB_STOP_REQ              (X2AP_RRM_IF_API_BASE + 10)
#define X2AP_RRM_RSU_RRM_STOP_RES              (X2AP_RRM_IF_API_BASE + 11)
#define X2AP_RRM_RSU_RRM_UPDATE                (X2AP_RRM_IF_API_BASE + 12)
#define X2AP_RRM_RSU_RRM_UPDATE_IND            (X2AP_RRM_IF_API_BASE + 13)
#define X2AP_RRM_LI_RRM_LOAD_INFORMATION_REQ   (X2AP_RRM_IF_API_BASE + 14)
#define X2AP_RRM_LI_RRM_LOAD_INFORMATION_RES   (X2AP_RRM_IF_API_BASE + 15)
#define X2AP_RRM_LI_RRM_LOAD_INFORMATION_IND   (X2AP_RRM_IF_API_BASE + 16)
#define X2AP_RRM_ENB_CONFIG_UPDATE_REQ         (X2AP_RRM_IF_API_BASE + 17)
#define X2AP_RRM_ENB_CONFIG_UPDATE_IND         (X2AP_RRM_IF_API_BASE + 19)
#define X2AP_RRM_RESET_REQ                     (X2AP_RRM_IF_API_BASE + 20)
#define X2AP_RRM_ENB_CONFIG_UPDATE_RES         (X2AP_RRM_IF_API_BASE + 18)
#define X2AP_RRM_RESET_RES                     (X2AP_RRM_IF_API_BASE + 21)
#define X2AP_RRM_RESET_IND                     (X2AP_RRM_IF_API_BASE + 22)
#define X2AP_RRM_RLF_IND                       (X2AP_RRM_IF_API_BASE + 23)

/***********s1ap apis **********/
#define S1AP_RRM_API_BASE                   0x0700
#define S1AP_RRM_ENB_DIRECT_INFO_TRANSFER      (S1AP_RRM_API_BASE + 1)	
#define S1AP_RRM_MME_DIRECT_INFO_TRANSFER      (S1AP_RRM_API_BASE + 2)	
#define S1AP_RRM_ENB_CONFIG_TRANSFER           (S1AP_RRM_API_BASE + 3)	
#define S1AP_RRM_MME_CONFIG_TRANSFER           (S1AP_RRM_API_BASE + 4)	
#define S1AP_RRM_PWS_REQ                       (S1AP_RRM_API_BASE + 5)	
#define S1AP_RRM_PWS_RESP                      (S1AP_RRM_API_BASE + 6)	
#define S1AP_RRM_PWS_CNF                       (S1AP_RRM_API_BASE + 7)	
#define S1AP_RRM_KILL_REQ                      (S1AP_RRM_API_BASE + 8)	
#define S1AP_RRM_KILL_RESP                     (S1AP_RRM_API_BASE + 9)	
#define S1AP_RRM_KILL_CNF                      (S1AP_RRM_API_BASE + 10)	
#define RRC_RRM_MAX_API                         S1AP_RRM_MME_DIRECT_INFO_TRANSFER

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
#define RRC_OAM_CONFIG_STATS_REQ              (RRC_OAM_API_BASE + 29)
#define RRC_OAM_CONFIG_STATS_RESP             (RRC_OAM_API_BASE + 30)
#define RRC_OAM_MAX_API                       RRC_OAM_CONFIG_STATS_RESP

#define RRM_OAM_API_BASE                      0x0000
#define RRM_OAM_INIT_IND_RESP                  (RRM_OAM_API_BASE + 2)
#define RRM_OAM_SET_TRANS_MODE_REQ             (RRM_OAM_API_BASE + 3)
#define RRM_OAM_SET_TRANS_MODE_RESP            (RRM_OAM_API_BASE + 4)
#define RRM_OAM_SET_ROHC_PROFILE_REQ           (RRM_OAM_API_BASE + 5)
#define RRM_OAM_SET_UE_SEMI_STATIC_PARAM_REQ   (RRM_OAM_API_BASE + 6)
#define RRM_OAM_SET_RLC_MODE_REQ               (RRM_OAM_API_BASE + 7)
#define RRM_OAM_SET_RLC_MODE_PARAM_REQ         (RRM_OAM_API_BASE + 8)
#define RRM_OAM_SET_TDD_PARAM_REQ              (RRM_OAM_API_BASE + 9)
#define RRM_OAM_SET_MAC_PARAM_REQ              (RRM_OAM_API_BASE + 10)
#define RRM_OAM_SET_UE_SRS_PARAM_REQ           (RRM_OAM_API_BASE + 11)
#define RRM_OAM_INIT_REQ                       (RRM_OAM_API_BASE + 12)
#define RRM_OAM_SET_PHY_PARAM_REQ              (RRM_OAM_API_BASE + 13)
#define RRM_OAM_INIT_IND		       (RRM_OAM_API_BASE + 19)
#define RRM_OAM_CELL_DELETE_REQ                (RRM_OAM_API_BASE + 22)
#define RRM_OAM_CELL_DELETE_RESP               (RRM_OAM_API_BASE + 23)
#define RRM_OAM_CELL_SETUP_RESP                (RRM_OAM_API_BASE + 24)
#define RRM_OAM_SET_RLF_TIMERS_AND_CONSTANTS_PARAM_R9_REQ (RRM_OAM_API_BASE + 29)
#define RRM_OAM_SET_LOGICAL_CHANNEL_CONFIG_PARAM_REQ (RRM_OAM_API_BASE + 30)
/***********X2ap apis **********/
#define X2AP_OAM_API_BASE                       1000
#define X2AP_OAM_INIT_IND                      (X2AP_OAM_API_BASE + 1)
#define X2AP_OAM_PROVISION_REQ                 (X2AP_OAM_API_BASE + 3)
#define X2AP_OAM_PROVISION_RESP                (X2AP_OAM_API_BASE + 4)
#define X2AP_OAM_LINK_DOWN_IND                 (X2AP_OAM_API_BASE + 7)
#define X2AP_OAM_LINK_UP_IND                   (X2AP_OAM_API_BASE + 8)
#define X2AP_OAM_ADD_ENB_REQ                   (X2AP_OAM_API_BASE + 11)
#define X2AP_OAM_ADD_ENB_RES                   (X2AP_OAM_API_BASE + 12)

/***********s1ap - oam apis **********/

#define S1AP_OAM_API_BASE                      		0x0500
#define S1AP_OAM_S1AP_LINK_STATUS_IND          	(S1AP_OAM_API_BASE + 15)
#define S1AP_OAM_ADD_MME_REQ          	        (S1AP_OAM_API_BASE + 16)
#define S1AP_OAM_ADD_MME_RES          	        (S1AP_OAM_API_BASE + 17)
#define S1AP_OAM_ENB_CONFIG_UPDATE          	(S1AP_OAM_API_BASE + 11) 
#define S1AP_OAM_ENB_CONFIG_UPDATE_RESPONSE     (S1AP_OAM_API_BASE + 12)
/********************************************************************
 * PDCP - OAM APIs
 *******************************************************************/
#define PDCP_OAM_API_BASE                     0x0401
#define PDCP_INIT_LAYER_IND		       (PDCP_OAM_API_BASE + 21)

#define PDCP_CONFIGURE_KPI_STATS_REQ     (PDCP_OAM_API_BASE+ )
#define PDCP_CONFIGURE_KPI_STATS_CNF     (PDCP_OAM_API_BASE+ )
#define PDCP_KPI_STATS_IND               (PDCP_OAM_API_BASE+ )
#define PDCP_GET_KPI_STATS_REQ           (PDCP_OAM_API_BASE+ )
#define PDCP_GET_KPI_STATS_CNF           (PDCP_OAM_API_BASE+ )
#define PDCP_NOTIFY_OAM_DEVICE_FAILURE    (PDCP_OAM_API_BASE+ 22)
/********************************************************************
 * RLC - OAM APIs
 *******************************************************************/
#define RLC_OAM_API_BASE                     0x0201
#define RLC_INIT_LAYER_IND		(RLC_MESSAGE_API_START + 30)

#define RLC_CONFIGURE_KPI_STATS_REQ     (RLC_OAM_API_BASE+ 17)
#define RLC_CONFIGURE_KPI_STATS_CNF     (RLC_OAM_API_BASE+ 18)
#define RLC_KPI_STATS_IND               (RLC_OAM_API_BASE+ 19)
#define RLC_GET_KPI_STATS_REQ           (RLC_OAM_API_BASE+ 20)
#define RLC_GET_KPI_STATS_CNF           (RLC_OAM_API_BASE+ 21)
/********************************************************************
 * MAC - OAM APIs
 *******************************************************************/
#define MAC_OAM_API_BASE                     0x0001
#define MAC_INIT_LAYER_IND	        (MAC_OAM_API_BASE+ 26)
#define MAC_MODIFY_LAYER_REQ      	(MAC_OAM_API_BASE+ 30)
#define MAC_CONFIGURE_KPI_STATS_REQ     (MAC_OAM_API_BASE+ 35)
#define MAC_CONFIGURE_KPI_STATS_CNF     (MAC_OAM_API_BASE+ 36)
#define MAC_KPI_STATS_IND               (MAC_OAM_API_BASE+ 37)
#define MAC_GET_KPI_STATS_REQ           (MAC_OAM_API_BASE+ 38)
#define MAC_GET_KPI_STATS_CNF           (MAC_OAM_API_BASE+ 39)
#define MAC_RECONFIG_SCHEDULER_PARAMS   (MAC_OAM_API_BASE+ 40)
#define MAC_UE_SINR_TA_REQ		(MAC_OAM_API_BASE+ 41)
#define MAC_UE_SINR_TA_RESP		(MAC_OAM_API_BASE+ 42)
/********************************************************************
 * RRM - MAC APIs
 *******************************************************************/
#define RRM_MAC_REQ_MESSAGE_API_START            0x0001
#define RRM_MAC_CELL_CONFIG_REQ	        1 
#define RRM_MAC_RECONFIG_SCHEDULER_REQ	2        
#define RRM_MAC_UE_RECONFIG_REQ	         3
#define RRM_MAC_CNF_MESSAGE_API_START            0x0100
#define RRM_MAC_CELL_CONFIG_CNF	        100
#define RRM_MAC_SCHEDULER_RECONFIG_CNF	       101 
#define RRM_MAC_UE_RECONFIG_CNF	        102
#define RRM_MAC_IND_MESSAGE_API_START            0x0200
#define RRM_MAC_PERIODIC_REPORT_IND	       200 
#endif /* _RRC_EXT_API_H_ */
