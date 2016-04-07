/******************************************************************************
*
*   FILE NAME: phy_api.h
*
*   DESCRIPTION:
*       This file contains MAC<=>PHY interface message id, enumerations.
*
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/
#ifndef FAPI_LTE_MSG_H_
#define FAPI_LTE_MSG_H_

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif



/*API-IDs rerserved for Physical layer*/
#define PHY_PARAM_REQUEST               0x00
#define PHY_PARAM_RESPONSE              0x01
#define PHY_CELL_CONFIG_REQUEST         0x02
#define PHY_CELL_CONFIG_RESPONSE        0x03
#define PHY_START_REQUEST               0x04
#define PHY_STOP_REQUEST                0x05
#define PHY_STOP_INDICATION             0x06
#define PHY_UE_CONFIG_REQUEST           0x07
#define PHY_UE_CONFIG_RESPONSE          0x08
#define PHY_ERROR_INDICATION            0x09

#define PHY_DL_CONFIG_REQUEST          0x80
#define PHY_UL_CONFIG_REQUEST          0x81
#define PHY_UL_SUBFRAME_INDICATION     0x82
#define PHY_DL_HI_DCI0_REQUEST         0x83
#define PHY_DL_TX_REQUEST              0x84
#define PHY_UL_HARQ_INDICATION         0x85
#define PHY_UL_CRC_INDICATION          0x86
#define PHY_UL_RX_ULSCH_INDICATION     0x87
#define PHY_UL_RACH_INDICATION         0x88
#define PHY_UL_SRS_INDICATION          0x89
#define PHY_UL_RX_SR_INDICATION        0x8a
#define PHY_UL_RX_CQI_INDICATION       0x8b


/* This macro is used for declaring array of variable length */
#define FAPI_VAR_SIZE(x) 1

/* L1 Error Indication */

typedef enum FAPI_L1ErrorCodes_enT
{
     FAPI_MSG_OK,
     FAPI_MSG_INVALID_STATE,
     FAPI_MSG_INVALID_CONFIG,
     FAPI_SFN_OUT_OF_SYNC,
     FAPI_MSG_SUBFRAME_ERR,
     FAPI_MSG_BCH_MISSING,
     FAPI_MSG_INVALID_SFN,
     FAPI_MSG_HI_ERR,
     FAPI_MSG_TX_ERR

}FAPI_L1ErrorCodes_en;

/* PHY CELL CONFIG */
typedef enum FAPI_Config_enT
{
   FAPI_DUPLEXING_MODE = 1,
   FAPI_PCFICH_POWER_OFFSET,
   FAPI_P_B,
   FAPI_DL_CYCLIC_PREFIX_TYPE,
   FAPI_UL_CYCLIC_PREFIX_TYPE,
/* RF Config */
   FAPI_DL_CHANNEL_BANDWIDTH,
   FAPI_UL_CHANNEL_BANDWIDTH,
   FAPI_REFERENCE_SIGNAL_POWER,
   FAPI_TX_ANTENNA_PORTS,
   FAPI_RX_ANTENNA_PORTS,
/* RF CONFIG TAGS ENDS */
/* PHICH CONFIG */
   FAPI_PHICH_RESOURCE,
   FAPI_PHICH_DURATION,
   FAPI_PHICH_POWER_OFFSET,
/* PHICH CONFIG ENDS */
/* SCH COnfig */
   FAPI_PRIMARY_SYNC_SIGNAL,
   FAPI_SECONDARY_SYNC_SIGNAL,
   FAPI_PHYSICAL_CELL_ID,
/* SCH COnfig  Ends */
/* PRACH Config */
   FAPI_CONFIGURATION_INDEX,
   FAPI_ROOT_SEQUENCE_INDEX,
   FAPI_ZERO_CORRELATION_ZONE_CONFIGURATION,
   FAPI_HIGH_SPEED_FLAG,
   FAPI_FREQUENCY_OFFSET,
/* PRACH Config  Ends */
/* PUSCH Config */
   FAPI_HOPPING_MODE,
   FAPI_HOPPIG_OFFSET,
   FAPI_NUM_OF_SUB_BANDS,
/* PUSCH Config  Ends */
/* PUCCH Config */
   FAPI_DELTA_PUCCH_SHIFT,
   FAPI_N_CQI_RB,
   FAPI_N_AN_CS,
   FAPI_N_1_PUCCH_AN,
/* PUCCH Config Ends */
/* SRS Config */
   FAPI_BANDWIDTH_CONFIGURATION,
   FAPI_MAX_UP_PTS,
   FAPI_SRS_SUB_FRAME_CONFIGURATION,
   FAPI_SRS_ACK_NACK_SRS_SIMULTANEOUS_TRANSMISSION,
/* SRS Config Ends */
/* Uplink reference signal Config */
   FAPI_UPLINK_RS_HOPPING,
   FAPI_GROUP_ASSIGNMENT,
   FAPI_CYCLIC_SHIFT_1_FOR_DMRS,
/* Uplink reference signal Config Ends */
/* TDD Frame Structure Config */
   FAPI_SUB_FRAME_ASSIGNMENT,
   FAPI_SPECIAL_SUB_FRAME_PATTERNS,
/* TDD Frame Structure Config Ends */

/* below tags are used by L1 to reports its physical capabilities to L2/L3 software */
   FAPI_DL_BANDWIDTH_SUPPORT = 40,
   FAPI_UL_BANDWIDTH_SUPPORT,
   FAPI_DL_MODULATION_SUPPORT,
   FAPI_UL_MODULATION_SUPPORT,
   FAPI_PHY_ANTENNA_CAPABILITY,
/* below tags are used by L2/L3 software to configure the interaction between L2/L3 and L1 */

   FAPI_DATA_REPORT_MODE = 50,
   FAPI_SFN_SF,

/* the below tag is used by L1 to report its current status */
   FAPI_PHY_STATE = 60

}FAPI_Config_en;

/* L1 states */
typedef enum FAPI_PHYStates_enT
{
    FAPI_IDLE,
    FAPI_CONFIGURED,
    FAPI_RUNNING

}FAPI_PHYStates_en;
/* L1 states Ends */

/* POSSIBLE PHICH RESOURCE VALUES */
typedef enum FAPI_phichResourceValues_enT
{
   FAPI_PHICH_R_ONE_SIXTH,
   FAPI_PHICH_R_HALF,
   FAPI_PHICH_R_ONE,
   FAPI_PHICH_R_TWO

}FAPI_phichResourceValues_en;

/* Types of Duplexing Mode */
typedef enum FAPI_duplexingMode_enT
{
   FAPI_TDD,
   FAPI_FDD,
   FAPI_HD_FDD

}FAPI_duplexingMode_en;

/* Types of Cylic Prefix */
typedef enum FAPI_cyclicPrefix_enT
{
   FAPI_CP_NORMAL,
   FAPI_CP_EXTENDED

}FAPI_cyclicPrefix_en;

/* UL/DL Channel Bandwidth */
typedef enum FAPI_uldlChannelBw_enT
{
    FAPI_CHANNEL_BW_6RB = 6,
    FAPI_CHANNEL_BW_15RB = 15,
    FAPI_CHANNEL_BW_25RB = 25,
    FAPI_CHANNEL_BW_50RB = 50,
    FAPI_CHANNEL_BW_75RB = 75,
    FAPI_CHANNEL_BW_100RB = 100

}FAPI_uldlChannelBw_en;

/* No. of Tx Antenna Ports */
typedef enum FAPI_txAntennaPort_enT
{
    FAPI_TX_ANTENNA_PORT_1 = 1,
    FAPI_TX_ANTENNA_PORT_2 = 2,
    FAPI_TX_ANTENNA_PORT_4 = 4

}FAPI_txAntennaPort_en;

/* No. of Rx Antenna Ports */
typedef enum FAPI_rxAntennaPort_enT
{
    FAPI_RX_ANTENNA_PORT_1 = 1,
    FAPI_RX_ANTENNA_PORT_2 = 2,
    FAPI_RX_ANTENNA_PORT_4 = 4

}FAPI_rxAntennaPort_en;

/* Phich Duration */
typedef enum FAPI_phichDuration_enT
{
    FAPI_PHICH_D_NORMAL,
    FAPI_PHICH_D_EXTENDED

}FAPI_phichDuration_en;

/* High Speed Flag */
typedef enum FAPI_highSpeedFlag_enT
{
    FAPI_HS_UNRESTRICTED_SET,
    FAPI_HS_RESTRICTED_SET

}FAPI_highSpeedFlag_en;

/* Hopping Mode */
typedef enum FAPI_hoppingMode_enT
{
   FAPI_HM_INTER_SF,
   FAPI_HM_INTRA_INTER_SF

}FAPI_hoppingMode_en;

/* Types of hopping */
typedef enum FAPI_hoppingType_enT
{
   FAPI_RS_NO_HOPPING,
   FAPI_RS_GROUP_HOPPING,
   FAPI_RS_SEQUENCE_HOPPING

}FAPI_hoppingType_en;

/* Physical Antenna Capabililty */
typedef enum FAPI_phyAntennaCapability_enT
{
    FAPI_PHY_ANTENNA_CAP_1 = 1,
    FAPI_PHY_ANTENNA_CAP_2 = 2,
    FAPI_PHY_ANTENNA_CAP_4 = 4

}FAPI_phyAntennaCapability_en;

/* AN Repetition Factor */
typedef enum FAPI_anRepetitionFactor_enT
{
    FAPI_AN_REPETITION_FACTOR_2 = 2,
    FAPI_AN_REPETITION_FACTOR_4 = 4,
    FAPI_AN_REPETITION_FACTOR_6 = 6

} FAPI_anRepetitionFactor_en;

/* SPS DL Config Scheduling Interval */
typedef enum FAPI_spsDlConfigSchedIntrval_enT
{
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_10 = 10,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_20 = 20,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_32 = 32,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_40 = 40,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_64 = 64,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_80 = 80,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_128 = 128,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_160 = 160,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_320 = 320,
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL_640 = 640

}FAPI_spsDlConfigSchedIntrval_en;

/* Types of Resource Allocation */
typedef enum FAPI_resAllcType_enT
{
   FAPI_RES_ALLOC_TYPE_0,
   FAPI_RES_ALLOC_TYPE_1,
   FAPI_RES_ALLOC_TYPE_2

}FAPI_resAllcType_en;

/* vRB Assignment Flag */
typedef enum vRBAssignmentFlag_enT
{
    FAPI_LOCALISED,
    FAPI_DISTRIBUTED

}vRBAssignmentFlag_en;

/* tb To CodeWordSwap Flag */
typedef enum FAPI_tbToCodeWordSwapFlag_enT
{
    FAPI_NOSWAPPING,
    FAPI_SWAPPED

}FAPI_tbToCodeWordSwapFlag_en;

/* types of TPC */
typedef enum FAPI_tpcValue_enT
{
    FAPI_TX_POWER_CONTROL_MINUS_4 = -4,
    FAPI_TX_POWER_CONTROL_MINUS_1 = -1,
    FAPI_TX_POWER_CONTROL_0 = 0,
    FAPI_TX_POWER_CONTROL_1 = 1,
    FAPI_TX_POWER_CONTROL_3 = 3,
    FAPI_TX_POWER_CONTROL_4 = 4

}FAPI_tpcValue_en;

/* Types of Transmission Scheme */
typedef enum FAPI_transScheme_enT
{
    FAPI_SINGLE_ANTENNA_PORT_0,
    FAPI_TX_DIVERSITY,
    FAPI_LARGE_DELAY_CDD,
    FAPI_CLOSED_LOOP_SPATIAL_MULTIPLEXING,
    FAPI_MULTI_USER_MIMO,
    FAPI_CLOSED_LOOP_RANK_1_PRECODING,
    FAPI_SINGLE_ANTENNA_PORT_5

}FAPI_transScheme_en;

/* Types of RNTI */
typedef enum FAPI_rntiType_enT
{
    FAPI_C_RNTI = 1,
    FAPI_RA_RNTI_P_RNTI_SI_RNTI,
    FAPI_SPS_CRNTI,
    FAPI_OTHER_CRNTI

}FAPI_rntiType_en;

/* types of AggegationLevel */
typedef enum FAPI_aggregationLevel_enT
{
    FAPI_AGGEGATION_LEVEL_1 = 1,
    FAPI_AGGEGATION_LEVEL_2 = 2,
    FAPI_AGGEGATION_LEVEL_4 = 4,
    FAPI_AGGEGATION_LEVEL_8 = 8

}FAPI_aggregationLevel_en;

/* P-A values */
typedef enum FAPI_paValue_enT
{
    FAPI_DB_MINUS6,
    FAPI_DB_MINUS_4DOT77,
    FAPI_DB_MINUS_3,
    FAPI_DB_MINUS_1DOT77,
    FAPI_DB0,
    FAPI_DB1,
    FAPI_DB2,
    FAPI_DB3

}FAPI_paValue_en;

/* Types of modulation*/
typedef enum FAPI_modulationType_enT
{
    FAPI_QPSK = 2,
    FAPI_16QAM = 4,
    FAPI_64QAM = 6

}FAPI_modulationType_en;

/* ul Tx Mode type */
typedef enum FAPI_ulTxMode_enT
{
    FAPI_ULTX_SISO_SIMO,
    FAPI_ULTX_MIMO

}FAPI_ulTxMode_en;

/* Types of HI Values */
typedef enum FAPI_hiValue_enT
{
    FAPI_HI_NACK,
    FAPI_HI_ACK
}FAPI_hiValue_en;

/* Types of CQI Request */
typedef enum FAPI_cqiRequest_enT
{
    FAPI_APERIODIC_CQI_NOT_REQUESTED,
    FAPI_APERIODIC_CQI_REQUESTED

}FAPI_cqiRequest_en;

/* ue Tx Antenna Selection */
typedef enum FAPI_ueTxAntennaSelection_enT
{
    FAPI_ANT_PORT_NOT_CONFIGURED = 0,
    FAPI_CONF_UE_PORT_0 = 1,
    FAPI_CONF_UE_PORT_1 = 2

}FAPI_ueTxAntennaSelection_en;

/* types of DL Assignment Index */
typedef enum FAPI_dlAssignmentIndex_enT
{
    FAPI_DL_ASSGN_INDEX_1 = 1,
    FAPI_DL_ASSGN_INDEX_2,
    FAPI_DL_ASSGN_INDEX_3,
    FAPI_DL_ASSGN_INDEX_4

}dlAssignmentIndex_en;

/* types of HARQ feedback TB1-TB2 */
typedef enum FAPI_harqFeedback_enT
{
    FAPI_ACK = 1,
    FAPI_NACK,
    FAPI_ACK_OR_NACK,
    FAPI_DTX,
    FAPI_ACK_OR_DTX,
    FAPI_NACK_OR_DTX,
    FAPI_ACK_OR_NACK_OR_DTX

}FAPI_harqFeedback_en;

/* CRC FLAGS */
typedef enum FAPI_crcFlags_enT
{
    FAPI_CRC_CORRECT,
    FAPI_CRC_ERROR

}FAPI_crcFlags_en;

/* UE CNFIG Possible Tags */
typedef enum FAPI_ueConig_enT
{
    FAPI_HANDLE = 100,
    FAPI_RNTI,
/* CQI CONFIG */
    FAPI_CQI_PUCCH_RESOURCE_INDEX,
    FAPI_CQI_PMI_CONFIG_INDEX,
    FAPI_CQI_RI_CONFIG_INDEX,
    FAPI_CQI_SIMULTANEOUS_ACK_NACK_CQI,
/* CQI CONFIG ENDS */
/* ACK/NACK CONFIG */
    FAPI_AN_REPETITION_FACTOR,
    FAPI_AN_N1_PUCCH_AN_REP,
    FAPI_TDD_ACK_NACK_FEEDBACK,
/* ACK/NACK CONFIG  Ends*/
/* SRS CONFIG */
    FAPI_SRS_BANDWIDTH,
    FAPI_SRS_HOPPING_BANDWIDTH,
    FAPI_FREQUENCY_DOMAIN_POSITION,
    FAPI_SRS_DURATION,
    FAPI_ISRS_SRS_CONFIG_INDEX,
    FAPI_TRANSMISSION_COMB,
    FAPI_SOUNDING_REFERENCE_SYCLIC_SHIFT,
/* SRS CONFIG  Ends */
/* SR CONFIG */
    FAPI_SR_PUCCH_RESOURCE_INDEX,
    FAPI_SR_CONFIG_INDEX,
/* SR CONFIG Ends */
/* SPS CONFIG */
   FAPI_SPS_DL_CONFIG_SCHD_INTERVAL,
   FAPI_SPS_DL_N1_PUCCH_AN_PERSISTENT
/* SPS CONFIG  Ends*/
}FAPI_ueConig_en;

/* enum definition for UL/DL config/tx request */

typedef enum FAPI_dlPDUTypeInfo_enT
{
    FAPI_DCI_DL_PDU,
    FAPI_BCH_PDU,
    FAPI_MCH_PDU,
    FAPI_DLSCH_PDU,
    FAPI_PCH_PDU
}FAPI_dlPDUTypeInfo_en;

typedef enum FAPI_dlDCIFormatInfo_enT
{
    FAPI_DL_DCI_FORMAT_1,
    FAPI_DL_DCI_FORMAT_1A,
    FAPI_DL_DCI_FORMAT_1B,
    FAPI_DL_DCI_FORMAT_1C,
    FAPI_DL_DCI_FORMAT_1D,
    FAPI_DL_DCI_FORMAT_2,
    FAPI_DL_DCI_FORMAT_2A

}FAPI_dlDCIFormatInfo_en;

typedef enum FAPI_ulDCIFormatInfo_enT
{
    FAPI_UL_DCI_FORMAT_0,
    FAPI_UL_DCI_FORMAT_3,
    FAPI_UL_DCI_FORMAT_3A

}FAPI_ulDCIFormatInfo_en;

typedef enum FAPI_hiDCIPduInfo_en
{
    FAPI_HI_PDU,
    FAPI_DCI_UL_PDU

}FAPI_HiDCI0PduInfo_en;

typedef enum FAPI_ulConfigPduInfo_enT
{
    FAPI_ULSCH,
    FAPI_ULSCH_CQI_RI,
    FAPI_ULSCH_HARQ,
    FAPI_ULSCH_CQI_HARQ_RI,
    FAPI_UCI_CQI,
    FAPI_UCI_SR,
    FAPI_UCI_HARQ,
    FAPI_UCI_SR_HARQ,
    FAPI_UCI_CQI_HARQ,
    FAPI_UCI_CQI_SR,
    FAPI_UCI_CQI_SR_HARQ,
    FAPI_SRS

}FAPI_ulConfigPduInfo_en;

#endif 
