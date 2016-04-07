/******************************************************************************
*
*   FILE NAME: FAPICommonDissector.c 
*
*   DESCRIPTION:
*       This file contains FAPI common dissector code.
*
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/
#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "gmodule.h"
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <string.h>
#include <packet-mac-lte.h> 


#include "../include/FAPIDissector.h"
#include "../include/phy_api.h"
#include "../include/common.h"

extern  int      IS_LITTLE_ENDIAN    ;
/*
guint64 fapi_get_64 (tvbuff_t *tvb, const gint offset)
{
  if (IS_LITTLE_ENDIAN)
    return tvb_get_letoh64 (tvb, offset);
  else
    return tvb_get_ntoh64 (tvb, offset);
}*/
guint32 fapi_get_32 (tvbuff_t *tvb, const gint offset)
{
  if (IS_LITTLE_ENDIAN)
    return tvb_get_letohl (tvb, offset);
  else
    return tvb_get_ntohl (tvb, offset);
}
guint32 fapi_get_24 (tvbuff_t *tvb, const gint offset)
{
  if (IS_LITTLE_ENDIAN)
    return tvb_get_letoh24 (tvb, offset);
  else
    return tvb_get_ntoh24 (tvb, offset);
}
guint16 fapi_get_16 (tvbuff_t *tvb, const gint offset)
{
  if (IS_LITTLE_ENDIAN)
    return tvb_get_letohs (tvb, offset);
  else
    return tvb_get_ntohs (tvb, offset);
}
 
extern gint ett_L1  ;
extern gint ett_L1_payload  ;
extern gint ett_L1_FAPI_ueConfig_st  ;
extern gint ett_L1_FAPI_cellConfig_st  ;
extern gint ett_L1_FAPI_paramResponseTLV_st  ;
extern gint ett_L1_FAPI_dciFormat1_st  ;
extern gint ett_L1_FAPI_dciFormat1_st_padding  ;
extern gint ett_L1_FAPI_dciFormat1C_st_padding  ;
extern gint ett_L1_FAPI_dciFormat1A_st  ;
extern gint ett_L1_FAPI_dciFormat1A_st_padding  ;
extern gint ett_L1_FAPI_dciFormat1B_st  ;
extern gint ett_L1_FAPI_dciFormat1B_st_padding  ;
extern gint ett_L1_FAPI_dciFormat1C_st  ;
extern gint ett_L1_FAPI_dciFormat1D_st  ;
extern gint ett_L1_FAPI_dciFormat1D_st_padding  ;
extern gint ett_L1_FAPI_dciFormat2_st  ;
extern gint ett_L1_FAPI_dciFormat2A_st  ;
extern gint ett_L1_FAPI_dciDLPduInfo_st  ;
extern gint ett_L1_FAPI_bchConfigPDUInfo_st  ;
extern gint ett_L1_FAPI_bchConfigPDUInfo_st_padding  ;
extern gint ett_L1_FAPI_mchConfigPDUInfo_st  ;
extern gint ett_L1_FAPI_mchConfigPDUInfo_st_padding  ;
extern gint ett_L1_FAPI_beamFormingVectorInfo_st  ;
extern gint ett_L1_FAPI_dlSCHConfigPDUInfo_st  ;
extern gint ett_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector  ;
extern gint ett_L1_FAPI_pchPduConfigInfo_st  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_DCIPdu  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_BCHPdu  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_MCHPdu  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_PChPdu  ;
extern gint ett_L1_FAPI_dlConfigPDUInfo_st_padding  ;
extern gint ett_L1_FAPI_dlTLVInfo_st  ;
extern gint ett_L1_FAPI_dlPduInfo_st  ;
extern gint ett_L1_FAPI_dlPduInfo_st_dlTLVInfo  ;
extern gint ett_L1_FAPI_dlHiPduInfo_st  ;
extern gint ett_L1_FAPI_dlDCIPduInfo_st  ;
extern gint ett_L1_FAPI_dlDCIPduInfo_st_padding  ;
extern gint ett_L1_FAPI_cqiPduInfo_st  ;
extern gint ett_L1_FAPI_cqiPduInfo_st_padding  ;
extern gint ett_L1_FAPI_srPduInfo_st  ;
extern gint ett_L1_FAPI_tddHarqPduInfo_st  ;
extern gint ett_L1_FAPI_tddHarqPduInfo_st_padding  ;
extern gint ett_L1_FAPI_fddHarqPduInfo_st  ;
extern gint ett_L1_FAPI_fddHarqPduInfo_st_padding  ;
extern gint ett_L1_FAPI_ulSCHHarqInfo_st_padding  ;
extern gint ett_L1_FAPI_ulPDUConfigInfo_st_padding  ;
extern gint ett_L1_FAPI_srsPduInfo_st  ;
extern gint ett_L1_FAPI_srsPduInfo_st_padding  ;
extern gint ett_L1_FAPI_cqiRiPduInfo_st  ;
extern gint ett_L1_FAPI_cqiRiPduInfo_st_padding  ;
extern gint ett_L1_FAPI_uciSrPduInfo_st  ;
extern gint ett_L1_FAPI_uciSrPduInfo_st_srInfo  ;
extern gint ett_L1_FAPI_uciCqiPduInfo_st  ;
extern gint ett_L1_FAPI_uciCqiPduInfo_st_padding  ;
extern gint ett_L1_FAPI_uciCqiPduInfo_st_cqiInfo  ;
extern gint ett_L1_FAPI_uciHarqPduInfo_st  ;
extern gint ett_L1_FAPI_uciHarqPduInfo_st_padding  ;
extern gint ett_L1_FAPI_uciHarqPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_uciSrHarqPduInfo_st  ;
extern gint ett_L1_FAPI_uciSrHarqPduInfo_st_srInfo  ;
extern gint ett_L1_FAPI_uciSrHarqPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_uciCqiHarqPduInfo_st  ;
extern gint ett_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo  ;
extern gint ett_L1_FAPI_uciCqiHarqPduInfo_st_padding  ;
extern gint ett_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_uciCqiSrPduInfo_st  ;
extern gint ett_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo  ;
extern gint ett_L1_FAPI_uciCqiSrPduInfo_st_srInfo  ;
extern gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st  ;
extern gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo  ;
extern gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo  ;
extern gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_ulSCHPduInfo_st  ;
extern gint ett_L1_FAPI_initialTxParam_st  ;
extern gint ett_L1_FAPI_initialTxParam_st_padding  ;
extern gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st  ;
extern gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo  ;
extern gint ett_L1_FAPI_ulSCHHarqInfo_st  ;
extern gint ett_L1_FAPI_ulSCHHarqPduInfo_st  ;
extern gint ett_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo  ;
extern gint ett_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo  ;
extern gint ett_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st  ;
extern gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo  ;
extern gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo  ;
extern gint ett_L1_FAPI_ulPDUConfigInfo_st  ;
extern gint ett_L1_FAPI_ulDataPduIndication_st  ;
extern gint ett_L1_FAPI_ulDataPduIndication_st_padding  ;
extern gint ett_L1_FAPI_fddHarqPduIndication_st  ;
extern gint ett_L1_FAPI_tddBundlingHarqInfo_st  ;
extern gint ett_L1_FAPI_tddMultiplexingHarqInfo_st  ;
extern gint ett_L1_FAPI_tddSpcialBundlingHarqInfo_st  ;
//FAPI_tddHarqPduIndication_st_count  ;
extern gint ett_L1_FAPI_tddHarqPduIndication_st  ;
extern gint ett_L1_FAPI_crcPduIndication_st  ;
extern gint ett_L1_FAPI_crcPduIndication_st_padding  ;
extern gint ett_L1_FAPI_cqiPduIndication_st  ;
extern gint ett_L1_FAPI_cqiPduIndication_st_padding  ;
extern gint ett_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding  ;
extern gint ett_L1_FAPI_tddBundlingHarqInfo_st_padding  ;
extern gint ett_L1_FAPI_srPduIndication_st  ;
extern gint ett_L1_FAPI_srPduIndication_st_padding  ;
extern gint ett_L1_FAPI_rachPduIndication_st  ;
extern gint ett_L1_FAPI_rachPduIndication_st_padding  ;
extern gint ett_L1_FAPI_srsPduIndication_st  ;
extern gint ett_L1_FAPI_errMsgBody1_st  ;
extern gint ett_L1_FAPI_errMsgBody2_st  ;
extern gint ett_L1_FAPI_errMsgBody2_st_padding  ;
extern gint ett_L1_FAPI_errMsgBody3_st  ;
extern gint ett_L1_FAPI_errMsgBody4_st  ;
extern gint ett_L1_FAPI_l1ApiMsg_st  ;
extern gint ett_L1_FAPI_paramRequest_st  ;
extern gint ett_L1_FAPI_paramResponse_st  ;
extern gint ett_L1_FAPI_paramResponse_st_padding  ;
extern gint ett_L1_FAPI_paramResponse_st_tlvs  ;
extern gint ett_L1_FAPI_phyStart_st  ;
extern gint ett_L1_FAPI_phyStop_st  ;
extern gint ett_L1_FAPI_phyStopIndication_st  ;
extern gint ett_L1_FAPI_phyCellConfigRequest_st  ;
extern gint ett_L1_FAPI_phyCellConfigRequest_st_padding  ;
extern gint ett_L1_FAPI_phyCellConfigRequest_st_configtlvs  ;
extern gint ett_L1_FAPI_phyCellConfigResp_st  ;
extern gint ett_L1_FAPI_phyCellConfigResp_st_padding  ;
extern gint ett_L1_FAPI_phyCellConfigResp_st_listOfTLV  ;
extern gint ett_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv  ;
extern gint ett_L1_FAPI_ueConfigRequest_st  ;
extern gint ett_L1_FAPI_ueConfigRequest_st_tlvs  ;
extern gint ett_L1_FAPI_phyUeConfigResp_st  ;
extern gint ett_L1_FAPI_phyUeConfigResp_st_padding  ;
extern gint ett_L1_FAPI_phyUeConfigResp_st_listOfTLV  ;
extern gint ett_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv  ;
extern gint ett_L1_FAPI_phyErrorIndication_st  ;
extern gint ett_L1_FAPI_phyErrorIndication_st_padding  ;
extern gint ett_L1_FAPI_phyErrorIndication_st_msgBody1  ;
extern gint ett_L1_FAPI_phyErrorIndication_st_msgBody2  ;
extern gint ett_L1_FAPI_phyErrorIndication_st_msgBody3  ;
extern gint ett_L1_FAPI_phyErrorIndication_st_msgBody4  ;
extern gint ett_L1_FAPI_subFrameIndication_st  ;
extern gint ett_L1_FAPI_dlConfigRequest_st  ;
extern gint ett_L1_FAPI_dlConfigRequest_st_padding  ;
extern gint ett_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo  ;
extern gint ett_L1_FAPI_ulConfigRequest_st  ;
extern gint ett_L1_FAPI_ulConfigRequest_st_padding  ;
extern gint ett_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo  ;
extern gint ett_L1_FAPI_dlHiDCIPduInfo_st  ;
extern gint ett_L1_FAPI_dlDataTxRequest_st  ;
extern gint ett_L1_FAPI_dlDataTxRequest_st_dlPduInfo  ;
extern gint ett_L1_FAPI_rxULSCHIndication_st  ;
extern gint ett_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo  ;
extern gint ett_L1_FAPI_harqIndication_st  ;
extern gint ett_L1_FAPI_harqIndication_st_harqPduInfo  ;
extern gint ett_L1_FAPI_crcIndication_st  ;
extern gint ett_L1_FAPI_crcIndication_st_crcPduInfo  ;
extern gint ett_L1_FAPI_rxSRIndication_st  ;
extern gint ett_L1_FAPI_rxSRIndication_st_srPduInfo  ;
extern gint ett_L1_FAPI_rxCqiIndication_st  ;
extern gint ett_L1_FAPI_rxCqiIndication_st_cqiPduInfo  ;
extern gint ett_L1_FAPI_rachIndication_st  ;
extern gint ett_L1_FAPI_rachIndication_st_rachPduInfo  ;
extern gint ett_L1_FAPI_srsIndication_st  ;
extern gint ett_L1_FAPI_srsIndication_st_srsPduInfo  ;
extern gint ett_L1_lte_phy_header  ;
extern int hf_L1_FAPI_ueConfig_st_tagLen  ;
extern int hf_L1_FAPI_ueConfig_st_value  ;
extern int hf_L1_FAPI_ueConfig_st_value1  ;
extern int hf_L1_FAPI_ueConfig_st_value2  ;
extern int hf_L1_FAPI_cellConfig_st  ;
extern int hf_L1_FAPI_cellConfig_st_tag  ;
extern int hf_L1_FAPI_cellConfig_st_tagLen  ;
extern int hf_L1_FAPI_cellConfig_st_value  ;
extern int hf_L1_FAPI_paramResponseTLV_st  ;
extern int hf_L1_FAPI_paramResponseTLV_st_tag  ;
extern int hf_L1_FAPI_paramResponseTLV_st_tagLen  ;
extern int hf_L1_FAPI_paramResponseTLV_st_value  ;
extern int hf_L1_FAPI_dciFormat1_st  ;
extern int hf_L1_FAPI_dciFormat1_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat1_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat1_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat1_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat1_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat1_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat1_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat1_st_tpc  ;
extern int hf_L1_FAPI_dciFormat1_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat1_st_txPower  ;
extern int hf_L1_FAPI_dciFormat1_st_rntiType  ;
extern int hf_L1_FAPI_dciFormat1_st_padding_array  ;
extern int hf_L1_FAPI_dciFormat1_st_padding  ;
extern int hf_L1_FAPI_dciFormat1C_st_padding  ;
extern int hf_L1_FAPI_dciFormat1A_st  ;
extern int hf_L1_FAPI_dciFormat1A_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat1A_st_vRBassignmentFlag  ;
extern int hf_L1_FAPI_dciFormat1A_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat1A_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat1A_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat1A_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat1A_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat1A_st_tpc  ;
extern int hf_L1_FAPI_dciFormat1A_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat1A_st_allocatePrachFlag  ;
extern int hf_L1_FAPI_dciFormat1A_st_preambleIndex  ;
extern int hf_L1_FAPI_dciFormat1A_st_txPower  ;
extern int hf_L1_FAPI_dciFormat1A_st_pRACHMaskIndex  ;
extern int hf_L1_FAPI_dciFormat1A_st_rntiType  ;
extern int hf_L1_FAPI_dciFormat1A_st_padding_array  ;
extern int hf_L1_FAPI_dciFormat1A_st_padding  ;
extern int hf_L1_FAPI_dciFormat1B_st  ;
extern int hf_L1_FAPI_dciFormat1B_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat1B_st_vRBassignmentFlag  ;
extern int hf_L1_FAPI_dciFormat1B_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat1B_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat1B_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat1B_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat1B_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat1B_st_tPMI  ;
extern int hf_L1_FAPI_dciFormat1B_st_pmi  ;
extern int hf_L1_FAPI_dciFormat1B_st_tpc  ;
extern int hf_L1_FAPI_dciFormat1B_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat1B_st_txPower  ;
extern int hf_L1_FAPI_dciFormat1B_st_nGAP  ;
extern int hf_L1_FAPI_dciFormat1B_st_padding_array  ;
extern int hf_L1_FAPI_dciFormat1B_st_padding  ;
extern int hf_L1_FAPI_dciFormat1C_st  ;
extern int hf_L1_FAPI_dciFormat1C_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat1C_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat1C_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat1C_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat1C_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat1C_st_nGAP  ;
extern int hf_L1_FAPI_dciFormat1C_st_tbSizeIndex  ;
extern int hf_L1_FAPI_dciFormat1C_st_txPower  ;
extern int hf_L1_FAPI_dciFormat1D_st  ;
extern int hf_L1_FAPI_dciFormat1D_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat1D_st_vRBassignmentFlag  ;
extern int hf_L1_FAPI_dciFormat1D_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat1D_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat1D_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat1D_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat1D_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat1D_st_tPMI  ;
extern int hf_L1_FAPI_dciFormat1D_st_tpc  ;
extern int hf_L1_FAPI_dciFormat1D_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat1D_st_nGAP  ;
extern int hf_L1_FAPI_dciFormat1D_st_txPower  ;
extern int hf_L1_FAPI_dciFormat1D_st_dlPowerOffset  ;
extern int hf_L1_FAPI_dciFormat1D_st_padding_array  ;
extern int hf_L1_FAPI_dciFormat1D_st_padding  ;
extern int hf_L1_FAPI_dciFormat2_st  ;
extern int hf_L1_FAPI_dciFormat2_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat2_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat1A_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat1B_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat1C_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat1D_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat2_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat2_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat2_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat2_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag  ;
extern int hf_L1_FAPI_dciFormat2_st_mcs_2  ;
extern int hf_L1_FAPI_dciFormat2_st_redundancyVersion_2  ;
extern int hf_L1_FAPI_dciFormat2_st_newDataIndicator_2  ;
extern int hf_L1_FAPI_dciFormat2_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat2_st_preCodingInfo  ;
extern int hf_L1_FAPI_dciFormat2_st_tpc  ;
extern int hf_L1_FAPI_dciFormat2_st_txPower  ;
extern int hf_L1_FAPI_dciFormat2_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat2_st_rntiType  ;
extern int hf_L1_FAPI_dciFormat2A_st  ;
extern int hf_L1_FAPI_dciFormat2A_st_aggregationLevel  ;
extern int hf_L1_FAPI_dciFormat2A_st_resAllocationType  ;
extern int hf_L1_FAPI_dciFormat2A_st_mcs_1  ;
extern int hf_L1_FAPI_dciFormat2A_st_redundancyVersion_1  ;
extern int hf_L1_FAPI_dciFormat2A_st_rbCoding  ;
extern int hf_L1_FAPI_dciFormat2A_st_newDataIndicator_1  ;
extern int hf_L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag  ;
extern int hf_L1_FAPI_dciFormat2A_st_mcs_2  ;
extern int hf_L1_FAPI_dciFormat2A_st_redundancyVersion_2  ;
extern int hf_L1_FAPI_dciFormat2A_st_newDataIndicator_2  ;
extern int hf_L1_FAPI_dciFormat2A_st_harqProcessNum  ;
extern int hf_L1_FAPI_dciFormat2A_st_preCodingInfo  ;
extern int hf_L1_FAPI_dciFormat2A_st_tpc  ;
extern int hf_L1_FAPI_dciFormat2A_st_txPower  ;
extern int hf_L1_FAPI_dciFormat2A_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dciFormat2A_st_rntiType  ;
extern int hf_L1_FAPI_dciDLPduInfo_st  ;
extern int hf_L1_FAPI_dciDLPduInfo_st_dciFormat  ;
extern int GLOBE_FAPI_DL_DCI_FORMAT_1  ;
extern int hf_L1_FAPI_dciDLPduInfo_st_cceIndex  ;
extern int hf_L1_FAPI_dciDLPduInfo_st_rnti  ;
extern int hf_L1_FAPI_dciDLPduInfo_st_dciPdu  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st_bchPduLen  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st_pduIndex  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st_txPower  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st_padding_array  ;
extern int hf_L1_FAPI_bchConfigPDUInfo_st_padding  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_mchPduLen  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_pduIndex  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_rnti  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_resAllocationType  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_modulationType  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_rbCoding  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_txPower  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_padding_array  ;
extern int hf_L1_FAPI_mchConfigPDUInfo_st_padding  ;
extern int hf_L1_FAPI_beamFormingVectorInfo_st  ;
extern int hf_L1_FAPI_beamFormingVectorInfo_st_subBandIndex  ;
extern int hf_L1_FAPI_beamFormingVectorInfo_st_numOfAntenna  ;
extern int hf_L1_FAPI_beamFormingVectorInfo_st_bfValue_per_antenna  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_dlschPduLen  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_pduIndex  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_rnti  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_rbCoding  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_mcs  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_redundancyVersion  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_transportBlocks  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfLayers  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfSubBand  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_ueCatagoryCapacity  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_pA  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_deltaPowerOffsetAIndex  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_nGap  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_nPRB  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numRbPerSubBand  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numbfVector  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_subBandInfo  ;
extern int hf_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_pchPduLen  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_pduIndex  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_pRNTI  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_resAllocationType  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_rbCoding  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_mcs  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_redundancyVersion  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_numOftransportBlocks  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_transmissionScheme  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_numOfLayers  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_codeBookIndex  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_ueCatagoryCapacity  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_pA  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_nPRB  ;
extern int hf_L1_FAPI_pchPduConfigInfo_st_txPower  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_pduType  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_pduSize  ;
//int hf_L1_FAPI_dlConfigPDUInfo_st_vishal  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_DCIPdu  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_BCHPdu  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_MCHPdu  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_PChPdu  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_padding_array  ;
extern int hf_L1_FAPI_dlConfigPDUInfo_st_padding  ;
extern int hf_L1_FAPI_dlTLVInfo_st  ;
extern int hf_L1_FAPI_dlTLVInfo_st_tag  ;
extern int hf_L1_FAPI_dlTLVInfo_st_tagLen  ;
//int hf_L1_FAPI_dlTLVInfo_st_padding  ;
extern int hf_L1_FAPI_dlTLVInfo_st_value  ;
extern int hf_L1_FAPI_dlPduInfo_st  ;
extern int hf_L1_FAPI_dlPduInfo_st_pduLen  ;
extern int hf_L1_FAPI_dlPduInfo_st_pduIndex  ;
extern int hf_L1_FAPI_dlPduInfo_st_numOfTLV  ;
extern int hf_L1_FAPI_dlPduInfo_st_dlTLVInfo  ;
extern int hf_L1_FAPI_dlHiPduInfo_st  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_pduType  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_hipduSize  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_rbStart  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_cyclicShift2_forDMRS  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_hiValue  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_iPHICH  ;
extern int hf_L1_FAPI_dlHiPduInfo_st_txPower  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_pduType  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_uldcipduSize  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_ulDCIFormat  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_cceIndex  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_rnti  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_aggLevel  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_rbStart  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_numOfRB  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_mcs  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_cyclicShift2_forDMRS  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_freqEnabledFlag  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_freqHoppingBits  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_newDataIndication  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_ueTxAntennaSelection  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_tpc  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_cqiRequest  ;
extern int hf_L1_FAPI_ulConfigRequest_st_sfnsf  ;
//FAPI_ulPDUConfigInfo_st_count  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_ulIndex  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_dlAssignmentIndex  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_padding  ;
extern int hf_L1_FAPI_dlDCIPduInfo_st_tpcBitMap  ;
extern int hf_L1_FAPI_cqiPduInfo_st  ;
extern int hf_L1_FAPI_cqiPduInfo_st_pucchIndex  ;
extern int hf_L1_FAPI_cqiPduInfo_st_dlCqiPmiSize  ;
extern int hf_L1_FAPI_cqiPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_cqiPduInfo_st_padding  ;
extern int hf_L1_FAPI_srPduInfo_st  ;
extern int hf_L1_FAPI_srPduInfo_st_pucchIndex  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_harqSize  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_acknackMode  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_numOfPUCCHResource  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_0  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_1  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_2  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_3  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_tddHarqPduInfo_st_padding  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex1  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st_harqSize  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_fddHarqPduInfo_st_padding  ;
extern int hf_L1_FAPI_ulSCHHarqInfo_st_padding  ;
extern int hf_L1_FAPI_ulPDUConfigInfo_st_padding  ;
extern int hf_L1_FAPI_srsPduInfo_st  ;
extern int hf_L1_FAPI_srsPduInfo_st_handle  ;
extern int hf_L1_FAPI_srsPduInfo_st_size  ;
extern int hf_L1_FAPI_srsPduInfo_st_rnti  ;
extern int hf_L1_FAPI_srsPduInfo_st_srsBandWidth  ;
extern int hf_L1_FAPI_srsPduInfo_st_freqDomainPosition  ;
extern int hf_L1_FAPI_srsPduInfo_st_srsHoppingBandWidth  ;
extern int hf_L1_FAPI_srsPduInfo_st_transmissionComb  ;
extern int hf_L1_FAPI_srsPduInfo_st_isrsSRSConfigIndex  ;
extern int hf_L1_FAPI_srsPduInfo_st_soundingRefCyclicShift  ;
extern int hf_L1_FAPI_srsPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_srsPduInfo_st_padding  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRank_1  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRankGT_1  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_riSize  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetCQI  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetRI  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_cqiRiPduInfo_st_padding  ;
extern int hf_L1_FAPI_uciSrPduInfo_st  ;
extern int hf_L1_FAPI_uciSrPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciSrPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciSrPduInfo_st_srInfo  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st_padding  ;
extern int hf_L1_FAPI_uciCqiPduInfo_st_cqiInfo  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st_padding  ;
extern int hf_L1_FAPI_uciHarqPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_uciSrHarqPduInfo_st  ;
extern int hf_L1_FAPI_uciSrHarqPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciSrHarqPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciSrHarqPduInfo_st_srInfo  ;
extern int hf_L1_FAPI_uciSrHarqPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_padding_array  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_padding  ;
extern int hf_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_uciCqiSrPduInfo_st  ;
extern int hf_L1_FAPI_uciCqiSrPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciCqiSrPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo  ;
extern int hf_L1_FAPI_uciCqiSrPduInfo_st_srInfo  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_handle  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_rnti  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo  ;
extern int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_handle  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_size  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_rnti  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_rbStart  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_numOfRB  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_modulationType  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_cyclicShift2forDMRS  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingenabledFlag  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingBits  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_newDataIndication  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_redundancyVersion  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_harqProcessNumber  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_ulTxMode  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_currentTxNB  ;
extern int hf_L1_FAPI_ulSCHPduInfo_st_nSRS  ;
extern int hf_L1_FAPI_initialTxParam_st  ;
extern int hf_L1_FAPI_initialTxParam_st_nSRSInitial  ;
extern int hf_L1_FAPI_initialTxParam_st_initialNumOfRB  ;
extern int hf_L1_FAPI_initialTxParam_st_padding_array  ;
extern int hf_L1_FAPI_initialTxParam_st_padding  ;
extern int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st  ;
extern int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo  ;
extern int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo  ;
extern int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo  ;
extern int hf_L1_FAPI_ulSCHHarqPduInfo_st  ;
extern int hf_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo  ;
extern int hf_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo  ;
extern int hf_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo  ;
extern int hf_L1_FAPI_ulSCHHarqInfo_st  ;
extern int hf_L1_FAPI_ulSCHHarqInfo_st_harqSize  ;
extern int hf_L1_FAPI_ulSCHHarqInfo_st_deltaOffsetHarq  ;
extern int hf_L1_FAPI_ulSCHHarqInfo_st_ackNackMode  ;
extern int hf_L1_FAPI_ulSCHCqiRiPduInfo_st  ;
extern int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo  ;
extern int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo  ;
extern int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo  ;
extern int hf_L1_FAPI_ulPDUConfigInfo_st  ;
extern int hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType  ;
extern int hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduSize  ;
extern int hf_L1_FAPI_ulPDUConfigInfo_st_ulPduConfigInfo  ;
extern int hf_L1_FAPI_ulDataPduIndication_st  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_handle  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_rnti  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_length  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_dataOffset  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_timingAdvance  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_ulCqi  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_padding_array  ;
extern int hf_L1_FAPI_ulDataPduIndication_st_padding  ;
extern int hf_L1_FAPI_fddHarqPduIndication_st  ;
extern int hf_L1_FAPI_fddHarqPduIndication_st_rnti  ;
extern int hf_L1_FAPI_fddHarqPduIndication_st_harqTB1  ;
extern int hf_L1_FAPI_fddHarqPduIndication_st_harqTB2  ;
extern int hf_L1_FAPI_tddBundlingHarqInfo_st  ;
extern int hf_L1_FAPI_tddBundlingHarqInfo_st_value0  ;
extern int hf_L1_FAPI_tddBundlingHarqInfo_st_value1  ;
extern int hf_L1_FAPI_tddMultiplexingHarqInfo_st  ;
extern int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value0  ;
extern int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value1  ;
extern int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value2  ;
extern int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value3  ;
extern int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st  ;
extern int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_value_0  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st_handle  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st_rnti  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st_mode  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st_numOfAckNack  ;
extern int hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer  ;
extern int hf_L1_FAPI_crcPduIndication_st  ;
extern int hf_L1_FAPI_crcPduIndication_st_handle  ;
extern int hf_L1_FAPI_crcPduIndication_st_rnti  ;
extern int hf_L1_FAPI_crcPduIndication_st_crcFlag  ;
extern int hf_L1_FAPI_crcPduIndication_st_padding_array  ;
extern int hf_L1_FAPI_crcPduIndication_st_padding  ;
extern int hf_L1_FAPI_cqiPduIndication_st  ;
extern int hf_L1_FAPI_cqiPduIndication_st_handle  ;
extern int hf_L1_FAPI_cqiPduIndication_st_rnti  ;
extern int hf_L1_FAPI_cqiPduIndication_st_length  ;
extern int hf_L1_FAPI_cqiPduIndication_st_dataOffset  ;
extern int hf_L1_FAPI_cqiPduIndication_st_timingAdvance  ;
extern int hf_L1_FAPI_cqiPduIndication_st_ulCqi  ;
extern int hf_L1_FAPI_cqiPduIndication_st_ri  ;
extern int hf_L1_FAPI_cqiPduIndication_st_padding_array  ;
extern int hf_L1_FAPI_cqiPduIndication_st_padding  ;
extern int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding  ;
extern int hf_L1_FAPI_tddBundlingHarqInfo_st_padding  ;
extern int hf_L1_FAPI_srPduIndication_st  ;
extern int hf_L1_FAPI_srPduIndication_st_handle  ;
extern int hf_L1_FAPI_srPduIndication_st_rnti  ;
extern int hf_L1_FAPI_srPduIndication_st_padding_array  ;
extern int hf_L1_FAPI_srPduIndication_st_padding  ;
extern int hf_L1_FAPI_rachPduIndication_st  ;
extern int hf_L1_FAPI_rachPduIndication_st_rnti  ;
extern int hf_L1_FAPI_rachPduIndication_st_timingAdvance  ;
extern int hf_L1_FAPI_rachPduIndication_st_preamble  ;
extern int hf_L1_FAPI_rachPduIndication_st_padding_array  ;
extern int hf_L1_FAPI_rachPduIndication_st_padding  ;
extern int hf_L1_FAPI_srsPduIndication_st  ;
extern int hf_L1_FAPI_srsPduIndication_st_handle  ;
extern int hf_L1_FAPI_srsPduIndication_st_rnti  ;
extern int hf_L1_FAPI_srsPduIndication_st_dopplerEstimation  ;
extern int hf_L1_FAPI_srsPduIndication_st_timingAdvance  ;
extern int hf_L1_FAPI_srsPduIndication_st_numOfRB  ;
extern int hf_L1_FAPI_srsPduIndication_st_rbStart  ;
extern int hf_L1_FAPI_srsPduIndication_st_snr  ;
extern int hf_L1_FAPI_errMsgBody1_st  ;
extern int hf_L1_FAPI_errMsgBody1_st_recvdSfnSf  ;
extern int hf_L1_FAPI_errMsgBody1_st_expectedSfnSf  ;
extern int hf_L1_FAPI_errMsgBody2_st  ;
extern int hf_L1_FAPI_errMsgBody2_st_subErrCode  ;
extern int hf_L1_FAPI_errMsgBody2_st_direction  ;
extern int hf_L1_FAPI_errMsgBody2_st_rnti  ;
extern int hf_L1_FAPI_errMsgBody2_st_pduType  ;
extern int hf_L1_FAPI_errMsgBody2_st_padding_array  ;
extern int hf_L1_FAPI_errMsgBody2_st_padding  ;
extern int hf_L1_FAPI_errMsgBody3_st  ;
extern int hf_L1_FAPI_errMsgBody3_st_subErrCode  ;
extern int hf_L1_FAPI_errMsgBody3_st_phichLowestulRbIndex  ;
extern int hf_L1_FAPI_errMsgBody4_st  ;
extern int hf_L1_FAPI_errMsgBody4_st_subErrCode  ;
extern int hf_L1_FAPI_errMsgBody4_st_pduIndex  ;
extern int hf_L1_FAPI_l1ApiMsg_st  ;
extern int hf_L1_FAPI_l1ApiMsg_st_msgId  ;
extern int hf_L1_FAPI_l1ApiMsg_st_lenVendorSpecific  ;
extern int hf_L1_FAPI_l1ApiMsg_st_msgLen  ;
extern int hf_L1_FAPI_l1ApiMsg_st_msgBody  ;
extern int hf_L1_FAPI_l1ApiMsg_st_vendorMsgBody  ;
extern int hf_L1_FAPI_paramRequest_st  ;
extern int hf_L1_FAPI_paramRequest_st_msgId  ;
extern int hf_L1_FAPI_paramResponse_st  ;
extern int hf_L1_FAPI_paramResponse_st_errCode  ;
extern int hf_L1_FAPI_paramResponse_st_numOfTlv  ;
extern int hf_L1_FAPI_paramResponse_st_padding_array  ;
extern int hf_L1_FAPI_paramResponse_st_padding  ;
extern int hf_L1_FAPI_paramResponse_st_tlvs  ;
extern int hf_L1_FAPI_phyStart_st  ;
extern int hf_L1_FAPI_phyStart_st_msgId  ;
extern int hf_L1_FAPI_phyStop_st  ;
extern int hf_L1_FAPI_phyStop_st_msgId  ;
extern int hf_L1_FAPI_phyStopIndication_st  ;
extern int hf_L1_FAPI_phyStopIndication_st_msgId  ;
extern int hf_L1_FAPI_phyCellConfigRequest_st  ;
extern int hf_L1_FAPI_phyCellConfigRequest_st_numOfTlv  ;
extern int hf_L1_FAPI_phyCellConfigRequest_st_padding_array  ;
extern int hf_L1_FAPI_phyCellConfigRequest_st_padding  ;
extern int hf_L1_FAPI_phyCellConfigRequest_st_configtlvs  ;
extern int hf_L1_FAPI_phyCellConfigResp_st  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_errorCode  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_numOfInvalidOrunsupportedTLV  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_numOfMissingTLV  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_padding_array  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_padding  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_listOfTLV  ;
extern int hf_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv  ;
extern int hf_L1_FAPI_ueConfigRequest_st  ;
extern int hf_L1_FAPI_ueConfigRequest_st_numOfTlv  ;
extern int hf_L1_FAPI_ueConfigRequest_st_tlvs  ;
extern int hf_L1_FAPI_phyUeConfigResp_st  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_errorCode  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_numOfInvalidOrunsupportedTLV  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_numOfMissingTLV  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_padding_array  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_padding  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_listOfTLV  ;
extern int hf_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv  ;
extern int hf_L1_FAPI_phyErrorIndication_st  ;
extern int hf_L1_FAPI_phyErrorIndication_st_msgId  ;
extern int hf_L1_FAPI_phyErrorIndication_st_padding_array  ;
extern int hf_L1_FAPI_phyErrorIndication_st_padding  ;
extern int hf_L1_FAPI_phyErrorIndication_st_errorCode  ;
extern int hf_L1_FAPI_phyErrorIndication_st_msgBody1  ;
extern int hf_L1_FAPI_phyErrorIndication_st_msgBody2  ;
extern int hf_L1_FAPI_phyErrorIndication_st_msgBody3  ;
extern int hf_L1_FAPI_phyErrorIndication_st_msgBody4  ;
extern int hf_L1_FAPI_subFrameIndication_st  ;
extern int hf_L1_FAPI_subFrameIndication_st_sf  ;
extern int hf_L1_FAPI_subFrameIndication_st_sfn  ;
extern int hf_L1_FAPI_dlConfigRequest_st  ;
extern int hf_L1_FAPI_dlConfigRequest_st_sf  ;
extern int hf_L1_FAPI_dlConfigRequest_st_sfn  ;
extern int hf_L1_FAPI_dlConfigRequest_st_length  ;
extern int hf_L1_FAPI_dlConfigRequest_st_cfi  ;
extern int hf_L1_FAPI_dlConfigRequest_st_numDCI  ;
extern int hf_L1_FAPI_dlConfigRequest_st_numOfPDU  ;
extern int hf_L1_FAPI_dlConfigRequest_st_txPowerForPCFICH  ;
extern int hf_L1_FAPI_dlConfigRequest_st_numOfPDSCHRNTI  ;
extern int hf_L1_FAPI_dlConfigRequest_st_padding_array  ;
extern int hf_L1_FAPI_dlConfigRequest_st_padding  ;
extern int hf_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo  ;
extern int hf_L1_FAPI_ulConfigRequest_st  ;
extern int hf_L1_FAPI_ulConfigRequest_st_sf  ;
extern int hf_L1_FAPI_ulConfigRequest_st_sfn  ;
extern int hf_L1_FAPI_ulConfigRequest_st_ulConfigLen  ;
extern int hf_L1_FAPI_ulConfigRequest_st_numOfPdu  ;
extern int hf_L1_FAPI_ulConfigRequest_st_rachFreqResources  ;
extern int hf_L1_FAPI_ulConfigRequest_st_srsPresent  ;
extern int hf_L1_FAPI_ulConfigRequest_st_padding_array  ;
extern int hf_L1_FAPI_ulConfigRequest_st_padding  ;
extern int hf_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st_sf  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st_sfn  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st_numOfDCI  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st_numOfHI  ;
extern int hf_L1_FAPI_dlHiDCIPduInfo_st_hidciPduInfo  ;
extern int hf_L1_FAPI_dlDataTxRequest_st  ;
extern int hf_L1_FAPI_dlDataTxRequest_st_sf  ;
extern int hf_L1_FAPI_dlDataTxRequest_st_sfn  ;
extern int hf_L1_FAPI_dlDataTxRequest_st_numOfPDU  ;
extern int hf_L1_FAPI_dlDataTxRequest_st_dlPduInfo  ;
extern int hf_L1_FAPI_rxULSCHIndication_st  ;
extern int hf_L1_FAPI_rxULSCHIndication_st_sf  ;
extern int hf_L1_FAPI_rxULSCHIndication_st_sfn  ;
extern int hf_L1_FAPI_rxULSCHIndication_st_numOfPdu  ;
extern int hf_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo  ;
extern int hf_L1_FAPI_rxULSCHIndication_st_pduBuffer  ;
extern int hf_L1_FAPI_harqIndication_st  ;
extern int hf_L1_FAPI_harqIndication_st_sf  ;
extern int hf_L1_FAPI_harqIndication_st_sfn  ;
extern int hf_L1_FAPI_harqIndication_st_numOfHarq  ;
extern int hf_L1_FAPI_harqIndication_st_harqPduInfo  ;
extern int hf_L1_FAPI_crcIndication_st  ;
extern int hf_L1_FAPI_crcIndication_st_sf  ;
extern int hf_L1_FAPI_crcIndication_st_sfn  ;
extern int hf_L1_FAPI_crcIndication_st_numOfCrc  ;
extern int hf_L1_FAPI_crcIndication_st_crcPduInfo  ;
extern int hf_L1_FAPI_rxSRIndication_st  ;
extern int hf_L1_FAPI_rxSRIndication_st_sf  ;
extern int hf_L1_FAPI_rxSRIndication_st_sfn  ;
extern int hf_L1_FAPI_rxSRIndication_st_numOfSr  ;
extern int hf_L1_FAPI_rxSRIndication_st_srPduInfo  ;
extern int hf_L1_FAPI_rxCqiIndication_st  ;
extern int hf_L1_FAPI_rxCqiIndication_st_sf  ;
extern int hf_L1_FAPI_rxCqiIndication_st_sfn  ;
extern int hf_L1_FAPI_rxCqiIndication_st_numOfCqi  ;
extern int hf_L1_FAPI_rxCqiIndication_st_cqiPduInfo  ;
extern int hf_L1_FAPI_rxCqiIndication_st_pduBuffer  ;
extern int hf_L1_FAPI_rachIndication_st  ;
extern int hf_L1_FAPI_rachIndication_st_sf  ;
extern int hf_L1_FAPI_rachIndication_st_sfn  ;
extern int hf_L1_FAPI_rachIndication_st_numOfPreamble  ;
extern int hf_L1_FAPI_rachIndication_st_rachPduInfo  ;
extern int hf_L1_FAPI_srsIndication_st  ;
extern int hf_L1_FAPI_srsIndication_st_sf  ;
extern int hf_L1_FAPI_srsIndication_st_sfn  ;
extern int hf_L1_FAPI_srsIndication_st_numOfUe  ;
extern int hf_L1_FAPI_srsIndication_st_srsPduInfo  ;
extern int hf_L1_lte_phy_header  ;
extern int hf_L1_lte_phy_header_msgId  ;
extern int hf_L1_lte_phy_header_lenVendorSpecific  ;
extern int hf_L1_lte_phy_header_msgLen  ;
extern int hf_L1_FAPI_harqIndication_st_sfnsf  ;

extern int      g_radio_type        ;
int      g_ul_rnti_type      ;
static struct mac_lte_info * p_mac_lte_info	= NULL;
static struct mac_lte_info   mac_info[65535][10]	= {{{0,},},};
static unsigned short	     sfsfn		= 0;
static unsigned short	     PDUIndex		= 0;

static guint16  pdu_variable_length[512] = {0};
static guint8   pdu_index = 0;


static guint16  g_pduBuffer[512] = {0};
static guint8   g_pduOffset = 0;

static guint16  g_frameBuffer[512] = {0};
static guint8   g_frameOffset = 0;
static guint8   duplex_mode = 0xff;

/*Change start for the HARQ Indication*/
//static gint ett_L1 = -1;
//static gint ett_L1_payload = -1;
//FAPI_harqIndication_st_count = -1;
//static gint ett_L1_FAPI_harqIndication_st = -1;
//static gint ett_L1_FAPI_harqIndication_st_harqPduInfo = -1;
int FAPI_tddHarqPduIndication_st_count = -1;
//static gint ett_L1_FAPI_tddHarqPduIndication_st = -1;
/*Change end or the HARQ indication*/



extern int hf_L1_unparsed_data ;
extern int hf_L1_FAPI_ueConfig_st ;
extern int hf_L1_FAPI_ueConfig_st_tag ;


int dissect_L1_FAPI_ueConfig_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
        guint i =0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 tag = 0;
	guint8 tagLen = 0;
	guint8 value = 0;
	guint16 value1 = 0;
	guint32 value2 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ueConfig_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ueConfig_st);
	tag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ueConfig_st_tag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tagLen = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ueConfig_st_tagLen, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != tagLen)
	{
        if (100 == tag)
        {   
	        value2 = fapi_get_32(tvb, offset + offset_counter);
	        local_ptr_to_currently_added_item =
                proto_tree_add_item(subtree,hf_L1_FAPI_ueConfig_st_value2, tvb,offset + offset_counter,4, IS_LITTLE_ENDIAN);
                offset_counter +=4; 
        }
        else if (101 == tag || 102 == tag || 103 == tag || 104 == tag ||
                 107 == tag || 113 == tag || 116 == tag || 118 == tag ||
                 119 == tag)
        {
	        value1 = fapi_get_16(tvb, offset + offset_counter);;
	        local_ptr_to_currently_added_item =
                proto_tree_add_item(subtree,hf_L1_FAPI_ueConfig_st_value1,tvb,offset + offset_counter,2, IS_LITTLE_ENDIAN);
                offset_counter += 2;            
        }    
        else
        {
	        local_ptr_to_currently_added_item =
                proto_tree_add_item(subtree,hf_L1_FAPI_ueConfig_st_value,
                tvb,offset + offset_counter,1, IS_LITTLE_ENDIAN);
                offset_counter += 2;            

        }    

	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_cellConfig_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 tag = 0;
	guint8 tagLen = 0;
	guint16 value = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cellConfig_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cellConfig_st);
	tag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cellConfig_st_tag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tagLen = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cellConfig_st_tagLen, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	value = fapi_get_16(tvb, offset + offset_counter);
        if(tag == 0x01)
         duplex_mode = value;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cellConfig_st_value, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_paramResponseTLV_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 tag = 0;
	guint8 tagLen = 0;
	guint16 value = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_paramResponseTLV_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_paramResponseTLV_st);
	tag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponseTLV_st_tag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tagLen = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponseTLV_st_tagLen, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	value = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponseTLV_st_value, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat1_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dciFormat1_st_padding_tree;
	proto_item *L1_FAPI_dciFormat1_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 resAllocationType = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 harqProcessNum = 0;
	guint8 tpc = 0;
	guint8 dlAssignmentIndex = 0;
	guint16 txPower = 0;
	guint8 rntiType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat1_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat1_st);

	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	rntiType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save RNTI Type */
//	mac_info [sfsfn][PDUIndex].rntiType	= g_ul_rnti_type; /* FAPI bug. RNTI coming is not correct. So using same as UL */
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_rntiType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_dciFormat1_st_padding_item=proto_tree_add_text(subtree, tvb, offset + offset_counter, -1, "Padding array [1]");
	L1_FAPI_dciFormat1_st_padding_tree=proto_item_add_subtree(L1_FAPI_dciFormat1_st_padding_item, ett_L1_FAPI_dciFormat1_st_padding);
	temp_start_offset_holder = offset_counter;
	for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dciFormat1_st_padding_tree, hf_L1_FAPI_dciFormat1_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
		if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
		}
	}
	proto_item_set_len(L1_FAPI_dciFormat1_st_padding_item,offset_counter - temp_start_offset_holder);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat1A_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dciFormat1A_st_padding_tree;
	proto_item *L1_FAPI_dciFormat1A_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 vRBassignmentFlag = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 harqProcessNum = 0;
	guint8 resAllocationType = 0;
	guint8 tpc = 0;
	guint8 dlAssignmentIndex = 0;
	guint8 allocatePrachFlag = 0;
	guint8 preambleIndex = 0;
	guint16 txPower = 0;
	guint8 pRACHMaskIndex = 0;
	guint8 rntiType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat1A_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat1A_st);
	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	vRBassignmentFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_vRBassignmentFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	allocatePrachFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_allocatePrachFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	preambleIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_preambleIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	pRACHMaskIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_pRACHMaskIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rntiType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save RNTI Type */

//    mac_info [sfsfn][PDUIndex].rntiType   = g_ul_rnti_type; /*Previously, here it was C_RNTI*/
/*    if(rntiType == 1)
    {    
	mac_info [sfsfn].rntiType	= C_RNTI;
    }
    if(rntiType == 3)
    {
    mac_info [sfsfn].rntiType   = SPS_RNTI;
    }
*/

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_rntiType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    
	offset_counter += 1;
/*****SPR 946 CHANGES ***********/


//	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
//	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1A_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
//	offset_counter += 1;


/*******************************/
	L1_FAPI_dciFormat1A_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "Padding array [1]");
	L1_FAPI_dciFormat1A_st_padding_tree=proto_item_add_subtree(L1_FAPI_dciFormat1A_st_padding_item, ett_L1_FAPI_dciFormat1A_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dciFormat1A_st_padding_tree, hf_L1_FAPI_dciFormat1A_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_dciFormat1A_st_padding_item,offset_counter - temp_start_offset_holder);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat1B_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_dciFormat1B_st_padding_tree;

	proto_item *L1_FAPI_dciFormat1B_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 vRBassignmentFlag = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 harqProcessNum = 0;
	guint8 tPMI = 0;
	guint8 pmi = 0;
	guint8 tpc = 0;
	guint8 dlAssignmentIndex = 0;
	guint16 txPower = 0;
	guint8 nGAP = 0;
	guint8 resAllocationType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat1B_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat1B_st);

	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	vRBassignmentFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_vRBassignmentFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tPMI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_tPMI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pmi = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_pmi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	nGAP = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_nGAP, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
/*****SPR 946 CHANGES ***********/


//	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
//	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1B_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
//	offset_counter += 1;


/*******************************/
	L1_FAPI_dciFormat1B_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_dciFormat1B_st_padding_tree=proto_item_add_subtree(L1_FAPI_dciFormat1B_st_padding_item, ett_L1_FAPI_dciFormat1B_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dciFormat1B_st_padding_tree, hf_L1_FAPI_dciFormat1B_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
	proto_item_set_len(L1_FAPI_dciFormat1B_st_padding_item,offset_counter - temp_start_offset_holder);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat1C_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_item *L1_FAPI_dciFormat1C_st_padding_item;
	proto_tree *L1_FAPI_dciFormat1C_st_padding_tree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint8 newDataIndicator_1 = 0;
	guint32 rbCoding = 0;
	guint8 nGAP = 0;
	guint8 tbSizeIndex = 0;
	guint16 txPower = 0;
	guint8 resAllocationType = 0;
	guint8 loop_counter0 = 0;
	guint8 loop_counter1 = 0;
	guint8 loop_counter2 = 0;
	guint8 loop_counter3 = 0;
//	guint8 loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat1C_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat1C_st);
	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level 	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	nGAP = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_nGAP, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tbSizeIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_tbSizeIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
/*****SPR 946 CHANGES ***********/


//	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
//	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1C_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
//	offset_counter += 1;

	L1_FAPI_dciFormat1C_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [3]");
	L1_FAPI_dciFormat1C_st_padding_tree=proto_item_add_subtree(L1_FAPI_dciFormat1C_st_padding_item, ett_L1_FAPI_dciFormat1C_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 4;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dciFormat1C_st_padding_tree, hf_L1_FAPI_dciFormat1C_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
	proto_item_set_len(L1_FAPI_dciFormat1C_st_padding_item,offset_counter - temp_start_offset_holder);

/*******************************/

	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat1D_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dciFormat1D_st_padding_tree;
	proto_item *L1_FAPI_dciFormat1D_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 vRBassignmentFlag = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 harqProcessNum = 0;
	guint8 tPMI = 0;
	guint8 tpc = 0;
	guint8 dlAssignmentIndex = 0;
	guint8 nGAP = 0;
	guint16 txPower = 0;
	guint8 dlPowerOffset = 0;
	guint8 resAllocationType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat1D_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat1D_st);
	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	vRBassignmentFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_vRBassignmentFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tPMI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_tPMI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nGAP = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_nGAP, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dlPowerOffset = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_dlPowerOffset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
/*****SPR 946 CHANGES ***********/


	//resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
//	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1D_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
//	offset_counter += 1;

/********************************/


	L1_FAPI_dciFormat1D_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "Padding array [2]");
	L1_FAPI_dciFormat1D_st_padding_tree=proto_item_add_subtree(L1_FAPI_dciFormat1D_st_padding_item, ett_L1_FAPI_dciFormat1D_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dciFormat1D_st_padding_tree, hf_L1_FAPI_dciFormat1D_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_dciFormat1D_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat2_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 resAllocationType = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 tbToCodeWordSwapFlag = 0;
	guint8 mcs_2 = 0;
	guint8 redundancyVersion_2 = 0;
	guint8 newDataIndicator_2 = 0;
	guint8 harqProcessNum = 0;
	guint8 preCodingInfo = 0;
	guint8 tpc = 0;
	guint16 txPower = 0;
	guint8 dlAssignmentIndex = 0;
	guint8 rntiType = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat2_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat2_st);
	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tbToCodeWordSwapFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_mcs_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_redundancyVersion_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndicator_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_newDataIndicator_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	preCodingInfo = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_preCodingInfo, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rntiType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save RNTI Type */
//	mac_info [sfsfn][PDUIndex].rntiType	= g_ul_rnti_type; /*Previously, here it was C_RNTI*/
/*     if(rntiType == 1)
             {
              mac_info [sfsfn].rntiType   = C_RNTI;
             }
             if(rntiType == 3)
             {
              mac_info [sfsfn].rntiType   = SPS_RNTI;
             }
*/
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2_st_rntiType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dciFormat2A_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 aggregationLevel = 0;
	guint8 resAllocationType = 0;
	guint8 mcs_1 = 0;
	guint8 redundancyVersion_1 = 0;
	guint32 rbCoding = 0;
	guint8 newDataIndicator_1 = 0;
	guint8 tbToCodeWordSwapFlag = 0;
	guint8 mcs_2 = 0;
	guint8 redundancyVersion_2 = 0;
	guint8 newDataIndicator_2 = 0;
	guint8 harqProcessNum = 0;
	guint8 preCodingInfo = 0;
	guint8 tpc = 0;
	guint16 txPower = 0;
	guint8 dlAssignmentIndex = 0;
	guint8 rntiType = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciFormat2A_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciFormat2A_st);
	aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Aggregation Level */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.aggregation_level	= aggregationLevel;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Resource Allocator */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_allocation_type	= resAllocationType;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save MCS */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.mcs_index	= mcs_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_mcs_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_1 = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save Redundancy Version */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.redundancy_version_index	= redundancyVersion_1;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_redundancyVersion_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	newDataIndicator_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_newDataIndicator_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tbToCodeWordSwapFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_mcs_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_redundancyVersion_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndicator_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_newDataIndicator_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNum = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_harqProcessNum, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	preCodingInfo = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_preCodingInfo, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rntiType = tvb_get_guint8(tvb, offset + offset_counter);
	/* Save RNTI Type */
//	mac_info [sfsfn][PDUIndex].rntiType	= g_ul_rnti_type; /*Previously, here it was C_RNTI */
/*     if(rntiType == 1)
     {
     mac_info [sfsfn].rntiType   = C_RNTI;
     }
     if(rntiType == 3)
     {
     mac_info [sfsfn].rntiType   = SPS_RNTI;
     }
*/
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat2A_st_rntiType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dciDLPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 dciFormat = 0;
	guint8 cceIndex = 0;
	guint16 rnti = 0;
	guint8 dciPdu = 0;
	guint8 aggregationLevel  = 0;
       
	item = proto_tree_add_item(tree, hf_L1_FAPI_dciDLPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dciDLPduInfo_st);
	dciFormat = tvb_get_guint8(tvb, offset + offset_counter);
        GLOBE_FAPI_DL_DCI_FORMAT_1 = dciFormat;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciDLPduInfo_st_dciFormat, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cceIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciDLPduInfo_st_cceIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

        //aggregationLevel = tvb_get_guint8(tvb, offset + offset_counter);

       /* Save Aggregation Level */

        //local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciFormat1_st_aggregationLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        //offset_counter += 1;


	rnti = fapi_get_16(tvb, offset + offset_counter);
#if 0
	if((rnti >= 0x01 && rnti <= 0x3c) && rnti != 0x33)
	{
	
		mac_info[sfsfn][PDUIndex].rntiType = RA_RNTI;

	}
	if(rnti == 0x33)
	{
		mac_info[sfsfn][PDUIndex].rntiType = C_RNTI;
	}
	if(rnti == 0xffff)
	{
		mac_info[sfsfn][PDUIndex].rntiType = SI_RNTI;
	} 

	
	/* Save MCS */
	mac_info [sfsfn][PDUIndex].rnti	= rnti;
#endif
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dciDLPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.present = TRUE;

	if (0 != 1)
	{
            
            if (0 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 1;
		offset_counter +=dissect_L1_FAPI_dciFormat1_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (1 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 2;
                offset_counter +=dissect_L1_FAPI_dciFormat1A_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (2 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 3;
                offset_counter +=dissect_L1_FAPI_dciFormat1B_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (3 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 4;
                offset_counter +=dissect_L1_FAPI_dciFormat1C_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (4 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 5;
                offset_counter +=dissect_L1_FAPI_dciFormat1D_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (5 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 6;
                offset_counter +=dissect_L1_FAPI_dciFormat2_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
            else if (6 == dciFormat)
            {
//		mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.dci_format = 7;
                offset_counter +=dissect_L1_FAPI_dciFormat2A_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
            }
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_bchConfigPDUInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_bchConfigPDUInfo_st_padding_tree;
	proto_item *L1_FAPI_bchConfigPDUInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 bchPduLen = 0;
	guint16 pduIndex = 0;
	guint16 txPower = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_bchConfigPDUInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_bchConfigPDUInfo_st);
	bchPduLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_bchConfigPDUInfo_st_bchPduLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pduIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_bchConfigPDUInfo_st_pduIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	PDUIndex = pduIndex;
		mac_info [sfsfn][PDUIndex].radioType	= g_radio_type;
		mac_info [sfsfn][PDUIndex].direction	= DIRECTION_DOWNLINK;
//		mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
        mac_info [sfsfn][PDUIndex].rntiType = NO_RNTI;          /**********TEST 25 NOV***********/

	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_bchConfigPDUInfo_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_bchConfigPDUInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [2]");
	L1_FAPI_bchConfigPDUInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_bchConfigPDUInfo_st_padding_item, ett_L1_FAPI_bchConfigPDUInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_bchConfigPDUInfo_st_padding_tree, hf_L1_FAPI_bchConfigPDUInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_bchConfigPDUInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_mchConfigPDUInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_mchConfigPDUInfo_st_padding_tree;
	proto_item *L1_FAPI_mchConfigPDUInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 mchPduLen = 0;
	guint16 pduIndex = 0;
	guint16 rnti = 0;
	guint8 resAllocationType = 0;
	guint8 modulationType = 0;
	guint32 rbCoding = 0;
	guint16 txPower = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_mchConfigPDUInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_mchConfigPDUInfo_st);
	mchPduLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_mchPduLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pduIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_pduIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	PDUIndex = pduIndex;
		mac_info [sfsfn][PDUIndex].radioType	= g_radio_type;
		mac_info [sfsfn][PDUIndex].direction	= DIRECTION_DOWNLINK;
//		mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
	rnti = fapi_get_16(tvb, offset + offset_counter);

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	modulationType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_modulationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_mchConfigPDUInfo_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_mchConfigPDUInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_mchConfigPDUInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_mchConfigPDUInfo_st_padding_item, ett_L1_FAPI_mchConfigPDUInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_mchConfigPDUInfo_st_padding_tree, hf_L1_FAPI_mchConfigPDUInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_mchConfigPDUInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_beamFormingVectorInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 subBandIndex = 0;
	guint8 numOfAntenna = 0;
	guint16 bfValue_per_antenna = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_beamFormingVectorInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_beamFormingVectorInfo_st);
	subBandIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_beamFormingVectorInfo_st_subBandIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfAntenna = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_beamFormingVectorInfo_st_numOfAntenna, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
		for(loop_counter = 0; loop_counter < numOfAntenna; loop_counter++ ){
		bfValue_per_antenna = fapi_get_16(tvb, offset + offset_counter);
		local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_beamFormingVectorInfo_st_bfValue_per_antenna, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
		offset_counter += 2;
		}
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dlSCHConfigPDUInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 dlschPduLen = 0;
	guint16 pduIndex = 0;
	guint16 rnti = 0;
	guint8 resAllocationType = 0;
	guint8 vRBassignmentFlag = 0;
	guint32 rbCoding = 0;
	guint8 mcs = 0;
	guint8 redundancyVersion = 0;
	guint8 transportBlocks = 0;
	guint8 tbToCodeWordSwapFlag = 0;
	guint8 transmissionScheme = 0;
	guint8 numOfLayers = 0;
	guint8 numOfSubBand = 0;
	guint8 ueCatagoryCapacity = 0;
	guint8 pA = 0;
	guint8 deltaPowerOffsetAIndex = 0;
	guint8 nGap = 0;
	guint8 nPRB = 0;
	guint16 numRbPerSubBand = 0;
	guint16 numbfVector = 0;
	guint8 subBandInfo = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlSCHConfigPDUInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlSCHConfigPDUInfo_st);
	dlschPduLen = fapi_get_16(tvb, offset + offset_counter);
	/* Save DL SCH PDU Length */
	//mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_block_length	= dlschPduLen;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_dlschPduLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pduIndex = fapi_get_16(tvb, offset + offset_counter);
	PDUIndex = pduIndex;
		mac_info [sfsfn][PDUIndex].radioType	= g_radio_type;
		mac_info [sfsfn][PDUIndex].direction	= DIRECTION_DOWNLINK;
//		mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_block_length	= dlschPduLen - 12;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_pduIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	//printf("\n\n\n\ntest rnti value = %d \n\n\n\n",rnti);
	mac_info [sfsfn][PDUIndex].rnti = rnti;
//	mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
	mac_info [sfsfn][PDUIndex].isPredefinedData		= FALSE;
       	if((mac_info [sfsfn][PDUIndex].rnti >= 0x01 && mac_info [sfsfn][PDUIndex].rnti <= 0x3c) && mac_info [sfsfn][PDUIndex].rnti != 0x33)
	{
	
	         mac_info[sfsfn][PDUIndex].rntiType = RA_RNTI;

	}
	    if(mac_info [sfsfn][PDUIndex].rnti == 0xffff)
	    {
    	   	 mac_info [sfsfn][PDUIndex].rntiType = SI_RNTI;
	    }
	    if((mac_info [sfsfn][PDUIndex].rnti == 0x33)||(mac_info [sfsfn][PDUIndex].rnti == 0x34))
	    {
	        mac_info [sfsfn][PDUIndex].rntiType = C_RNTI;
	    }
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	vRBassignmentFlag = tvb_get_guint8(tvb, offset + offset_counter);
        if(GLOBE_FAPI_DL_DCI_FORMAT_1 == 1 || GLOBE_FAPI_DL_DCI_FORMAT_1 == 2 || GLOBE_FAPI_DL_DCI_FORMAT_1 ==4)
         local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
   
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	mcs = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_mcs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_redundancyVersion, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	transportBlocks = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_transportBlocks, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tbToCodeWordSwapFlag = tvb_get_guint8(tvb, offset + offset_counter);
        if(GLOBE_FAPI_DL_DCI_FORMAT_1 == 5 || GLOBE_FAPI_DL_DCI_FORMAT_1 == 6)
         local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	transmissionScheme = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfLayers = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfLayers, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(transmissionScheme == 3 || transmissionScheme == 4 || transmissionScheme == 5)
        {
	 numOfSubBand = tvb_get_guint8(tvb, offset + offset_counter);
	 local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfSubBand, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        }
        offset_counter += 1;
	ueCatagoryCapacity = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_ueCatagoryCapacity, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pA = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_pA, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaPowerOffsetAIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_deltaPowerOffsetAIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nGap = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_nGap, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nPRB = tvb_get_guint8(tvb, offset + offset_counter);

        if(GLOBE_FAPI_DL_DCI_FORMAT_1 == 1) 
	 local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_nPRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numRbPerSubBand = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_numRbPerSubBand, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	numbfVector = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_numbfVector, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
		if (0 != numOfSubBand)
		{
			local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlSCHConfigPDUInfo_st_subBandInfo, tvb, offset + offset_counter, numOfSubBand, IS_LITTLE_ENDIAN);
			offset_counter += numOfSubBand;
		}
		for(loop_counter = 0; loop_counter < numbfVector; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_beamFormingVectorInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

//		offset_counter = dlschPduLen;
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_pchPduConfigInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pchPduLen = 0;
	guint16 pduIndex = 0;
	guint16 pRNTI = 0;
	guint8 resAllocationType = 0;
	guint8 vRBassignmentFlag = 0;
	guint32 rbCoding = 0;
	guint8 mcs = 0;
	guint8 redundancyVersion = 0;
	guint8 numOftransportBlocks = 0;
	guint8 tbToCodeWordSwapFlag = 0;
	guint8 transmissionScheme = 0;
	guint8 numOfLayers = 0;
	guint8 codeBookIndex = 0;
	guint8 ueCatagoryCapacity = 0;
	guint8 pA = 0;
	guint8 nPRB = 0;
	guint16 txPower = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_pchPduConfigInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_pchPduConfigInfo_st);
	pchPduLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_pchPduLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pduIndex = fapi_get_16(tvb, offset + offset_counter);
	PDUIndex = pduIndex;
		mac_info [sfsfn][PDUIndex].radioType	= g_radio_type;
		mac_info [sfsfn][PDUIndex].direction	= DIRECTION_DOWNLINK;
//		mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_pduIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pRNTI = fapi_get_16(tvb, offset + offset_counter);
     if(pRNTI == 0xfffe)
             {
                         mac_info [sfsfn][PDUIndex].rntiType = P_RNTI;
             }

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_pRNTI, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	resAllocationType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_resAllocationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	vRBassignmentFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbCoding = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_rbCoding, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	mcs = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_mcs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_redundancyVersion, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOftransportBlocks = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_numOftransportBlocks, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tbToCodeWordSwapFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	transmissionScheme = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_transmissionScheme, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfLayers = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_numOfLayers, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	codeBookIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_codeBookIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ueCatagoryCapacity = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_ueCatagoryCapacity, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pA = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_pA, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nPRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_nPRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_pchPduConfigInfo_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dlConfigPDUInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dlConfigPDUInfo_st_padding_tree;
	proto_item *L1_FAPI_dlConfigPDUInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint remaining_length = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 pduType = 0;
	guint8 pduSize = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	guint8 vishal = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlConfigPDUInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlConfigPDUInfo_st);
	pduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigPDUInfo_st_pduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pduSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigPDUInfo_st_pduSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_dlConfigPDUInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,2, "Padding array [2]");
	L1_FAPI_dlConfigPDUInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_dlConfigPDUInfo_st_padding_item, ett_L1_FAPI_dlConfigPDUInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dlConfigPDUInfo_st_padding_tree, hf_L1_FAPI_dlConfigPDUInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
    		}
        	if (0 == pduType)
        	{
			dissect_L1_FAPI_dciDLPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
			offset_counter += pduSize - 4;
        	}
	        else if(1 == pduType )
       	 	{
			dissect_L1_FAPI_bchConfigPDUInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
			
			offset_counter += pduSize - 4;
#if 0
/**************** TEST 25 NOV STARTS ****************************/
			remaining_length = tvb_length_remaining(tvb, offset + offset_counter);
			if(remaining_length == 0)
			{
				
				mac_info[sfsfn][PDUIndex].rntiType = NO_RNTI;
			}
/**************** TEST 25 NOV ENDS *****************************/
#endif
        	}
	        else if (2 == pduType)
       		{
//		        offset_counter += 2;
			dissect_L1_FAPI_mchConfigPDUInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
			offset_counter += pduSize - 4;
        	}
	        else if (3 == pduType)
        	{
			dissect_L1_FAPI_dlSCHConfigPDUInfo_st(tvb, pinfo, subtree, offset + offset_counter,-1 , &local_ptr_to_currently_added_item);
			offset_counter += pduSize - 4;

#if 0
/* test */
	vishal = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigPDUInfo_st_vishal, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
#endif
        	}
	        else if (4 == pduType)
	        {
			dissect_L1_FAPI_pchPduConfigInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item); 
			offset_counter += pduSize - 4;
	        }

		
#if 0        
		L1_FAPI_dlConfigPDUInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_dlConfigPDUInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_dlConfigPDUInfo_st_padding_item, ett_L1_FAPI_dlConfigPDUInfo_st_padding);
		temp_start_offset_holder = offset_counter;
	for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
		local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dlConfigPDUInfo_st_padding_tree, hf_L1_FAPI_dlConfigPDUInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
		offset_counter += 1;
    }
#endif    
		if(NULL != local_ptr_to_currently_added_item){
			g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
			proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
		}
		proto_item_set_len(L1_FAPI_dlConfigPDUInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_mac (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len)
{
	tvbuff_t *         mac_tvb 		= tvb_new_subset(tvb, offset, len, len);
	dissector_handle_t lte_mac_handle 	= find_dissector("mac-lte");

	if (NULL == mac_tvb || NULL == lte_mac_handle)
	{
		return 0;
	}

	if (p_mac_lte_info == NULL) {
		return 0;
	}

	p_add_proto_data(pinfo->fd, proto_get_id_by_filter_name("mac-lte"), p_mac_lte_info);
	proto_tree_add_text(tree, tvb, offset, len, "MAC-LTE");

	/*
	 * dissect the embedded MAC message
	 */
	call_dissector(lte_mac_handle, mac_tvb, pinfo, tree);
        return 0;
}

int dissect_L1_FAPI_dlTLVInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint increamental_length = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 tag = 0;
	guint16 tagLen = 0;
	guint32 value = 0;
	guint32 padding = 0;
        guint remaining_length;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlTLVInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlTLVInfo_st);
	tag = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlTLVInfo_st_tag, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	tagLen = fapi_get_16(tvb, offset + offset_counter);
	/* Save Resource Block Length */
//	mac_info [sfsfn][PDUIndex].detailed_phy_info.dl_info.resource_block_length	= tagLen;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlTLVInfo_st_tagLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

//       padding = fapi_get_32(tvb, offset + offset_counter);
  //     local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlTLVInfo_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    //   offset_counter += 4; 

	/* init mac_lte_info */
	p_mac_lte_info = p_get_proto_data(((packet_info *)pinfo)->fd, proto_get_id_by_filter_name("mac-lte"));
	if (p_mac_lte_info == NULL) {
		p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
		memset ((unsigned char *)p_mac_lte_info, 0, sizeof (struct mac_lte_info));
	}
	/* Send PDU to MAC dissector */
	memcpy (p_mac_lte_info, &(mac_info[sfsfn][PDUIndex]), sizeof(struct mac_lte_info));
	if((tagLen % 4) == 0)
	{

		increamental_length = tagLen;

	}
	else
	{
                increamental_length = (tagLen + (4 - (tagLen % 4))) ;
		/*if(tagLen > 4)
		{
			increamental_length = (tagLen + (4 - (tagLen % 4))) ;
//			offset_counter += (tagLen + (4 - (tagLen % 4))) ;
		}
		else if (tagLen < 4)
		{
			increamental_length = (tagLen + (4 - (tagLen % 4)));
//			increamental_length = 4 + (tagLen + (4 - (tagLen % 4)));
//			offset_counter += 4 + (tagLen + (4 - (tagLen % 4))) ;
		}*/
	}

	dissect_mac (tvb, pinfo, subtree, offset + offset_counter, increamental_length);
	offset_counter += increamental_length;


/********* Commenting the value field, increamenting the offset after dissection of mac ****************
*
*        tagLen /= 4; 
		for(loop_counter = 0; loop_counter < tagLen; loop_counter++ ){
			value = fapi_get_32(tvb, offset + offset_counter);
			local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlTLVInfo_st_value, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
			offset_counter += 4;
		}
********************************-----23 November 2010 ---***********************************************/

		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_dlPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pduLen = 0;
	guint16 pduIndex = 0;
	guint32 numOfTLV = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlPduInfo_st);
	pduLen = fapi_get_16(tvb, offset + offset_counter);
	/* Save Length */
//	mac_info [sfsfn][PDUIndex].length	= pduLen;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlPduInfo_st_pduLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pduIndex = fapi_get_16(tvb, offset + offset_counter);
	PDUIndex = pduIndex;                    /** 25 NOV **/
	mac_info [sfsfn][PDUIndex].length	= pduLen -12;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlPduInfo_st_pduIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	numOfTLV = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlPduInfo_st_numOfTLV, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0; loop_counter < numOfTLV; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_dlTLVInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	}
	offset_counter = pduLen;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dlHiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 pduType = 0;
	guint8 hipduSize = 0;
	guint8 rbStart = 0;
	guint8 cyclicShift2_forDMRS = 0;
	guint8 hiValue = 0;
	guint8 iPHICH = 0;
	guint16 txPower = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlHiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlHiPduInfo_st);
	pduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_pduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	hipduSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_hipduSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbStart = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_rbStart, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cyclicShift2_forDMRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_cyclicShift2_forDMRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	hiValue = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_hiValue, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	iPHICH = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_iPHICH, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	txPower = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiPduInfo_st_txPower, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dlDCIPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dlDCIPduInfo_st_padding_tree;
	proto_item *L1_FAPI_dlDCIPduInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 pduType = 0;
	guint8 uldcipduSize = 0;
	guint8 ulDCIFormat = 0;
	guint8 cceIndex = 0;
	guint16 rnti = 0;
	guint8 aggLevel = 0;
	guint8 rbStart = 0;
	guint8 numOfRB = 0;
	guint8 mcs = 0;
	guint8 cyclicShift2_forDMRS = 0;
	guint8 freqEnabledFlag = 0;
	guint8 freqHoppingBits = 0;
	guint8 newDataIndication = 0;
	guint8 ueTxAntennaSelection = 0;
	guint8 tpc = 0;
	guint8 cqiRequest = 0;
	guint8 ulIndex = 0;
	guint8 dlAssignmentIndex = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	guint32 tpcBitMap = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlDCIPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlDCIPduInfo_st);
	pduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_pduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	uldcipduSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_uldcipduSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ulDCIFormat = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_ulDCIFormat, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cceIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_cceIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	aggLevel = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_aggLevel, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rbStart = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_rbStart, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_numOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	mcs = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_mcs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cyclicShift2_forDMRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_cyclicShift2_forDMRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqEnabledFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_freqEnabledFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqHoppingBits = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_freqHoppingBits, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_newDataIndication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ueTxAntennaSelection = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_ueTxAntennaSelection, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	tpc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_tpc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cqiRequest = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_cqiRequest, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ulIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_ulIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlAssignmentIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_dlAssignmentIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_dlDCIPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "Padding array [1]");
	L1_FAPI_dlDCIPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_dlDCIPduInfo_st_padding_item, ett_L1_FAPI_dlDCIPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dlDCIPduInfo_st_padding_tree, hf_L1_FAPI_dlDCIPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_dlDCIPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		tpcBitMap = fapi_get_32(tvb, offset + offset_counter);
		local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDCIPduInfo_st_tpcBitMap, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
		offset_counter += 4;
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
/*
int dissect_L1_FAPI_cqiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_cqiPduInfo_st_padding_tree;

	proto_item *L1_FAPI_cqiPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pucchIndex = 0;
	guint8 dlCqiPmiSize = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cqiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cqiPduInfo_st);
	pucchIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduInfo_st_pucchIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dlCqiPmiSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduInfo_st_dlCqiPmiSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_cqiPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "Padding array [1]");
	L1_FAPI_cqiPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_cqiPduInfo_st_padding_item, ett_L1_FAPI_cqiPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_cqiPduInfo_st_padding_tree, hf_L1_FAPI_cqiPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_cqiPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
			if(NULL != ptr_to_currently_added_item){
				*ptr_to_currently_added_item = item;
			}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_srPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pucchIndex = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srPduInfo_st);
	pucchIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srPduInfo_st_pucchIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_tddHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_tddHarqPduInfo_st_padding_tree;
	proto_item *L1_FAPI_tddHarqPduInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 harqSize = 0;
	guint8 acknackMode = 0;
	guint8 numOfPUCCHResource = 0;
	guint8 n_PUCCH_1_0 = 0;
	guint8 n_PUCCH_1_1 = 0;
	guint8 n_PUCCH_1_2 = 0;
	guint8 n_PUCCH_1_3 = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddHarqPduInfo_st);
	harqSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_harqSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	acknackMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_acknackMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfPUCCHResource = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_numOfPUCCHResource, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	n_PUCCH_1_0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	n_PUCCH_1_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	n_PUCCH_1_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	n_PUCCH_1_3 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_tddHarqPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "Padding array [1]");
	L1_FAPI_tddHarqPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_tddHarqPduInfo_st_padding_item, ett_L1_FAPI_tddHarqPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_tddHarqPduInfo_st_padding_tree, hf_L1_FAPI_tddHarqPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_tddHarqPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
int dissect_L1_FAPI_fddHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_fddHarqPduInfo_st_padding_tree;
	proto_item *L1_FAPI_fddHarqPduInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pucchIndex = 0;
	guint16 pucchIndex1 = 0;
	guint8 harqSize = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	//guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_fddHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_fddHarqPduInfo_st);
	pucchIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pucchIndex1 = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex1, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	harqSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduInfo_st_harqSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_fddHarqPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [3]");
	L1_FAPI_fddHarqPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_fddHarqPduInfo_st_padding_item, ett_L1_FAPI_fddHarqPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_fddHarqPduInfo_st_padding_tree, hf_L1_FAPI_fddHarqPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_fddHarqPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

/*
int dissect_L1_FAPI_ulSCHHarqInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_ulSCHHarqInfo_st_padding_tree;
	proto_item *L1_FAPI_ulSCHHarqInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 harqSize = 0;
	guint8 deltaOffsetHarq = 0;
	guint8 ackNackMode = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHHarqInfo_st, tvb,offset + offset_counter, -1, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHHarqInfo_st);
	harqSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_harqSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetHarq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_deltaOffsetHarq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ackNackMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_ackNackMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_ulSCHHarqInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [1]");
	L1_FAPI_ulSCHHarqInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_ulSCHHarqInfo_st_padding_item, ett_L1_FAPI_ulSCHHarqInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_ulSCHHarqInfo_st_padding_tree, hf_L1_FAPI_ulSCHHarqInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_ulSCHHarqInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

*/


/*
int dissect_L1_FAPI_srsPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_srsPduInfo_st_padding_tree;
	proto_item *L1_FAPI_srsPduInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 size = 0;
	guint16 rnti = 0;
	guint8 srsBandWidth = 0;
	guint8 freqDomainPosition = 0;
	guint8 srsHoppingBandWidth = 0;
	guint8 transmissionComb = 0;
	guint16 isrsSRSConfigIndex = 0;
	guint8 soundingRefCyclicShift = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srsPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srsPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	size = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_size, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	srsBandWidth = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_srsBandWidth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqDomainPosition = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_freqDomainPosition, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	srsHoppingBandWidth = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_srsHoppingBandWidth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	transmissionComb = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_transmissionComb, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	isrsSRSConfigIndex = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_isrsSRSConfigIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	soundingRefCyclicShift = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_soundingRefCyclicShift, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_srsPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [1]");
	L1_FAPI_srsPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_srsPduInfo_st_padding_item, ett_L1_FAPI_srsPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_srsPduInfo_st_padding_tree, hf_L1_FAPI_srsPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_srsPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/

/*
int dissect_L1_FAPI_cqiRiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_cqiRiPduInfo_st_padding_tree;

	proto_item *L1_FAPI_cqiRiPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 dlCqiPmiSizeRank_1 = 0;
	guint8 dlCqiPmiSizeRankGT_1 = 0;
	guint8 riSize = 0;
	guint8 deltaOffsetCQI = 0;
	guint8 deltaOffsetRI = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cqiRiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cqiRiPduInfo_st);
	dlCqiPmiSizeRank_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRank_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlCqiPmiSizeRankGT_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRankGT_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	riSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_riSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetCQI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetCQI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetRI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetRI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_cqiRiPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [3]");
	L1_FAPI_cqiRiPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_cqiRiPduInfo_st_padding_item, ett_L1_FAPI_cqiRiPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_cqiRiPduInfo_st_padding_tree, hf_L1_FAPI_cqiRiPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_cqiRiPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_uciSrPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciSrPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciSrPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*int dissect_L1_FAPI_uciCqiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_uciCqiPduInfo_st_padding_tree;
	proto_item *L1_FAPI_uciCqiPduInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_uciCqiPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_uciCqiPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_uciCqiPduInfo_st_padding_item, ett_L1_FAPI_uciCqiPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_uciCqiPduInfo_st_padding_tree, hf_L1_FAPI_uciCqiPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_uciCqiPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_uciHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_uciHarqPduInfo_st_padding_tree;

	proto_item *L1_FAPI_uciHarqPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciHarqPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_uciHarqPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_uciHarqPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_uciHarqPduInfo_st_padding_item, ett_L1_FAPI_uciHarqPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_uciHarqPduInfo_st_padding_tree, hf_L1_FAPI_uciHarqPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_uciHarqPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_uciSrHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciSrHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciSrHarqPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_uciCqiHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_uciCqiHarqPduInfo_st_padding_tree;

	proto_item *L1_FAPI_uciCqiHarqPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiHarqPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_uciCqiHarqPduInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "Padding array [2]");
	L1_FAPI_uciCqiHarqPduInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_uciCqiHarqPduInfo_st_padding_item, ett_L1_FAPI_uciCqiHarqPduInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_uciCqiHarqPduInfo_st_padding_tree, hf_L1_FAPI_uciCqiHarqPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_uciCqiHarqPduInfo_st_padding_item,offset_counter - temp_start_offset_holder);
		offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
int dissect_L1_FAPI_uciCqiSrPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiSrPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiSrPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiSrPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiSrPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_uciCqiSrHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiSrHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiSrHarqPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiSrHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiSrHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        
        if(duplex_mode == 0)
        {
         offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }
        else if(duplex_mode == 1)
        {
         offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }

//	offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

/*int dissect_L1_FAPI_ulSCHPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 size = 0;
	guint16 rnti = 0;
	guint8 rbStart = 0;
	guint8 numOfRB = 0;
	guint8 modulationType = 0;
	guint8 cyclicShift2forDMRS = 0;
	guint8 freqHoppingenabledFlag = 0;
	guint8 freqHoppingBits = 0;
	guint8 newDataIndication = 0;
	guint8 redundancyVersion = 0;
	guint8 harqProcessNumber = 0;
	guint8 ulTxMode = 0;
	guint8 currentTxNB = 0;
	guint8 nSRS = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHPduInfo_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
//    p_mac_lte_info->ueid = handle;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
    
	size = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_size, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rnti = fapi_get_16(tvb, offset + offset_counter);
   // p_mac_lte_info->rnti = rnti;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rbStart = tvb_get_guint8(tvb, offset + offset_counter);
//    p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start = rbStart;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_rbStart, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_numOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	modulationType = tvb_get_guint8(tvb, offset + offset_counter);
  //  p_mac_lte_info->detailed_phy_info.ul_info.modulation_type = modulationType;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_modulationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cyclicShift2forDMRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_cyclicShift2forDMRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqHoppingenabledFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingenabledFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqHoppingBits = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingBits, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_newDataIndication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_redundancyVersion, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNumber = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_harqProcessNumber, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ulTxMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_ulTxMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	currentTxNB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_currentTxNB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nSRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_nSRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_initialTxParam_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_initialTxParam_st_padding_tree;

	proto_item *L1_FAPI_initialTxParam_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 nSRSInitial = 0;
	guint8 initialNumOfRB = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_initialTxParam_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_initialTxParam_st);
	nSRSInitial = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_initialTxParam_st_nSRSInitial, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	initialNumOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_initialTxParam_st_initialNumOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_initialTxParam_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [2]");
	L1_FAPI_initialTxParam_st_padding_tree=proto_item_add_subtree(L1_FAPI_initialTxParam_st_padding_item, ett_L1_FAPI_initialTxParam_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_initialTxParam_st_padding_tree, hf_L1_FAPI_initialTxParam_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_initialTxParam_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/

/*
int dissect_L1_FAPI_ulSCHCqiHarqRIPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_cqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_ulSCHHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHHarqPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
#if 0
	offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
#endif
	offset_counter += dissect_L1_FAPI_ulSCHHarqInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_ulSCHCqiRiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHCqiRiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHCqiRiPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_cqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	
	offset_counter += dissect_L1_FAPI_ulSCHHarqInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
*/
/*old*/
int dissect_L1_FAPI_ulPDUConfigInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_ulPDUConfigInfo_st_padding_tree;
	proto_item *L1_FAPI_ulPDUConfigInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 ulConfigPduType = 0;
	guint8 ulConfigPduSize = 0;
	guint8 ulPduConfigInfo = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulPDUConfigInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulPDUConfigInfo_st);
	ulConfigPduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ulConfigPduSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_ulPDUConfigInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,2, "Padding array [1]");
	L1_FAPI_ulPDUConfigInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_ulPDUConfigInfo_st_padding_item, ett_L1_FAPI_ulPDUConfigInfo_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_ulPDUConfigInfo_st_padding_tree, hf_L1_FAPI_ulPDUConfigInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
	
	if (0 != 1)
	{
            if (0 == ulConfigPduType)
            {
                dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);    
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (1 == ulConfigPduType)
            {
                dissect_L1_FAPI_ulSCHCqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            } 
            else if (2 == ulConfigPduType)
            {
                dissect_L1_FAPI_ulSCHHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (3 == ulConfigPduType)
            {
                dissect_L1_FAPI_ulSCHCqiHarqRIPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (4 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciCqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (5 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciSrPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (6 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (7 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciSrHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (8 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciCqiHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (9 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciCqiSrPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (10 == ulConfigPduType)
            {
                dissect_L1_FAPI_uciCqiSrHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            }
            else if (11 == ulConfigPduType)
            {
                dissect_L1_FAPI_srsPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//		offset_counter += ulConfigPduSize - 2;
            } 
        }
//		ulConfigPduSize = ulConfigPduSize + (4 - (ulConfigPduSize % 4)) ;
		offset_counter = ulConfigPduSize ;
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_ulDataPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_ulDataPduIndication_st_padding_tree;

	proto_item *L1_FAPI_ulDataPduIndication_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint16 length = 0;
	guint16 dataOffset = 0;
	guint16 timingAdvance = 0;
	guint8 ulCqi = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;

	/* fill mac_lte_info with UL PHY info present */
//	p_mac_lte_info->detailed_phy_info.ul_info.present = TRUE;

	item = proto_tree_add_item(tree, hf_L1_FAPI_ulDataPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulDataPduIndication_st);
	handle = fapi_get_32(tvb, offset + offset_counter);
	/* fill mac_lte_info with ueid */
//	p_mac_lte_info->ueid = handle;

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = fapi_get_16(tvb, offset + offset_counter);
	/* fill mac_lte_info with rnti */
	p_mac_lte_info->rnti = rnti;

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	length = fapi_get_16(tvb, offset + offset_counter);
	/* fill mac_lte_info with resource_block_length */
//	p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length = length;

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_length, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    pdu_variable_length[pdu_index++] = length;
	offset_counter += 2;
	dataOffset = fapi_get_16(tvb, offset + offset_counter);
	/* fill mac_lte_info with resource_block_start */
//	p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start = dataOffset;

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_dataOffset, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	timingAdvance = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_timingAdvance, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	ulCqi = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulDataPduIndication_st_ulCqi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	L1_FAPI_ulDataPduIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "Padding array [3]");
	L1_FAPI_ulDataPduIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_ulDataPduIndication_st_padding_item, ett_L1_FAPI_ulDataPduIndication_st_padding);
	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_ulDataPduIndication_st_padding_tree, hf_L1_FAPI_ulDataPduIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_ulDataPduIndication_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_fddHarqPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 rnti = 0;
	guint8 harqTB1 = 0;
	guint8 harqTB2 = 0;

	item = proto_tree_add_item(tree, hf_L1_FAPI_fddHarqPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_fddHarqPduIndication_st);
	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	harqTB1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduIndication_st_harqTB1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	harqTB2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_fddHarqPduIndication_st_harqTB2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_tddBundlingHarqInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
        proto_tree *L1_FAPI_tddBundlingHarqInfo_st_padding_tree;
        proto_item *L1_FAPI_tddBundlingHarqInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 value0 = 0;
	guint8 value1 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddBundlingHarqInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddBundlingHarqInfo_st);

	value0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddBundlingHarqInfo_st_value0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	value1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddBundlingHarqInfo_st_value1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        /*change to add the padding[2] start*/
        L1_FAPI_tddBundlingHarqInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [2]");
        L1_FAPI_tddBundlingHarqInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_tddBundlingHarqInfo_st_padding_item, ett_L1_FAPI_tddBundlingHarqInfo_st_padding);
        temp_start_offset_holder = offset_counter;

                for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
                        local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_tddBundlingHarqInfo_st_padding_tree, hf_L1_FAPI_tddBundlingHarqInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
                        offset_counter += 1;

                        if(NULL != local_ptr_to_currently_added_item){
                                g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
                                proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
                        }
                }
                proto_item_set_len(L1_FAPI_tddBundlingHarqInfo_st_padding_item,offset_counter - temp_start_offset_holder);

        /*change to add the padding[2] start*/
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_tddMultiplexingHarqInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 value0 = 0;
	guint8 value1 = 0;
	guint8 value2 = 0;
	guint8 value3 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddMultiplexingHarqInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddMultiplexingHarqInfo_st);

	value0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddMultiplexingHarqInfo_st_value0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	value1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddMultiplexingHarqInfo_st_value1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	value2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddMultiplexingHarqInfo_st_value2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	value3 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddMultiplexingHarqInfo_st_value3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_tddSpcialBundlingHarqInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
        proto_tree *L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_tree;
        proto_item *L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 value_0 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddSpcialBundlingHarqInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddSpcialBundlingHarqInfo_st);

	value_0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_value_0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

        /*change to add the padding[2] start*/
       L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [3]");
       L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_tree=proto_item_add_subtree(L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_item, ett_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding);
        temp_start_offset_holder = offset_counter;

                for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
                        local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_tree, hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
                        offset_counter += 1;

                        if(NULL != local_ptr_to_currently_added_item){
                                g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
                                proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
                        }
                }
                proto_item_set_len(L1_FAPI_tddSpcialBundlingHarqInfo_st_padding_item,offset_counter - temp_start_offset_holder); 
       /*change to add the padding[2] start*/
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
/*
int dissect_L1_FAPI_tddHarqPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint8 mode = 0;
	guint8 numOfAckNack = 0;
	guint8 harqBuffer = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddHarqPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddHarqPduIndication_st);

	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numOfAckNack = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_numOfAckNack, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

		if (0 != 4)
		{
			local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
			offset_counter += 4;
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}
*/
int dissect_L1_FAPI_crcPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_crcPduIndication_st_padding_tree;

	proto_item *L1_FAPI_crcPduIndication_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint8 crcFlag = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_crcPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_crcPduIndication_st);

	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	crcFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcPduIndication_st_crcFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_crcPduIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [1]");
	L1_FAPI_crcPduIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_crcPduIndication_st_padding_item, ett_L1_FAPI_crcPduIndication_st_padding);
	temp_start_offset_holder = offset_counter;

		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_crcPduIndication_st_padding_tree, hf_L1_FAPI_crcPduIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_crcPduIndication_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_cqiPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_cqiPduIndication_st_padding_tree;

	proto_item *L1_FAPI_cqiPduIndication_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint16 length = 0;
	guint16 dataOffset = 0;
	guint16 timingAdvance = 0;
	guint8 ulCqi = 0;
	guint8 ri = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cqiPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cqiPduIndication_st);

	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	length = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_length, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    pdu_variable_length[pdu_index++] = length;
	offset_counter += 2;

	dataOffset = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_dataOffset, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	timingAdvance = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_timingAdvance, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	ulCqi = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_ulCqi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	ri = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduIndication_st_ri, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_cqiPduIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [2]");
	L1_FAPI_cqiPduIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_cqiPduIndication_st_padding_item, ett_L1_FAPI_cqiPduIndication_st_padding);
	temp_start_offset_holder = offset_counter;

		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_cqiPduIndication_st_padding_tree, hf_L1_FAPI_cqiPduIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;

			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_cqiPduIndication_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	
	return offset_counter;
}

int dissect_L1_FAPI_srPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_srPduIndication_st_padding_tree;

	proto_item *L1_FAPI_srPduIndication_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srPduIndication_st);

	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	L1_FAPI_srPduIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [2]");
	L1_FAPI_srPduIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_srPduIndication_st_padding_item, ett_L1_FAPI_srPduIndication_st_padding);
	temp_start_offset_holder = offset_counter;

		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_srPduIndication_st_padding_tree, hf_L1_FAPI_srPduIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;

			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}

		proto_item_set_len(L1_FAPI_srPduIndication_st_padding_item,offset_counter - temp_start_offset_holder);
		proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_rachPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

/*	proto_tree *L1_FAPI_rachPduIndication_st_padding_tree;

	proto_item *L1_FAPI_rachPduIndication_st_padding_item; */

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 rnti = 0;
	guint16 timingAdvance = 0;
	guint8 preamble = 0;
    guint remaining_length;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_rachPduIndication_st, tvb,offset + offset_counter, -1, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_rachPduIndication_st);

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	timingAdvance = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachPduIndication_st_timingAdvance, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

     preamble = tvb_get_guint8(tvb, offset + offset_counter);
     local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachPduIndication_st_preamble, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
/*	L1_FAPI_rachPduIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [3]");
	L1_FAPI_rachPduIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_rachPduIndication_st_padding_item, ett_L1_FAPI_rachPduIndication_st_padding);

	temp_start_offset_holder = offset_counter;


		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_rachPduIndication_st_padding_tree, hf_L1_FAPI_rachPduIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}

		
	proto_item_set_len(L1_FAPI_rachPduIndication_st_padding_item,offset_counter - temp_start_offset_holder); */
	proto_item_set_len(item, offset_counter);
	
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_srsPduIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint16 dopplerEstimation = 0;
	guint16 timingAdvance = 0;
	guint8 numOfRB = 0;
	guint8 rbStart = 0;
	guint8 snr = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srsPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srsPduIndication_st);

	handle = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	dopplerEstimation = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_dopplerEstimation, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	timingAdvance = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_timingAdvance, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	numOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_numOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rbStart = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_rbStart, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	if (0 != numOfRB)
	{
		local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduIndication_st_snr, tvb, offset + offset_counter, numOfRB, IS_LITTLE_ENDIAN);
	if (1==numOfRB%4)
	{    
		offset_counter += (numOfRB+3);
    	}
	if (2==numOfRB%4)
	{    
		offset_counter += (numOfRB+2);
    	}
	if (3==numOfRB%4)
	{    
		offset_counter += (numOfRB+1);
	}
	if (0==numOfRB%4)
	{    
		offset_counter += numOfRB;
	}
	}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_errMsgBody1_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 recvdSfnSf = 0;
	guint16 expectedSfnSf = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_errMsgBody1_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_errMsgBody1_st);

	recvdSfnSf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody1_st_recvdSfnSf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	expectedSfnSf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody1_st_expectedSfnSf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_errMsgBody2_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_errMsgBody2_st_padding_tree;
	proto_item *L1_FAPI_errMsgBody2_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 subErrCode = 0;
	guint8 direction = 0;
	guint16 rnti = 0;
	guint8 pduType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_errMsgBody2_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_errMsgBody2_st);

	subErrCode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody2_st_subErrCode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	direction = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody2_st_direction, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rnti = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody2_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	pduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody2_st_pduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_errMsgBody2_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "padding array [1]");
	L1_FAPI_errMsgBody2_st_padding_tree=proto_item_add_subtree(L1_FAPI_errMsgBody2_st_padding_item, ett_L1_FAPI_errMsgBody2_st_padding);
	temp_start_offset_holder = offset_counter;

		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_errMsgBody2_st_padding_tree, hf_L1_FAPI_errMsgBody2_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_errMsgBody2_st_padding_item,offset_counter - temp_start_offset_holder);

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	
	return offset_counter;
}

int dissect_L1_FAPI_errMsgBody3_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 subErrCode = 0;
	guint8 phichLowestulRbIndex = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_errMsgBody3_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_errMsgBody3_st);

	subErrCode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody3_st_subErrCode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	phichLowestulRbIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody3_st_phichLowestulRbIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	proto_item_set_len(item, offset_counter);
	
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	
	return offset_counter;
}

int dissect_L1_FAPI_errMsgBody4_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 subErrCode = 0;
	guint8 pduIndex = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_errMsgBody4_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_errMsgBody4_st);

	subErrCode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody4_st_subErrCode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	pduIndex = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_errMsgBody4_st_pduIndex, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
		
	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
		
	return offset_counter;
}

int dissect_L1_FAPI_l1ApiMsg_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 msgId = 0;
	guint8 lenVendorSpecific = 0;
	guint16 msgLen = 0;
	guint8 msgBody = 0;
	guint8 vendorMsgBody = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_l1ApiMsg_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_l1ApiMsg_st);

	msgId = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_l1ApiMsg_st_msgId, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	lenVendorSpecific = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_l1ApiMsg_st_lenVendorSpecific, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	msgLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_l1ApiMsg_st_msgLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	if (0 != msgLen)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_l1ApiMsg_st_msgBody, tvb, offset + offset_counter, msgLen, IS_LITTLE_ENDIAN);
	offset_counter += msgLen;
	}

	if (0 != lenVendorSpecific)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_l1ApiMsg_st_vendorMsgBody, tvb, offset + offset_counter, lenVendorSpecific, IS_LITTLE_ENDIAN);
	offset_counter += lenVendorSpecific;
	}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_paramRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);

	item = proto_tree_add_item(tree, hf_L1_FAPI_paramRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_paramRequest_st);

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_paramResponse_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_paramResponse_st_padding_tree;
	proto_item *L1_FAPI_paramResponse_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 errCode = 0;
	guint8 numOfTlv = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_paramResponse_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_paramResponse_st);

	errCode = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponse_st_errCode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

       // errCode = tvb_get_guint8(tvb, offset + offset_counter);
        //local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponse_st_errCode, tvb, offset + offset_counter,1, IS_LITTLE_ENDIAN);
       // offset_counter += 1;

	numOfTlv = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_paramResponse_st_numOfTlv, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_paramResponse_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [3]");
	L1_FAPI_paramResponse_st_padding_tree=proto_item_add_subtree(L1_FAPI_paramResponse_st_padding_item, ett_L1_FAPI_paramResponse_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_paramResponse_st_padding_tree, hf_L1_FAPI_paramResponse_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
	
	proto_item_set_len(L1_FAPI_paramResponse_st_padding_item,offset_counter - temp_start_offset_holder);
		for(loop_counter = 0; loop_counter < numOfTlv; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_paramResponseTLV_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_phyStart_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_phyStart_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyStart_st);

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_phyStop_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_phyStop_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyStop_st);

	proto_item_set_len(item, offset_counter);

	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}

	return offset_counter;
}

int dissect_L1_FAPI_phyStopIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);

	item = proto_tree_add_item(tree, hf_L1_FAPI_phyStopIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyStopIndication_st);

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
		
	return offset_counter;
}

int dissect_L1_FAPI_phyCellConfigRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_phyCellConfigRequest_st_padding_tree;
	proto_item *L1_FAPI_phyCellConfigRequest_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 numOfTlv = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;

	item = proto_tree_add_item(tree, hf_L1_FAPI_phyCellConfigRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyCellConfigRequest_st);
	numOfTlv = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyCellConfigRequest_st_numOfTlv, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_phyCellConfigRequest_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [3]");
	L1_FAPI_phyCellConfigRequest_st_padding_tree=proto_item_add_subtree(L1_FAPI_phyCellConfigRequest_st_padding_item, ett_L1_FAPI_phyCellConfigRequest_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_phyCellConfigRequest_st_padding_tree, hf_L1_FAPI_phyCellConfigRequest_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}

	proto_item_set_len(L1_FAPI_phyCellConfigRequest_st_padding_item,offset_counter - temp_start_offset_holder);
		for(loop_counter = 0; loop_counter < numOfTlv; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_cellConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_phyCellConfigResp_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_phyCellConfigResp_st_padding_tree;
	proto_item *L1_FAPI_phyCellConfigResp_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 errorCode = 0;
	guint8 numOfInvalidOrunsupportedTLV = 0;
	guint8 numOfMissingTLV = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_phyCellConfigResp_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyCellConfigResp_st);

	errorCode = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyCellConfigResp_st_errorCode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	numOfInvalidOrunsupportedTLV = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyCellConfigResp_st_numOfInvalidOrunsupportedTLV, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numOfMissingTLV = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyCellConfigResp_st_numOfMissingTLV, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_phyCellConfigResp_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [2]");
	L1_FAPI_phyCellConfigResp_st_padding_tree=proto_item_add_subtree(L1_FAPI_phyCellConfigResp_st_padding_item, ett_L1_FAPI_phyCellConfigResp_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_phyCellConfigResp_st_padding_tree, hf_L1_FAPI_phyCellConfigResp_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		proto_item_set_len(L1_FAPI_phyCellConfigResp_st_padding_item,offset_counter - temp_start_offset_holder);

		for(loop_counter = 0; loop_counter < numOfInvalidOrunsupportedTLV; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_cellConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

		for(loop_counter = 0; loop_counter < numOfMissingTLV; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_cellConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	return offset_counter;
}

int dissect_L1_FAPI_ueConfigRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 numOfTlv = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ueConfigRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ueConfigRequest_st);

	numOfTlv = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ueConfigRequest_st_numOfTlv, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	for(loop_counter = 0; loop_counter < numOfTlv; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_ueConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_phyUeConfigResp_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_phyUeConfigResp_st_padding_tree;
	proto_item *L1_FAPI_phyUeConfigResp_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 errorCode = 0;
	guint8 numOfInvalidOrunsupportedTLV = 0;
	guint8 numOfMissingTLV = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_phyUeConfigResp_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyUeConfigResp_st);

	errorCode = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyUeConfigResp_st_errorCode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

	numOfInvalidOrunsupportedTLV = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyUeConfigResp_st_numOfInvalidOrunsupportedTLV, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numOfMissingTLV = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyUeConfigResp_st_numOfMissingTLV, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_phyUeConfigResp_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,-1, "padding array [2]");
	L1_FAPI_phyUeConfigResp_st_padding_tree=proto_item_add_subtree(L1_FAPI_phyUeConfigResp_st_padding_item, ett_L1_FAPI_phyUeConfigResp_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 2;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_phyUeConfigResp_st_padding_tree, hf_L1_FAPI_phyUeConfigResp_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}

	proto_item_set_len(L1_FAPI_phyUeConfigResp_st_padding_item,offset_counter - temp_start_offset_holder);
		for(loop_counter = 0; loop_counter < numOfInvalidOrunsupportedTLV; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_ueConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	for(loop_counter = 0; loop_counter < numOfMissingTLV; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_ueConfig_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);

		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_phyErrorIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_phyErrorIndication_st_padding_tree;

	proto_item *L1_FAPI_phyErrorIndication_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 msgId = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	guint32 errorCode = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_phyErrorIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_phyErrorIndication_st);

	msgId = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyErrorIndication_st_msgId, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_phyErrorIndication_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter,	-1, "padding array [3]");
	L1_FAPI_phyErrorIndication_st_padding_tree=proto_item_add_subtree(L1_FAPI_phyErrorIndication_st_padding_item, ett_L1_FAPI_phyErrorIndication_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 3;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_phyErrorIndication_st_padding_tree, hf_L1_FAPI_phyErrorIndication_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}

	proto_item_set_len(L1_FAPI_phyErrorIndication_st_padding_item,offset_counter - temp_start_offset_holder);

	errorCode = fapi_get_32(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_phyErrorIndication_st_errorCode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;

    if (3 == errorCode || 6 == errorCode)
    {    
	offset_counter += dissect_L1_FAPI_errMsgBody1_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if (4 == errorCode)
    {    
	offset_counter += dissect_L1_FAPI_errMsgBody2_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if (7 == errorCode)
    {    
	offset_counter += dissect_L1_FAPI_errMsgBody3_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if (8 == errorCode)
    {    
	offset_counter += dissect_L1_FAPI_errMsgBody4_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_subFrameIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;

	item = proto_tree_add_item(tree, hf_L1_FAPI_subFrameIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_subFrameIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_subFrameIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_subFrameIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_dlConfigRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_dlConfigRequest_st_padding_tree;
	proto_item *L1_FAPI_dlConfigRequest_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 length = 0;
	guint8 cfi = 0;
	guint8 numDCI = 0;
	guint16 numOfPDU = 0;
	guint16 txPowerForPCFICH = 0;
	guint8 numOfPDSCHRNTI = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlConfigRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlConfigRequest_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	/* Save sf-sfn */
	sfsfn = sf;

	for(PDUIndex = 0; PDUIndex < 10; PDUIndex++)
	{
		mac_info [sfsfn][PDUIndex].radioType	= g_radio_type;
		mac_info [sfsfn][PDUIndex].direction	= DIRECTION_DOWNLINK;
//		mac_info [sfsfn][PDUIndex].subframeNumber	= sf & 0x000f;
//		mac_info [sfsfn][PDUIndex].isPredefinedData		= FALSE;
	}


	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	length = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_length, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	cfi = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_cfi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numDCI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_numDCI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numOfPDU = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_numOfPDU, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

        txPowerForPCFICH = fapi_get_16(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_txPowerForPCFICH, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;

        numOfPDSCHRNTI = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_numOfPDSCHRNTI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;

//	txPowerForPCFICH = fapi_get_16(tvb, offset + offset_counter);
//	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlConfigRequest_st_txPowerForPCFICH, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
//	offset_counter += 2;


	L1_FAPI_dlConfigRequest_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [1]");
	L1_FAPI_dlConfigRequest_st_padding_tree=proto_item_add_subtree(L1_FAPI_dlConfigRequest_st_padding_item, ett_L1_FAPI_dlConfigRequest_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_dlConfigRequest_st_padding_tree, hf_L1_FAPI_dlConfigRequest_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		
	proto_item_set_len(L1_FAPI_dlConfigRequest_st_padding_item,offset_counter - temp_start_offset_holder);
		for(loop_counter = 0; loop_counter < numOfPDU; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_dlConfigPDUInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);

		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
        GLOBE_FAPI_DL_DCI_FORMAT_1 = -1;
	return offset_counter;
}
/*old*/
int dissect_L1_FAPI_ulConfigRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	proto_tree *L1_FAPI_ulConfigRequest_st_padding_tree;
	proto_item *L1_FAPI_ulConfigRequest_st_padding_item;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 ulConfigLen = 0;
	guint8 numOfPdu = 0;
	guint8 rachFreqResources = 0;
	guint8 srsPresent = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulConfigRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulConfigRequest_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter +=2;

	ulConfigLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_ulConfigLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	numOfPdu = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_numOfPdu, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	rachFreqResources = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_rachFreqResources, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	srsPresent = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_srsPresent, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	L1_FAPI_ulConfigRequest_st_padding_item=proto_tree_add_text(subtree, tvb, offset  + offset_counter, -1, "padding array [1]");
	L1_FAPI_ulConfigRequest_st_padding_tree=proto_item_add_subtree(L1_FAPI_ulConfigRequest_st_padding_item, ett_L1_FAPI_ulConfigRequest_st_padding);

	temp_start_offset_holder = offset_counter;
		for(loop_counter = 0; loop_counter < 1;loop_counter++ ){
			local_ptr_to_currently_added_item = proto_tree_add_item(L1_FAPI_ulConfigRequest_st_padding_tree, hf_L1_FAPI_ulConfigRequest_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
			offset_counter += 1;
			if(NULL != local_ptr_to_currently_added_item){
				g_snprintf( temporary_string_holder,MAX_TEMP_STRING_LEN, " [%d] ",loop_counter );
				proto_item_append_text(local_ptr_to_currently_added_item, temporary_string_holder);
			}
		}
		
	proto_item_set_len(L1_FAPI_ulConfigRequest_st_padding_item,offset_counter - temp_start_offset_holder);
		for(loop_counter = 0; loop_counter < numOfPdu; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_ulPDUConfigInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_dlHiDCIPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint8 numOfDCI = 0;
	guint8 numOfHI = 0;
	guint8 hidciPduInfo = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlHiDCIPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlHiDCIPduInfo_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiDCIPduInfo_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiDCIPduInfo_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;

	numOfDCI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiDCIPduInfo_st_numOfDCI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	numOfHI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlHiDCIPduInfo_st_numOfHI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	if (0 != (numOfHI+numOfDCI))
	{
	        for (loop_counter = 0; loop_counter < numOfHI; loop_counter++)
	        {
       		     offset_counter +=dissect_L1_FAPI_dlHiPduInfo_st(tvb, pinfo, subtree,offset + offset_counter, -1,&local_ptr_to_currently_added_item);
        	}

	        for (loop_counter = 0; loop_counter < numOfDCI; loop_counter++)
	        {
	            offset_counter +=dissect_L1_FAPI_dlDCIPduInfo_st(tvb, pinfo,subtree,offset + offset_counter,-1,&local_ptr_to_currently_added_item);
	        }    
	}

	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}

	return offset_counter;
}

int dissect_L1_FAPI_dlDataTxRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfPDU = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_dlDataTxRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_dlDataTxRequest_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	sfsfn = sf;
//	PDUIndex = 0;
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDataTxRequest_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDataTxRequest_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfPDU = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_dlDataTxRequest_st_numOfPDU, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	offset_counter += 2;
		for(loop_counter = 0; loop_counter < numOfPDU; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_dlPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);

		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_rxULSCHIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfPdu = 0;
	guint8 pduBuffer = 0;

	/* init mac_lte_info */

	p_mac_lte_info = p_get_proto_data(((packet_info *)pinfo)->fd, proto_get_id_by_filter_name("mac-lte"));

	if (p_mac_lte_info == NULL) {
		p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
		memset ((unsigned char *)p_mac_lte_info, 0, sizeof (struct mac_lte_info));
	}

	p_mac_lte_info->radioType = g_radio_type; /* Should be derived from FAPI */
	p_mac_lte_info->direction = DIRECTION_UPLINK;
	p_mac_lte_info->rntiType  = g_ul_rnti_type;

	item = proto_tree_add_item(tree, hf_L1_FAPI_rxULSCHIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_rxULSCHIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);

	/* fill mac_lte_info with sfn */
	p_mac_lte_info->subframeNumber = (sf & 0x000f);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxULSCHIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);

	/* fill mac_lte_info with sfn */
	p_mac_lte_info->isPredefinedData = FALSE;
	p_mac_lte_info->reTxCount = 0;
	p_mac_lte_info->crcStatusValid = FALSE;

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxULSCHIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfPdu = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxULSCHIndication_st_numOfPdu, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

        pdu_index = 0;
        	for(loop_counter = 0; loop_counter < 512; loop_counter++ )
        	{
   	     		pdu_variable_length[loop_counter] = 0;
		}    

		for(loop_counter = 0; loop_counter < numOfPdu; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_ulDataPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	    for (loop_counter = 0; loop_counter < pdu_index; loop_counter++)
	    {    
            	if (0 != pdu_variable_length[loop_counter])
	    	{
	            for (loop_counter = 0; loop_counter < pdu_index; loop_counter++)
        	    {    
		            local_ptr_to_currently_added_item = proto_tree_add_item(subtree,hf_L1_FAPI_rxULSCHIndication_st_pduBuffer, tvb, offset +offset_counter, pdu_variable_length[loop_counter], IS_LITTLE_ENDIAN);

			    /* fill mac_lte_info with sf */
			    p_mac_lte_info->length = pdu_variable_length[loop_counter];

			    dissect_mac (tvb, pinfo, subtree, offset +offset_counter, pdu_variable_length[loop_counter]);
		            offset_counter += pdu_variable_length[loop_counter];
	            }
	    	}
    	    }
    
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
/*
int dissect_L1_FAPI_harqIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfHarq = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_harqIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_harqIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfHarq = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_numOfHarq, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

		for(loop_counter = 0; loop_counter < numOfHarq; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_fddHarqPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}
*/
int dissect_L1_FAPI_crcIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfCrc = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_crcIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_crcIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfCrc = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_crcIndication_st_numOfCrc, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

		for(loop_counter = 0; loop_counter < numOfCrc; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_crcPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
	
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}
	
	return offset_counter;
}

int dissect_L1_FAPI_rxSRIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfSr = 0;
    guint remaining_length;
	item = proto_tree_add_item(tree, hf_L1_FAPI_rxSRIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_rxSRIndication_st);


//	p_mac_lte_info = p_get_proto_data(((packet_info *)pinfo)->fd, proto_get_id_by_filter_name("mac-lte"));

//	if (p_mac_lte_info == NULL) {
//		p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
//		memset ((unsigned char *)p_mac_lte_info, 0, sizeof (struct mac_lte_info));
//	}

//	p_mac_lte_info->radioType = g_radio_type; /* Should be derived from FAPI */
//  p_mac_lte_info->direction = DIRECTION_UPLINK;
//  p_mac_lte_info->rntiType  = C_RNTI;



	sf = fapi_get_16(tvb, offset + offset_counter);
	/* fill mac_lte_info with sfn */
//	p_mac_lte_info->subframeNumber = (sf & 0x000f);




	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxSRIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxSRIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfSr = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxSRIndication_st_numOfSr, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

//	            for (loop_counter = 0; loop_counter < numOfSr; loop_counter++)
  //    	        {    
    //             local_ptr_to_currently_added_item = proto_tree_add_item(subtree,hf_L1_FAPI_rxULSCHIndication_st_pduBuffer, tvb, offset +offset_counter, pdu_variable_length[loop_counter], IS_LITTLE_ENDIAN);

    //            remaining_length = tvb_length_remaining(tvb , offset + offset_counter);
			    /* fill mac_lte_info with sf */
//			    p_mac_lte_info->length = remaining_length;

//			    dissect_mac (tvb, pinfo, subtree, offset +offset_counter, remaining_length);
//		            offset_counter += remaining_length;
//	            }
//	    	}


		for(loop_counter = 0; loop_counter < numOfSr; loop_counter++ ){
            offset_counter += dissect_L1_FAPI_srPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }

     proto_item_set_len(item, offset_counter);

		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_rxCqiIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfCqi = 0;
	guint8 pduBuffer = 0;
	guint8 count = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_rxCqiIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_rxCqiIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxCqiIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxCqiIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfCqi = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rxCqiIndication_st_numOfCqi, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
        pdu_index = 0;

        	for(loop_counter = 0; loop_counter < 512; loop_counter++ ){
		        pdu_variable_length[loop_counter] = 0;
	        }    

		for(loop_counter = 0; loop_counter < numOfCqi; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_cqiPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	    for (loop_counter = 0; loop_counter < pdu_index; loop_counter++)
	    {    
	        if (0 != pdu_variable_length[loop_counter])
	        {
			local_ptr_to_currently_added_item = proto_tree_add_item(subtree,hf_L1_FAPI_rxCqiIndication_st_pduBuffer,tvb, offset +offset_counter, pdu_variable_length[loop_counter] , IS_LITTLE_ENDIAN);
                        if(pdu_variable_length[loop_counter] < 8)
                        {
			    count = 1;
                            //offset_counter += pdu_variable_length[loop_counter];
                            offset_counter += count;
                            
                        }
                        
	        }
	    }

	proto_item_set_len(item, offset_counter);

		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_rachIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50; 
    char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
    guint remaining_length = 0;
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfPreamble = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_rachIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_rachIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	/* fill mac_lte_info with sfn */
//	p_mac_lte_info->subframeNumber = (sf & 0x000f);

	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter +=2;


	numOfPreamble = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_rachIndication_st_numOfPreamble, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

		for(loop_counter = 0; loop_counter < numOfPreamble; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_rachPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_FAPI_srsIndication_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfUe = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srsIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srsIndication_st);

	sf = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	sfn = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter +=2;

	numOfUe = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsIndication_st_numOfUe, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

		for(loop_counter = 0; loop_counter < numOfUe; loop_counter++ ){
			offset_counter += dissect_L1_FAPI_srsPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
		}

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

int dissect_L1_lte_phy_header (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;
	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 msgId = 0;
	guint8 lenVendorSpecific = 0;
	guint16 msgLen = 0;
	item = proto_tree_add_item(tree, hf_L1_lte_phy_header, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_lte_phy_header);

	msgId = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_lte_phy_header_msgId, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	lenVendorSpecific = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_lte_phy_header_lenVendorSpecific, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;

	msgLen = fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_lte_phy_header_msgLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;

	proto_item_set_len(item, offset_counter);
		if(NULL != ptr_to_currently_added_item){
			*ptr_to_currently_added_item = item;
		}

	return offset_counter;
}

 int dissect_L1_FAPI_harqIndication_st(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 1;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sf = 0;
	guint16 sfn = 0;
	guint16 numOfHarq = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_harqIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_harqIndication_st);
        sf = fapi_get_16(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_sf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

        sfn = fapi_get_16(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_sfn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);

	offset_counter += 2;
	//numOfHarq = phy_get_16(tvb, offset + offset_counter);
	numOfHarq  =fapi_get_16(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_harqIndication_st_numOfHarq, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	
           for(loop_counter = 0; loop_counter < numOfHarq ; loop_counter++  )
         {
           if(duplex_mode == 0)
           {
               offset_counter += dissect_L1_FAPI_tddHarqPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
           }
           else  // to handle fdd and hd-fdd         
	   {
            offset_counter += dissect_L1_FAPI_fddHarqPduIndication_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);        
           }
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

 int dissect_L1_FAPI_tddHarqPduIndication_st(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;

	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint8 mode = 0;
	guint8 numOfAckNack = 0;
	guint8 harqBuffer = 0;
        guint8 value_0;
        guint8 value_1;
        guint8 value_2;
        guint8 value_3;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddHarqPduIndication_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddHarqPduIndication_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfAckNack = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_numOfAckNack, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != numOfAckNack)
	{
	//local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, numOfAckNack, IS_LITTLE_ENDIAN);
//	offset_counter += numOfAckNack;
	
         if(mode == 0)
         {
          value_0 = tvb_get_guint8(tvb, offset + offset_counter);
          local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN); 
          offset_counter += 1;  
          value_1 = tvb_get_guint8(tvb, offset + offset_counter);
          local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
          offset_counter += 1;
         }
         if(mode == 1)
         { 
           value_0 = tvb_get_guint8(tvb, offset + offset_counter);
           local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
           offset_counter += 1;
           value_1 = tvb_get_guint8(tvb, offset + offset_counter);
           local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
           offset_counter += 1;
           value_2 = tvb_get_guint8(tvb, offset + offset_counter);
           local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
           offset_counter += 1;
           value_3 = tvb_get_guint8(tvb, offset + offset_counter);
           local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
           offset_counter += 1;
         }
         if(mode == 2)
         {
          value_0 = tvb_get_guint8(tvb, offset + offset_counter);
          local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
          offset_counter += 1;
         }

        }
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
/*
int dissect_L1_FAPI_ulConfigRequest_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 sfnsf = 0;
	guint16 ulConfigLen = 0;
	guint8 numOfPdu = 0;
	guint8 rachFreqResources = 0;
	guint8 srsPresent = 0;
	guint8 padding = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulConfigRequest_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulConfigRequest_st);
	sfnsf = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_sfnsf, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	ulConfigLen = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_ulConfigLen, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	numOfPdu = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_numOfPdu, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	rachFreqResources = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_rachFreqResources, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	srsPresent = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_srsPresent, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 1)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulConfigRequest_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	//if(numOfPdu > )
	//	numOfPdu = ;
	for(loop_counter = 0; loop_counter < numOfPdu; loop_counter++ ){
			FAPI_ulPDUConfigInfo_st_count= loop_counter;
			offset_counter += dissect_L1_FAPI_ulPDUConfigInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
*/
/*
int dissect_L1_FAPI_ulPDUConfigInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_ulPDUConfigInfo_st_padding_tree;

	proto_item *L1_FAPI_ulPDUConfigInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 ulConfigPduType = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
	guint loop_counter4 = 0;
	guint8 ulPduConfigInfo = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulPDUConfigInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulPDUConfigInfo_st);
	ulConfigPduType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulPDUConfigInfo_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulPDUConfigInfo_st_ulPduConfigInfo, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
        

             if (0 == ulConfigPduType)
             {
                 dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item); 
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (1 == ulConfigPduType)
             {
                 dissect_L1_FAPI_ulSCHCqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (2 == ulConfigPduType)
             {
                 dissect_L1_FAPI_ulSCHHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (3 == ulConfigPduType)
             {
                 dissect_L1_FAPI_ulSCHCqiHarqRIPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (4 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciCqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (5 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciSrPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (6 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item); //              offset_counter += ulConfigPduSize - 2;
             }
             else if (7 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciSrHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (8 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciCqiHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (9 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciCqiSrPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (10 == ulConfigPduType)
             {
                 dissect_L1_FAPI_uciCqiSrHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }
             else if (11 == ulConfigPduType)
             {
                 dissect_L1_FAPI_srsPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
 //              offset_counter += ulConfigPduSize - 2;
             }

	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
*/
int dissect_L1_FAPI_ulSCHPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 size = 0;
	guint16 rnti = 0;
	guint8 rbStart = 0;
	guint8 numOfRB = 0;
	guint8 modulationType = 0;
	guint8 cyclicShift2forDMRS = 0;
	guint8 freqHoppingenabledFlag = 0;
	guint8 freqHoppingBits = 0;
	guint8 newDataIndication = 0;
	guint8 redundancyVersion = 0;
	guint8 harqProcessNumber = 0;
	guint8 ulTxMode = 0;
	guint8 currentTxNB = 0;
	guint8 nSRS = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	size = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_size, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rbStart = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_rbStart, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_numOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	modulationType = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_modulationType, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	cyclicShift2forDMRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_cyclicShift2forDMRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqHoppingenabledFlag = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingenabledFlag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqHoppingBits = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingBits, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	newDataIndication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_newDataIndication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	redundancyVersion = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_redundancyVersion, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	harqProcessNumber = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_harqProcessNumber, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ulTxMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_ulTxMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	currentTxNB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_currentTxNB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	nSRS = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHPduInfo_st_nSRS, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_ulSCHCqiRiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHCqiRiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHCqiRiPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_cqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_cqiRiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_cqiRiPduInfo_st_padding_tree;

	proto_item *L1_FAPI_cqiRiPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 dlCqiPmiSizeRank_1 = 0;
	guint8 dlCqiPmiSizeRankGT_1 = 0;
	guint8 riSize = 0;
	guint8 deltaOffsetCQI = 0;
	guint8 deltaOffsetRI = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cqiRiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cqiRiPduInfo_st);
	dlCqiPmiSizeRank_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRank_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dlCqiPmiSizeRankGT_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRankGT_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	riSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_riSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetCQI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetCQI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetRI = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetRI, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 3)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiRiPduInfo_st_padding, tvb, offset + offset_counter, 3, IS_LITTLE_ENDIAN);
	offset_counter += 3;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}



int dissect_L1_FAPI_initialTxParam_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_initialTxParam_st_padding_tree;

	proto_item *L1_FAPI_initialTxParam_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 nSRSInitial = 0;
	guint8 initialNumOfRB = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_initialTxParam_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_initialTxParam_st);
	nSRSInitial = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_initialTxParam_st_nSRSInitial, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	initialNumOfRB = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_initialTxParam_st_initialNumOfRB, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_initialTxParam_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_ulSCHHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHHarqPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_ulSCHHarqInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_ulSCHHarqInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_ulSCHHarqInfo_st_padding_tree;

	proto_item *L1_FAPI_ulSCHHarqInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 harqSize = 0;
	guint8 deltaOffsetHarq = 0;
	guint8 ackNackMode = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHHarqInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHHarqInfo_st);
	harqSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_harqSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deltaOffsetHarq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_deltaOffsetHarq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ackNackMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_ackNackMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 1)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_ulSCHHarqInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_ulSCHCqiHarqRIPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st);
	offset_counter += dissect_L1_FAPI_ulSCHPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_cqiRiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_ulSCHHarqInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_initialTxParam_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_uciCqiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_uciCqiPduInfo_st_padding_tree;

	proto_item *L1_FAPI_uciCqiPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiPduInfo_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_uciSrHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciSrHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciSrHarqPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        
        if(duplex_mode == 0)
        {
         offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }
        else if(duplex_mode == 1)
        {
         offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }

//	offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_uciSrPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciSrPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciSrPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_uciHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_uciHarqPduInfo_st_padding_tree;

	proto_item *L1_FAPI_uciHarqPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciHarqPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciHarqPduInfo_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
        if(duplex_mode == 0)
        {
         offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }
        else if(duplex_mode == 1)
        {
         offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }

//	offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

/*
int dissect_L1_FAPI_uciSrHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciSrHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciSrHarqPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciSrHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_counter += dissect_L1_FAPI_srPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
*/
int dissect_L1_FAPI_uciCqiHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_uciCqiHarqPduInfo_st_padding_tree;

	proto_item *L1_FAPI_uciCqiHarqPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 rnti = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_uciCqiHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_uciCqiHarqPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiHarqPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_L1_FAPI_cqiPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiHarqPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if (0 != 2)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_uciCqiHarqPduInfo_st_padding, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}

        if(duplex_mode == 0)
        {
         offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }
        else if(duplex_mode == 1)
        {
         offset_counter += dissect_L1_FAPI_fddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }

//	offset_counter += dissect_L1_FAPI_tddHarqPduInfo_st(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_cqiPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_cqiPduInfo_st_padding_tree;

	proto_item *L1_FAPI_cqiPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pucchIndex = 0;
	guint8 dlCqiPmiSize = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_cqiPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_cqiPduInfo_st);
	pucchIndex = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduInfo_st_pucchIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dlCqiPmiSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduInfo_st_dlCqiPmiSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 1)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_cqiPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_srPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint16 pucchIndex = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srPduInfo_st);
	pucchIndex = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srPduInfo_st_pucchIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_tddHarqPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_tddHarqPduInfo_st_padding_tree;

	proto_item *L1_FAPI_tddHarqPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 harqSize = 0;
	guint8 acknackMode = 0;
	guint8 numOfPUCCHResource = 0;
	guint8 n_PUCCH_1_0 = 0;
	guint8 n_PUCCH_1_1 = 0;
	guint8 n_PUCCH_1_2 = 0;
	guint8 n_PUCCH_1_3 = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_tddHarqPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_tddHarqPduInfo_st);
	harqSize = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_harqSize, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	acknackMode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_acknackMode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	numOfPUCCHResource = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_numOfPUCCHResource, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	n_PUCCH_1_0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	n_PUCCH_1_1 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	n_PUCCH_1_2 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_2, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	n_PUCCH_1_3 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if (0 != 1)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_tddHarqPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_L1_FAPI_srsPduInfo_st (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	proto_tree *L1_FAPI_srsPduInfo_st_padding_tree;

	proto_item *L1_FAPI_srsPduInfo_st_padding_item;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint32 handle = 0;
	guint16 size = 0;
	guint16 rnti = 0;
	guint8 srsBandWidth = 0;
	guint8 freqDomainPosition = 0;
	guint8 srsHoppingBandWidth = 0;
	guint8 transmissionComb = 0;
	guint16 isrsSRSConfigIndex = 0;
	guint8 soundingRefCyclicShift = 0;
	guint loop_counter0 = 0;
	guint loop_counter1 = 0;
	guint loop_counter2 = 0;
	guint loop_counter3 = 0;
//	guint loop_counter4 = 0;
	item = proto_tree_add_item(tree, hf_L1_FAPI_srsPduInfo_st, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_L1_FAPI_srsPduInfo_st);
	handle = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_handle, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	size = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_size, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	rnti = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_rnti, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	srsBandWidth = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_srsBandWidth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	freqDomainPosition = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_freqDomainPosition, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	srsHoppingBandWidth = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_srsHoppingBandWidth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	transmissionComb = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_transmissionComb, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	isrsSRSConfigIndex = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_isrsSRSConfigIndex, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	soundingRefCyclicShift = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_soundingRefCyclicShift, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if (0 != 1)
	{
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_L1_FAPI_srsPduInfo_st_padding, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
