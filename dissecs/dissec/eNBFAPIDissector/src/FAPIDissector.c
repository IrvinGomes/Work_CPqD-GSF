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

#define ARRSIZE(array_name) (sizeof(array_name) / sizeof(array_name[0]))


void dissect_fapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static dissector_handle_t fapi_handle;
static int proto_fapi =-1;

/*
 *  Why there are so many ports are added into the FAPI Dissector ?
 **/

/*
 * Do we really need MAC , RLC, PDCP, RRC, RRM & OAM module Port of eNB Side ?
 **/

/*
 * static int global_port0 =1414; 
 */                                /* UT SETUP */

//static int global_port0 =10145;    /* MAC */    
//static int global_port1 =10245;    /* RLC */   /*UE MAC*/
//static int global_port2 =19256;    /* PDCP */  /*UE RRC*/
//static int global_port3 =3211;     /* RRC */
//static int global_port4 =10257;     /* RRM */  /*UE OAM*/
//static int global_port5 =10157;    /* OAM */
//static int global_port6 =34568;    /* PHY MODULE PORT */
static int global_port7 =8888;     /* PHY Rx PORT */
static int global_port8 =9999;     /* PHY Tx PORT */
static int global_port9 =9876;     /* Temp PORT */
static int global_port6 =9875;     /* Temp PORT */
static int global_port5 =19876;     /* Temp PORT */

static guint8 TypeOfTag=0; 

/* **Moved Start** */ 
int      g_radio_type        = 0;
int      g_ul_rnti_type      = 0;
int      IS_LITTLE_ENDIAN    = 1;
gint ett_L1 = -1;
gint ett_L1_payload = -1;
gint ett_L1_FAPI_ueConfig_st = -1;
gint ett_L1_FAPI_cellConfig_st = -1;
gint ett_L1_FAPI_paramResponseTLV_st = -1;
gint ett_L1_FAPI_dciFormat1_st = -1;
gint ett_L1_FAPI_dciFormat1_st_padding = -1;
gint ett_L1_FAPI_dciFormat1C_st_padding = -1;
gint ett_L1_FAPI_dciFormat1A_st = -1;
gint ett_L1_FAPI_dciFormat1A_st_padding = -1;
gint ett_L1_FAPI_dciFormat1B_st = -1;
gint ett_L1_FAPI_dciFormat1B_st_padding = -1;
gint ett_L1_FAPI_dciFormat1C_st = -1;
gint ett_L1_FAPI_dciFormat1D_st = -1;
gint ett_L1_FAPI_dciFormat1D_st_padding = -1;
gint ett_L1_FAPI_dciFormat2_st = -1;
gint ett_L1_FAPI_dciFormat2A_st = -1;
gint ett_L1_FAPI_dciDLPduInfo_st = -1;
gint ett_L1_FAPI_bchConfigPDUInfo_st = -1;
gint ett_L1_FAPI_bchConfigPDUInfo_st_padding = -1;
gint ett_L1_FAPI_mchConfigPDUInfo_st = -1;
gint ett_L1_FAPI_mchConfigPDUInfo_st_padding = -1;
gint ett_L1_FAPI_beamFormingVectorInfo_st = -1;
gint ett_L1_FAPI_dlSCHConfigPDUInfo_st = -1;
gint ett_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector = -1;
gint ett_L1_FAPI_pchPduConfigInfo_st = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_DCIPdu = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_BCHPdu = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_MCHPdu = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_PChPdu = -1;
gint ett_L1_FAPI_dlConfigPDUInfo_st_padding = -1;
gint ett_L1_FAPI_dlTLVInfo_st = -1;
gint ett_L1_FAPI_dlPduInfo_st = -1;
gint ett_L1_FAPI_dlPduInfo_st_dlTLVInfo = -1;
gint ett_L1_FAPI_dlHiPduInfo_st = -1;
gint ett_L1_FAPI_dlDCIPduInfo_st = -1;
gint ett_L1_FAPI_dlDCIPduInfo_st_padding = -1;
gint ett_L1_FAPI_cqiPduInfo_st = -1;
gint ett_L1_FAPI_cqiPduInfo_st_padding = -1;
gint ett_L1_FAPI_srPduInfo_st = -1;
gint ett_L1_FAPI_tddHarqPduInfo_st = -1;
gint ett_L1_FAPI_tddHarqPduInfo_st_padding = -1;
gint ett_L1_FAPI_fddHarqPduInfo_st = -1;
gint ett_L1_FAPI_fddHarqPduInfo_st_padding = -1;
gint ett_L1_FAPI_ulSCHHarqInfo_st_padding = -1;
gint ett_L1_FAPI_ulPDUConfigInfo_st_padding = -1;
gint ett_L1_FAPI_srsPduInfo_st = -1;
gint ett_L1_FAPI_srsPduInfo_st_padding = -1;
gint ett_L1_FAPI_cqiRiPduInfo_st = -1;
gint ett_L1_FAPI_cqiRiPduInfo_st_padding = -1;
gint ett_L1_FAPI_uciSrPduInfo_st = -1;
gint ett_L1_FAPI_uciSrPduInfo_st_srInfo = -1;
gint ett_L1_FAPI_uciCqiPduInfo_st = -1;
gint ett_L1_FAPI_uciCqiPduInfo_st_padding = -1;
gint ett_L1_FAPI_uciCqiPduInfo_st_cqiInfo = -1;
gint ett_L1_FAPI_uciHarqPduInfo_st = -1;
gint ett_L1_FAPI_uciHarqPduInfo_st_padding = -1;
gint ett_L1_FAPI_uciHarqPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_uciSrHarqPduInfo_st = -1;
gint ett_L1_FAPI_uciSrHarqPduInfo_st_srInfo = -1;
gint ett_L1_FAPI_uciSrHarqPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_uciCqiHarqPduInfo_st = -1;
gint ett_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo = -1;
gint ett_L1_FAPI_uciCqiHarqPduInfo_st_padding = -1;
gint ett_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_uciCqiSrPduInfo_st = -1;
gint ett_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo = -1;
gint ett_L1_FAPI_uciCqiSrPduInfo_st_srInfo = -1;
gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st = -1;
gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo = -1;
gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo = -1;
gint ett_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_ulSCHPduInfo_st = -1;
gint ett_L1_FAPI_initialTxParam_st = -1;
gint ett_L1_FAPI_initialTxParam_st_padding = -1;
gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st = -1;
gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo = -1;
gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo = -1;
gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo = -1;
gint ett_L1_FAPI_ulSCHHarqInfo_st = -1;
gint ett_L1_FAPI_ulSCHHarqPduInfo_st = -1;
gint ett_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo = -1;
gint ett_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo = -1;
gint ett_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo = -1;
gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st = -1;
gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo = -1;
gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo = -1;
gint ett_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo = -1;
gint ett_L1_FAPI_ulPDUConfigInfo_st = -1;
gint ett_L1_FAPI_ulDataPduIndication_st = -1;
gint ett_L1_FAPI_ulDataPduIndication_st_padding = -1;
gint ett_L1_FAPI_fddHarqPduIndication_st = -1;
gint ett_L1_FAPI_tddBundlingHarqInfo_st = -1;
gint ett_L1_FAPI_tddMultiplexingHarqInfo_st = -1;
gint ett_L1_FAPI_tddSpcialBundlingHarqInfo_st = -1;
//FAPI_tddHarqPduIndication_st_count = -1;
gint ett_L1_FAPI_tddHarqPduIndication_st = -1;
gint ett_L1_FAPI_crcPduIndication_st = -1;
gint ett_L1_FAPI_crcPduIndication_st_padding = -1;
gint ett_L1_FAPI_cqiPduIndication_st = -1;
gint ett_L1_FAPI_cqiPduIndication_st_padding = -1;
gint ett_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding = -1;
gint ett_L1_FAPI_tddBundlingHarqInfo_st_padding = -1;
gint ett_L1_FAPI_srPduIndication_st = -1;
gint ett_L1_FAPI_srPduIndication_st_padding = -1;
gint ett_L1_FAPI_rachPduIndication_st = -1;
gint ett_L1_FAPI_rachPduIndication_st_padding = -1;
gint ett_L1_FAPI_srsPduIndication_st = -1;
gint ett_L1_FAPI_errMsgBody1_st = -1;
gint ett_L1_FAPI_errMsgBody2_st = -1;
gint ett_L1_FAPI_errMsgBody2_st_padding = -1;
gint ett_L1_FAPI_errMsgBody3_st = -1;
gint ett_L1_FAPI_errMsgBody4_st = -1;
gint ett_L1_FAPI_l1ApiMsg_st = -1;
gint ett_L1_FAPI_paramRequest_st = -1;
gint ett_L1_FAPI_paramResponse_st = -1;
gint ett_L1_FAPI_paramResponse_st_padding = -1;
gint ett_L1_FAPI_paramResponse_st_tlvs = -1;
gint ett_L1_FAPI_phyStart_st = -1;
gint ett_L1_FAPI_phyStop_st = -1;
gint ett_L1_FAPI_phyStopIndication_st = -1;
gint ett_L1_FAPI_phyCellConfigRequest_st = -1;
gint ett_L1_FAPI_phyCellConfigRequest_st_padding = -1;
gint ett_L1_FAPI_phyCellConfigRequest_st_configtlvs = -1;
gint ett_L1_FAPI_phyCellConfigResp_st = -1;
gint ett_L1_FAPI_phyCellConfigResp_st_padding = -1;
gint ett_L1_FAPI_phyCellConfigResp_st_listOfTLV = -1;
gint ett_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv = -1;
gint ett_L1_FAPI_ueConfigRequest_st = -1;
gint ett_L1_FAPI_ueConfigRequest_st_tlvs = -1;
gint ett_L1_FAPI_phyUeConfigResp_st = -1;
gint ett_L1_FAPI_phyUeConfigResp_st_padding = -1;
gint ett_L1_FAPI_phyUeConfigResp_st_listOfTLV = -1;
gint ett_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv = -1;
gint ett_L1_FAPI_phyErrorIndication_st = -1;
gint ett_L1_FAPI_phyErrorIndication_st_padding = -1;
gint ett_L1_FAPI_phyErrorIndication_st_msgBody1 = -1;
gint ett_L1_FAPI_phyErrorIndication_st_msgBody2 = -1;
gint ett_L1_FAPI_phyErrorIndication_st_msgBody3 = -1;
gint ett_L1_FAPI_phyErrorIndication_st_msgBody4 = -1;
gint ett_L1_FAPI_subFrameIndication_st = -1;
gint ett_L1_FAPI_dlConfigRequest_st = -1;
gint ett_L1_FAPI_dlConfigRequest_st_padding = -1;
gint ett_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo = -1;
gint ett_L1_FAPI_ulConfigRequest_st = -1;
gint ett_L1_FAPI_ulConfigRequest_st_padding = -1;
gint ett_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo = -1;
gint ett_L1_FAPI_dlHiDCIPduInfo_st = -1;
gint ett_L1_FAPI_dlDataTxRequest_st = -1;
gint ett_L1_FAPI_dlDataTxRequest_st_dlPduInfo = -1;
gint ett_L1_FAPI_rxULSCHIndication_st = -1;
gint ett_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo = -1;
gint ett_L1_FAPI_harqIndication_st = -1;
gint ett_L1_FAPI_harqIndication_st_harqPduInfo = -1;
gint ett_L1_FAPI_crcIndication_st = -1;
gint ett_L1_FAPI_crcIndication_st_crcPduInfo = -1;
gint ett_L1_FAPI_rxSRIndication_st = -1;
gint ett_L1_FAPI_rxSRIndication_st_srPduInfo = -1;
gint ett_L1_FAPI_rxCqiIndication_st = -1;
gint ett_L1_FAPI_rxCqiIndication_st_cqiPduInfo = -1;
gint ett_L1_FAPI_rachIndication_st = -1;
gint ett_L1_FAPI_rachIndication_st_rachPduInfo = -1;
gint ett_L1_FAPI_srsIndication_st = -1;
gint ett_L1_FAPI_srsIndication_st_srsPduInfo = -1;
gint ett_L1_lte_phy_header = -1;


static gint *ett[] = {
	&ett_L1,
	&ett_L1_payload,
	&ett_L1_FAPI_ueConfig_st,
	&ett_L1_FAPI_cellConfig_st,
	&ett_L1_FAPI_paramResponseTLV_st,
	&ett_L1_FAPI_dciFormat1_st,
	&ett_L1_FAPI_dciFormat1_st_padding,
	&ett_L1_FAPI_dciFormat1C_st_padding,
	&ett_L1_FAPI_dciFormat1A_st,
	&ett_L1_FAPI_dciFormat1A_st_padding,
	&ett_L1_FAPI_dciFormat1B_st,
	&ett_L1_FAPI_dciFormat1B_st_padding,
	&ett_L1_FAPI_dciFormat1C_st,
	&ett_L1_FAPI_dciFormat1D_st,
	&ett_L1_FAPI_dciFormat1D_st_padding,
	&ett_L1_FAPI_dciFormat2_st,
	&ett_L1_FAPI_dciFormat2A_st,
	&ett_L1_FAPI_dciDLPduInfo_st,
	&ett_L1_FAPI_bchConfigPDUInfo_st,
	&ett_L1_FAPI_bchConfigPDUInfo_st_padding,
	&ett_L1_FAPI_mchConfigPDUInfo_st,
	&ett_L1_FAPI_mchConfigPDUInfo_st_padding,
	&ett_L1_FAPI_beamFormingVectorInfo_st,
	&ett_L1_FAPI_dlSCHConfigPDUInfo_st,
	&ett_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector,
	&ett_L1_FAPI_pchPduConfigInfo_st,
	&ett_L1_FAPI_dlConfigPDUInfo_st,
	&ett_L1_FAPI_dlConfigPDUInfo_st_DCIPdu,
	&ett_L1_FAPI_dlConfigPDUInfo_st_BCHPdu,
	&ett_L1_FAPI_dlConfigPDUInfo_st_MCHPdu,
	&ett_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu,
	&ett_L1_FAPI_dlConfigPDUInfo_st_PChPdu,
	&ett_L1_FAPI_dlConfigPDUInfo_st_padding,
	&ett_L1_FAPI_dlTLVInfo_st,
	&ett_L1_FAPI_dlPduInfo_st,
	&ett_L1_FAPI_dlPduInfo_st_dlTLVInfo,
	&ett_L1_FAPI_dlHiPduInfo_st,
	&ett_L1_FAPI_dlDCIPduInfo_st,
	&ett_L1_FAPI_dlDCIPduInfo_st_padding,
	&ett_L1_FAPI_cqiPduInfo_st,
	&ett_L1_FAPI_cqiPduInfo_st_padding,
	&ett_L1_FAPI_srPduInfo_st,
	&ett_L1_FAPI_tddHarqPduInfo_st,
	&ett_L1_FAPI_tddHarqPduInfo_st_padding,
	&ett_L1_FAPI_fddHarqPduInfo_st,
	&ett_L1_FAPI_ulSCHHarqInfo_st_padding,
	&ett_L1_FAPI_ulPDUConfigInfo_st_padding,
	&ett_L1_FAPI_fddHarqPduInfo_st_padding,
	&ett_L1_FAPI_srsPduInfo_st,
	&ett_L1_FAPI_srsPduInfo_st_padding,
	&ett_L1_FAPI_cqiRiPduInfo_st,
	&ett_L1_FAPI_cqiRiPduInfo_st_padding,
	&ett_L1_FAPI_uciSrPduInfo_st,
	&ett_L1_FAPI_uciSrPduInfo_st_srInfo,
	&ett_L1_FAPI_uciCqiPduInfo_st,
	&ett_L1_FAPI_uciCqiPduInfo_st_padding,
	&ett_L1_FAPI_uciCqiPduInfo_st_cqiInfo,
	&ett_L1_FAPI_uciHarqPduInfo_st,
	&ett_L1_FAPI_uciHarqPduInfo_st_padding,
	&ett_L1_FAPI_uciHarqPduInfo_st_harqInfo,
	&ett_L1_FAPI_uciSrHarqPduInfo_st,
	&ett_L1_FAPI_uciSrHarqPduInfo_st_srInfo,
	&ett_L1_FAPI_uciSrHarqPduInfo_st_harqInfo,
	&ett_L1_FAPI_uciCqiHarqPduInfo_st,
	&ett_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo,
	&ett_L1_FAPI_uciCqiHarqPduInfo_st_padding,
	&ett_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo,
	&ett_L1_FAPI_uciCqiSrPduInfo_st,
	&ett_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo,
	&ett_L1_FAPI_uciCqiSrPduInfo_st_srInfo,
	&ett_L1_FAPI_uciCqiSrHarqPduInfo_st,
	&ett_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo,
	&ett_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo,
	&ett_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo,
	&ett_L1_FAPI_ulSCHPduInfo_st,
	&ett_L1_FAPI_initialTxParam_st,
	&ett_L1_FAPI_initialTxParam_st_padding,
	&ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st,
	&ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo,
	&ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo,
	&ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo,
	&ett_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo,
	&ett_L1_FAPI_ulSCHHarqInfo_st,
	&ett_L1_FAPI_ulSCHHarqPduInfo_st,
	&ett_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo,
	&ett_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo,
	&ett_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo,
	&ett_L1_FAPI_ulSCHCqiRiPduInfo_st,
	&ett_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo,
	&ett_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo,
	&ett_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo,
	&ett_L1_FAPI_ulPDUConfigInfo_st,
	&ett_L1_FAPI_ulDataPduIndication_st,
	&ett_L1_FAPI_ulDataPduIndication_st_padding,
	&ett_L1_FAPI_fddHarqPduIndication_st,
	&ett_L1_FAPI_tddBundlingHarqInfo_st,
	&ett_L1_FAPI_tddMultiplexingHarqInfo_st,
	&ett_L1_FAPI_tddSpcialBundlingHarqInfo_st,
	&ett_L1_FAPI_tddHarqPduIndication_st,
	&ett_L1_FAPI_crcPduIndication_st,
	&ett_L1_FAPI_crcPduIndication_st_padding,
	&ett_L1_FAPI_cqiPduIndication_st,
	&ett_L1_FAPI_cqiPduIndication_st_padding,
	&ett_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding,
	&ett_L1_FAPI_tddBundlingHarqInfo_st_padding,
	&ett_L1_FAPI_srPduIndication_st,
	&ett_L1_FAPI_srPduIndication_st_padding,
	&ett_L1_FAPI_rachPduIndication_st,
	&ett_L1_FAPI_rachPduIndication_st_padding,
	&ett_L1_FAPI_srsPduIndication_st,
	&ett_L1_FAPI_errMsgBody1_st,
	&ett_L1_FAPI_errMsgBody2_st,
	&ett_L1_FAPI_errMsgBody2_st_padding,
	&ett_L1_FAPI_errMsgBody3_st,
	&ett_L1_FAPI_errMsgBody4_st,
	&ett_L1_FAPI_l1ApiMsg_st,
	&ett_L1_FAPI_paramRequest_st,
	&ett_L1_FAPI_paramResponse_st,
	&ett_L1_FAPI_paramResponse_st_padding,
	&ett_L1_FAPI_paramResponse_st_tlvs,
	&ett_L1_FAPI_phyStart_st,
	&ett_L1_FAPI_phyStop_st,
	&ett_L1_FAPI_phyStopIndication_st,
	&ett_L1_FAPI_phyCellConfigRequest_st,
	&ett_L1_FAPI_phyCellConfigRequest_st_padding,
	&ett_L1_FAPI_phyCellConfigRequest_st_configtlvs,
	&ett_L1_FAPI_phyCellConfigResp_st,
	&ett_L1_FAPI_phyCellConfigResp_st_padding,
	&ett_L1_FAPI_phyCellConfigResp_st_listOfTLV,
	&ett_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv,
	&ett_L1_FAPI_ueConfigRequest_st,
	&ett_L1_FAPI_ueConfigRequest_st_tlvs,
	&ett_L1_FAPI_phyUeConfigResp_st,
	&ett_L1_FAPI_phyUeConfigResp_st_padding,
	&ett_L1_FAPI_phyUeConfigResp_st_listOfTLV,
	&ett_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv,
	&ett_L1_FAPI_phyErrorIndication_st,
	&ett_L1_FAPI_phyErrorIndication_st_padding,
	&ett_L1_FAPI_phyErrorIndication_st_msgBody1,
	&ett_L1_FAPI_phyErrorIndication_st_msgBody2,
	&ett_L1_FAPI_phyErrorIndication_st_msgBody3,
	&ett_L1_FAPI_phyErrorIndication_st_msgBody4,
	&ett_L1_FAPI_subFrameIndication_st,
	&ett_L1_FAPI_dlConfigRequest_st,
	&ett_L1_FAPI_dlConfigRequest_st_padding,
	&ett_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo,
	&ett_L1_FAPI_ulConfigRequest_st,
	&ett_L1_FAPI_ulConfigRequest_st_padding,
	&ett_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo,
	&ett_L1_FAPI_dlHiDCIPduInfo_st,
	&ett_L1_FAPI_dlDataTxRequest_st,
	&ett_L1_FAPI_dlDataTxRequest_st_dlPduInfo,
	&ett_L1_FAPI_rxULSCHIndication_st,
	&ett_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo,
	&ett_L1_FAPI_harqIndication_st,
	&ett_L1_FAPI_harqIndication_st_harqPduInfo,
	&ett_L1_FAPI_crcIndication_st,
	&ett_L1_FAPI_crcIndication_st_crcPduInfo,
	&ett_L1_FAPI_rxSRIndication_st,
	&ett_L1_FAPI_rxSRIndication_st_srPduInfo,
	&ett_L1_FAPI_rxCqiIndication_st,
	&ett_L1_FAPI_rxCqiIndication_st_cqiPduInfo,
	&ett_L1_FAPI_rachIndication_st,
	&ett_L1_FAPI_rachIndication_st_rachPduInfo,
	&ett_L1_FAPI_srsIndication_st,
	&ett_L1_FAPI_srsIndication_st_srsPduInfo,
	&ett_L1_lte_phy_header
};

/* **Moved End** */
/* **Moved Start** */
 

static const range_string L1_FAPI_ueConfig_st_tag_values[] = {
	{ 100,100,"FAPI_HANDLE" },
	{ 101,101,"FAPI_RNTI" },
	{ 102,102,"FAPI_CQI_PUCCH_RESOURCE_INDEX" },
	{ 103,103,"FAPI_CQI_PMI_CONFIG_INDEX" },
	{ 104,104,"FAPI_CQI_RI_CONFIG_INDEX" },
	{ 105,105,"FAPI_CQI_SIMULTANEOUS_ACK_NACK_CQI" },
	{ 106,106,"FAPI_AN_REPETITION_FACTOR" },
	{ 107,107,"FAPI_AN_N1_PUCCH_AN_REP" },
	{ 108,108,"FAPI_TDD_AVK_NACK_FEEDBACK" },
	{ 109,109,"FAPI_SRS_BANDWIDTH" },
	{ 110,110,"FAPI_SRS_HOPPING_BANDWIDTH" },
	{ 111,111,"FAPI_FREQUENCY_DOMAIN_POSITION" },
	{ 112,112,"FAPI_SRS_DURATION" },
	{ 113,113,"FAPI_ISRS_SRS_CONFIG_INDEX" },
	{ 114,114,"FAPI_TRANSMISSION_COMB" },
	{ 115,115,"FAPI_SOUNDING_REFERENCE_SYCLIC_SHIFT" },
	{ 116,116,"FAPI_SR_PUCCH_RESOURCE_INDEX" },
	{ 117,117,"FAPI_SR_CONFIG_INDEX" },
	{ 118,118,"FAPI_SPS_DL_CONFIG_SCHD_INTERVAL" },
	{ 119,119,"FAPI_SPS_DL_N1_PUCCH_AN_PERSISTENT"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_ueConfig_st_tagLen = -1;
int hf_L1_FAPI_ueConfig_st_value = -1;
int hf_L1_FAPI_ueConfig_st_value1 = -1;
int hf_L1_FAPI_ueConfig_st_value2 = -1;
int hf_L1_FAPI_cellConfig_st = -1;
int hf_L1_FAPI_cellConfig_st_tag = -1;

static const range_string L1_FAPI_cellConfig_st_tag_values[] = {
	{ 1,1,"FAPI_DUPLEXING_MODE" },
	{ 2,2,"FAPI_PCFICH_POWER_OFFSET" },
	{ 3,3,"FAPI_P_B" },
	{ 4,4,"FAPI_DL_CYCLIC_PREFIX_TYPE" },
	{ 5,5,"FAPI_UL_CYCLIC_PREFIX_TYPE" },
	{ 6,6,"FAPI_DL_CHANNEL_BANDWIDTH" },
	{ 7,7,"FAPI_UL_CHANNEL_BANDWIDTH" },
	{ 8,8,"FAPI_REFERENCE_SIGNAL_POWER" },
	{ 9,9,"FAPI_TX_ANTENNA_PORTS" },
	{ 10,10,"FAPI_RX_ANTENNRA_PORTS" },
	{ 11,11,"FAPI_PHICH_RESOURCE" },
	{ 12,12,"FAPI_PHICH_DURRATION" },
	{ 13,13,"FAPI_PHICH_POWER_OFFSET" },
	{ 14,14,"FAPI_PRIMARY_SYNC_SIGN4AL" },
	{ 15,15,"FAPI_SECONDARY_SYNC_SIGNAL" },
	{ 16,16,"FAPI_PHYSICAL_CELL_ID" },
	{ 17,17,"FAPI_CONFIGURATION_INDEX" },
	{ 18,18,"FAPI_ROOT_SEQUENCE_INDEX" },
	{ 19,19,"FAPI_ZERO_CORRELATION_ZONE_CONFIGURATION" },
	{ 20,20,"FAPI_HIGH_SPEED_FLAG" },
	{ 21,21,"FAPI_FREQUENCY_OFFSET" },
	{ 22,22,"FAPI_HOPPING_MODE" },
	{ 23,23,"FAPI_HOPPING_OFFSET" },
	{ 24,24,"FAPI_NUM_OF_SUB_BANDS" },
	{ 25,25,"FAPI_DELTA_PUCCH_SHIFT" },
	{ 26,26,"FAPI_N_CQI_RB" },
	{ 27,27,"FAPI_N_AN_CS" },
	{ 28,28,"FAPI_N_1_PUCCH_AN" },
	{ 29,29,"FAPI_BANDWIDTH_CONFIGURATION" },
	{ 30,30,"FAPI_MAX_UP_PTS" },
	{ 31,31,"FAPI_SRS_SUB_FRAME_CONFIGURATION" },
	{ 32,32,"FAPI_SRS_ACK_NACK_SRS_SIMULTANEOUS_TRANSMISSION" },
	{ 33,33,"FAPI_UPLINK_RS_HOPPING" },
	{ 34,34,"FAPI_GROUP_ASSIGNMENT" },
	{ 35,35,"FAPI_CYCLIC_SHIFT_1_FOR_DMRS" },
	{ 36,36,"FAPI_SUB_FRAME_ASSIGNMENT" },
	{ 37,37,"FAPI_SPECIAL_SUB_FRAME_PATTERNS" },
	{ 40,40,"FAPI_DL_BANDWIDTH_SUPPORT" },
	{ 41,41,"FAPI_UL_BANDWIDTH_SUPPORT" },
	{ 42,42,"FAPI_DL_MODULATION_SUPPORT" },
	{ 43,43,"FAPI_UL_MODULATION_SUPPORT" },
	{ 44,44,"FAPI_PHY_ANTENNA_CAPABILITY" },
	{ 50,50,"FAPI_DATA_REPORT_MODE" },
	{ 51,51,"FAPI_SFN_SF" },
	{ 60,60,"FAPI_PHY_STATE"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_cellConfig_st_tagLen = -1;
int hf_L1_FAPI_cellConfig_st_value = -1;
int hf_L1_FAPI_paramResponseTLV_st = -1;
int hf_L1_FAPI_paramResponseTLV_st_tag = -1;

static const range_string L1_FAPI_paramResponseTLV_st_tag_values[] = {
	{ 1,1,"FAPI_DUPLEXING_MODE" },
	{ 2,2,"FAPI_PCFICH_POWER_OFFSET" },
	{ 3,3,"FRAPI_P_B" },
	{ 4,4,"FAPI_DL_CYCLIC_PREFIX_TYPE" },
	{ 5,5,"FAPI_UL_CYCLIC_PREFIX_TYPE" },
	{ 6,6,"FAPI_DL_CHANNEL_BANDWIDTH" },
	{ 7,7,"FAPI_UL_CHANNEL_BANDWIDTH" },
	{ 8,8,"FAPI_REFERENCE_SIGNAL_POWER" },
	{ 9,9,"FAPI_TX_ANTENNA_PORTS" },
	{ 10,10,"FAPI_RX_ANTENNRA_PORTS" },
	{ 11,11,"FAPI_PHICH_RESOURCE" },
	{ 12,12,"FAPI_PHICH_DURRATION" },
	{ 13,13,"FAPI_PHICH_POWER_OFFSET" },
	{ 14,14,"FAPI_PRIMARY_SYNC_SIGN4AL" },
	{ 15,15,"FAPI_SECONDARY_SYNC_SIGNAL" },
	{ 16,16,"FAPI_PHYSICAL_CELL_ID" },
	{ 17,17,"FAPI_CONFIGURATION_INDEX" },
	{ 18,18,"FAPI_ROOT_SEQUENCE_INDEX" },
	{ 19,19,"FAPI_ZERO_CORRELATION_ZONE_CONFIGURATION" },
	{ 20,20,"FAPI_HIGH_SPEED_FLAG" },
	{ 21,21,"FAPI_HOPPING_MODE" },
	{ 22,22,"FAPI_HOPPIG_OFFSET" },
	{ 23,23,"FAPI_NUM_OF_SUB_BANDS" },
	{ 24,24,"FAPI_DELTA_PUCCH_SHIFT" },
	{ 25,25,"FAPI_N_CQI_RB" },
	{ 26,26,"FAPI_N_AN_CS" },
	{ 27,27,"FAPI_N_1_PUCCH_AN" },
	{ 28,28,"FAPI_BANDWIDTH_CONFIGURATION" },
	{ 29,29,"FAPI_MAX_UP_PTS" },
	{ 30,30,"FAPI_SRS_SUB_FRAME_CONFIGURATION" },
	{ 31,31,"FAPI_SRS_ACK_NACK_SRS_SIMULTANEOUS_TRANSMISSION" },
	{ 32,32,"FAPI_UPLINK_RS_HOPPING" },
	{ 33,33,"FAPI_GROUP_ASSIGNMENT" },
	{ 34,34,"FAPI_CYCLIC_SHIFT_1_FOR_DMRS" },
	{ 35,35,"FAPI_SUB_FRAME_ASSIGNMENT" },
	{ 36,36,"FAPI_SPECIAL_SUB_FRAME_PATTERNS" },
	{ 40,40,"FAPI_DL_BANDWIDTH_SUPPORT" },
	{ 41,41,"FAPI_UL_BANDWIDTH_SUPPORT" },
	{ 42,42,"FAPI_DL_MODULATION_SUPPORT" },
	{ 43,43,"FAPI_UL_MODULATION_SUPPORT" },
	{ 44,44,"FAPI_PHY_ANTENNA_CAPABILITY" },
	{ 50,50,"FAPI_DATA_REPORT_MODE" },
	{ 51,51,"FAPI_SFN_SF" },
	{ 60,60,"FAPI_PHY_STATE"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_paramResponseTLV_st_tagLen = -1;
int hf_L1_FAPI_paramResponseTLV_st_value = -1;
int hf_L1_FAPI_dciFormat1_st = -1;
int hf_L1_FAPI_dciFormat1_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat1_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1_st_resAllocationType = -1;

static const range_string L1_FAPI_dciFormat1_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat1_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat1_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat1_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat1_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat1_st_tpc = -1;

static const range_string L1_FAPI_dciFormat1_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat1_st_txPower = -1;
int hf_L1_FAPI_dciFormat1_st_rntiType = -1;

static const range_string L1_FAPI_dciFormat1_st_rntiType_values[] = {
	{ 1,1,"FAPI_C_RNTI" },
	{ 2,2,"FAPI_RA_RNTI_P_RNTI_SI_RNTI" },
	{ 3,3,"FAPI_SPS_CRNTI" },
	{ 4,4,"FAPI_OTHER_CRNTI"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1_st_padding_array = -1;
int hf_L1_FAPI_dciFormat1_st_padding = -1;
int hf_L1_FAPI_dciFormat1C_st_padding = -1;
int hf_L1_FAPI_dciFormat1A_st = -1;
int hf_L1_FAPI_dciFormat1A_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat1A_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1A_st_vRBassignmentFlag = -1;

static const range_string L1_FAPI_dciFormat1A_st_vRBassignmentFlag_values[] = {
	{ 0,0,"FAPI_LOCALISED" },
	{ 1,1,"FAPI_DISTRIBUTED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1A_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat1A_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat1A_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat1A_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat1A_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat1A_st_tpc = -1;

static const range_string L1_FAPI_dciFormat1A_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1A_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat1A_st_allocatePrachFlag = -1;
int hf_L1_FAPI_dciFormat1A_st_preambleIndex = -1;
int hf_L1_FAPI_dciFormat1A_st_txPower = -1;
int hf_L1_FAPI_dciFormat1A_st_pRACHMaskIndex = -1;
int hf_L1_FAPI_dciFormat1A_st_rntiType = -1;

static const range_string L1_FAPI_dciFormat1A_st_rntiType_values[] = {
	{ 1,1,"FAPI_C_RNTI" },
	{ 2,2,"FAPI_RA_RNTI_P_RNTI_SI_RNTI" },
	{ 3,3,"FAPI_SPS_CRNTI" },
	{ 4,4,"FAPI_OTHER_CRNTI"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1A_st_padding_array = -1;
int hf_L1_FAPI_dciFormat1A_st_padding = -1;
int hf_L1_FAPI_dciFormat1B_st = -1;
int hf_L1_FAPI_dciFormat1B_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat1B_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1B_st_vRBassignmentFlag = -1;

static const range_string L1_FAPI_dciFormat1B_st_vRBassignmentFlag_values[] = {
	{ 0,0,"FAPI_LOCALISED" },
	{ 1,1,"FAPI_DISTRIBUTED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1B_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat1B_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat1B_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat1B_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat1B_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat1B_st_tPMI = -1;
int hf_L1_FAPI_dciFormat1B_st_pmi = -1;
int hf_L1_FAPI_dciFormat1B_st_tpc = -1;

static const range_string L1_FAPI_dciFormat1B_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1B_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat1B_st_txPower = -1;
int hf_L1_FAPI_dciFormat1B_st_nGAP = -1;
int hf_L1_FAPI_dciFormat1B_st_padding_array = -1;
int hf_L1_FAPI_dciFormat1B_st_padding = -1;
int hf_L1_FAPI_dciFormat1C_st = -1;
int hf_L1_FAPI_dciFormat1C_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat1C_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1C_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat1C_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat1C_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat1C_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat1C_st_nGAP = -1;
int hf_L1_FAPI_dciFormat1C_st_tbSizeIndex = -1;
int hf_L1_FAPI_dciFormat1C_st_txPower = -1;
int hf_L1_FAPI_dciFormat1D_st = -1;
int hf_L1_FAPI_dciFormat1D_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat1D_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1D_st_vRBassignmentFlag = -1;

static const range_string L1_FAPI_dciFormat1D_st_vRBassignmentFlag_values[] = {
	{ 0,0,"FAPI_LOCALISED" },
	{ 1,1,"FAPI_DISTRIBUTED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1D_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat1D_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat1D_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat1D_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat1D_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat1D_st_tPMI = -1;
int hf_L1_FAPI_dciFormat1D_st_tpc = -1;

static const range_string L1_FAPI_dciFormat1D_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat1D_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat1D_st_nGAP = -1;
int hf_L1_FAPI_dciFormat1D_st_txPower = -1;
int hf_L1_FAPI_dciFormat1D_st_dlPowerOffset = -1;
int hf_L1_FAPI_dciFormat1D_st_padding_array = -1;
int hf_L1_FAPI_dciFormat1D_st_padding = -1;
int hf_L1_FAPI_dciFormat2_st = -1;
int hf_L1_FAPI_dciFormat2_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat2_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2_st_resAllocationType = -1;
int hf_L1_FAPI_dciFormat1A_st_resAllocationType = -1;
int hf_L1_FAPI_dciFormat1B_st_resAllocationType = -1;
int hf_L1_FAPI_dciFormat1C_st_resAllocationType = -1;
int hf_L1_FAPI_dciFormat1D_st_resAllocationType = -1;

static const range_string L1_FAPI_dciFormat2_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat2_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat2_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat2_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag = -1;

static const range_string L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag_values[] = {
	{ 0,0,"FAPI_NOSWAPPING" },
	{ 1,1,"FAPI_SWAPPED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2_st_mcs_2 = -1;
int hf_L1_FAPI_dciFormat2_st_redundancyVersion_2 = -1;
int hf_L1_FAPI_dciFormat2_st_newDataIndicator_2 = -1;
int hf_L1_FAPI_dciFormat2_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat2_st_preCodingInfo = -1;
int hf_L1_FAPI_dciFormat2_st_tpc = -1;

static const range_string L1_FAPI_dciFormat2_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2_st_txPower = -1;
int hf_L1_FAPI_dciFormat2_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat2_st_rntiType = -1;

static const range_string L1_FAPI_dciFormat2_st_rntiType_values[] = {
	{ 1,1,"FAPI_C_RNTI" },
	{ 2,2,"FAPI_RA_RNTI_P_RNTI_SI_RNTI" },
	{ 3,3,"FAPI_SPS_CRNTI" },
	{ 4,4,"FAPI_OTHER_CRNTI"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2A_st = -1;
int hf_L1_FAPI_dciFormat2A_st_aggregationLevel = -1;

static const range_string L1_FAPI_dciFormat2A_st_aggregationLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2A_st_resAllocationType = -1;

static const range_string L1_FAPI_dciFormat2A_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2A_st_mcs_1 = -1;
int hf_L1_FAPI_dciFormat2A_st_redundancyVersion_1 = -1;
int hf_L1_FAPI_dciFormat2A_st_rbCoding = -1;
int hf_L1_FAPI_dciFormat2A_st_newDataIndicator_1 = -1;
int hf_L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag = -1;

static const range_string L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag_values[] = {
	{ 0,0,"FAPI_NOSWAPPING" },
	{ 1,1,"FAPI_SWAPPED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2A_st_mcs_2 = -1;
int hf_L1_FAPI_dciFormat2A_st_redundancyVersion_2 = -1;
int hf_L1_FAPI_dciFormat2A_st_newDataIndicator_2 = -1;
int hf_L1_FAPI_dciFormat2A_st_harqProcessNum = -1;
int hf_L1_FAPI_dciFormat2A_st_preCodingInfo = -1;
int hf_L1_FAPI_dciFormat2A_st_tpc = -1;

static const range_string L1_FAPI_dciFormat2A_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciFormat2A_st_txPower = -1;
int hf_L1_FAPI_dciFormat2A_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dciFormat2A_st_rntiType = -1;

static const range_string L1_FAPI_dciFormat2A_st_rntiType_values[] = {
	{ 1,1,"FAPI_C_RNTI" },
	{ 2,2,"FAPI_RA_RNTI_P_RNTI_SI_RNTI" },
	{ 3,3,"FAPI_SPS_CRNTI" },
	{ 4,4,"FAPI_OTHER_CRNTI"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dciDLPduInfo_st = -1;
int hf_L1_FAPI_dciDLPduInfo_st_dciFormat = -1;

static const range_string L1_FAPI_dciDLPduInfo_st_dciFormat_values[] = {
	{ 0,0,"FAPI_DL_DCI_FORMAT_1" },
	{ 1,1,"FAPI_DL_DCI_FORMAT_1A" },
	{ 2,2,"FAPI_DL_DCI_FORMAT_1B" },
	{ 3,3,"FAPI_DL_DCI_FORMAT_1C" },
	{ 4,4,"FAPI_DL_DCI_FORMAT_1D" },
	{ 5,5,"FAPI_DL_DCI_FORMAT_2" },
	{ 6,6,"FAPI_DL_DCI_FORMAT_2A"},
	{ 0,0, NULL }
};


int GLOBE_FAPI_DL_DCI_FORMAT_1 = -1;


int hf_L1_FAPI_dciDLPduInfo_st_cceIndex = -1;
int hf_L1_FAPI_dciDLPduInfo_st_rnti = -1;
int hf_L1_FAPI_dciDLPduInfo_st_dciPdu = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st_bchPduLen = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st_pduIndex = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st_txPower = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st_padding_array = -1;
int hf_L1_FAPI_bchConfigPDUInfo_st_padding = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_mchPduLen = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_pduIndex = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_rnti = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_resAllocationType = -1;

static const range_string L1_FAPI_mchConfigPDUInfo_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_mchConfigPDUInfo_st_modulationType = -1;

static const range_string L1_FAPI_mchConfigPDUInfo_st_modulationType_values[] = {
	{ 2,2,"FAPI_QPSK" },
	{ 4,4,"FAPI_16QAM" },
	{ 6,6,"FAPI_64QAM"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_mchConfigPDUInfo_st_rbCoding = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_txPower = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_padding_array = -1;
int hf_L1_FAPI_mchConfigPDUInfo_st_padding = -1;
int hf_L1_FAPI_beamFormingVectorInfo_st = -1;
int hf_L1_FAPI_beamFormingVectorInfo_st_subBandIndex = -1;
int hf_L1_FAPI_beamFormingVectorInfo_st_numOfAntenna = -1;
int hf_L1_FAPI_beamFormingVectorInfo_st_bfValue_per_antenna = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_dlschPduLen = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_pduIndex = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_rnti = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType = -1;

static const range_string L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag = -1;

static const range_string L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag_values[] = {
	{ 0,0,"FAPI_LOCALISED" },
	{ 1,1,"FAPI_DISTRIBUTED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_rbCoding = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_mcs = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_redundancyVersion = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_transportBlocks = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag = -1;

static const range_string L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag_values[] = {
	{ 0,0,"FAPI_NOSWAPPING" },
	{ 1,1,"FAPI_SWAPPED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme = -1;

static const range_string L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme_values[] = {
	{ 0,0,"FAPI_SINGLE_ANTENNA_PORT_0" },
	{ 1,1,"FAPI_TX_DIVERSITY" },
	{ 2,2,"FAPI_LARGE_DELAY_CDD" },
	{ 3,3,"FAPI_CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
	{ 4,4,"FAPI_MULTI_USER_MIMO" },
	{ 5,5,"FAPI_CLOSED_LOOP_RANK_1_PRECODING" },
	{ 6,6,"FAPI_SINGLE_ANTENNA_PORT_5"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfLayers = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfSubBand = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_ueCatagoryCapacity = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_pA = -1;

static const range_string L1_FAPI_dlSCHConfigPDUInfo_st_pA_values[] = {
	{ 0,0,"FAPI_DB_MINUS6" },
	{ 1,1,"FAPI_DB_MINUS_4DOT77" },
	{ 2,2,"FAPI_DB_MINUS_3" },
	{ 3,3,"FAPI_DB_MINUS_1DOT77" },
	{ 4,4,"FAPI_DB0" },
	{ 5,5,"FAPI_DB1" },
	{ 6,6,"FAPI_DB2" },
	{ 7,7,"FAPI_DB3"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_deltaPowerOffsetAIndex = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_nGap = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_nPRB = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numRbPerSubBand = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_numbfVector = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_subBandInfo = -1;
int hf_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector = -1;
int hf_L1_FAPI_pchPduConfigInfo_st = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_pchPduLen = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_pduIndex = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_pRNTI = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_resAllocationType = -1;

static const range_string L1_FAPI_pchPduConfigInfo_st_resAllocationType_values[] = {
	{ 0,0,"FAPI_RES_ALLOC_TYPE_0" },
	{ 1,1,"FAPI_RES_ALLOC_TYPE_1" },
	{ 2,2,"FAPI_RES_ALLOC_TYPE_2"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag = -1;

static const range_string L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag_values[] = {
	{ 0,0,"FAPI_LOCALISED" },
	{ 1,1,"FAPI_DISTRIBUTED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_pchPduConfigInfo_st_rbCoding = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_mcs = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_redundancyVersion = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_numOftransportBlocks = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag = -1;

static const range_string L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag_values[] = {
	{ 0,0,"FAPI_NOSWAPPING" },
	{ 1,1,"FAPI_SWAPPED"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_pchPduConfigInfo_st_transmissionScheme = -1;

static const range_string L1_FAPI_pchPduConfigInfo_st_transmissionScheme_values[] = {
	{ 0,0,"FAPI_SINGLE_ANTENNA_PORT_0" },
	{ 1,1,"FAPI_TX_DIVERSITY" },
	{ 2,2,"FAPI_LARGE_DELAY_CDD" },
	{ 3,3,"FAPI_CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
	{ 4,4,"FAPI_MULTI_USER_MIMO" },
	{ 5,5,"FAPI_CLOSED_LOOP_RANK_1_PRECODING" },
	{ 6,6,"FAPI_SINGLE_ANTENNA_PORT_5"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_pchPduConfigInfo_st_numOfLayers = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_codeBookIndex = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_ueCatagoryCapacity = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_pA = -1;

static const range_string L1_FAPI_pchPduConfigInfo_st_pA_values[] = {
	{ 0,0,"FAPI_DB_MINUS6" },
	{ 1,1,"FAPI_DB_MINUS_4DOT77" },
	{ 2,2,"FAPI_DB_MINUS_3" },
	{ 3,3,"FAPI_DB_MINUS_1DOT77" },
	{ 4,4,"FAPI_DB0" },
	{ 5,5,"FAPI_DB1" },
	{ 6,6,"FAPI_DB2" },
	{ 7,7,"FAPI_DB3"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_pchPduConfigInfo_st_nPRB = -1;
int hf_L1_FAPI_pchPduConfigInfo_st_txPower = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_pduType = -1;

static const range_string L1_FAPI_dlConfigPDUInfo_st_pduType_values[] = {
	{ 0,0,"FAPI_DCI_DL_PDU" },
	{ 1,1,"FAPI_BCH_PDU" },
	{ 2,2,"FAPI_MCH_PDU" },
	{ 3,3,"FAPI_DLSCH_PDU" },
	{ 4,4,"FAPI_PCH_PDU"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlConfigPDUInfo_st_pduSize = -1;
//int hf_L1_FAPI_dlConfigPDUInfo_st_vishal = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_DCIPdu = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_BCHPdu = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_MCHPdu = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_PChPdu = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_padding_array = -1;
int hf_L1_FAPI_dlConfigPDUInfo_st_padding = -1;
int hf_L1_FAPI_dlTLVInfo_st = -1;
int hf_L1_FAPI_dlTLVInfo_st_tag = -1;
int hf_L1_FAPI_dlTLVInfo_st_tagLen = -1;
//int hf_L1_FAPI_dlTLVInfo_st_padding = -1;
int hf_L1_FAPI_dlTLVInfo_st_value = -1;
int hf_L1_FAPI_dlPduInfo_st = -1;
int hf_L1_FAPI_dlPduInfo_st_pduLen = -1;
int hf_L1_FAPI_dlPduInfo_st_pduIndex = -1;
int hf_L1_FAPI_dlPduInfo_st_numOfTLV = -1;
int hf_L1_FAPI_dlPduInfo_st_dlTLVInfo = -1;
int hf_L1_FAPI_dlHiPduInfo_st = -1;
int hf_L1_FAPI_dlHiPduInfo_st_pduType = -1;
int hf_L1_FAPI_dlHiPduInfo_st_hipduSize = -1;
int hf_L1_FAPI_dlHiPduInfo_st_rbStart = -1;
int hf_L1_FAPI_dlHiPduInfo_st_cyclicShift2_forDMRS = -1;
int hf_L1_FAPI_dlHiPduInfo_st_hiValue = -1;

static const range_string L1_FAPI_dlHiPduInfo_st_hiValue_values[] = {
	{ 0,0,"FAPI_HI_NACK" },
	{ 1,1,"FAPI_HI_ACK"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlHiPduInfo_st_iPHICH = -1;
int hf_L1_FAPI_dlHiPduInfo_st_txPower = -1;
int hf_L1_FAPI_dlDCIPduInfo_st = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_pduType = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_uldcipduSize = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_ulDCIFormat = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_cceIndex = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_rnti = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_aggLevel = -1;

static const range_string L1_FAPI_dlDCIPduInfo_st_aggLevel_values[] = {
	{ 1,1,"FAPI_AGGEGATION_LEVEL_1" },
	{ 2,2,"FAPI_AGGEGATION_LEVEL_2" },
	{ 4,4,"FAPI_AGGEGATION_LEVEL_4" },
	{ 8,8,"FAPI_AGGEGATION_LEVEL_8"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlDCIPduInfo_st_rbStart = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_numOfRB = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_mcs = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_cyclicShift2_forDMRS = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_freqEnabledFlag = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_freqHoppingBits = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_newDataIndication = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_ueTxAntennaSelection = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_tpc = -1;

static const range_string L1_FAPI_dlDCIPduInfo_st_tpc_values[] = {
	{ 0,0,"FAPI_TX_POWER_CONTROL_MINUS_4" },
	{ 1,1,"FAPI_TX_POWER_CONTROL_MINUS_1" },
	{ 2,2,"FAPI_TX_POWER_CONTROL_0" },
	{ 3,3,"FAPI_TX_POWER_CONTROL_1" },
	{ 4,4,"FAPI_TX_POWER_CONTROL_3" },
	{ 5,5,"FAPI_TX_POWER_CONTROL_4"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_dlDCIPduInfo_st_cqiRequest = -1;

static const range_string L1_FAPI_dlDCIPduInfo_st_cqiRequest_values[] = {
	{ 0,0,"FAPI_APERIODIC_CQI_NOT_REQUESTED" },
	{ 1,1,"FAPI_APERIODIC_CQI_REQUESTED"},
	{ 0,0, NULL }
};

int hf_L1_FAPI_ulConfigRequest_st_sfnsf = -1;
//FAPI_ulPDUConfigInfo_st_count = -1;

int hf_L1_FAPI_dlDCIPduInfo_st_ulIndex = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_dlAssignmentIndex = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_padding_array = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_padding = -1;
int hf_L1_FAPI_dlDCIPduInfo_st_tpcBitMap = -1;
int hf_L1_FAPI_cqiPduInfo_st = -1;
int hf_L1_FAPI_cqiPduInfo_st_pucchIndex = -1;
int hf_L1_FAPI_cqiPduInfo_st_dlCqiPmiSize = -1;
int hf_L1_FAPI_cqiPduInfo_st_padding_array = -1;
int hf_L1_FAPI_cqiPduInfo_st_padding = -1;
int hf_L1_FAPI_srPduInfo_st = -1;
int hf_L1_FAPI_srPduInfo_st_pucchIndex = -1;
int hf_L1_FAPI_tddHarqPduInfo_st = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_harqSize = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_acknackMode = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_numOfPUCCHResource = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_0 = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_1 = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_2 = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_3 = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_padding_array = -1;
int hf_L1_FAPI_tddHarqPduInfo_st_padding = -1;
int hf_L1_FAPI_fddHarqPduInfo_st = -1;
int hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex = -1;
int hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex1 = -1;
int hf_L1_FAPI_fddHarqPduInfo_st_harqSize = -1;
int hf_L1_FAPI_fddHarqPduInfo_st_padding_array = -1;
int hf_L1_FAPI_fddHarqPduInfo_st_padding = -1;
int hf_L1_FAPI_ulSCHHarqInfo_st_padding = -1;
int hf_L1_FAPI_ulPDUConfigInfo_st_padding = -1;
int hf_L1_FAPI_srsPduInfo_st = -1;
int hf_L1_FAPI_srsPduInfo_st_handle = -1;
int hf_L1_FAPI_srsPduInfo_st_size = -1;
int hf_L1_FAPI_srsPduInfo_st_rnti = -1;
int hf_L1_FAPI_srsPduInfo_st_srsBandWidth = -1;
int hf_L1_FAPI_srsPduInfo_st_freqDomainPosition = -1;
int hf_L1_FAPI_srsPduInfo_st_srsHoppingBandWidth = -1;
int hf_L1_FAPI_srsPduInfo_st_transmissionComb = -1;
int hf_L1_FAPI_srsPduInfo_st_isrsSRSConfigIndex = -1;
int hf_L1_FAPI_srsPduInfo_st_soundingRefCyclicShift = -1;
int hf_L1_FAPI_srsPduInfo_st_padding_array = -1;
int hf_L1_FAPI_srsPduInfo_st_padding = -1;
int hf_L1_FAPI_cqiRiPduInfo_st = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRank_1 = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRankGT_1 = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_riSize = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetCQI = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetRI = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_padding_array = -1;
int hf_L1_FAPI_cqiRiPduInfo_st_padding = -1;
int hf_L1_FAPI_uciSrPduInfo_st = -1;
int hf_L1_FAPI_uciSrPduInfo_st_handle = -1;
int hf_L1_FAPI_uciSrPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciSrPduInfo_st_srInfo = -1;
int hf_L1_FAPI_uciCqiPduInfo_st = -1;
int hf_L1_FAPI_uciCqiPduInfo_st_handle = -1;
int hf_L1_FAPI_uciCqiPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciCqiPduInfo_st_padding_array = -1;
int hf_L1_FAPI_uciCqiPduInfo_st_padding = -1;
int hf_L1_FAPI_uciCqiPduInfo_st_cqiInfo = -1;
int hf_L1_FAPI_uciHarqPduInfo_st = -1;
int hf_L1_FAPI_uciHarqPduInfo_st_handle = -1;
int hf_L1_FAPI_uciHarqPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciHarqPduInfo_st_padding_array = -1;
int hf_L1_FAPI_uciHarqPduInfo_st_padding = -1;
int hf_L1_FAPI_uciHarqPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_uciSrHarqPduInfo_st = -1;
int hf_L1_FAPI_uciSrHarqPduInfo_st_handle = -1;
int hf_L1_FAPI_uciSrHarqPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciSrHarqPduInfo_st_srInfo = -1;
int hf_L1_FAPI_uciSrHarqPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_handle = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_padding_array = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_padding = -1;
int hf_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_uciCqiSrPduInfo_st = -1;
int hf_L1_FAPI_uciCqiSrPduInfo_st_handle = -1;
int hf_L1_FAPI_uciCqiSrPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo = -1;
int hf_L1_FAPI_uciCqiSrPduInfo_st_srInfo = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_handle = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_rnti = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo = -1;
int hf_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_ulSCHPduInfo_st = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_handle = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_size = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_rnti = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_rbStart = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_numOfRB = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_modulationType = -1;

static const range_string L1_FAPI_ulSCHPduInfo_st_modulationType_values[] = {
	{ 2,2,"FAPI_QPSK" },
	{ 4,4,"FAPI_16QAM" },
	{ 6,6,"FAPI_64QAM"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_ulSCHPduInfo_st_cyclicShift2forDMRS = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingenabledFlag = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingBits = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_newDataIndication = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_redundancyVersion = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_harqProcessNumber = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_ulTxMode = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_currentTxNB = -1;
int hf_L1_FAPI_ulSCHPduInfo_st_nSRS = -1;
int hf_L1_FAPI_initialTxParam_st = -1;
int hf_L1_FAPI_initialTxParam_st_nSRSInitial = -1;
int hf_L1_FAPI_initialTxParam_st_initialNumOfRB = -1;
int hf_L1_FAPI_initialTxParam_st_padding_array = -1;
int hf_L1_FAPI_initialTxParam_st_padding = -1;
int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st = -1;
int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo = -1;
int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo = -1;
int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo = -1;
int hf_L1_FAPI_ulSCHHarqPduInfo_st = -1;
int hf_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo = -1;
int hf_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo = -1;
int hf_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo = -1;
int hf_L1_FAPI_ulSCHHarqInfo_st = -1;
int hf_L1_FAPI_ulSCHHarqInfo_st_harqSize = -1;
int hf_L1_FAPI_ulSCHHarqInfo_st_deltaOffsetHarq = -1;
int hf_L1_FAPI_ulSCHHarqInfo_st_ackNackMode = -1;
int hf_L1_FAPI_ulSCHCqiRiPduInfo_st = -1;
int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo = -1;
int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo = -1;
int hf_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo = -1;
int hf_L1_FAPI_ulPDUConfigInfo_st = -1;
int hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType = -1;

static const range_string L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType_values[] = {
	{ 0,0,"FAPI_ULSCH" },
	{ 1,1,"FAPI_ULSCH_CQI_RI" },
	{ 2,2,"FAPI_ULSCH_HARQ" },
	{ 3,3,"FAPI_ULSCH_CQI_HARQ_RI" },
	{ 4,4,"FAPI_UCI_CQI" },
	{ 5,5,"FAPI_UCI_SR" },
	{ 6,6,"FAPI_UCI_HARQ" },
	{ 7,7,"FAPI_UCI_SR_HARQ" },
	{ 8,8,"FAPI_UCI_CQI_HARQ" },
	{ 9,9,"FAPI_UCI_CQI_SR" },
	{ 10,10,"FAPI_UCI_CQI_SR_HARQ" },
	{ 11,11,"FAPI_SRS"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduSize = -1;
int hf_L1_FAPI_ulPDUConfigInfo_st_ulPduConfigInfo = -1;
int hf_L1_FAPI_ulDataPduIndication_st = -1;
int hf_L1_FAPI_ulDataPduIndication_st_handle = -1;
int hf_L1_FAPI_ulDataPduIndication_st_rnti = -1;
int hf_L1_FAPI_ulDataPduIndication_st_length = -1;
int hf_L1_FAPI_ulDataPduIndication_st_dataOffset = -1;
int hf_L1_FAPI_ulDataPduIndication_st_timingAdvance = -1;
int hf_L1_FAPI_ulDataPduIndication_st_ulCqi = -1;
int hf_L1_FAPI_ulDataPduIndication_st_padding_array = -1;
int hf_L1_FAPI_ulDataPduIndication_st_padding = -1;
int hf_L1_FAPI_fddHarqPduIndication_st = -1;
int hf_L1_FAPI_fddHarqPduIndication_st_rnti = -1;
int hf_L1_FAPI_fddHarqPduIndication_st_harqTB1 = -1;

static const range_string L1_FAPI_fddHarqPduIndication_st_harqTB1_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_fddHarqPduIndication_st_harqTB2 = -1;

static const range_string L1_FAPI_fddHarqPduIndication_st_harqTB2_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddBundlingHarqInfo_st = -1;
int hf_L1_FAPI_tddBundlingHarqInfo_st_value0 = -1;

static const range_string L1_FAPI_tddBundlingHarqInfo_st_value0_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddBundlingHarqInfo_st_value1 = -1;

static const range_string L1_FAPI_tddBundlingHarqInfo_st_value1_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddMultiplexingHarqInfo_st = -1;
int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value0 = -1;

static const range_string L1_FAPI_tddMultiplexingHarqInfo_st_value0_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value1 = -1;

static const range_string L1_FAPI_tddMultiplexingHarqInfo_st_value1_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value2 = -1;

static const range_string L1_FAPI_tddMultiplexingHarqInfo_st_value2_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddMultiplexingHarqInfo_st_value3 = -1;

static const range_string L1_FAPI_tddMultiplexingHarqInfo_st_value3_values[] = {
	{ 1,1,"FAPI_ACK" },
	{ 2,2,"FAPI_NACK" },
	{ 3,3,"FAPI_ACK_OR_NACK" },
	{ 4,4,"FAPI_DTX" },
	{ 5,5,"FAPI_ACK_OR_DTX" },
	{ 6,6,"FAPI_NACK_OR_DTX" },
	{ 7,7,"FAPI_ACK_OR_NACK_OR_DTX"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st = -1;
int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_value_0 = -1;
int hf_L1_FAPI_tddHarqPduIndication_st = -1;
int hf_L1_FAPI_tddHarqPduIndication_st_handle = -1;
int hf_L1_FAPI_tddHarqPduIndication_st_rnti = -1;
int hf_L1_FAPI_tddHarqPduIndication_st_mode = -1;


int hf_L1_FAPI_tddHarqPduIndication_st_numOfAckNack = -1;
int hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer = -1;
int hf_L1_FAPI_crcPduIndication_st = -1;
int hf_L1_FAPI_crcPduIndication_st_handle = -1;
int hf_L1_FAPI_crcPduIndication_st_rnti = -1;
int hf_L1_FAPI_crcPduIndication_st_crcFlag = -1;

static const range_string L1_FAPI_crcPduIndication_st_crcFlag_values[] = {
	{ 0,0,"CRC_CORRECT" },
	{ 1,1,"CRC_ERROR"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_crcPduIndication_st_padding_array = -1;
int hf_L1_FAPI_crcPduIndication_st_padding = -1;
int hf_L1_FAPI_cqiPduIndication_st = -1;
int hf_L1_FAPI_cqiPduIndication_st_handle = -1;
int hf_L1_FAPI_cqiPduIndication_st_rnti = -1;
int hf_L1_FAPI_cqiPduIndication_st_length = -1;
int hf_L1_FAPI_cqiPduIndication_st_dataOffset = -1;
int hf_L1_FAPI_cqiPduIndication_st_timingAdvance = -1;
int hf_L1_FAPI_cqiPduIndication_st_ulCqi = -1;
int hf_L1_FAPI_cqiPduIndication_st_ri = -1;
int hf_L1_FAPI_cqiPduIndication_st_padding_array = -1;
int hf_L1_FAPI_cqiPduIndication_st_padding = -1;
int hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding = -1;
int hf_L1_FAPI_tddBundlingHarqInfo_st_padding = -1;
int hf_L1_FAPI_srPduIndication_st = -1;
int hf_L1_FAPI_srPduIndication_st_handle = -1;
int hf_L1_FAPI_srPduIndication_st_rnti = -1;
int hf_L1_FAPI_srPduIndication_st_padding_array = -1;
int hf_L1_FAPI_srPduIndication_st_padding = -1;
int hf_L1_FAPI_rachPduIndication_st = -1;
int hf_L1_FAPI_rachPduIndication_st_rnti = -1;
int hf_L1_FAPI_rachPduIndication_st_timingAdvance = -1;
int hf_L1_FAPI_rachPduIndication_st_preamble = -1;
int hf_L1_FAPI_rachPduIndication_st_padding_array = -1;
int hf_L1_FAPI_rachPduIndication_st_padding = -1;
int hf_L1_FAPI_srsPduIndication_st = -1;
int hf_L1_FAPI_srsPduIndication_st_handle = -1;
int hf_L1_FAPI_srsPduIndication_st_rnti = -1;
int hf_L1_FAPI_srsPduIndication_st_dopplerEstimation = -1;
int hf_L1_FAPI_srsPduIndication_st_timingAdvance = -1;
int hf_L1_FAPI_srsPduIndication_st_numOfRB = -1;
int hf_L1_FAPI_srsPduIndication_st_rbStart = -1;
int hf_L1_FAPI_srsPduIndication_st_snr = -1;
int hf_L1_FAPI_errMsgBody1_st = -1;
int hf_L1_FAPI_errMsgBody1_st_recvdSfnSf = -1;
int hf_L1_FAPI_errMsgBody1_st_expectedSfnSf = -1;
int hf_L1_FAPI_errMsgBody2_st = -1;
int hf_L1_FAPI_errMsgBody2_st_subErrCode = -1;
int hf_L1_FAPI_errMsgBody2_st_direction = -1;
int hf_L1_FAPI_errMsgBody2_st_rnti = -1;
int hf_L1_FAPI_errMsgBody2_st_pduType = -1;
int hf_L1_FAPI_errMsgBody2_st_padding_array = -1;
int hf_L1_FAPI_errMsgBody2_st_padding = -1;
int hf_L1_FAPI_errMsgBody3_st = -1;
int hf_L1_FAPI_errMsgBody3_st_subErrCode = -1;
int hf_L1_FAPI_errMsgBody3_st_phichLowestulRbIndex = -1;
int hf_L1_FAPI_errMsgBody4_st = -1;
int hf_L1_FAPI_errMsgBody4_st_subErrCode = -1;
int hf_L1_FAPI_errMsgBody4_st_pduIndex = -1;
int hf_L1_FAPI_l1ApiMsg_st = -1;
int hf_L1_FAPI_l1ApiMsg_st_msgId = -1;
int hf_L1_FAPI_l1ApiMsg_st_lenVendorSpecific = -1;
int hf_L1_FAPI_l1ApiMsg_st_msgLen = -1;
int hf_L1_FAPI_l1ApiMsg_st_msgBody = -1;
int hf_L1_FAPI_l1ApiMsg_st_vendorMsgBody = -1;
int hf_L1_FAPI_paramRequest_st = -1;
int hf_L1_FAPI_paramRequest_st_msgId = -1;
int hf_L1_FAPI_paramResponse_st = -1;
int hf_L1_FAPI_paramResponse_st_errCode = -1;

static const range_string L1_FAPI_paramResponse_st_errCode_values[] = {
	{ 0,0,"FSAPI_MSG_OK" },
	{ 1,1,"FAPI_MSG_INVALID_STATE (The received message is not valid in the PHY current state)" },
	{ 2,2,"FAPI_MSG_INVALID_CONFIG (The configuration provided in the CONFIG.request message  was invalid)" },
	{ 3,3,"FAPI_SFN_OUT_OF_SYNC (The DL_CONFIG.request was received with a different SFN than the PHY expected)" },
	{ 4,4,"FAPI_MSG_SUBFRAME_ERR (An error was received in DL_CONFIG.request or UL_CONFIG.request. The sub-error code should be analyzed)" },
	{ 5,5,"FAPI_MSG_BCH_MISSING (A BCH PDU was expected in the DL_CONFIG.request message for this subframe. However, it was not present)" },
	{ 6,6,"FAPI_MSG_INVALID_SFN (The received HI_DCI0.request or TX.request message included a SFN/SF value which was not expected. The message has been ignored.)" },
	{ 7,7,"FAPI_MSG_HI_ERR (An error was received in HI_DCI.request. The sub-error code should be analyzed)" },
	{ 8,8,"FAPI_MSG_TX_ERR (An error was received in TX.request. The sub-error code should be analyzed)"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_paramResponse_st_numOfTlv = -1;
int hf_L1_FAPI_paramResponse_st_padding_array = -1;
int hf_L1_FAPI_paramResponse_st_padding = -1;
int hf_L1_FAPI_paramResponse_st_tlvs = -1;
int hf_L1_FAPI_phyStart_st = -1;
int hf_L1_FAPI_phyStart_st_msgId = -1;
int hf_L1_FAPI_phyStop_st = -1;
int hf_L1_FAPI_phyStop_st_msgId = -1;
int hf_L1_FAPI_phyStopIndication_st = -1;
int hf_L1_FAPI_phyStopIndication_st_msgId = -1;
int hf_L1_FAPI_phyCellConfigRequest_st = -1;
int hf_L1_FAPI_phyCellConfigRequest_st_numOfTlv = -1;
int hf_L1_FAPI_phyCellConfigRequest_st_padding_array = -1;
int hf_L1_FAPI_phyCellConfigRequest_st_padding = -1;
int hf_L1_FAPI_phyCellConfigRequest_st_configtlvs = -1;
int hf_L1_FAPI_phyCellConfigResp_st = -1;
int hf_L1_FAPI_phyCellConfigResp_st_errorCode = -1;

static const range_string L1_FAPI_phyCellConfigResp_st_errorCode_values[] = {
	{ 0,0,"FSAPI_MSG_OK" },
	{ 1,1,"FAPI_MSG_INVALID_STATE" },
	{ 2,2,"FAPI_MSG_INVALID_CONFIG" },
	{ 3,3,"FAPI_SFN_OUT_OF_SYNC" },
	{ 4,4,"FAPI_MSG_SUBFRAME_ERR" },
	{ 5,5,"FAPI_MSG_BCH_MISSING" },
	{ 6,6,"FAPI_MSG_INVALID_SFN" },
	{ 7,7,"FAPI_MSG_HI_ERR" },
	{ 8,8,"FAPI_MSG_TX_ERR"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_phyCellConfigResp_st_numOfInvalidOrunsupportedTLV = -1;
int hf_L1_FAPI_phyCellConfigResp_st_numOfMissingTLV = -1;
int hf_L1_FAPI_phyCellConfigResp_st_padding_array = -1;
int hf_L1_FAPI_phyCellConfigResp_st_padding = -1;
int hf_L1_FAPI_phyCellConfigResp_st_listOfTLV = -1;
int hf_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv = -1;
int hf_L1_FAPI_ueConfigRequest_st = -1;
int hf_L1_FAPI_ueConfigRequest_st_numOfTlv = -1;
int hf_L1_FAPI_ueConfigRequest_st_tlvs = -1;
int hf_L1_FAPI_phyUeConfigResp_st = -1;
int hf_L1_FAPI_phyUeConfigResp_st_errorCode = -1;

static const range_string L1_FAPI_phyUeConfigResp_st_errorCode_values[] = {
	{ 0,0,"FSAPI_MSG_OK" },
	{ 1,1,"FAPI_MSG_INVALID_STATE" },
	{ 2,2,"FAPI_MSG_INVALID_CONFIG" },
	{ 3,3,"FAPI_SFN_OUT_OF_SYNC" },
	{ 4,4,"FAPI_MSG_SUBFRAME_ERR" },
	{ 5,5,"FAPI_MSG_BCH_MISSING" },
	{ 6,6,"FAPI_MSG_INVALID_SFN" },
	{ 7,7,"FAPI_MSG_HI_ERR" },
	{ 8,8,"FAPI_MSG_TX_ERR"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_phyUeConfigResp_st_numOfInvalidOrunsupportedTLV = -1;
int hf_L1_FAPI_phyUeConfigResp_st_numOfMissingTLV = -1;
int hf_L1_FAPI_phyUeConfigResp_st_padding_array = -1;
int hf_L1_FAPI_phyUeConfigResp_st_padding = -1;
int hf_L1_FAPI_phyUeConfigResp_st_listOfTLV = -1;
int hf_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv = -1;
int hf_L1_FAPI_phyErrorIndication_st = -1;
int hf_L1_FAPI_phyErrorIndication_st_msgId = -1;
int hf_L1_FAPI_phyErrorIndication_st_padding_array = -1;
int hf_L1_FAPI_phyErrorIndication_st_padding = -1;
int hf_L1_FAPI_phyErrorIndication_st_errorCode = -1;

static const range_string L1_FAPI_phyErrorIndication_st_errorCode_values[] = {
	{ 0,0,"FSAPI_MSG_OK" },
	{ 1,1,"FAPI_MSG_INVALID_STATE" },
	{ 2,2,"FAPI_MSG_INVALID_CONFIG" },
	{ 3,3,"FAPI_SFN_OUT_OF_SYNC" },
	{ 4,4,"FAPI_MSG_SUBFRAME_ERR" },
	{ 5,5,"FAPI_MSG_BCH_MISSING" },
	{ 6,6,"FAPI_MSG_INVALID_SFN" },
	{ 7,7,"FAPI_MSG_HI_ERR" },
	{ 8,8,"FAPI_MSG_TX_ERR"},
	{ 0,0, NULL }
};
int hf_L1_FAPI_phyErrorIndication_st_msgBody1 = -1;
int hf_L1_FAPI_phyErrorIndication_st_msgBody2 = -1;
int hf_L1_FAPI_phyErrorIndication_st_msgBody3 = -1;
int hf_L1_FAPI_phyErrorIndication_st_msgBody4 = -1;
int hf_L1_FAPI_subFrameIndication_st = -1;
int hf_L1_FAPI_subFrameIndication_st_sf = -1;
int hf_L1_FAPI_subFrameIndication_st_sfn = -1;
int hf_L1_FAPI_dlConfigRequest_st = -1;
int hf_L1_FAPI_dlConfigRequest_st_sf = -1;
int hf_L1_FAPI_dlConfigRequest_st_sfn = -1;
int hf_L1_FAPI_dlConfigRequest_st_length = -1;
int hf_L1_FAPI_dlConfigRequest_st_cfi = -1;
int hf_L1_FAPI_dlConfigRequest_st_numDCI = -1;
int hf_L1_FAPI_dlConfigRequest_st_numOfPDU = -1;
int hf_L1_FAPI_dlConfigRequest_st_txPowerForPCFICH = -1;
int hf_L1_FAPI_dlConfigRequest_st_numOfPDSCHRNTI = -1;
int hf_L1_FAPI_dlConfigRequest_st_padding_array = -1;
int hf_L1_FAPI_dlConfigRequest_st_padding = -1;
int hf_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo = -1;
int hf_L1_FAPI_ulConfigRequest_st = -1;
int hf_L1_FAPI_ulConfigRequest_st_sf = -1;
int hf_L1_FAPI_ulConfigRequest_st_sfn = -1;
int hf_L1_FAPI_ulConfigRequest_st_ulConfigLen = -1;
int hf_L1_FAPI_ulConfigRequest_st_numOfPdu = -1;
int hf_L1_FAPI_ulConfigRequest_st_rachFreqResources = -1;
int hf_L1_FAPI_ulConfigRequest_st_srsPresent = -1;
int hf_L1_FAPI_ulConfigRequest_st_padding_array = -1;
int hf_L1_FAPI_ulConfigRequest_st_padding = -1;
int hf_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st_sf = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st_sfn = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st_numOfDCI = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st_numOfHI = -1;
int hf_L1_FAPI_dlHiDCIPduInfo_st_hidciPduInfo = -1;
int hf_L1_FAPI_dlDataTxRequest_st = -1;
int hf_L1_FAPI_dlDataTxRequest_st_sf = -1;
int hf_L1_FAPI_dlDataTxRequest_st_sfn = -1;
int hf_L1_FAPI_dlDataTxRequest_st_numOfPDU = -1;
int hf_L1_FAPI_dlDataTxRequest_st_dlPduInfo = -1;
int hf_L1_FAPI_rxULSCHIndication_st = -1;
int hf_L1_FAPI_rxULSCHIndication_st_sf = -1;
int hf_L1_FAPI_rxULSCHIndication_st_sfn = -1;
int hf_L1_FAPI_rxULSCHIndication_st_numOfPdu = -1;
int hf_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo = -1;
int hf_L1_FAPI_rxULSCHIndication_st_pduBuffer = -1;
int hf_L1_FAPI_harqIndication_st = -1;
int hf_L1_FAPI_harqIndication_st_sf = -1;
int hf_L1_FAPI_harqIndication_st_sfn = -1;
int hf_L1_FAPI_harqIndication_st_numOfHarq = -1;
int hf_L1_FAPI_harqIndication_st_harqPduInfo = -1;
int hf_L1_FAPI_crcIndication_st = -1;
int hf_L1_FAPI_crcIndication_st_sf = -1;
int hf_L1_FAPI_crcIndication_st_sfn = -1;
int hf_L1_FAPI_crcIndication_st_numOfCrc = -1;
int hf_L1_FAPI_crcIndication_st_crcPduInfo = -1;
int hf_L1_FAPI_rxSRIndication_st = -1;
int hf_L1_FAPI_rxSRIndication_st_sf = -1;
int hf_L1_FAPI_rxSRIndication_st_sfn = -1;
int hf_L1_FAPI_rxSRIndication_st_numOfSr = -1;
int hf_L1_FAPI_rxSRIndication_st_srPduInfo = -1;
int hf_L1_FAPI_rxCqiIndication_st = -1;
int hf_L1_FAPI_rxCqiIndication_st_sf = -1;
int hf_L1_FAPI_rxCqiIndication_st_sfn = -1;
int hf_L1_FAPI_rxCqiIndication_st_numOfCqi = -1;
int hf_L1_FAPI_rxCqiIndication_st_cqiPduInfo = -1;
int hf_L1_FAPI_rxCqiIndication_st_pduBuffer = -1;
int hf_L1_FAPI_rachIndication_st = -1;
int hf_L1_FAPI_rachIndication_st_sf = -1;
int hf_L1_FAPI_rachIndication_st_sfn = -1;
int hf_L1_FAPI_rachIndication_st_numOfPreamble = -1;
int hf_L1_FAPI_rachIndication_st_rachPduInfo = -1;
int hf_L1_FAPI_srsIndication_st = -1;
int hf_L1_FAPI_srsIndication_st_sf = -1;
int hf_L1_FAPI_srsIndication_st_sfn = -1;
int hf_L1_FAPI_srsIndication_st_numOfUe = -1;
int hf_L1_FAPI_srsIndication_st_srsPduInfo = -1;
int hf_L1_lte_phy_header = -1;
int hf_L1_lte_phy_header_msgId = -1;
int hf_L1_lte_phy_header_lenVendorSpecific = -1;
int hf_L1_lte_phy_header_msgLen = -1;
int hf_L1_FAPI_harqIndication_st_sfnsf = -1;
int hf_L1_unparsed_data = -1;
int hf_L1_FAPI_ueConfig_st = -1;
int hf_L1_FAPI_ueConfig_st_tag = -1;


static hf_register_info hf[] = {
{ &hf_L1_unparsed_data, 
	{ "Unparsed protocol data","L1.unparsed_data",FT_BYTES,BASE_NONE, NULL, 0x0,"Unparsed frr protocol data", HFILL }},
{ &hf_L1_FAPI_ueConfig_st, 
	{ "UE CONFIG ","L1.FAPI_ueConfig_st",FT_NONE, BASE_NONE, NULL, 0x0,"UE CONFIG ", HFILL }},
{ &hf_L1_FAPI_ueConfig_st_tag, 
	{ "Tag","L1.FAPI_ueConfig_st.tag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_ueConfig_st_tag_values), 0x0,"Tag", HFILL }},
{ &hf_L1_FAPI_ueConfig_st_tagLen, 
	{ "Tag Len","L1.FAPI_ueConfig_st.tagLen",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Tag Len", HFILL }},
{ &hf_L1_FAPI_ueConfig_st_value, 
	{ "value","L1.FAPI_ueConfig_st.value",FT_BYTES,BASE_NONE ,NULL,0x0,"value", HFILL }},
{ &hf_L1_FAPI_ueConfig_st_value1, 
	{ "value","L1.FAPI_ueConfig_st.value1",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"value", HFILL }},
{ &hf_L1_FAPI_ueConfig_st_value2, 
	{ "value","L1.FAPI_ueConfig_st.value2",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"value", HFILL }},
{ &hf_L1_FAPI_cellConfig_st, 
	{ "CELL CONFIG","L1.FAPI_cellConfig_st",FT_NONE, BASE_NONE, NULL, 0x0,"CELL CONFIG", HFILL }},
{ &hf_L1_FAPI_cellConfig_st_tag, 
	{ "Tag","L1.FAPI_cellConfig_st.tag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_cellConfig_st_tag_values), 0x0,"Tag", HFILL }},
{ &hf_L1_FAPI_cellConfig_st_tagLen, 
	{ "Tag Length","L1.FAPI_cellConfig_st.tagLen",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Tag Length", HFILL }},
{ &hf_L1_FAPI_cellConfig_st_value, 
	{ "Value","L1.FAPI_cellConfig_st.value",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Value", HFILL }},
{ &hf_L1_FAPI_paramResponseTLV_st, 
	{ "PARAM RESPONSE TLV","L1.FAPI_paramResponseTLV_st",FT_NONE, BASE_NONE, NULL, 0x0,"PARAM RESPONSE TLV", HFILL }},
{ &hf_L1_FAPI_paramResponseTLV_st_tag, 
	{ "Tag","L1.FAPI_paramResponseTLV_st.tag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_paramResponseTLV_st_tag_values), 0x0,"Tag", HFILL }},
{ &hf_L1_FAPI_paramResponseTLV_st_tagLen, 
	{ "Tag Length","L1.FAPI_paramResponseTLV_st.tagLen",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Tag Length", HFILL }},
{ &hf_L1_FAPI_paramResponseTLV_st_value, 
	{ "Value","L1.FAPI_paramResponseTLV_st.value",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Value", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st, 
	{ "DCI FORMAT1 ","L1.FAPI_dciFormat1_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT1 ", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat1_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat1_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat1_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat1_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat1_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat1_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat1_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat1_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat1_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat1_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_rntiType, 
	{ "rnti Type","L1.FAPI_dciFormat1_st.rntiType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1_st_rntiType_values), 0x0,"rnti Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1_st_padding, 
	{ "Padding","L1.FAPI_dciFormat1_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_padding, 
	{ "Padding","L1.FAPI_dciFormat1C_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st, 
	{ "DCI FORMAT1A ","L1.FAPI_dciFormat1A_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT1A ", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat1A_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1A_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_vRBassignmentFlag, 
	{ "VRB assignment Flag","L1.FAPI_dciFormat1A_st.vRBassignmentFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1A_st_vRBassignmentFlag_values), 0x0,"VRB assignment Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat1A_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat1A_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat1A_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat1A_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat1A_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat1A_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1A_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat1A_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_allocatePrachFlag, 
	{ "Allocate PRACH Flag","L1.FAPI_dciFormat1A_st.allocatePrachFlag",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Allocate PRACH Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_preambleIndex, 
	{ "preamble Index","L1.FAPI_dciFormat1A_st.preambleIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"preamble Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat1A_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_pRACHMaskIndex, 
	{ "PRACH Mask Index","L1.FAPI_dciFormat1A_st.pRACHMaskIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PRACH Mask Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_rntiType, 
	{ "rnti Type","L1.FAPI_dciFormat1A_st.rntiType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1A_st_rntiType_values), 0x0,"rnti Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_padding, 
	{ "Padding","L1.FAPI_dciFormat1A_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st, 
	{ "DCI FORMAT1B ","L1.FAPI_dciFormat1B_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT1B ", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat1B_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1B_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_vRBassignmentFlag, 
	{ "VRB assignment Flag","L1.FAPI_dciFormat1B_st.vRBassignmentFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1B_st_vRBassignmentFlag_values), 0x0,"VRB assignment Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat1B_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat1B_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat1B_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat1B_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat1B_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_tPMI, 
	{ "tPMI","L1.FAPI_dciFormat1B_st.tPMI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"tPMI", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_pmi, 
	{ "PMI","L1.FAPI_dciFormat1B_st.pmi",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PMI", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat1B_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1B_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat1B_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat1B_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_nGAP, 
	{ "n GAP","L1.FAPI_dciFormat1B_st.nGAP",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n GAP", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_padding, 
	{ "Padding","L1.FAPI_dciFormat1B_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st, 
	{ "DCI FORMAT1C ","L1.FAPI_dciFormat1C_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT1C ", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat1C_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1C_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat1C_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat1C_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat1C_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat1C_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_nGAP, 
	{ "n GAP","L1.FAPI_dciFormat1C_st.nGAP",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n GAP", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_tbSizeIndex, 
	{ "TB SIZE INDEX","L1.FAPI_dciFormat1C_st.tbSizeIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"TB SIZE INDEX", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat1C_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st, 
	{ "DCI FORMAT1D ","L1.FAPI_dciFormat1D_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT1D ", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat1D_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1D_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_vRBassignmentFlag, 
	{ "VRB assignment Flag","L1.FAPI_dciFormat1D_st.vRBassignmentFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1D_st_vRBassignmentFlag_values), 0x0,"VRB assignment Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat1D_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat1D_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat1D_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat1D_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat1D_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_tPMI, 
	{ "tPMI","L1.FAPI_dciFormat1D_st.tPMI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"tPMI", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat1D_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat1D_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat1D_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_nGAP, 
	{ "n GAP","L1.FAPI_dciFormat1D_st.nGAP",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n GAP", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat1D_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_dlPowerOffset, 
	{ "DL POWER Offset","L1.FAPI_dciFormat1D_st.dlPowerOffset",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DL POWER Offset", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_padding, 
	{ "Padding","L1.FAPI_dciFormat1D_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st, 
	{ "DCI FORMAT2 ","L1.FAPI_dciFormat2_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT2 ", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat2_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat2_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1A_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat1A_st.resAllocationType",FT_UINT8,BASE_HEX_DEC ,NULL, 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1B_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat1B_st.resAllocationType",FT_UINT8,BASE_HEX_DEC ,NULL, 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1C_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat1C_st.resAllocationType",FT_UINT8,BASE_HEX_DEC ,NULL, 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat1D_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat1D_st.resAllocationType",FT_UINT8,BASE_HEX_DEC ,NULL, 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat2_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat2_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat2_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat2_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag, 
	{ "tb To Code Word Swap Flag","L1.FAPI_dciFormat2_st.tbToCodeWordSwapFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2_st_tbToCodeWordSwapFlag_values), 0x0,"tb To Code Word Swap Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_mcs_2, 
	{ "MCS 2","L1.FAPI_dciFormat2_st.mcs_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_redundancyVersion_2, 
	{ "redundancy Version 2","L1.FAPI_dciFormat2_st.redundancyVersion_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_newDataIndicator_2, 
	{ "new Data Indicator 2","L1.FAPI_dciFormat2_st.newDataIndicator_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat2_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_preCodingInfo, 
	{ "Pre Coding Info","L1.FAPI_dciFormat2_st.preCodingInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Pre Coding Info", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat2_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat2_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat2_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat2_st_rntiType, 
	{ "rnti Type","L1.FAPI_dciFormat2_st.rntiType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2_st_rntiType_values), 0x0,"rnti Type", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st, 
	{ "DCI FORMAT2A ","L1.FAPI_dciFormat2A_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI FORMAT2A ", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_aggregationLevel, 
	{ "aggregation Level","L1.FAPI_dciFormat2A_st.aggregationLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2A_st_aggregationLevel_values), 0x0,"aggregation Level", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dciFormat2A_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2A_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_mcs_1, 
	{ "MCS 1","L1.FAPI_dciFormat2A_st.mcs_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_redundancyVersion_1, 
	{ "redundancy Version 1","L1.FAPI_dciFormat2A_st.redundancyVersion_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_rbCoding, 
	{ "RB Coding","L1.FAPI_dciFormat2A_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_newDataIndicator_1, 
	{ "new Data Indicator 1","L1.FAPI_dciFormat2A_st.newDataIndicator_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 1", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag, 
	{ "tb To Code Word Swap Flag","L1.FAPI_dciFormat2A_st.tbToCodeWordSwapFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2A_st_tbToCodeWordSwapFlag_values), 0x0,"tb To Code Word Swap Flag", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_mcs_2, 
	{ "MCS 2","L1.FAPI_dciFormat2A_st.mcs_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_redundancyVersion_2, 
	{ "redundancy Version 2","L1.FAPI_dciFormat2A_st.redundancyVersion_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_newDataIndicator_2, 
	{ "new Data Indicator 2","L1.FAPI_dciFormat2A_st.newDataIndicator_2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indicator 2", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_harqProcessNum, 
	{ "harq Process Num","L1.FAPI_dciFormat2A_st.harqProcessNum",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Process Num", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_preCodingInfo, 
	{ "Pre Coding Info","L1.FAPI_dciFormat2A_st.preCodingInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Pre Coding Info", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_tpc, 
	{ "TPC","L1.FAPI_dciFormat2A_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2A_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_txPower, 
	{ "tx Power","L1.FAPI_dciFormat2A_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_dlAssignmentIndex, 
	{ "dl Assignment Index","L1.FAPI_dciFormat2A_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl Assignment Index", HFILL }},
{ &hf_L1_FAPI_dciFormat2A_st_rntiType, 
	{ "rnti Type","L1.FAPI_dciFormat2A_st.rntiType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciFormat2A_st_rntiType_values), 0x0,"rnti Type", HFILL }},
{ &hf_L1_FAPI_dciDLPduInfo_st, 
	{ "DCI DL PDU INFO","L1.FAPI_dciDLPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DCI DL PDU INFO", HFILL }},
{ &hf_L1_FAPI_dciDLPduInfo_st_dciFormat, 
	{ "DciFormat","L1.FAPI_dciDLPduInfo_st.dciFormat",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dciDLPduInfo_st_dciFormat_values), 0x0,"DciFormat", HFILL }},
{ &hf_L1_FAPI_dciDLPduInfo_st_cceIndex, 
	{ "CCE Index","L1.FAPI_dciDLPduInfo_st.cceIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CCE Index", HFILL }},
{ &hf_L1_FAPI_dciDLPduInfo_st_rnti, 
	{ "rnti","L1.FAPI_dciDLPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_dciDLPduInfo_st_dciPdu, 
	{ "DCI PDU","L1.FAPI_dciDLPduInfo_st.dciPdu",FT_BYTES,BASE_NONE ,NULL,0x0,"DCI PDU", HFILL }},
{ &hf_L1_FAPI_bchConfigPDUInfo_st, 
	{ "BCH CONFIG PDU INFO","L1.FAPI_bchConfigPDUInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"BCH CONFIG PDU INFO", HFILL }},
{ &hf_L1_FAPI_bchConfigPDUInfo_st_bchPduLen, 
	{ "bch Pdu Len","L1.FAPI_bchConfigPDUInfo_st.bchPduLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"bch Pdu Len", HFILL }},
{ &hf_L1_FAPI_bchConfigPDUInfo_st_pduIndex, 
	{ "pdu Index","L1.FAPI_bchConfigPDUInfo_st.pduIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Index", HFILL }},
{ &hf_L1_FAPI_bchConfigPDUInfo_st_txPower, 
	{ "transmission Power","L1.FAPI_bchConfigPDUInfo_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"transmission Power", HFILL }},
{ &hf_L1_FAPI_bchConfigPDUInfo_st_padding, 
	{ "padding","L1.FAPI_bchConfigPDUInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st, 
	{ "MCH CONFIG PDU INFO","L1.FAPI_mchConfigPDUInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"MCH CONFIG PDU INFO", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_mchPduLen, 
	{ "mch Pdu Len","L1.FAPI_mchConfigPDUInfo_st.mchPduLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"mch Pdu Len", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_pduIndex, 
	{ "pdu Index","L1.FAPI_mchConfigPDUInfo_st.pduIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Index", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_rnti, 
	{ "rnti","L1.FAPI_mchConfigPDUInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_mchConfigPDUInfo_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_mchConfigPDUInfo_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_modulationType, 
	{ "modulation Type","L1.FAPI_mchConfigPDUInfo_st.modulationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_mchConfigPDUInfo_st_modulationType_values), 0x0,"modulation Type", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_rbCoding, 
	{ "RB Coding","L1.FAPI_mchConfigPDUInfo_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_txPower, 
	{ "transmission Power","L1.FAPI_mchConfigPDUInfo_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"transmission Power", HFILL }},
{ &hf_L1_FAPI_mchConfigPDUInfo_st_padding, 
	{ "Padding","L1.FAPI_mchConfigPDUInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_beamFormingVectorInfo_st, 
	{ "BEAM FORMING VECTOR INFO","L1.FAPI_beamFormingVectorInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"BEAM FORMING VECTOR INFO", HFILL }},
{ &hf_L1_FAPI_beamFormingVectorInfo_st_subBandIndex, 
	{ "sub Band Index","L1.FAPI_beamFormingVectorInfo_st.subBandIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sub Band Index", HFILL }},
{ &hf_L1_FAPI_beamFormingVectorInfo_st_numOfAntenna, 
	{ "num Of Antenna","L1.FAPI_beamFormingVectorInfo_st.numOfAntenna",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of Antenna", HFILL }},
{ &hf_L1_FAPI_beamFormingVectorInfo_st_bfValue_per_antenna, 
	{ "bf Value per antenna","L1.FAPI_beamFormingVectorInfo_st.bfValue_per_antenna",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"bf Value per antenna", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st, 
	{ "DLSCH CONFIG PDU INFO","L1.FAPI_dlSCHConfigPDUInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DLSCH CONFIG PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_dlschPduLen, 
	{ "dlsch Pdu Len","L1.FAPI_dlSCHConfigPDUInfo_st.dlschPduLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"dlsch Pdu Len", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_pduIndex, 
	{ "pdu Index","L1.FAPI_dlSCHConfigPDUInfo_st.pduIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Index", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_rnti, 
	{ "rnti","L1.FAPI_dlSCHConfigPDUInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_dlSCHConfigPDUInfo_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlSCHConfigPDUInfo_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag, 
	{ "vRB assignment Flag","L1.FAPI_dlSCHConfigPDUInfo_st.vRBassignmentFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlSCHConfigPDUInfo_st_vRBassignmentFlag_values), 0x0,"vRB assignment Flag", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_rbCoding, 
	{ "rb Coding","L1.FAPI_dlSCHConfigPDUInfo_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rb Coding", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_mcs, 
	{ "MCS","L1.FAPI_dlSCHConfigPDUInfo_st.mcs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_redundancyVersion, 
	{ "redundancy Version","L1.FAPI_dlSCHConfigPDUInfo_st.redundancyVersion",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_transportBlocks, 
	{ "transport Blocks","L1.FAPI_dlSCHConfigPDUInfo_st.transportBlocks",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"transport Blocks", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag, 
	{ "tb To Code Word Swap Flag","L1.FAPI_dlSCHConfigPDUInfo_st.tbToCodeWordSwapFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlSCHConfigPDUInfo_st_tbToCodeWordSwapFlag_values), 0x0,"tb To Code Word Swap Flag", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme, 
	{ "transmission Scheme","L1.FAPI_dlSCHConfigPDUInfo_st.transmissionScheme",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlSCHConfigPDUInfo_st_transmissionScheme_values), 0x0,"transmission Scheme", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfLayers, 
	{ "num Of Layers","L1.FAPI_dlSCHConfigPDUInfo_st.numOfLayers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of Layers", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_numOfSubBand, 
	{ "num Of SubBand","L1.FAPI_dlSCHConfigPDUInfo_st.numOfSubBand",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of SubBand", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_ueCatagoryCapacity, 
	{ "ue Catagory Capacity","L1.FAPI_dlSCHConfigPDUInfo_st.ueCatagoryCapacity",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ue Catagory Capacity", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_pA, 
	{ "pA","L1.FAPI_dlSCHConfigPDUInfo_st.pA",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlSCHConfigPDUInfo_st_pA_values), 0x0,"pA", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_deltaPowerOffsetAIndex, 
	{ "delta Power Offset A Index","L1.FAPI_dlSCHConfigPDUInfo_st.deltaPowerOffsetAIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"delta Power Offset A Index", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_nGap, 
	{ "n Gap","L1.FAPI_dlSCHConfigPDUInfo_st.nGap",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n Gap", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_nPRB, 
	{ "n PRB","L1.FAPI_dlSCHConfigPDUInfo_st.nPRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n PRB", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_numRbPerSubBand, 
	{ "num Rb Per Sub Band","L1.FAPI_dlSCHConfigPDUInfo_st.numRbPerSubBand",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"num Rb Per Sub Band", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_numbfVector, 
	{ "num bf Vector","L1.FAPI_dlSCHConfigPDUInfo_st.numbfVector",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"num bf Vector", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_subBandInfo, 
	{ "sub Band Info","L1.FAPI_dlSCHConfigPDUInfo_st.subBandInfo",FT_BYTES,BASE_NONE ,NULL,0x0,"sub Band Info", HFILL }},
{ &hf_L1_FAPI_dlSCHConfigPDUInfo_st_bfVector, 
	{ "bf Vector","L1.FAPI_dlSCHConfigPDUInfo_st.bfVector",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"bf Vector", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st, 
	{ "PCH PDU CONFIG INFO","L1.FAPI_pchPduConfigInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"PCH PDU CONFIG INFO", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_pchPduLen, 
	{ "pch Pdu Len","L1.FAPI_pchPduConfigInfo_st.pchPduLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pch Pdu Len", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_pduIndex, 
	{ "pdu Index","L1.FAPI_pchPduConfigInfo_st.pduIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Index", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_pRNTI, 
	{ "p RNTI","L1.FAPI_pchPduConfigInfo_st.pRNTI",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"p RNTI", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_resAllocationType, 
	{ "res Allocation Type","L1.FAPI_pchPduConfigInfo_st.resAllocationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_pchPduConfigInfo_st_resAllocationType_values), 0x0,"res Allocation Type", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag, 
	{ "vRB assignment Flag","L1.FAPI_pchPduConfigInfo_st.vRBassignmentFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_pchPduConfigInfo_st_vRBassignmentFlag_values), 0x0,"vRB assignment Flag", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_rbCoding, 
	{ "RB Coding","L1.FAPI_pchPduConfigInfo_st.rbCoding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"RB Coding", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_mcs, 
	{ "MCS","L1.FAPI_pchPduConfigInfo_st.mcs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_redundancyVersion, 
	{ "redundancy Version","L1.FAPI_pchPduConfigInfo_st.redundancyVersion",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"redundancy Version", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_numOftransportBlocks, 
	{ "num Of transport Blocks","L1.FAPI_pchPduConfigInfo_st.numOftransportBlocks",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of transport Blocks", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag, 
	{ "tb To Code Word Swap Flag","L1.FAPI_pchPduConfigInfo_st.tbToCodeWordSwapFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_pchPduConfigInfo_st_tbToCodeWordSwapFlag_values), 0x0,"tb To Code Word Swap Flag", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_transmissionScheme, 
	{ "transmission Scheme","L1.FAPI_pchPduConfigInfo_st.transmissionScheme",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_pchPduConfigInfo_st_transmissionScheme_values), 0x0,"transmission Scheme", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_numOfLayers, 
	{ "num Of Layers","L1.FAPI_pchPduConfigInfo_st.numOfLayers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of Layers", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_codeBookIndex, 
	{ "code Book Index","L1.FAPI_pchPduConfigInfo_st.codeBookIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"code Book Index", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_ueCatagoryCapacity, 
	{ "Ue Catagory Capacity","L1.FAPI_pchPduConfigInfo_st.ueCatagoryCapacity",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Ue Catagory Capacity", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_pA, 
	{ "pA","L1.FAPI_pchPduConfigInfo_st.pA",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_pchPduConfigInfo_st_pA_values), 0x0,"pA", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_nPRB, 
	{ "n PRB","L1.FAPI_pchPduConfigInfo_st.nPRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n PRB", HFILL }},
{ &hf_L1_FAPI_pchPduConfigInfo_st_txPower, 
	{ "tx Power","L1.FAPI_pchPduConfigInfo_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"tx Power", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st, 
	{ "DL CONFIG PDU INFO","L1.FAPI_dlConfigPDUInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL CONFIG PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_pduType, 
	{ "PduType","L1.FAPI_dlConfigPDUInfo_st.pduType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlConfigPDUInfo_st_pduType_values), 0x0,"PduType", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_pduSize, 
	{ "pdu Size","L1.FAPI_dlConfigPDUInfo_st.pduSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pdu Size", HFILL }},
//{ &hf_L1_FAPI_dlConfigPDUInfo_st_vishal, 
//	{ "vishal","L1.FAPI_dlConfigPDUInfo_st.vishal",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"vishal", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_DCIPdu, 
	{ "DCI Pdu","L1.FAPI_dlConfigPDUInfo_st.DCIPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DCI Pdu", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_BCHPdu, 
	{ "BCH Pdu","L1.FAPI_dlConfigPDUInfo_st.BCHPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"BCH Pdu", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_MCHPdu, 
	{ "MCH Pdu","L1.FAPI_dlConfigPDUInfo_st.MCHPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCH Pdu", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_DlSCHPdu, 
	{ "DlSCH Pdu","L1.FAPI_dlConfigPDUInfo_st.DlSCHPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DlSCH Pdu", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_PChPdu, 
	{ "PCh Pdu","L1.FAPI_dlConfigPDUInfo_st.PChPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PCh Pdu", HFILL }},
{ &hf_L1_FAPI_dlConfigPDUInfo_st_padding, 
	{ "Padding","L1.FAPI_dlConfigPDUInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dlTLVInfo_st, 
	{ "DL TLV INFO","L1.FAPI_dlTLVInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL TLV INFO", HFILL }},
{ &hf_L1_FAPI_dlTLVInfo_st_tag, 
	{ "Tag","L1.FAPI_dlTLVInfo_st.tag",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Tag", HFILL }},
{ &hf_L1_FAPI_dlTLVInfo_st_tagLen, 
	{ "Tag Len","L1.FAPI_dlTLVInfo_st.tagLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Tag Len", HFILL }},
//{ &hf_L1_FAPI_dlTLVInfo_st_padding, 
//	{ "padding","L1.FAPI_dlTLVInfo_st.padding",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Tag Len", HFILL }},
{ &hf_L1_FAPI_dlTLVInfo_st_value, 
	{ "value","L1.FAPI_dlTLVInfo_st.value",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"value", HFILL }},
{ &hf_L1_FAPI_dlPduInfo_st, 
	{ "DL PDU INFO","L1.FAPI_dlPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlPduInfo_st_pduLen, 
	{ "pdu Len","L1.FAPI_dlPduInfo_st.pduLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Len", HFILL }},
{ &hf_L1_FAPI_dlPduInfo_st_pduIndex, 
	{ "pdu Index","L1.FAPI_dlPduInfo_st.pduIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pdu Index", HFILL }},
{ &hf_L1_FAPI_dlPduInfo_st_numOfTLV, 
	{ "num Of TLV","L1.FAPI_dlPduInfo_st.numOfTLV",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"num Of TLV", HFILL }},
{ &hf_L1_FAPI_dlPduInfo_st_dlTLVInfo, 
	{ "DL TLV Info","L1.FAPI_dlPduInfo_st.dlTLVInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DL TLV Info", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st, 
	{ "DL HI PDU INFO","L1.FAPI_dlHiPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL HI PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_pduType, 
	{ "pdu Type","L1.FAPI_dlHiPduInfo_st.pduType",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pdu Type", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_hipduSize, 
	{ "hi pdu Size","L1.FAPI_dlHiPduInfo_st.hipduSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"hi pdu Size", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_rbStart, 
	{ "RB Start","L1.FAPI_dlHiPduInfo_st.rbStart",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RB Start", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_cyclicShift2_forDMRS, 
	{ "cyclic Shift2 for DMRS","L1.FAPI_dlHiPduInfo_st.cyclicShift2_forDMRS",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cyclic Shift2 for DMRS", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_hiValue, 
	{ "HI Value","L1.FAPI_dlHiPduInfo_st.hiValue",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlHiPduInfo_st_hiValue_values), 0x0,"HI Value", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_iPHICH, 
	{ "I PHICH","L1.FAPI_dlHiPduInfo_st.iPHICH",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"I PHICH", HFILL }},
{ &hf_L1_FAPI_dlHiPduInfo_st_txPower, 
	{ "transmission Power","L1.FAPI_dlHiPduInfo_st.txPower",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"transmission Power", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st, 
	{ "DL DCI PDU INFO","L1.FAPI_dlDCIPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL DCI PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_pduType, 
	{ "pdu Type","L1.FAPI_dlDCIPduInfo_st.pduType",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pdu Type", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_uldcipduSize, 
	{ "UL dci pdu Size","L1.FAPI_dlDCIPduInfo_st.uldcipduSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL dci pdu Size", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_ulDCIFormat, 
	{ "ul DCI Format","L1.FAPI_dlDCIPduInfo_st.ulDCIFormat",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul DCI Format", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_cceIndex, 
	{ "cce Index","L1.FAPI_dlDCIPduInfo_st.cceIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cce Index", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_rnti, 
	{ "rnti","L1.FAPI_dlDCIPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_aggLevel, 
	{ "Agg Level","L1.FAPI_dlDCIPduInfo_st.aggLevel",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlDCIPduInfo_st_aggLevel_values), 0x0,"Agg Level", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_rbStart, 
	{ "RB Start","L1.FAPI_dlDCIPduInfo_st.rbStart",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RB Start", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_numOfRB, 
	{ "num Of RB","L1.FAPI_dlDCIPduInfo_st.numOfRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of RB", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_mcs, 
	{ "MCS","L1.FAPI_dlDCIPduInfo_st.mcs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"MCS", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_cyclicShift2_forDMRS, 
	{ "cyclic Shift2 for DMRS","L1.FAPI_dlDCIPduInfo_st.cyclicShift2_forDMRS",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cyclic Shift2 for DMRS", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_freqEnabledFlag, 
	{ "freq Enabled Flag","L1.FAPI_dlDCIPduInfo_st.freqEnabledFlag",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"freq Enabled Flag", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_freqHoppingBits, 
	{ "freq Hopping Bits","L1.FAPI_dlDCIPduInfo_st.freqHoppingBits",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"freq Hopping Bits", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_newDataIndication, 
	{ "new Data Indication","L1.FAPI_dlDCIPduInfo_st.newDataIndication",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"new Data Indication", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_ueTxAntennaSelection, 
	{ "ue Tx Antenna Selection","L1.FAPI_dlDCIPduInfo_st.ueTxAntennaSelection",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ue Tx Antenna Selection", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_tpc, 
	{ "TPC","L1.FAPI_dlDCIPduInfo_st.tpc",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlDCIPduInfo_st_tpc_values), 0x0,"TPC", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_cqiRequest, 
	{ "cqi Request","L1.FAPI_dlDCIPduInfo_st.cqiRequest",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_dlDCIPduInfo_st_cqiRequest_values), 0x0,"cqi Request", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_ulIndex, 
	{ "UL Index","L1.FAPI_dlDCIPduInfo_st.ulIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL Index", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_dlAssignmentIndex, 
	{ "DL Assignment Index","L1.FAPI_dlDCIPduInfo_st.dlAssignmentIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DL Assignment Index", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_padding, 
	{ "Padding","L1.FAPI_dlDCIPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_dlDCIPduInfo_st_tpcBitMap, 
	{ "TPC Bit Map","L1.FAPI_dlDCIPduInfo_st.tpcBitMap",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"TPC Bit Map", HFILL }},
{ &hf_L1_FAPI_cqiPduInfo_st, 
	{ "CQI PDU INFO","L1.FAPI_cqiPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"CQI PDU INFO", HFILL }},
{ &hf_L1_FAPI_cqiPduInfo_st_pucchIndex, 
	{ "pucch Index","L1.FAPI_cqiPduInfo_st.pucchIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pucch Index", HFILL }},
{ &hf_L1_FAPI_cqiPduInfo_st_dlCqiPmiSize, 
	{ "DL Cqi Pmi Size","L1.FAPI_cqiPduInfo_st.dlCqiPmiSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DL Cqi Pmi Size", HFILL }},
{ &hf_L1_FAPI_cqiPduInfo_st_padding, 
	{ "Padding","L1.FAPI_cqiPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_srPduInfo_st, 
	{ "SR PDU INFO","L1.FAPI_srPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"SR PDU INFO", HFILL }},
{ &hf_L1_FAPI_srPduInfo_st_pucchIndex, 
	{ "pucch Index","L1.FAPI_srPduInfo_st.pucchIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pucch Index", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st, 
	{ "TDD HARQ PDU INFO","L1.FAPI_tddHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"TDD HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_harqSize, 
	{ "harq Size","L1.FAPI_tddHarqPduInfo_st.harqSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Size", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_acknackMode, 
	{ "ack nack Mode","L1.FAPI_tddHarqPduInfo_st.acknackMode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ack nack Mode", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_numOfPUCCHResource, 
	{ "num Of PUCCH Resource","L1.FAPI_tddHarqPduInfo_st.numOfPUCCHResource",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num Of PUCCH Resource", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_0, 
	{ "n_PUCCH_1_0","L1.FAPI_tddHarqPduInfo_st.n_PUCCH_1_0",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"n_PUCCH_1_0", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_1, 
	{ "n_PUCCH_1_1","L1.FAPI_tddHarqPduInfo_st.n_PUCCH_1_1",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"n_PUCCH_1_1", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_2, 
	{ "n_PUCCH_1_2","L1.FAPI_tddHarqPduInfo_st.n_PUCCH_1_2",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"n_PUCCH_1_2", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_n_PUCCH_1_3, 
	{ "n_PUCCH_1_3","L1.FAPI_tddHarqPduInfo_st.n_PUCCH_1_3",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"n_PUCCH_1_3", HFILL }},
{ &hf_L1_FAPI_tddHarqPduInfo_st_padding, 
	{ "Padding","L1.FAPI_tddHarqPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_fddHarqPduInfo_st, 
	{ "FDD HARQ PDU INFO","L1.FAPI_fddHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"FDD HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex, 
	{ "pucch Index","L1.FAPI_fddHarqPduInfo_st.pucchIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pucch Index", HFILL }},
{ &hf_L1_FAPI_fddHarqPduInfo_st_pucchIndex1, 
	{ "pucch Index1","L1.FAPI_fddHarqPduInfo_st.pucchIndex1",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pucch Index1", HFILL }},
{ &hf_L1_FAPI_fddHarqPduInfo_st_harqSize, 
	{ "harq Size","L1.FAPI_fddHarqPduInfo_st.harqSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harq Size", HFILL }},
{ &hf_L1_FAPI_fddHarqPduInfo_st_padding, 
	{ "Padding","L1.FAPI_fddHarqPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqInfo_st_padding, 
	{ "Padding","L1.FAPI_ulSCHHarqInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_ulPDUConfigInfo_st_padding, 
	{ "Padding","L1.FAPI_ulPDUConfigInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st, 
	{ "SRS PDU INFO","L1.FAPI_srsPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"SRS PDU INFO", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_handle, 
	{ "handle","L1.FAPI_srsPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"handle", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_size, 
	{ "size","L1.FAPI_srsPduInfo_st.size",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"size", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_rnti, 
	{ "rnti","L1.FAPI_srsPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_srsBandWidth, 
	{ "srs BandWidth","L1.FAPI_srsPduInfo_st.srsBandWidth",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"srs BandWidth", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_freqDomainPosition, 
	{ "freq Domain Position","L1.FAPI_srsPduInfo_st.freqDomainPosition",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"freq Domain Position", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_srsHoppingBandWidth, 
	{ "srs Hopping BandWidth","L1.FAPI_srsPduInfo_st.srsHoppingBandWidth",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"srs Hopping BandWidth", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_transmissionComb, 
	{ "transmission Comb","L1.FAPI_srsPduInfo_st.transmissionComb",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"transmission Comb", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_isrsSRSConfigIndex, 
	{ "Isrs SRS Config Index","L1.FAPI_srsPduInfo_st.isrsSRSConfigIndex",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Isrs SRS Config Index", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_soundingRefCyclicShift, 
	{ "sounding Ref Cyclic Shift","L1.FAPI_srsPduInfo_st.soundingRefCyclicShift",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sounding Ref Cyclic Shift", HFILL }},
{ &hf_L1_FAPI_srsPduInfo_st_padding, 
	{ "Padding","L1.FAPI_srsPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st, 
	{ "CQI RI PDU INFO","L1.FAPI_cqiRiPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"CQI RI PDU INFO", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRank_1, 
	{ "Dl CQI PMI Size Rank 1","L1.FAPI_cqiRiPduInfo_st.dlCqiPmiSizeRank_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Dl CQI PMI Size Rank 1", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_dlCqiPmiSizeRankGT_1, 
	{ "Dl CQI PMI Size GT 1","L1.FAPI_cqiRiPduInfo_st.dlCqiPmiSizeRankGT_1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Dl CQI PMI Size GT 1", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_riSize, 
	{ "RI Size","L1.FAPI_cqiRiPduInfo_st.riSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RI Size", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetCQI, 
	{ "Delta Offset CQI","L1.FAPI_cqiRiPduInfo_st.deltaOffsetCQI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Delta Offset CQI", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_deltaOffsetRI, 
	{ "Delta Offset RI","L1.FAPI_cqiRiPduInfo_st.deltaOffsetRI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Delta Offset RI", HFILL }},
{ &hf_L1_FAPI_cqiRiPduInfo_st_padding, 
	{ "Padding","L1.FAPI_cqiRiPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_uciSrPduInfo_st, 
	{ "UCI SR PDU INFO","L1.FAPI_uciSrPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI SR PDU INFO", HFILL }},
{ &hf_L1_FAPI_uciSrPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciSrPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciSrPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciSrPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciSrPduInfo_st_srInfo, 
	{ "SR Info","L1.FAPI_uciSrPduInfo_st.srInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SR Info", HFILL }},
{ &hf_L1_FAPI_uciCqiPduInfo_st, 
	{ "UCI CQI PDU Info","L1.FAPI_uciCqiPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI CQI PDU Info", HFILL }},
{ &hf_L1_FAPI_uciCqiPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciCqiPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciCqiPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciCqiPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciCqiPduInfo_st_padding, 
	{ "Padding","L1.FAPI_uciCqiPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_uciCqiPduInfo_st_cqiInfo, 
	{ "CQI Info","L1.FAPI_uciCqiPduInfo_st.cqiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI Info", HFILL }},
{ &hf_L1_FAPI_uciHarqPduInfo_st, 
	{ "UCI HARQ PDU Info","L1.FAPI_uciHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI HARQ PDU Info", HFILL }},
{ &hf_L1_FAPI_uciHarqPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciHarqPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciHarqPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciHarqPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciHarqPduInfo_st_padding, 
	{ "Padding","L1.FAPI_uciHarqPduInfo_st.padding",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_uciHarqPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_uciHarqPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_uciSrHarqPduInfo_st, 
	{ "UCI SR HARQ PDU INFO","L1.FAPI_uciSrHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI SR HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_uciSrHarqPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciSrHarqPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciSrHarqPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciSrHarqPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciSrHarqPduInfo_st_srInfo, 
	{ "SR Info","L1.FAPI_uciSrHarqPduInfo_st.srInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SR Info", HFILL }},
{ &hf_L1_FAPI_uciSrHarqPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_uciSrHarqPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st, 
	{ "UCI CQI HARQ PDU INFO","L1.FAPI_uciCqiHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI CQI HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciCqiHarqPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st_cqiInfo, 
	{ "CQI Info","L1.FAPI_uciCqiHarqPduInfo_st.cqiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI Info", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciCqiHarqPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st_padding, 
	{ "Padding","L1.FAPI_uciCqiHarqPduInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_uciCqiHarqPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_uciCqiHarqPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_uciCqiSrPduInfo_st, 
	{ "UCI CQI SR PDU INFO","L1.FAPI_uciCqiSrPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI CQI SR PDU INFO", HFILL }},
{ &hf_L1_FAPI_uciCqiSrPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciCqiSrPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciCqiSrPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciCqiSrPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciCqiSrPduInfo_st_cqiInfo, 
	{ "CQI Info","L1.FAPI_uciCqiSrPduInfo_st.cqiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI Info", HFILL }},
{ &hf_L1_FAPI_uciCqiSrPduInfo_st_srInfo, 
	{ "SR Info","L1.FAPI_uciCqiSrPduInfo_st.srInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SR Info", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st, 
	{ "UCI CQI SR HARQ PDU INFO","L1.FAPI_uciCqiSrHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UCI CQI SR HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st_handle, 
	{ "Handle","L1.FAPI_uciCqiSrHarqPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st_rnti, 
	{ "RNTI","L1.FAPI_uciCqiSrHarqPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st_srInfo, 
	{ "SR Info","L1.FAPI_uciCqiSrHarqPduInfo_st.srInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SR Info", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st_cqiInfo, 
	{ "CQI Info","L1.FAPI_uciCqiSrHarqPduInfo_st.cqiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI Info", HFILL }},
{ &hf_L1_FAPI_uciCqiSrHarqPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_uciCqiSrHarqPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st, 
	{ "ULSCH PDU INFO","L1.FAPI_ulSCHPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"ULSCH PDU INFO", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_handle, 
	{ "Handle","L1.FAPI_ulSCHPduInfo_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_size, 
	{ "Size","L1.FAPI_ulSCHPduInfo_st.size",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Size", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_rnti, 
	{ "Rnti","L1.FAPI_ulSCHPduInfo_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Rnti", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_rbStart, 
	{ "RB Start","L1.FAPI_ulSCHPduInfo_st.rbStart",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RB Start", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_numOfRB, 
	{ "Num of RB","L1.FAPI_ulSCHPduInfo_st.numOfRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of RB", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_modulationType, 
	{ "Modulation Type","L1.FAPI_ulSCHPduInfo_st.modulationType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_ulSCHPduInfo_st_modulationType_values), 0x0,"Modulation Type", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_cyclicShift2forDMRS, 
	{ "Cyclic Shift2 for DMRS","L1.FAPI_ulSCHPduInfo_st.cyclicShift2forDMRS",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Cyclic Shift2 for DMRS", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingenabledFlag, 
	{ "Frequency Hopping Enabled Flag","L1.FAPI_ulSCHPduInfo_st.freqHoppingenabledFlag",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Frequency Hopping Enabled Flag", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_freqHoppingBits, 
	{ "Frequency Hopping Bits","L1.FAPI_ulSCHPduInfo_st.freqHoppingBits",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Frequency Hopping Bits", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_newDataIndication, 
	{ "New Data Indication","L1.FAPI_ulSCHPduInfo_st.newDataIndication",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"New Data Indication", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_redundancyVersion, 
	{ "Redundancy Version","L1.FAPI_ulSCHPduInfo_st.redundancyVersion",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Redundancy Version", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_harqProcessNumber, 
	{ "Harq Process Number","L1.FAPI_ulSCHPduInfo_st.harqProcessNumber",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Harq Process Number", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_ulTxMode, 
	{ "Ul Tx Mode","L1.FAPI_ulSCHPduInfo_st.ulTxMode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Ul Tx Mode", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_currentTxNB, 
	{ "Current Tx NB","L1.FAPI_ulSCHPduInfo_st.currentTxNB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Current Tx NB", HFILL }},
{ &hf_L1_FAPI_ulSCHPduInfo_st_nSRS, 
	{ "nSRS","L1.FAPI_ulSCHPduInfo_st.nSRS",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"nSRS", HFILL }},
{ &hf_L1_FAPI_initialTxParam_st, 
	{ "INITIAL Tx PARAM","L1.FAPI_initialTxParam_st",FT_NONE, BASE_NONE, NULL, 0x0,"INITIAL Tx PARAM", HFILL }},
{ &hf_L1_FAPI_initialTxParam_st_nSRSInitial, 
	{ "nSRS Initial","L1.FAPI_initialTxParam_st.nSRSInitial",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"nSRS Initial", HFILL }},
{ &hf_L1_FAPI_initialTxParam_st_initialNumOfRB, 
	{ "Initial Num of RB","L1.FAPI_initialTxParam_st.initialNumOfRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Initial Num of RB", HFILL }},
{ &hf_L1_FAPI_initialTxParam_st_padding, 
	{ "padding","L1.FAPI_initialTxParam_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st, 
	{ "ULSCH CQI HARQ RI PDU INFO","L1.FAPI_ulSCHCqiHarqRIPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"ULSCH CQI HARQ RI PDU INFO", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_ulSchPduInfo, 
	{ "UlSch PDU Info","L1.FAPI_ulSCHCqiHarqRIPduInfo_st.ulSchPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UlSch PDU Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_cqiRiInfo, 
	{ "CQI RI Info","L1.FAPI_ulSCHCqiHarqRIPduInfo_st.cqiRiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI RI Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_ulSCHCqiHarqRIPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiHarqRIPduInfo_st_initialTxParamInfo, 
	{ "Initial Tx Param Info","L1.FAPI_ulSCHCqiHarqRIPduInfo_st.initialTxParamInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Initial Tx Param Info", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqPduInfo_st, 
	{ "ULSCH HARQ PDU INFO","L1.FAPI_ulSCHHarqPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"ULSCH HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqInfo_st, 
	{ "ULSCH HARQ INFO","L1.FAPI_ulSCHHarqInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"ULSCH HARQ PDU INFO", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqInfo_st_harqSize, 
	{ "HARQ SIZE","L1.FAPI_ulSCHHarqInfo_st.harqSize",FT_UINT8, BASE_HEX_DEC, NULL, 0x0,"HARQ SIZE", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqInfo_st_deltaOffsetHarq, 
	{ "DELTA OFFSET HARQ","L1.FAPI_ulSCHHarqInfo_st.deltaOffsetHarq",FT_UINT8, BASE_HEX_DEC, NULL, 0x0,"DELTA OFFSET HARQ", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqInfo_st_ackNackMode, 
	{ "ACK NACK MODE","L1.FAPI_ulSCHHarqInfo_st.ackNackMode",FT_UINT8, BASE_HEX_DEC, NULL, 0x0,"DELTA OFFSET HARQ", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqPduInfo_st_ulSCHPduInfo, 
	{ "UlSch PDU Info","L1.FAPI_ulSCHHarqPduInfo_st.ulSCHPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UlSch PDU Info", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqPduInfo_st_harqInfo, 
	{ "HARQ Info","L1.FAPI_ulSCHHarqPduInfo_st.harqInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"HARQ Info", HFILL }},
{ &hf_L1_FAPI_ulSCHHarqPduInfo_st_initialTxParamInfo, 
	{ "Initial Tx Param Info","L1.FAPI_ulSCHHarqPduInfo_st.initialTxParamInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Initial Tx Param Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiRiPduInfo_st, 
	{ "ULSCH CQI RI PDU INFO","L1.FAPI_ulSCHCqiRiPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"ULSCH CQI RI PDU INFO", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiRiPduInfo_st_ulSCHPduInfo, 
	{ "UlSch PDU Info","L1.FAPI_ulSCHCqiRiPduInfo_st.ulSCHPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UlSch PDU Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiRiPduInfo_st_cqiRiInfo, 
	{ "CQI RI Info","L1.FAPI_ulSCHCqiRiPduInfo_st.cqiRiInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI RI Info", HFILL }},
{ &hf_L1_FAPI_ulSCHCqiRiPduInfo_st_initialTxParamInfo, 
	{ "Initial Tx Param Info","L1.FAPI_ulSCHCqiRiPduInfo_st.initialTxParamInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Initial Tx Param Info", HFILL }},
{ &hf_L1_FAPI_ulPDUConfigInfo_st, 
	{ "UL PDU CONFIGURATION INFO","L1.FAPI_ulPDUConfigInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"UL PDU CONFIGURATION INFO", HFILL }},
{ &hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType, 
	{ "ULConfigPduType","L1.FAPI_ulPDUConfigInfo_st.ulConfigPduType",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_ulPDUConfigInfo_st_ulConfigPduType_values), 0x0,"ULConfigPduType", HFILL }},
{ &hf_L1_FAPI_ulPDUConfigInfo_st_ulConfigPduSize, 
	{ "UL Config PDU Size","L1.FAPI_ulPDUConfigInfo_st.ulConfigPduSize",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL Config PDU Size", HFILL }},
{ &hf_L1_FAPI_ulPDUConfigInfo_st_ulPduConfigInfo, 
	{ "Ul PDU Config Info","L1.FAPI_ulPDUConfigInfo_st.ulPduConfigInfo",FT_BYTES,BASE_NONE ,NULL,0x0,"Ul PDU Config Info", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st, 
	{ "UL Data PDU Indication","L1.FAPI_ulDataPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"UL Data PDU Indication", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_handle, 
	{ "Handle","L1.FAPI_ulDataPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_ulDataPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_length, 
	{ "Length","L1.FAPI_ulDataPduIndication_st.length",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Length", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_dataOffset, 
	{ "Data Offset","L1.FAPI_ulDataPduIndication_st.dataOffset",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Data Offset", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_timingAdvance, 
	{ "Timing Advance","L1.FAPI_ulDataPduIndication_st.timingAdvance",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Timing Advance", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_ulCqi, 
	{ "UL CQI","L1.FAPI_ulDataPduIndication_st.ulCqi",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL CQI", HFILL }},
{ &hf_L1_FAPI_ulDataPduIndication_st_padding, 
	{ "Padding","L1.FAPI_ulDataPduIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Padding", HFILL }},
{ &hf_L1_FAPI_fddHarqPduIndication_st, 
	{ "FDD HARQ PDU Indication","L1.FAPI_fddHarqPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"FDD HARQ PDU Indication", HFILL }},
{ &hf_L1_FAPI_fddHarqPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_fddHarqPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_fddHarqPduIndication_st_harqTB1, 
	{ "HARQ TB 1","L1.FAPI_fddHarqPduIndication_st.harqTB1",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_fddHarqPduIndication_st_harqTB1_values), 0x0,"HARQ TB 1", HFILL }},
{ &hf_L1_FAPI_fddHarqPduIndication_st_harqTB2, 
	{ "HARQ TB 2","L1.FAPI_fddHarqPduIndication_st.harqTB2",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_fddHarqPduIndication_st_harqTB2_values), 0x0,"HARQ TB 2", HFILL }},
{ &hf_L1_FAPI_tddBundlingHarqInfo_st, 
	{ "TDD BUNDLING HARQ INFO","L1.FAPI_tddBundlingHarqInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"TDD BUNDLING HARQ INFO", HFILL }},
{ &hf_L1_FAPI_tddBundlingHarqInfo_st_value0, 
	{ "value_0","L1.FAPI_tddBundlingHarqInfo_st.value0",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddBundlingHarqInfo_st_value0_values), 0x0,"value_0", HFILL }},
{ &hf_L1_FAPI_tddBundlingHarqInfo_st_value1, 
	{ "value_1","L1.FAPI_tddBundlingHarqInfo_st.value1",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddBundlingHarqInfo_st_value1_values), 0x0,"value_1", HFILL }},
{ &hf_L1_FAPI_tddMultiplexingHarqInfo_st, 
	{ "TDD MULTIPLEXING HARQ INFO","L1.FAPI_tddMultiplexingHarqInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"TDD MULTIPLEXING HARQ INFO", HFILL }},
{ &hf_L1_FAPI_tddMultiplexingHarqInfo_st_value0, 
	{ "value0","L1.FAPI_tddMultiplexingHarqInfo_st.value0",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddMultiplexingHarqInfo_st_value0_values), 0x0,"value0", HFILL }},
{ &hf_L1_FAPI_tddMultiplexingHarqInfo_st_value1, 
	{ "value1","L1.FAPI_tddMultiplexingHarqInfo_st.value1",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddMultiplexingHarqInfo_st_value1_values), 0x0,"value1", HFILL }},
{ &hf_L1_FAPI_tddMultiplexingHarqInfo_st_value2, 
	{ "value2","L1.FAPI_tddMultiplexingHarqInfo_st.value2",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddMultiplexingHarqInfo_st_value2_values), 0x0,"value2", HFILL }},
{ &hf_L1_FAPI_tddMultiplexingHarqInfo_st_value3, 
	{ "value3","L1.FAPI_tddMultiplexingHarqInfo_st.value3",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_tddMultiplexingHarqInfo_st_value3_values), 0x0,"value3", HFILL }},
{ &hf_L1_FAPI_tddSpcialBundlingHarqInfo_st, 
	{ "TDD SPECIAL BUNDLING HARQ","L1.FAPI_tddSpcialBundlingHarqInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"TDD SPECIAL BUNDLING HARQ", HFILL }},
{ &hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_value_0, 
	{ "Value_0","L1.FAPI_tddSpcialBundlingHarqInfo_st.value_0",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Value_0", HFILL }},
{ &hf_L1_FAPI_crcPduIndication_st, 
	{ "CRC PDU Indication","L1.FAPI_crcPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"CRC PDU Indication", HFILL }},
{ &hf_L1_FAPI_crcPduIndication_st_handle, 
	{ "Handle","L1.FAPI_crcPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_crcPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_crcPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_crcPduIndication_st_crcFlag, 
	{ "CRC Flag","L1.FAPI_crcPduIndication_st.crcFlag",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_crcPduIndication_st_crcFlag_values), 0x0,"CRC Flag", HFILL }},
{ &hf_L1_FAPI_crcPduIndication_st_padding, 
	{ "padding","L1.FAPI_crcPduIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st, 
	{ "CQI PDU Indication","L1.FAPI_cqiPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"CQI PDU Indication", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_handle, 
	{ "Handle","L1.FAPI_cqiPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_cqiPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_length, 
	{ "LENGTH","L1.FAPI_cqiPduIndication_st.length",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"LENGTH", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_dataOffset, 
	{ "Data Offset","L1.FAPI_cqiPduIndication_st.dataOffset",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Data Offset", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_timingAdvance, 
	{ "Timing Advance","L1.FAPI_cqiPduIndication_st.timingAdvance",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Timing Advance", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_ulCqi, 
	{ "UL CQI","L1.FAPI_cqiPduIndication_st.ulCqi",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL CQI", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_ri, 
	{ "RI","L1.FAPI_cqiPduIndication_st.ri",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RI", HFILL }},
{ &hf_L1_FAPI_cqiPduIndication_st_padding, 
	{ "padding","L1.FAPI_cqiPduIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_tddSpcialBundlingHarqInfo_st_padding,
        { "padding","L1.FAPI_tddSpcialBundlingHarqInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_tddBundlingHarqInfo_st_padding,
        { "padding","L1.FAPI_tddBundlingHarqInfo_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},

{ &hf_L1_FAPI_srPduIndication_st, 
	{ "SR PDU INFO","L1.FAPI_srPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"SR PDU INFO", HFILL }},
{ &hf_L1_FAPI_srPduIndication_st_handle, 
	{ "Handle","L1.FAPI_srPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_srPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_srPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_srPduIndication_st_padding, 
	{ "padding","L1.FAPI_srPduIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_rachPduIndication_st, 
	{ "RACH PDU INFO","L1.FAPI_rachPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"RACH PDU INFO", HFILL }},
{ &hf_L1_FAPI_rachPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_rachPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_rachPduIndication_st_timingAdvance, 
	{ "Timing Advance","L1.FAPI_rachPduIndication_st.timingAdvance",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Timing Advance", HFILL }},
{ &hf_L1_FAPI_rachPduIndication_st_preamble, 
	{ "Preamble","L1.FAPI_rachPduIndication_st.preamble",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Preamble", HFILL }},
{ &hf_L1_FAPI_rachPduIndication_st_padding, 
	{ "padding","L1.FAPI_rachPduIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st, 
	{ "SRS PDU Info","L1.FAPI_srsPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"SRS PDU Info", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_handle, 
	{ "Handle","L1.FAPI_srsPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"Handle", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_rnti, 
	{ "RNTI","L1.FAPI_srsPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_dopplerEstimation, 
	{ "Doppler Estimation","L1.FAPI_srsPduIndication_st.dopplerEstimation",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Doppler Estimation", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_timingAdvance, 
	{ "Timing Advance","L1.FAPI_srsPduIndication_st.timingAdvance",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Timing Advance", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_numOfRB, 
	{ "Num of RB","L1.FAPI_srsPduIndication_st.numOfRB",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of RB", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_rbStart, 
	{ "RB Start","L1.FAPI_srsPduIndication_st.rbStart",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RB Start", HFILL }},
{ &hf_L1_FAPI_srsPduIndication_st_snr, 
	{ "SNR","L1.FAPI_srsPduIndication_st.snr",FT_BYTES,BASE_NONE ,NULL,0x0,"SNR", HFILL }},
{ &hf_L1_FAPI_errMsgBody1_st, 
	{ "ERROR MSG BODY 1","L1.FAPI_errMsgBody1_st",FT_NONE, BASE_NONE, NULL, 0x0,"ERROR MSG BODY 1", HFILL }},
{ &hf_L1_FAPI_errMsgBody1_st_recvdSfnSf, 
	{ "Recieved Sfn Sf","L1.FAPI_errMsgBody1_st.recvdSfnSf",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Recieved Sfn Sf", HFILL }},
{ &hf_L1_FAPI_errMsgBody1_st_expectedSfnSf, 
	{ "Expected Sfn Sf","L1.FAPI_errMsgBody1_st.expectedSfnSf",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Expected Sfn Sf", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st, 
	{ "ERROR MSG BODY 2","L1.FAPI_errMsgBody2_st",FT_NONE, BASE_NONE, NULL, 0x0,"ERROR MSG BODY 2", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st_subErrCode, 
	{ "SUB Error Code","L1.FAPI_errMsgBody2_st.subErrCode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SUB Error Code", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st_direction, 
	{ "Direction","L1.FAPI_errMsgBody2_st.direction",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Direction", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st_rnti, 
	{ "RNTI","L1.FAPI_errMsgBody2_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"RNTI", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st_pduType, 
	{ "PDU Type","L1.FAPI_errMsgBody2_st.pduType",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PDU Type", HFILL }},
{ &hf_L1_FAPI_errMsgBody2_st_padding, 
	{ "padding","L1.FAPI_errMsgBody2_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_errMsgBody3_st, 
	{ "ERROR MSG BODY 3","L1.FAPI_errMsgBody3_st",FT_NONE, BASE_NONE, NULL, 0x0,"ERROR MSG BODY 3", HFILL }},
{ &hf_L1_FAPI_errMsgBody3_st_subErrCode, 
	{ "SUB Error Code","L1.FAPI_errMsgBody3_st.subErrCode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SUB Error Code", HFILL }},
{ &hf_L1_FAPI_errMsgBody3_st_phichLowestulRbIndex, 
	{ "PHICH Lowest UL RB Index","L1.FAPI_errMsgBody3_st.phichLowestulRbIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PHICH Lowest UL RB Index", HFILL }},
{ &hf_L1_FAPI_errMsgBody4_st, 
	{ "ERROR MSG BODY 4","L1.FAPI_errMsgBody4_st",FT_NONE, BASE_NONE, NULL, 0x0,"ERROR MSG BODY 4", HFILL }},
{ &hf_L1_FAPI_errMsgBody4_st_subErrCode, 
	{ "Sub Error Code","L1.FAPI_errMsgBody4_st.subErrCode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Sub Error Code", HFILL }},
{ &hf_L1_FAPI_errMsgBody4_st_pduIndex, 
	{ "PDU Index","L1.FAPI_errMsgBody4_st.pduIndex",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"PDU Index", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st, 
	{ "L1 API MSG","L1.FAPI_l1ApiMsg_st",FT_NONE, BASE_NONE, NULL, 0x0,"L1 API MSG", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st_msgId, 
	{ "Msg Id","L1.FAPI_l1ApiMsg_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st_lenVendorSpecific, 
	{ "Len Vendor Specific","L1.FAPI_l1ApiMsg_st.lenVendorSpecific",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Len Vendor Specific", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st_msgLen, 
	{ "Msg Length","L1.FAPI_l1ApiMsg_st.msgLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Msg Length", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st_msgBody, 
	{ "Msg Body","L1.FAPI_l1ApiMsg_st.msgBody",FT_BYTES,BASE_NONE ,NULL,0x0,"Msg Body", HFILL }},
{ &hf_L1_FAPI_l1ApiMsg_st_vendorMsgBody, 
	{ "Vendor Msg Body","L1.FAPI_l1ApiMsg_st.vendorMsgBody",FT_BYTES,BASE_NONE ,NULL,0x0,"Vendor Msg Body", HFILL }},
{ &hf_L1_FAPI_paramRequest_st, 
	{ "PHY PARAM REQUEST ","L1.FAPI_paramRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY PARAM REQUEST ", HFILL }},
{ &hf_L1_FAPI_paramRequest_st_msgId, 
	{ "Msg Id","L1.FAPI_paramRequest_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_FAPI_paramResponse_st, 
	{ "PHY PARAM RESPONSE","L1.FAPI_paramResponse_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY PARAM RESPONSE", HFILL }},
{ &hf_L1_FAPI_paramResponse_st_errCode, 
	{ "ErrCode","L1.FAPI_paramResponse_st.errCode",FT_UINT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_paramResponse_st_errCode_values), 0x0,"ErrCode", HFILL }},
{ &hf_L1_FAPI_paramResponse_st_numOfTlv, 
	{ "Num of TLV","L1.FAPI_paramResponse_st.numOfTlv",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of TLV", HFILL }},
{ &hf_L1_FAPI_paramResponse_st_padding, 
	{ "padding","L1.FAPI_paramResponse_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_paramResponse_st_tlvs, 
	{ "TLVs","L1.FAPI_paramResponse_st.tlvs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"TLVs", HFILL }},
{ &hf_L1_FAPI_phyStart_st, 
	{ "PHY START","L1.FAPI_phyStart_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY START", HFILL }},
{ &hf_L1_FAPI_phyStart_st_msgId, 
	{ "Msg Id","L1.FAPI_phyStart_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_FAPI_phyStop_st, 
	{ "PHY STOP","L1.FAPI_phyStop_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY STOP", HFILL }},
{ &hf_L1_FAPI_phyStop_st_msgId, 
	{ "Msg Id","L1.FAPI_phyStop_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_FAPI_phyStopIndication_st, 
	{ "PHY STOP INDICATION","L1.FAPI_phyStopIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY STOP INDICATION", HFILL }},
{ &hf_L1_FAPI_phyStopIndication_st_msgId, 
	{ "Msg Id","L1.FAPI_phyStopIndication_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_FAPI_phyCellConfigRequest_st, 
	{ "PHY CELL CONFIG REQUEST","L1.FAPI_phyCellConfigRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY CELL CONFIG REQUEST", HFILL }},
{ &hf_L1_FAPI_phyCellConfigRequest_st_numOfTlv, 
	{ "Num of TLV","PhyCellConfigReq.numOfTlv",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of TLV", HFILL }},
{ &hf_L1_FAPI_phyCellConfigRequest_st_padding, 
	{ "padding","L1.FAPI_phyCellConfigRequest_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_phyCellConfigRequest_st_configtlvs, 
	{ "Config TLVs","L1.FAPI_phyCellConfigRequest_st.configtlvs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Config TLVs", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st, 
	{ "PHY CELL CONFIG RESP","L1.FAPI_phyCellConfigResp_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY CELL CONFIG RESP", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_errorCode, 
	{ "ErrorCode","L1.FAPI_phyCellConfigResp_st.errorCode",FT_UINT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_phyCellConfigResp_st_errorCode_values), 0x0,"ErrorCode", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_numOfInvalidOrunsupportedTLV, 
	{ "Num of Invalid Or Unsupported Tlvs","L1.FAPI_phyCellConfigResp_st.numOfInvalidOrunsupportedTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of Invalid Or Unsupported Tlvs", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_numOfMissingTLV, 
	{ "Num of Missing Tlvs","L1.FAPI_phyCellConfigResp_st.numOfMissingTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of Missing Tlvs", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_padding, 
	{ "padding","L1.FAPI_phyCellConfigResp_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_listOfTLV, 
	{ "List of TLVs","L1.FAPI_phyCellConfigResp_st.listOfTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"List of TLVs", HFILL }},
{ &hf_L1_FAPI_phyCellConfigResp_st_listOfMissingTlv, 
	{ "List of Missing TLVs","L1.FAPI_phyCellConfigResp_st.listOfMissingTlv",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"List of Missing TLVs", HFILL }},
{ &hf_L1_FAPI_ueConfigRequest_st, 
	{ "UE CONFIG REQUEST","L1.FAPI_ueConfigRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"UE CONFIG REQUEST", HFILL }},
{ &hf_L1_FAPI_ueConfigRequest_st_numOfTlv, 
	{ "Num of TLV","L1.FAPI_ueConfigRequest_st.numOfTlv",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of TLV", HFILL }},
{ &hf_L1_FAPI_ueConfigRequest_st_tlvs, 
	{ "TLVs","L1.FAPI_ueConfigRequest_st.tlvs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"TLVs", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st, 
	{ "PHY UE CONFIG RESP","L1.FAPI_phyUeConfigResp_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY UE CONFIG RESP", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_errorCode, 
	{ "ErrorCode","L1.FAPI_phyUeConfigResp_st.errorCode",FT_UINT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_phyUeConfigResp_st_errorCode_values), 0x0,"ErrorCode", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_numOfInvalidOrunsupportedTLV, 
	{ "Num of Invalid Or Unsupported TLV","L1.FAPI_phyUeConfigResp_st.numOfInvalidOrunsupportedTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of Invalid Or Unsupported TLV", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_numOfMissingTLV, 
	{ "Num of Missing TLV","L1.FAPI_phyUeConfigResp_st.numOfMissingTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of Missing TLV", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_padding, 
	{ "padding","L1.FAPI_phyUeConfigResp_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_listOfTLV, 
	{ "List of TLV","L1.FAPI_phyUeConfigResp_st.listOfTLV",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"List of TLV", HFILL }},
{ &hf_L1_FAPI_phyUeConfigResp_st_listOfMissingTlv, 
	{ "List of Missing TLV","L1.FAPI_phyUeConfigResp_st.listOfMissingTlv",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"List of Missing TLV", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st, 
	{ "PHY ERROR INDICATION","L1.FAPI_phyErrorIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"PHY ERROR INDICATION", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_msgId, 
	{ "Msg ID","L1.FAPI_phyErrorIndication_st.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg ID", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_padding, 
	{ "padding","L1.FAPI_phyErrorIndication_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_errorCode, 
	{ "ErrorCode","L1.FAPI_phyErrorIndication_st.errorCode",FT_UINT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&L1_FAPI_phyErrorIndication_st_errorCode_values), 0x0,"ErrorCode", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_msgBody1, 
	{ "Error msgBody1","L1.FAPI_phyErrorIndication_st.msgBody1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Error msgBody1", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_msgBody2, 
	{ "Error msgBody2","L1.FAPI_phyErrorIndication_st.msgBody2",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Error msgBody2", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_msgBody3, 
	{ "Error msgBody3","L1.FAPI_phyErrorIndication_st.msgBody3",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Error msgBody3", HFILL }},
{ &hf_L1_FAPI_phyErrorIndication_st_msgBody4, 
	{ "Error msgBody4","L1.FAPI_phyErrorIndication_st.msgBody4",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Error msgBody4", HFILL }},
{ &hf_L1_FAPI_subFrameIndication_st, 
	{ "SUB FRAME INDICATION","L1.FAPI_subFrameIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"SUB FRAME INDICATION", HFILL }},
{ &hf_L1_FAPI_subFrameIndication_st_sf, 
	{ "Sf","L1.FAPI_subFrameIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_subFrameIndication_st_sfn, 
	{ "Sfn","L1.FAPI_subFrameIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st, 
	{ "DL CONFIG REQUEST","L1.FAPI_dlConfigRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL CONFIG REQUEST", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_sf, 
	{ "Sf","L1.FAPI_dlConfigRequest_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_sfn, 
	{ "Sfn","L1.FAPI_dlConfigRequest_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_length, 
	{ "Length","L1.FAPI_dlConfigRequest_st.length",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Length", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_cfi, 
	{ "CFI","L1.FAPI_dlConfigRequest_st.cfi",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CFI", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_numDCI, 
	{ "Num of DCI","L1.FAPI_dlConfigRequest_st.numDCI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of DCI", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_numOfPDU, 
	{ "Num of PDU","L1.FAPI_dlConfigRequest_st.numOfPDU",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of PDU", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_txPowerForPCFICH, 
	{ "Tx Power for PCFICH","L1.FAPI_dlConfigRequest_st.txPowerForPCFICH",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Tx Power for PCFICH", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_numOfPDSCHRNTI, 
	{ "Num of PDSCH RNTI","L1.FAPI_dlConfigRequest_st.numOfPDSCHRNTI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of PDSCH RNTI", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_padding, 
	{ "padding","L1.FAPI_dlConfigRequest_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_dlConfigRequest_st_dlConfigpduInfo, 
	{ "Dl Config PDU Info","L1.FAPI_dlConfigRequest_st.dlConfigpduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Dl Config PDU Info", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st, 
	{ "UL CONFIG REQUEST","L1.FAPI_ulConfigRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"UL CONFIG REQUEST", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_sf, 
	{ "Sf","L1.FAPI_ulConfigRequest_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_sfn, 
	{ "Sfn","L1.FAPI_ulConfigRequest_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_ulConfigLen, 
	{ "UL Config Length","L1.FAPI_ulConfigRequest_st.ulConfigLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"UL Config Length", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_numOfPdu, 
	{ "Num of PDU","L1.FAPI_ulConfigRequest_st.numOfPdu",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of PDU", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_rachFreqResources, 
	{ "RACH Frequency Resources","L1.FAPI_ulConfigRequest_st.rachFreqResources",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RACH Frequency Resources", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_srsPresent, 
	{ "SRS Present","L1.FAPI_ulConfigRequest_st.srsPresent",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SRS Present", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_padding, 
	{ "padding","L1.FAPI_ulConfigRequest_st.padding",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"padding", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_ulPduConfigInfo, 
	{ "UL PDU Config Info","L1.FAPI_ulConfigRequest_st.ulPduConfigInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL PDU Config Info", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st, 
	{ "HI DCI0 PDU INFO","L1.FAPI_dlHiDCIPduInfo_st",FT_NONE, BASE_NONE, NULL, 0x0,"HI DCI0 PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st_sf, 
	{ "Sf","L1.FAPI_dlHiDCIPduInfo_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st_sfn, 
	{ "Sfn","L1.FAPI_dlHiDCIPduInfo_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st_numOfDCI, 
	{ "Num of DCI","L1.FAPI_dlHiDCIPduInfo_st.numOfDCI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of DCI", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st_numOfHI, 
	{ "Num of HI","L1.FAPI_dlHiDCIPduInfo_st.numOfHI",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Num of HI", HFILL }},
{ &hf_L1_FAPI_dlHiDCIPduInfo_st_hidciPduInfo, 
	{ "HI DCI PDU INFO","L1.FAPI_dlHiDCIPduInfo_st.hidciPduInfo",FT_BYTES,BASE_NONE ,NULL,0x0,"HI DCI PDU INFO", HFILL }},
{ &hf_L1_FAPI_dlDataTxRequest_st, 
	{ "DL DATA Tx REQUEST","L1.FAPI_dlDataTxRequest_st",FT_NONE, BASE_NONE, NULL, 0x0,"DL DATA Tx REQUEST", HFILL }},
{ &hf_L1_FAPI_dlDataTxRequest_st_sf, 
	{ "Sf","L1.FAPI_dlDataTxRequest_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_dlDataTxRequest_st_sfn, 
	{ "Sfn","L1.FAPI_dlDataTxRequest_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_dlDataTxRequest_st_numOfPDU, 
	{ "Num of PDU","L1.FAPI_dlDataTxRequest_st.numOfPDU",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of PDU", HFILL }},
{ &hf_L1_FAPI_dlDataTxRequest_st_dlPduInfo, 
	{ "DL PDU Info","L1.FAPI_dlDataTxRequest_st.dlPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"DL PDU Info", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st, 
	{ "Rx ULSCH INDICATION","L1.FAPI_rxULSCHIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"Rx ULSCH INDICATION", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st_sf, 
	{ "Sf","L1.FAPI_rxULSCHIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st_sfn, 
	{ "Sfn","L1.FAPI_rxULSCHIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st_numOfPdu, 
	{ "Num of PDU","L1.FAPI_rxULSCHIndication_st.numOfPdu",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of PDU", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st_ulDataPduInfo, 
	{ "UL DATA PDU Info","L1.FAPI_rxULSCHIndication_st.ulDataPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"UL DATA PDU Info", HFILL }},
{ &hf_L1_FAPI_rxULSCHIndication_st_pduBuffer, 
	{ "PDU Buffer","L1.FAPI_rxULSCHIndication_st.pduBuffer",FT_BYTES,BASE_NONE ,NULL,0x0,"PDU Buffer", HFILL }},
{ &hf_L1_FAPI_harqIndication_st_sf, 
	{ "Sf","L1.FAPI_harqIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_harqIndication_st_sfn, 
	{ "Sfn","L1.FAPI_harqIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_crcIndication_st, 
	{ "CRC INDICATION","L1.FAPI_crcIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"CRC INDICATION", HFILL }},
{ &hf_L1_FAPI_crcIndication_st_sf, 
	{ "Sf","L1.FAPI_crcIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_crcIndication_st_sfn, 
	{ "Sfn","L1.FAPI_crcIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_crcIndication_st_numOfCrc, 
	{ "Num of CRC","L1.FAPI_crcIndication_st.numOfCrc",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of CRC", HFILL }},
{ &hf_L1_FAPI_crcIndication_st_crcPduInfo, 
	{ "CRC PDU Info","L1.FAPI_crcIndication_st.crcPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CRC PDU Info", HFILL }},
{ &hf_L1_FAPI_rxSRIndication_st, 
	{ "Rx SR INDICATION","L1.FAPI_rxSRIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"Rx SR INDICATION", HFILL }},
{ &hf_L1_FAPI_rxSRIndication_st_sf, 
	{ "Sf","L1.FAPI_rxSRIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_rxSRIndication_st_sfn, 
	{ "Sfn","L1.FAPI_rxSRIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_rxSRIndication_st_numOfSr, 
	{ "Num of SR","L1.FAPI_rxSRIndication_st.numOfSr",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of SR", HFILL }},
{ &hf_L1_FAPI_rxSRIndication_st_srPduInfo, 
	{ "SR PDU Info","L1.FAPI_rxSRIndication_st.srPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SR PDU Info", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st, 
	{ "Rx CQI INDICATION","L1.FAPI_rxCqiIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"Rx CQI INDICATION", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st_sf, 
	{ "Sf","L1.FAPI_rxCqiIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st_sfn, 
	{ "Sfn","L1.FAPI_rxCqiIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st_numOfCqi, 
	{ "Num of CQI","L1.FAPI_rxCqiIndication_st.numOfCqi",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of CQI", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st_cqiPduInfo, 
	{ "CQI PDU Info","L1.FAPI_rxCqiIndication_st.cqiPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CQI PDU Info", HFILL }},
{ &hf_L1_FAPI_rxCqiIndication_st_pduBuffer, 
	{ "PDU Buffer","L1.FAPI_rxCqiIndication_st.pduBuffer",FT_BYTES,BASE_NONE ,NULL,0x0,"PDU Buffer", HFILL }},
{ &hf_L1_FAPI_rachIndication_st, 
	{ "RACH INDICATION","L1.FAPI_rachIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"RACH INDICATION", HFILL }},
{ &hf_L1_FAPI_rachIndication_st_sf, 
	{ "Sf","L1.FAPI_rachIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_rachIndication_st_sfn, 
	{ "Sfn","L1.FAPI_rachIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_rachIndication_st_numOfPreamble, 
	{ "Num of Preamble","L1.FAPI_rachIndication_st.numOfPreamble",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of Preamble", HFILL }},
{ &hf_L1_FAPI_rachIndication_st_rachPduInfo, 
	{ "RACH PDU Info","L1.FAPI_rachIndication_st.rachPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"RACH PDU Info", HFILL }},
{ &hf_L1_FAPI_srsIndication_st, 
	{ "SRS INDICATION","L1.FAPI_srsIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"SRS INDICATION", HFILL }},
{ &hf_L1_FAPI_srsIndication_st_sf, 
	{ "Sf","L1.FAPI_srsIndication_st.sf",FT_UINT16,BASE_DEC ,NULL,0x0F,"Sf", HFILL }},
{ &hf_L1_FAPI_srsIndication_st_sfn, 
	{ "Sfn","L1.FAPI_srsIndication_st.sfn",FT_UINT16,BASE_DEC ,NULL,0XFFF0,"Sfn", HFILL }},
{ &hf_L1_FAPI_srsIndication_st_numOfUe, 
	{ "Num of Ue","L1.FAPI_srsIndication_st.numOfUe",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Num of Ue", HFILL }},
{ &hf_L1_FAPI_srsIndication_st_srsPduInfo, 
	{ "SRS PDU Info","L1.FAPI_srsIndication_st.srsPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"SRS PDU Info", HFILL }},
{ &hf_L1_lte_phy_header, 
	{ "LTE-PHY Header IE","L1.lte_phy_header",FT_NONE, BASE_NONE, NULL, 0x0,"LTE-PHY Header IE", HFILL }},
{ &hf_L1_lte_phy_header_msgId, 
	{ "Msg Id","L1.lte_phy_header.msgId",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Msg Id", HFILL }},
{ &hf_L1_lte_phy_header_lenVendorSpecific, 
	{ "Len Ven Specific","L1.lte_phy_header.lenVendorSpecific",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"Len Ven Specific", HFILL }},
{ &hf_L1_lte_phy_header_msgLen, 
   { "BuffLength","L1.lte_phy_header.msgLen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"BuffLength", HFILL }},
{ &hf_L1_FAPI_harqIndication_st, 
	{ "FAPI_harqIndication_st","L1.FAPI_harqIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"FAPI_harqIndication_st", HFILL }},
{ &hf_L1_FAPI_harqIndication_st_sfnsf, 
	{ "sfnsf","L1.FAPI_harqIndication_st.sfnsf",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"sfnsf", HFILL }},
{ &hf_L1_FAPI_harqIndication_st_numOfHarq, 
	{ "numOfHarq","L1.FAPI_harqIndication_st.numOfHarq",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"numOfHarq", HFILL }},
{ &hf_L1_FAPI_harqIndication_st_harqPduInfo, 
	{ "harqPduInfo","L1.FAPI_harqIndication_st.harqPduInfo",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harqPduInfo", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st, 
	{ "FAPI_tddHarqPduIndication_st","L1.FAPI_tddHarqPduIndication_st",FT_NONE, BASE_NONE, NULL, 0x0,"FAPI_tddHarqPduIndication_st", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st_handle, 
	{ "handle","L1.FAPI_tddHarqPduIndication_st.handle",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"handle", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st_rnti, 
	{ "rnti","L1.FAPI_tddHarqPduIndication_st.rnti",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"rnti", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st_mode, 
	{ "mode","L1.FAPI_tddHarqPduIndication_st.mode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"mode", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st_numOfAckNack, 
	{ "numOfAckNack","L1.FAPI_tddHarqPduIndication_st.numOfAckNack",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"numOfAckNack", HFILL }},
{ &hf_L1_FAPI_tddHarqPduIndication_st_harqBuffer, 
	{ "harqBuffer","L1.FAPI_tddHarqPduIndication_st.harqBuffer",FT_BYTES,BASE_NONE ,NULL,0x0,"harqBuffer", HFILL }},
{ &hf_L1_FAPI_ulConfigRequest_st_sfnsf, 
	{ "sfnsf","L1.FAPI_ulConfigRequest_st.sfnsf",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"sfnsf", HFILL }}
};

/* **Moved End** */
#ifndef ENABLE_STATIC
#define ENABLE_STATIC

G_MODULE_EXPORT const gchar version[] = "0.0";


/****************************************************************************
 * Function Name  :proto_reg_handoff_fapi
 * Inputs         :None
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function creates the dissector and registers a routine
 *                 to be called to do the actual dissecting.
 ****************************************************************************/

void proto_reg_handoff_fapi()
{
    static gboolean initialized=FALSE;
    
    if (!initialized)
    {
       fapi_handle = create_dissector_handle(dissect_fapi, proto_fapi);
//       dissector_add("udp.port", global_port0, fapi_handle);
//       dissector_add("udp.port", global_port1, fapi_handle);
//       dissector_add("udp.port", global_port2, fapi_handle);
//       dissector_add("udp.port", global_port3, fapi_handle);
//       dissector_add("udp.port", global_port4, fapi_handle);
       dissector_add("udp.port", global_port5, fapi_handle);
       dissector_add("udp.port", global_port6, fapi_handle);
       dissector_add("udp.port", global_port7, fapi_handle);
       dissector_add("udp.port", global_port8, fapi_handle);
       dissector_add("udp.port", global_port9, fapi_handle);

    }
}  

/****************************************************************************
 * Function Name  :proto_register_fapi
 * Inputs         :None
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function registers the given protocol.
 ****************************************************************************/

void proto_register_fapi ()
{
  module_t *fapi_module;

  static enum_val_t radio_type_vals[] = {
    {"FDD_RADIO", "FDD", FDD_RADIO},
    {"TDD_RADIO", "TDD", TDD_RADIO},
    {NULL, NULL, -1}
  };

  static enum_val_t endianess_vals[] = {
    {"Little Endian", "LITTLE ENDIAN", 1},
    {"Big Endian", "BIG ENDIAN", 0},
    {NULL, NULL, -1}
  };

  static enum_val_t ul_rnti_type_vals[] = {
    {"C_RNTI",      "C_RNTI",               C_RNTI},
    {"P_RNTI",      "P_RNTI",               P_RNTI},
    {"RA_RNTI",     "RA_RNTI",              RA_RNTI},
    {"SI_RNTI",     "SI_RNTI",              SI_RNTI},
    {"SPS_RNTI",    "SPS_RNTI",             SPS_RNTI},
    {NULL,          NULL,                   -1}
  };

  if (proto_fapi == -1) 
  {
    proto_fapi = proto_register_protocol("FAPI", "FAPI", "fapi");

    proto_register_field_array (proto_fapi, hf, array_length(hf));

    proto_register_subtree_array (ett, array_length (ett));

    register_dissector("fapi", dissect_fapi, proto_fapi);

    /* Preferences */
    fapi_module = prefs_register_protocol(proto_fapi, NULL);

    prefs_register_enum_preference(fapi_module, "radio_type",
        "Radio Type (FDD/TDD)",
        "Radio Type (FDD/TDD)",
        &g_radio_type, radio_type_vals, FALSE);

    prefs_register_enum_preference(fapi_module, "ul_rnti_type",
        "Uplink RNTI Type",
        "By default RNTI Type is C_RNTI. Same Type is used in downlink"
        " as RNTI Type coming in downlink FAPI API is wrong.",
        &g_ul_rnti_type, ul_rnti_type_vals, FALSE);

    prefs_register_enum_preference(fapi_module, "is_little_endian",
        "Endianess for FAPI API IEs",
        "On Intel machines endianess is Little Endian."
        " On p2020 machine it is Big Endian",
        &IS_LITTLE_ENDIAN, endianess_vals, FALSE);
  } 
}
G_MODULE_EXPORT void plugin_register(void)
{
   if (proto_fapi == -1) 
   {
     
      proto_register_fapi();
     
   }
}
       
G_MODULE_EXPORT void plugin_reg_handoff(void)
{
    proto_reg_handoff_fapi();
}
           
#endif



/****************************************************************************
 * Function Name  :dissect_fapi 
 * Inputs         :tvbuff_t: *tvb, 
                   packet_info: *pinfo, 
                   proto_tree: *tree 
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function performs the decoding of the fields  
                   for LTE RRC RRM Messages(dissects the packets presented  
                   to it on Well Defined Port).C Data", "lte.macdata", FT_BYTES, BASE_HEX.

***************************************************************************/

void dissect_fapi (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{   
	guint32 offset=0;
        guint16 typeoftag=0;
        guint16 src = 0;
        guint16 dst = 0;
        proto_item *rrc_item=NULL,*main_item=NULL, *sub_item = NULL;
        proto_tree *rrc_tree=NULL,*main_tree= NULL,*sub_tree=NULL;

        proto_item *oam_item=NULL;
        proto_tree *oam_tree=NULL;

        if(check_col(pinfo->cinfo,COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo,COL_PROTOCOL, "Femto Forum API");
        }
                   
        typeoftag = tvb_get_guint8(tvb, offset);

        if(pinfo->cinfo && check_col(pinfo->cinfo,COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                     val_to_str(typeoftag, tagType_phy, "Unknown Packet"));
        }
        
/******* Changes for Endianness ********** 8DEC ***********/ 
        rrc_item=proto_tree_add_item(tree, hf_L1_lte_phy_header, tvb, 0, -1, FALSE);
        rrc_tree=proto_item_add_subtree(rrc_item, ett_L1);
        TypeOfTag = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(rrc_tree,hf_L1_lte_phy_header_msgId,tvb,offset,1,FALSE);
        offset+=1;
        proto_tree_add_item(rrc_tree,hf_L1_lte_phy_header_lenVendorSpecific,tvb,offset,1,FALSE);
        offset+=1;
        proto_tree_add_item(rrc_tree,hf_L1_lte_phy_header_msgLen,tvb,offset,2,IS_LITTLE_ENDIAN);
        offset+=2;
/********************************************************/

        main_tree=proto_item_add_subtree(main_item,ett_L1_lte_phy_header);

	if (tree)
	{
            switch( TypeOfTag  )
            {
                
                case PHY_PARAM_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_paramRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item );

                    break;
                }      

                case PHY_PARAM_RESPONSE:
                {
        	    offset += (guint32) dissect_L1_FAPI_paramResponse_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_CELL_CONFIG_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyCellConfigRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }
                case PHY_CELL_CONFIG_RESPONSE:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyCellConfigResp_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }
                case PHY_START_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyStart_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_STOP_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyStop_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_STOP_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyStopIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }                                                       

                case PHY_UE_CONFIG_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_ueConfigRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UE_CONFIG_RESPONSE:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyUeConfigResp_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_ERROR_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_phyErrorIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }
/******** SEE IT ***********/
                case PHY_DL_CONFIG_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_dlConfigRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_CONFIG_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_ulConfigRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_SUBFRAME_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_subFrameIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_DL_HI_DCI0_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_dlHiDCIPduInfo_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                } 
/*********SEE IT **********/ 
                case PHY_DL_TX_REQUEST:
                {
        	    offset += (guint32) dissect_L1_FAPI_dlDataTxRequest_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }
                case PHY_UL_HARQ_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_harqIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break ;
                }  
                case PHY_UL_CRC_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_crcIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_RX_ULSCH_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_rxULSCHIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_RACH_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_rachIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_SRS_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_srsIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }

                case PHY_UL_RX_SR_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_rxSRIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }
                case PHY_UL_RX_CQI_INDICATION:
                {
        	    offset += (guint32) dissect_L1_FAPI_rxCqiIndication_st(tvb, pinfo, tree, offset,-1, &rrc_item ); 

                    break;
                }   
		        default: 
		         
                    break;
		        
	        
           }
	
	}	
        return;
  
} 
