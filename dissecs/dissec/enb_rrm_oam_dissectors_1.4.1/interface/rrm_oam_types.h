/******************************************************************************
*
*   FILE NAME:
*
*       rrm_oam_types.h
*
*   DESCRIPTION:
*       This file contains the rrm's structures definitions to be used in the OAM APIs
*
*   DATE            AUTHOR      REFERENCE       REASON
*   31 Jan 2012    Aricent      ---------       Initial
*
*   Copyright (c) 2012, Aricent Inc. All Rights Reserved
*
******************************************************************************/
/*! \file   rrm_oam_types.h
 *  \brief  This file contains the RRM structures definitions to be used in OAM APIs
 *  \date   January 31, 2012
 *  \author Aricent
 */
/*!
 *  \copyright {Copyright (c) 2009, Aricent Inc. All Rights Reserved}
 */

#ifndef _RRM_OAM_TYPES_H
#define _RRM_OAM_TYPES_H
/*! \headerfile rrm_oam_defines.h <> */
#include "rrm_oam_defines.h"
/*! \headerfile rrm_api_defines.h <> */
#include "rrm_api_defines.h"
/*! \headerfile rrm_api_types.h <> */
#include "rrm_api_types.h"
/*! \headerfile rrm_son_intf.h <> */

/*! \  rrm_oam_pdsch_t
 *  \brief This struct contains lte cell ran physical layer PDSCH params
 *  \param p_b Enum variable for PDSCH Config Common 
 *  \param p_a Enum variable for PDSCH Config Dedicated
 */
typedef struct _rrm_oam_pdsch
{
	rrm_oam_pdsch_config_common_pb_et 	p_b;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_pdsch_config_dedicated_p_a_et  	p_a;/*^ M, 0, N, 0, 0 ^*/	
}rrm_oam_pdsch_t;

#define RRM_OAM_SRS_MAX_UP_PTS_PRESENT  0x01
/*! \  rrm_oam_srs_t
 *  \brief This struct contains lte cell ran Physical layer Sounding Reference Signal paramters 
 *  \param srsEnabled           Enum variable for enable/disable of srs
 *  \param srs_bandwidth_config Enum variable for Cell specific srs bandwidth configuration
 *  \param srs_subframe_config  Enum variable for srs subframe configuration
 *  \param srs_max_up_pts       Enum variable for defining whether reconfiguration of SRS applies to UpPts or not   
 *  \param ack_nack_srs_simultaneous_transmission Enum for whether UE can simultaneously transmit SRS & ACK/NACK or not
*/
typedef struct _rrm_oam_srs
{
	rrm_bitmask_t 			bitmask;/*^ BITMASK ^*/
	rrm_oam_srs_enabled_et 		srsEnabled;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_srs_bw_config_et	srs_bandwidth_config;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_srs_subframe_config_et	srs_subframe_config;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_srs_max_up_pts_et	srs_max_up_pts;/*^ O, RRM_OAM_SRS_MAX_UP_PTS_PRESENT, N, 0, 0 ^*/
	rrm_bool_et 			ack_nack_srs_simultaneous_transmission;/*^ M, 0, N, 0, 0 ^*/ 
}rrm_oam_srs_t;
/*! \  rrm_oam_prach_t
 *  \brief This struct contains lte cell physical layer PRACH params
 *  \param root_sequence_index A U16 type variable for logical root sequence index 
 *  \param configuration_index A U8 type variable for index into table defining PRACH resources within frame
 *  \param high_speed_flag A U8 type flag for determining whether unrestricted set(0:False ) or restricted set (1:True) of preambles is used or not
 *  \param zero_correlation_zone_config A U8 type variable preamble sequence generation
 *  \param frequency_offset First phy resource block available for PRACH denoted by phy resource block no.
 */
typedef struct _rrm_oam_prach
{
	U16	root_sequence_index;/*^ M, 0, B, 1, 837 ^*/
	U8	configuration_index;/*^ M, 0, H, 0, 63 ^*/
	U8	high_speed_flag;/*^ M, 0, H, 0, 1 ^*/
	U8	zero_correlation_zone_config;/*^ M, 0, H, 0, 15 ^*/
	U8	frequency_offset; /*^ M, 0, H, 0, 94 ^*/
}rrm_oam_prach_t;
/*! \ rrm_oam_pucch_t
 *  \brief This struct contains lte cell physical layer PUCCH params
 *  \param bitmask Bitmask Value
 *  \param delta_pucch_shift Possible values as per 3GPP spec 36.331 : 0 ,1 ,2
 *  \param n_rb_cqi Denotes Bandwidth in terms of resrc blocks that are available for use by PUCCH formats 2/2a/2b transmission in each slot 
 *  \param n1_pucch_an Parameter used to determine resources used for transmission of PUCCH format 1/1a/1b and 2/2a/2b
 *  \param cqi_pucch_resource_index U16 type for PUCCH resource index
 *  \param tdd_ack_nack_feedback_mode Determine ACK/NACK feedback modes for TDD Bundling or multiplexing
 *  \param pucch_cqi_sinr_value This is the threshold described for reliability decision of CQI on PUCCH
 */
#define RRM_OAM_TDD_ACK_NACK_FEEDBACK_MODE_PRESENT  0x0001
#define RRM_OAM_PUCCH_CQI_SINR_VAL_PRESENT          0x0002

typedef struct _rrm_oam_pucch
{
   rrm_bitmask_t    bitmask;/*^ BITMASK ^*/ 
   U8          	    delta_pucch_shift;/*^ M, 0, H, 0, 2 ^*/
   U8	            n_rb_cqi;/*^ M, 0, H, 0, 98 ^*/
   U16	            n1_pucch_an; /*^ M, 0, H, 0, 2047 ^*/
   U16	            cqi_pucch_resource_index;/*^ M, 0, H, 0, 1184 ^*/
   U8               tdd_ack_nack_feedback_mode;  /*^ O, RRM_OAM_TDD_ACK_NACK_FEEDBACK_MODE_PRESENT, N, 0, 0 ^*/
   U8               pucch_cqi_sinr_value;    /*^ O, RRM_OAM_PUCCH_CQI_SINR_VAL_PRESENT, N, 0, 0 ^*/
}rrm_oam_pucch_t;
/*! \ rrm_oam_pusch_t 
 *  \brief This struct contains lte cell physical layer PUSCH params
 *  \param n_sb Denotes number of sub-bands
 *  \param pusch_hopping_mode Determine if hopping is inter subframe or intra subframe 
 *  \param hopping_offset This is used to compute the set of phy resrce blocks to be used for transmission on PUSCH if Uplink freq hopping mode is enabled
 */
typedef struct _rrm_oam_pusch
{
	U8			 n_sb;/*^ M, 0, B, 1, 4 ^*/
	rrm_oam_hopping_mode_et  pusch_hopping_mode;/*^ M, 0, N, 0, 0 ^*/
	U8			hopping_offset; /*^ M, 0, H, 0, 98 ^*/
}rrm_oam_pusch_t;

/*! \ rrm_oam_ul_reference_signal_t
 *  \brief This struct contains lte cell physical layer Uplink Reference Signal params
 *  \param group_hopping_enabled Determine whether group hopping is enabled or not
 *  \param sequence_hopping_enabled Determine whether sequence hopping enabled or not
*/
typedef struct _rrm_oam_ul_reference_signal
{
	rrm_bool_et		group_hopping_enabled;/*^ M, 0, N, 0, 0 ^*/
	rrm_bool_et		sequence_hopping_enabled;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_ul_reference_signal_t;
/*!  \ rrm_oam_uplink_power_control_t
 *  \brief This struct contains lte cell physical layer Uplink Power Control params
 *  \param p_0_nominal_pusch Denotes the parameter used to compute the UL UE transmit power for transmission on PUSCH for semi persistent grants
 *  \param alpha Denotes the parameter used to compute the UL UE transmit power for transmission on PUSCH
 *  \param p_0_nominal_pucch Denotes the parameter used to compute the UL UE transmit power for transmission on PUCCH
 */
typedef struct _rrm_oam_uplink_power_control
{
	S8					p_0_nominal_pusch;/*^ M, 0, B, -126, 24 ^*/ 
	rrm_oam_alpha_et			alpha;/*^ M, 0, N, 0, 0 ^*/ 
	S8					p_0_nominal_pucch; /*^ M, 0, B, -127, -96 ^*/ 
}rrm_oam_uplink_power_control_t;

/*! \ rrm_oam_prs_t
 *  \brief This struct contains lte cell physical layer Positioning reference Signals params
 *  \param num_prs_resource_blocks Defines no of resource blocks used for PRS
 *  \param prs_configuration_index Variable for PRS configuration index
 *  \param num_consecutive_prs_subfames Defines the no of consecutive positioning subframes
 */
typedef struct _rrm_oam_prs
{
	U8	num_prs_resource_blocks;/*^ M, 0, N, 0, 0 ^*/
	U16	prs_configuration_index;/*^ M, 0, H, 0, 4095 ^*/
	rrm_oam_num_consecutive_prs_sf_et  num_consecutive_prs_subfames;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_prs_t;

#define RRM_OAM_N1_CS_PRESENT 0x01
/*! \ rrm_oam_addl_pucch_config_t 
 *  \brief This struct contains lte cell additional PUCCH physical layer params configurable by OAM
 *  \param bitmask Bitmask Value
 *  \param n1_cs Denotes no of cyclic shift used for PUCCH formats
 */
typedef struct _rrm_oam_addl_pucch_config_t
{
     rrm_bitmask_t         bitmask; /*^ BITMASK ^*/
     U8                    n1_cs; /*^ O, RRM_OAM_N1_CS_PRESENT, N, 0, 0^*/
}rrm_oam_addl_pucch_config_t;

#define RRM_OAM_PUSCH_ENABLE_64_QAM_PRESENT  0x0001
/*! \ rrm_oam_addl_pusch_config_t
 *  \brief This struct contains lte cell additional PUSCH physical layer params configurable by OAM
 *  \param bitmask Bitmask Value
 *  \param pusch_enable_64_qam Indicates whether PUSCH can use 64-QAM modulation technique or not
 */
typedef struct _rrm_oam_addl_pusch_config_t
{
   rrm_bitmask_t  bitmask; /*^ BITMASK ^*/
   U8             pusch_enable_64_qam; /*^ O, RRM_OAM_PUSCH_ENABLE_64_QAM_PRESENT, N, 0, 0^*/
}rrm_oam_addl_pusch_config_t;

#define  RRM_OAM_GROUP_ASSIGMENT_PUSCH_PRESENT                0x0001
#define  RRM_OAM_UL_REFER_SIGNAL_PUSCH_CYCLIC_SHIFT_PRESENT   0x0002
/*!  \ rrm_oam_addl_ul_reference_signal_params_t
 *  \brief This struct contains lte cell additional parameters related to Uplink Reference Signal
 *  \param bitmask Bitmask Value
 *  \param group_assignment_pusch Corresponds to parameter groupAssignmentPUSCH specified in 3GPP TS 36.331
 */ 
typedef struct _rrm_oam_addl_ul_reference_signal_params_t
{
  rrm_bitmask_t   bitmask; /*^ BITMASK ^*/
  U8              group_assignment_pusch;   /*^ O, RRM_OAM_GROUP_ASSIGMENT_PUSCH_PRESENT, N, 0, 0^*/
  U8              ul_reference_signal_pusch_cyclicshift; /*^ O, RRM_OAM_UL_REFER_SIGNAL_PUSCH_CYCLIC_SHIFT_PRESENT, N, 0, 0^*/
}rrm_oam_addl_ul_reference_signal_params_t;

#define RRM_OAM_ADDITIONAL_PUCCH_PARAMS_PRESENT 0x01
#define RRM_OAM_ADDITIONAL_PUSCH_PARAMS_PRESENT 0x02
#define RRM_OAM_ADDITIONAL_UL_REF_SIGNAL_PARAMS_PRESENT 0x04
/*! \ rrm_oam_addl_phy_params_t
 *  \brief This struct contains lte cell Physical layer additional parameters 
 *  \param bitmask Bitmask Value
 *  \param addl_pucch_parameters Denotes addl PUCCH params
 *  \param additional_pusch_parameters Denotes addl PUSCH params
 */
typedef struct _rrm_oam_addl_phy_params_t
{
      rrm_bitmask_t                       bitmask; /*^ BITMASK ^*/
      rrm_oam_addl_pucch_config_t         addl_pucch_parameters; /*^ O, RRM_OAM_ADDITIONAL_PUCCH_PARAMS_PRESENT, N, 0, 0^*/ 
	  rrm_oam_addl_pusch_config_t         additional_pusch_parameters;  /*^ O, RRM_OAM_ADDITIONAL_PUSCH_PARAMS_PRESENT, N, 0, 0^*/
	  rrm_oam_addl_ul_reference_signal_params_t  addtl_ul_reference_signal_params; /*^ O, RRM_OAM_ADDITIONAL_UL_REF_SIGNAL_PARAMS_PRESENT, N, 0, 0^*/
}rrm_oam_addl_phy_params_t;
/*! \ rrm_oam_tdd_frame_structure_t
 *  \brief This struct contains lte cell Physical layer TDD Configuration parameters
 *  \param sub_frame_assignment Defines the DL/UL subframe configuration
 *  \param special_sub_frame_patterns Defines configuration of the special subframe that contains the guard period between the downlink and uplink transmissions
 */
typedef struct _rrm_oam_tdd_frame_structure
{
    rrm_oam_sub_frame_asgmnt_et sub_frame_assignment;/*^ M, 0, B, 0, 6 ^*/
    rrm_oam_special_sub_frame_patterns_et   special_sub_frame_patterns;/*^ M, 0, B, 0, 8 ^*/
}rrm_oam_tdd_frame_structure_t;


#define RRM_OAM_PHYSICAL_LAYER_PARAM_PDSCH_CONFIG_PRESENT  0x01
#define RRM_OAM_PHYSICAL_LAYER_PARAM_SRS_CONFIG_PRESENT    0x02
#define RRM_OAM_PHYSICAL_LAYER_PARAM_PRACH_CONFIG_PRESENT  0x04
#define RRM_OAM_PHYSICAL_LAYER_PARAM_PUCCH_CONFIG_PRESENT  0x08
#define RRM_OAM_PHYSICAL_LAYER_PARAM_PUSCH_CONFIG_PRESENT  0x10
#define RRM_OAM_PHYSICAL_LAYER_PARAM_UL_REF_SIG_PRESENT    0x20
#define RRM_OAM_PHYSICAL_LAYER_PARAM_UL_POWER_CTRL_PRESENT 0x40
#define RRM_OAM_PHYSICAL_LAYER_PARAM_PRS_CONFIG_PRESENT    0x80
#define RRM_OAM_ADDITIONAL_PHYSICAL_LAYER_PARAM_PRESENT    0x100
#define RRM_OAM_PHYSICAL_LAYER_PARAM_TDD_FRAME_PRESENT     0x200
/*! \ rrm_oam_physical_layer_params_t
 *  \brief This struct contains lte cell Physical layer parameters
 *  \param bitmask Bitmask Value
 *  \param physical_layer_param_pdsch Denotes physical layer PDSCH params
 *  \param physical_layer_param_srs Denotes physical layer SRS params
 *  \param physical_layer_param_prach Denotes physical layer PRACH
 *  \param physical_layer_param_pucch Denotes physical layer PUCCH
 *  \param physical_layer_param_pusch Denotes physical layer PUSCH
 *  \param physical_layer_param_ul_reference_signal Denotes physical layer UL reference signal
 *  \param physical_layer_param_ul_power_control Denotes physical layer UL power control
 *  \param physical_layer_param_prs Denotes physical layer PRS params
 *  \param addl_physical_layer_params Denotes physical layer additional params
 *  \param physical_layer_param_tdd_frame_structure  Denotes physical layer TDD frame structure 
 */
typedef struct _rrm_oam_physical_layer_params 
{
	rrm_bitmask_t 		            bitmask; /*^ BITMASK ^*/
        rrm_oam_pdsch_t   	            physical_layer_param_pdsch; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_PDSCH_CONFIG_PRESENT, N, 0, 0 ^*/
        rrm_oam_srs_t     	            physical_layer_param_srs; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_SRS_CONFIG_PRESENT, N, 0, 0 ^*/ 
        rrm_oam_prach_t   	            physical_layer_param_prach; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_PRACH_CONFIG_PRESENT, N, 0, 0 ^*/
        rrm_oam_pucch_t   	            physical_layer_param_pucch; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_PUCCH_CONFIG_PRESENT, N, 0, 0 ^*/
        rrm_oam_pusch_t   	            physical_layer_param_pusch; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_PUSCH_CONFIG_PRESENT, N, 0, 0 ^*/
        rrm_oam_ul_reference_signal_t       physical_layer_param_ul_reference_signal; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_UL_REF_SIG_PRESENT, N, 0, 0 ^*/
        rrm_oam_uplink_power_control_t      physical_layer_param_ul_power_control; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_UL_POWER_CTRL_PRESENT, N, 0, 0 ^*/
        rrm_oam_prs_t                       physical_layer_param_prs; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_PRS_CONFIG_PRESENT , N, 0, 0 ^*/
        rrm_oam_addl_phy_params_t           addl_physical_layer_params; /*^ O, RRM_OAM_ADDITIONAL_PHYSICAL_LAYER_PARAM_PRESENT, N, 0, 0 ^*/
        rrm_oam_tdd_frame_structure_t       physical_layer_param_tdd_frame_structure; /*^ O, RRM_OAM_PHYSICAL_LAYER_PARAM_TDD_FRAME_PRESENT, N, 0, 0 ^*/
}rrm_oam_physical_layer_params_t;

/*! \ rrm_oam_preamble_groupA_info_t
 *  \brief This struct contains Group A RACH preamble information
 *  \param size_of_ra_group_a No of non dedicated random access preamble information
 *  \param message_size_group_a Denotes Threshold for preamble selection in 3GPP
 *  \param message_power_offset_group_b Denotes Threshold for preamble selection in TS 36.321 in terms of power
 */ 
typedef struct _rrm_oam_preamble_groupA_info
{
	rrm_oam_ra_preambles_group_a_size_et	size_of_ra_group_a;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_group_a_msg_size_et		message_size_group_a;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_group_b_msg_power_offset_et	message_power_offset_group_b;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_preamble_groupA_info_t;

# define RRM_OAM_RA_PREABLE_GROUPA_INFO_PRESENT     0x01
/*! \ rrm_oam_preamble_info_t
 *  \brief This struct contains RACH preamble info
 *  \param bitmask Bitmask Value
 *  \param number_of_ra_preambles No of non dedicated random access preambles
 *  \param ra_preamble_groupA_info Group A RACH preamble information
 */	
typedef struct _rrm_oam_preamble_info
{
	rrm_bitmask_t   			bitmask; /*^ BITMASK ^*/
	rrm_oam_ra_preamble_count_et		number_of_ra_preambles;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_preamble_groupA_info_t		ra_preamble_groupA_info;/*^ O, RRM_OAM_RA_PREABLE_GROUPA_INFO_PRESENT, N, 0, 0 ^*/
}rrm_oam_preamble_info_t;
/*! \ rrm_oam_rach_t
 *  \brief This struct contains RACH parameters
 *  \param preamble_info Defines the RACH preamble information
 *  \param power_ramping_step Denotes increase factor between subsequent random access preamble transmissions
 *  \param preamble_initial_received_target_power Denotes baseline for computation of transmit power for random access transmission params
 *  \param preamble_trans_max Denotes max no of random access preamble transmissions
 *  \param response_window_size Denotes duration of random access response window
 *  \param contention_resolution_timer Denotes contention resolution timer
 *  \param max_harq_msg_3tx Denotes max no of Msg3 HARQ transmissions
 */
typedef struct _rrm_oam_rach
{
	rrm_oam_preamble_info_t       		preamble_info;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_power_ramping_step_et		power_ramping_step;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_preamble_init_rec_target_pow_et	preamble_initial_received_target_power;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_preamble_trans_max_et		preamble_trans_max;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_ra_resp_win_size_et		response_window_size;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_mac_cont_resol_timer_et		contention_resolution_timer;/*^ M, 0, N, 0, 0 ^*/
	U8					max_harq_msg_3tx;/*^ M, 0, B, 1, 8 ^*/
}rrm_oam_rach_t;
/*! \  rrm_oam_short_drx_cycle_config_t
 *  \brief This struct contains short drx configuration
 *  \param short_drx_cycle Denotes short DRX Cycle value in no of subframes
 *  \param drx_short_cycle_timer Denotes duration of short DRX cycle in multiples of short DRX cycles 
 */
typedef struct _rrm_oam_short_drx_cycle_config
{
	rrm_oam_short_drx_cycle_et	short_drx_cycle; /*^ M, 0, N, 0, 0^*/
	U8				drx_short_cycle_timer; /*^ M, 0, N, 1, 16 ^*/
}rrm_oam_short_drx_cycle_config_t;


# define RRM_OAM_SHORT_DRX_CYCLE_PRESENT      0x01
/*! \ rrm_oam_drx_config_t
 *  \brief This struct contains DRX configuration parameters
 *  \param bitmask Bitmask Value
 *  \param num_applicable_qci Denotes no of qci classes this DRX configuration is applicable to
 *  \param applicable_qci_list[RRM_OAM_MAX_NUM_QCI_CLASSES] Denotes list of all qci classes on which this DRX configuration is applicable to
 *  \param on_duration_timer Denotes part of DRX cycle during which UE activley monitors PDCCH
 *  \param drx_inactivity_timer Denotes no of inactive consecutive PDCCH subframes that will activate short DRX cycle
 *  \param drx_retransmission_timer Denotes max no of consecutive PDCCH subframes UE must remain active expecting a DL transmission
 *  \param long_drx_cycle Denotes Long DRX Cycle value in no of sub frames
 *  \param drx_start_offset Parameter used to compute the starting frame of the DRX cycle
 *  \param short_drx_cycle Denotes Short DRX Configuration
 */
typedef struct _rrm_oam_drx_config
{
	rrm_bitmask_t                           bitmask;/*^ BITMASK ^*/
	U8					num_applicable_qci; /*^ M, 0, B, 1, 9 ^*/
	U8					applicable_qci_list[RRM_OAM_MAX_NUM_QCI_CLASSES]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/		
	rrm_oam_on_duration_timer_et		on_duration_timer;/*^ M, 0, H, 1, 15 ^*/
	rrm_oam_drx_inactivity_timer_et	        drx_inactivity_timer;/*^ M, 0, H, 1, 21 ^*/
	rrm_oam_drx_retransmission_timer_et	drx_retransmission_timer;/*^ M, 0, H, 1, 7 ^*/
	rrm_oam_long_drx_cycle_start_offset_et	long_drx_cycle;	/*^ M, 0, N, 0, 0 ^*/
	U16 				        drx_start_offset;/*^ M, 0, N, 0, 2559 ^*/			
	rrm_oam_short_drx_cycle_config_t	short_drx_cycle; /*^O, RRM_OAM_SHORT_DRX_CYCLE_PRESENT,  N, 0, 0 ^*/
}rrm_oam_drx_config_t;
/*! \ rrm_oam_drx_t
 *  \brief This struct contains DRX parameters
 *  \param drx_enabled Denotes whether DRX is enabled/disabled
 *  \param num_valid_drx_profiles Denotes how many configurations are there is drx_config array
 *  \param drx_config[RRM_OAM_MAX_NUM_DRX_PROFILE] Denotes DRX configuration params
 */
typedef struct _rrm_oam_drx
{
	rrm_bool_et 				drx_enabled;  /*^ M, 0, N, 0, 0 ^*/
	U8 					num_valid_drx_profiles; /*^ M, 0, B, 1, 2 ^*/ 
	rrm_oam_drx_config_t			drx_config[RRM_OAM_MAX_NUM_DRX_PROFILE]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/ 
}rrm_oam_drx_t;
/*! \ rrm_oam_srb_info_t
 *  \brief This struct contains SRB parameters information
 *  \param t_poll_retransmit Timer between successive poll transmissions
 *  \param poll_pdu Counter of PDU's between successive poll transmissions
 *  \param poll_byte Counter of PDU bytes transmitted between successive poll transmissions
 *  \param max_retx_threshold Used by transmitter of RLC entity to limit the no of retransmissions of an AMD PDU 
 *  \param t_reordering Used by receiver of an RLC entity to detect loss of RLC PDUsat lower rate
 *  \param t_status_prohibit Used by receiver of an AM RLC entity in order to prohibit transmission of STATUS PDU 
 */
typedef struct _rrm_oam_srb_info 
{
	rrm_oam_t_poll_retransmit_et	t_poll_retransmit;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_poll_pdu_et		poll_pdu;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_poll_byte_et		poll_byte;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_max_retx_threshold_et	max_retx_threshold;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_t_reordering_et		t_reordering;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_t_status_prohibit_et	t_status_prohibit;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_srb_info_t;

#define RRM_OAM_SRB_INFO_PRESENT  0x0001
/*! \ rrm_oam_srb_t
 * \brief This struct contains SRB parameters
 * \param bitmask Bitmask Value
 * \param default_configuration If true then default RLC configuration for corresponding SRB to be applied for a UE
 * \param srb_params Denotes srb params
 */
typedef struct _rrm_oam_srb
{
	rrm_bitmask_t 			bitmask;/*^ BITMASK ^*/
	rrm_bool_et			default_configuration;/*^ M, 0, N, 0, 0 ^*/	
	rrm_oam_srb_info_t		srb_params;/*^ O, RRM_OAM_SRB_INFO_PRESENT, N, 0, 0 ^*/	
}rrm_oam_srb_t;
/*! \ rrm_oam_cell_access_restriction_params_t
 * \brief This struct contains Cell access restriction parameters
 * \param bitmask Bitmask Value for future use
 * \param cell_barred Denotes if cell is barred or not
 * \param barring_for_emergency Denotes if cell is barred for Emergency services or not
 * \param intra_freq_reselection Denotes if cell reselection is allowed or not
 */
typedef struct _rrm_oam_cell_access_restriction_params
{
	rrm_bitmask_t					bitmask;
	rrm_oam_cell_barred_et		cell_barred;/*^ M, 0, H, 0, 1 ^*/
	rrm_bool_et			barring_for_emergency;/*^ M, 0, H, 0, 1 ^*/
	rrm_oam_intra_freq_reselection_et 	intra_freq_reselection; /*^ M, 0, H, 0, 1 ^*/	
}rrm_oam_cell_access_restriction_params_t;

/*! \ rrm_oam_cell_info_t
 *  \brief This struct contains Basic cell related data 
 *  \param eutran_global_cell_id Denotes Eutran Global Cell ID
 *  \param cell_access_restriction_params Denotes Cell Access restriction parameters
 */
typedef struct _rrm_oam_cell_info_t
{
	rrm_bitmask_t					bitmask;
        rrm_oam_eutran_global_cell_id_t           eutran_global_cell_id;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_cell_access_restriction_params_t  cell_access_restriction_params; /*^ M, 0, N, 0, 0 ^*/

}rrm_oam_cell_info_t;

/*! \ rrm_oam_speed_state_params_t
 *  \brief This struct contains speed state parameters of mobility information
 *  \param q_hyst_sf_medium Speed-dependent scaling factor for Qhyst in Medium-mobility state
 *  \param q_hyst_sf_high Speed-dependent scaling factor for Qhyst in High -mobility state
 *  \param t_evaluation Specifies the duration for evaluating allowed amount of cell 
 *                      reselection(s) required to enter mobility states
 *  \param t_hyst_normal The additional duration for evaluating criteria to enter normal mobility state
 *  \param n_cell_change_medium Specifies the number of cell reselections within T-evaluation to enter Medium-mobility state
 *  \param n_cell_change_high Specifies the number of cell reselections within T-evaluation to enter High-mobility state
 */
typedef struct _rrm_oam_speed_state_params
{
	rrm_oam_q_hyst_sf_et	q_hyst_sf_medium;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_q_hyst_sf_et	q_hyst_sf_high;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_t_evaluation_et	t_evaluation;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_t_hyst_normal_et	t_hyst_normal; /*^ M, 0, N, 0, 0 ^*/
	U8			n_cell_change_medium;/*^ M, 0, B, 1, 16 ^*/
	U8			n_cell_change_high;/*^ M, 0, B, 1, 16 ^*/
}rrm_oam_speed_state_params_t;
/*! \  rrm_oam_speed_scale_factors_t
 *  \brief This struct contains Specifies scaling factor for TreselectionEUTRA
 *         for inter-frequency reselection to this frequency carrier in mobility state
 *  \param t_reselection_eutra_sf_medium scaling factor for TreselectionEUTRA for inter-frequency reselection 
 *                                       to this frequency carrier in Medium-mobility state
 *  \param t_reselection_eutra_sf_high scaling factor for TreselectionEUTRA for inter-frequency reselection
 *                                     to this frequency carrier in High-mobility state
 */
typedef struct _rrm_oam_speed_scale_factors
{
	rrm_oam_speed_state_scale_factors_et 	t_reselection_eutra_sf_medium; /*^ M, 0, H, 0, 3 ^*/
	rrm_oam_speed_state_scale_factors_et	t_reselection_eutra_sf_high; /*^ M, 0, H, 0, 3 ^*/
}rrm_oam_speed_scale_factors_t;

#define RRM_OAM_Q_RX_LEV_MIN_OFFSET_PRESENT           0x01
#define RRM_OAM_S_INTRA_SEARCH_PRESENT                0x02
#define RRM_OAM_S_NON_INTRA_SEARCH_PRESENT            0x04
#define RRM_OAM_P_MAX_SIB1_PRESENT                    0x08
#define RRM_OAM_P_MAX_SIB3_PRESENT                    0x10
#define RRM_OAM_T_RESELECTION_EUTR_SPEED_SCALE_FACTOR_PRESENT 0x20
/*! \  rrm_oam_intra_freq_params_t
 *  \brief This struct contains Intra frequency parameters to be sent in system information broadcast
 *  \param bitmask Bitmask Value
 *  \param q_rx_lev_min_sib_1 Required minimum received RSRP level of a E-UTRA cell for cell selection
 *  \param q_rx_lev_min_offset Offset with respect to QrxLevMin taken into account in the computation of Srxlev for 
 *                             cell selection evaluation of cells detected during a periodic search for a higher
 *                             priority PLMN while camped normally in a VPLMN
 *  \param p_max_sib_1  used to limit the allowed UE uplink transmission power on the serving frequency
 *  \param p_max_sib_3  Value applicable for the intra-frequency neighbouring E-UTRA cells
 *  \param q_rx_lev_min_sib_3 Minimum required minimum received RSRP level for intra-frequency E-UTRA cell re-selection
 *  \param s_intra_search Threshold for intra-frequency measurements
 *  \param t_reselection_eutra Cell reselection timer for intra frequency E-UTRA cell reselection
 *  \param speed_scale_factors Specifies scaling factor for TreselectionEUTRA for inter-frequency reselection 
 *                             to this frequency carrier in mobility state
 *  \param s_non_intra_search 	This parameter is used to indicate an Rx level threshold for cell reselection
 *  \param cell_reselection_priority Absolute priority of the E-UTRAN serving carrier frequency used in the 
 *                                   inter-frequency and inter-RAT cell reselection procedure
 *  \param thresh_serving_low Threshold for serving frequency used in evaluation of reselection towards lower priority E-UTRAN frequency or RA
 *  \param neigh_cell_config Provides information related to MBSFN and TDD UL/DL configuration of neighbour cells of this frequency
 */
typedef struct _rrm_oam_intra_freq_params
{
	rrm_bitmask_t bitmask;/*^ BITMASK ^*/
	S8	q_rx_lev_min_sib_1;/*^ M, 0, B, -70, -22 ^*/
	U8	q_rx_lev_min_offset;/*^ O, RRM_OAM_Q_RX_LEV_MIN_OFFSET_PRESENT, B, 1, 8 ^*/
	S8	p_max_sib_1;/*^ O, RRM_OAM_P_MAX_SIB1_PRESENT, B, -30, 33 ^*/
	S8	p_max_sib_3;/*^ O, RRM_OAM_P_MAX_SIB3_PRESENT, B, -30, 33 ^*/
	S8	q_rx_lev_min_sib_3;/*^ M, 0, B, -70, -22 ^*/
	U8	s_intra_search;/*^ O, RRM_OAM_S_INTRA_SEARCH_PRESENT, H, 0, 31 ^*/
	U8	t_reselection_eutra;/*^ M, 0, H, 0, 7 ^*/
	rrm_oam_speed_scale_factors_t  speed_scale_factors; /*^ O, RRM_OAM_T_RESELECTION_EUTR_SPEED_SCALE_FACTOR_PRESENT, N, 0, 0 ^*/	
	U8	s_non_intra_search;/*^ O, RRM_OAM_S_NON_INTRA_SEARCH_PRESENT, H, 0, 31 ^*/
	U8	cell_reselection_priority; /*^ M, 0, H, 0, 7 ^*/
	U8	thresh_serving_low;/*^ M, 0, H, 0, 31 ^*/
	U8 	neigh_cell_config;/*^ M, 0, H, 0, 32 ^*/
}rrm_oam_intra_freq_params_t;

/*! \ rrm_oam_thresholdx_q_r9_t 
 *  \brief This struct contains two IEs corresponding to the cell reselection params
 *  \param thresh_serving_highq_r9 The IE is used to indicate a quality level threshold for cell reselection 
 *  \param thresh_serving_lowq_r9 The IE is used to indicate a quality level threshold for cell reselection
 */
typedef struct rrm_oam_thresholdx_q_r9
{
	U8	thresh_serving_highq_r9;/*^ M, 0, H, 0, 31 ^*/				 
	U8	thresh_serving_lowq_r9;	/*^ M, 0, H, 0, 31 ^*/			 
}rrm_oam_thresholdx_q_r9_t;

#define RRM_OAM_CM_OFFSET_FREQ_PRESENT                        0x01
#define RRM_OAM_INTER_FREQ_CELL_RESELECTION_PRIORITY_PRESENT  0x02
#define RRM_OAM_P_MAX_PRESENT                                 0x04
#define RRM_OAM_T_EUTR_SPEED_SCALE_FACTOR_PRESENT             0x08
#define RRM_OAM_Q_QUAL_MIN_R9_PRESENT                         0x10
#define RRM_OAM_THRESHX_Q_R9_PRESENT                          0x20
/*! \ rrm_oam_inter_freq_params_t
 *  \brief This struct denotes Inter-Frequency Parameters to be sent in SIB
 *  \param bitmask Bitmask Value
 *  \param eutra_carrier_arfcn Indicates the ARFCN of frequency carrier on which neighbouring cells are transmitting
 *  \param q_rx_lev_min_sib_5 min required received RSRP level on this E-UTRA frequency carrier
 *  \param q_offset_freq Offset applicable between serving and this frequency carrier
 *  \param cm_offset_freq connected mode offset frequency
 *  \param t_reselection_eutra Cell reselection timer for inter-frequency cell reselection to this E-UTRA frequency carrier
 *  \param cell_reselection_priority Absolute priority of this E-UTRA frequency carrier
 *  \param thresh_x_high Threshold used when reselecting from a lower priority E-UTRAN frequency
 *  \param thresh_x_low Threshold used when reselecting from a higher priority E-UTRAN frequency
 *  \param p_max This is  to limit the allowed UE uplink transmission power on this carrier frequency
 *  \param measurement_bandwidth indicate the maximum allowed measurement bandwidth on a carrier frequency
 *  \param presence_antenna_port1 used to indicate whether all the neighbouring cells use Antenna Port 1
 *  \param neigh_cell_config Provides info related to MBSFN and TDD UL/DL configuration of neighbour cells of this frequency
 *  \param speed_scale_factors Specifies scaling factor for TreselectionEUTRA for inter-frequency reselection 
 *  \param q_qual_min_r9 Qqualmin  as per spec 36.304
 *  \param threshx_q_r9 Containing two IEs corresponding to the cell reselection params
 */
typedef struct _rrm_oam_inter_freq_params
{
	rrm_bitmask_t                      bitmask; /*^ BITMASK ^*/
	U16                                eutra_carrier_arfcn; /*^ M, 0, N, 0, 65535^*/
	S8	                           q_rx_lev_min_sib_5; /*^ M, 0, B, -70, -22 ^*/
	rrm_oam_q_offset_range_et	   q_offset_freq;  /*^ M, 0, N, 0, 0 ^*/
    rrm_oam_q_offset_range_et      cm_offset_freq; /*^ O, RRM_OAM_CM_OFFSET_FREQ_PRESENT, H, 0, 30 ^*/
	U8	                           t_reselection_eutra;/*^ M, 0, H, 0, 7 ^*/
	U8	                           cell_reselection_priority;/*^ O, RRM_OAM_INTER_FREQ_CELL_RESELECTION_PRIORITY_PRESENT, H, 0, 7 ^*/
	U8	                           thresh_x_high;/*^ M, 0, H, 0, 31 ^*/
	U8	                           thresh_x_low;/*^ M, 0, H, 0, 31 ^*/
	S8	                           p_max;/*^ O, RRM_OAM_P_MAX_PRESENT, B, -30, 33 ^*/
	rrm_oam_measurement_bandwidth_et   measurement_bandwidth;/*^ M, 0, H, 0, 5 ^*/
	U8	                           presence_antenna_port1;/*^ M, 0, H, 0, 1 ^*/
	U8	                           neigh_cell_config;/*^ M, 0, H, 0, 32 ^*/
	rrm_oam_speed_scale_factors_t      speed_scale_factors; /*^ O, RRM_OAM_T_EUTR_SPEED_SCALE_FACTOR_PRESENT, N, 0, 0 ^*/
        S8                                 q_qual_min_r9;/*^ O, RRM_OAM_Q_QUAL_MIN_R9_PRESENT, B, -34, -3 ^*/
        rrm_oam_thresholdx_q_r9_t          threshx_q_r9; /*^ O, RRM_OAM_THRESHX_Q_R9_PRESENT, N, 0, 0 ^*/
}rrm_oam_inter_freq_params_t;

/*MEAS_CONFIG Start */
/*! \  rrm_oam_common_params_for_eutra_t
 *  \brief This struct contains Common parameters for eutra
 *  \param filter_coefficient_rsrp Filtering coefficient used for RSRP measurements
 *  \param filter_coefficient_rsrq Filtering coefficient used for RSRQ measurements
 *  \param a1_threshold_rsrp Threshold to be used in EUTRA measurement report triggering condition for event a1
 *  \param a1_threshold_rsrq Threshold to be used in EUTRA measurement report triggering condition for event a1
 *  \param a2_threshold_rsrp Threshold to be used in EUTRA measurement report triggering condition for event a2
 *  \param a2_threshold_rsrq Threshold to be used in EUTRA measurement report triggering condition for event a2
 *  \param a3_offset Offset to be used in evaluation of EUTRA measurement report triggering condition for event a3
 *  \param report_on_leave Indicates whether or not the UE shall initiate the measurementreporting procedure when the leaving condition is met
 *  \param a4_threshold_rsrp Threshold to be used in EUTRA measurement report triggering condition for event a4
 *  \param a4_threshold_rsrq Threshold to be used in EUTRA measurement report triggering condition for event a4
 *  \param a5_threshold_1rsrp Threshold1 to be used in EUTRA measurement report triggering condition for event a5
 *  \param a5_threshold_1rsrq Threshold1 to be used in EUTRA measurement report triggering condition for event a5
 *  \param a5_threshold_2rsrp Threshold2 to be used in EUTRA measurement report triggering condition for event a5
 *  \param a5_threshold_2rsrq Threshold2 to be used in EUTRA measurement report triggering condition for event a5
 *  \param hysteresis applied to entry and leave condition of a report triggering event
 *  \param time_to_trigger Time during which measurement report triggering condition needs to be met in order to trigger meas report
 *  \param trigger_quantity used to evaluate a measurement report triggering condition
 *  \param report_quantity meas quantities to be included in the meas report
 *  \param report_interval interval between successive meas report
 *  \param report_amount Number of times a measurement report is sent
 *  \param ps_ho_enabled To Enable/Disable PS_HO for EUTRAN
*/
typedef struct _rrm_oam_common_params_for_eutra
{
        rrm_filter_coefficient_et       filter_coefficient_rsrp;/*^ M, 0, H, 0, 14 ^*/
        rrm_filter_coefficient_et       filter_coefficient_rsrq;/*^ M, 0, H, 0, 14 ^*/
        U8      a1_threshold_rsrp;/*^ M, 0, H, 0, 97 ^*/
        U8      a1_threshold_rsrq;/*^ M, 0, H, 0, 34^*/
        U8      a2_threshold_rsrp;/*^ M, 0, H, 0, 97 ^*/
        U8      a2_threshold_rsrq;/*^ M, 0, H, 0, 34 ^*/
        S8      a3_offset;/*^ M, 0, B, -30, 30 ^*/
        U8      report_on_leave;/*^ M, 0, H, 0, 1 ^*/
        U8      a4_threshold_rsrp;/*^ M, 0, H, 0, 97 ^*/
        U8      a4_threshold_rsrq;/*^ M, 0, H, 0, 34 ^*/
        U8      a5_threshold_1rsrp;/*^ M, 0, H, 0, 97 ^*/
        U8      a5_threshold_1rsrq;/*^ M, 0, H, 0, 34 ^*/
        U8      a5_threshold_2rsrp;/*^ M, 0, H, 0, 97 ^*/
        U8      a5_threshold_2rsrq;/*^ M, 0, H, 0, 34 ^*/
        U8      hysteresis;/*^ M, 0, H, 0, 30 ^*/
        rrmc_time_to_trigger_et         time_to_trigger;/*^ M, 0, H, 0, 15 ^*/
        rrmc_trigger_quantity_et        trigger_quantity;/*^ M, 0, H, 0, 1 ^*/
        rrmc_report_quantity_et         report_quantity;/*^ M, 0, H, 0, 1 ^*/
        rrmc_report_interval_et         report_interval;/*^ M, 0, H, 0, 12 ^*/
        rrmc_report_amount_et           report_amount;/*^ M, 0, H, 0, 7 ^*/
        U8      ps_ho_enabled;        /*^ M, 0, H, 0, 1 ^*/    /* rrm_bool_et */
}rrm_oam_common_params_for_eutra_t;
/*! \  rrm_oam_ue_generic_cdma2000_params_t
 *  \brief This struct contains Parameters used by UEs for CDMA2000 cell
 *  \param bitmask Bitmask Value
 *  \param auth Current authentication mode
 *  \param max_num_alt_so max num of alternative service option nos that the mobile station is allowed to include in Origination msg or in Page Response msg
 *  \param use_sync_id Sync ID supported indicator
 *  \param mob_qos indicate whether mobile station is allowed to request QoS settings in Origination msg or continuation msg or enhanced Origination msg 
 *  \param bypass_reg_ind indication to bypass power up registration upon the change of bands , serving systems & frequency bands 
 *  \param max_add_serv_instance Maximum number of additional service reference identifiers allowed in origination
 *  \param parameter_reg Parameter-change registration enable
 *  \param reg_dist Distance from last registration that causes a distance based registration to occur
 *  \param pref_msid_type Preferred mobile station identifier field type
 *  \param ext_pref_msid_type Extended preferred mobile station identifier field type
 *  \param meid_reqd MEID Required Indicator
 *  \param mcc Mobile Country Code
 *  \param imsi_11_12 11th  and 12th digits of the IMSI
 *  \param imsi_t_supported IMSI_T support indicator
 *  \param reconnect_msg_ind Reconnect Message supported indicator
 *  \param rer_mode_supported Radio environment reporting mode supported indicator
 *  \param pilot_report Pilot reporting indicator
 *  \param sdb_supported Short Data Burst supported indicator
 *  \param auto_fcso_allowed Autonomous Fast Call Setup Order allowed indicator
 *  \param sdb_in_rcnm_ind Short Data Burst allowed in Reconnect Message indicator
 *  \param daylt Daylight Savings Time indicator
 *  \param gcsna_l2_ack_timer If the IWS is configured to use GCSNA L2 ack, this field is set to 1
 *  \param gcsna_sequence_context_timer If GCSNASequenceContextTimer_Included is set to 0
 *  \param lp_sec The number of leap seconds that have occurred since the start of System Time
 */
typedef struct _rrm_oam_ue_generic_params_cdma2000_t
{
    rrm_bitmask_t                      bitmask; /*^ BITMASK ^*/
#define RRM_OAM_AUTH_INCLUDED_PRESENT                    0x000001
#define RRM_OAM_MAX_NUM_ALT_SO_INCLUDED_PRESENT          0x000002
#define RRM_OAM_USE_SYNC_ID_INCLUDED_PRESENT             0x000004
#define  RRM_OAM_MOB_QOS_INCLUDED_PRESENT                0x000008
#define  RRM_OAM_BYPASS_REG_IND_INCLUDED_PRESENT         0x000010
#define  RRM_OAM_MAX_ADD_SERV_INSTANCE_INCLUDED_PRESENT  0x000020
#define  RRM_OAM_PARAMETER_REG_INCLUDED_PRESENT          0x000040
#define  RRM_OAM_REG_DIST_INCLUDED_PRESENT               0x000080
#define  RRM_OAM_PREF_MSID_TYPE_INCLUDED_PRESENT         0x000100
#define  RRM_OAM_EXT_PREF_MSID_TYPE_INCLUDED_PRESENT     0x000200
#define  RRM_OAM_MEID_REQD_INCLUDED_PRESENT              0x000400
#define  RRM_OAM_MCC_INCLUDED_PRESENT                    0x000800
#define  RRM_OAM_IMSI_11_12_INCLUDED_PRESENT             0x001000
#define  RRM_OAM_IMSI_T_SUPPORTED_INCLUDED_PRESENT       0x002000
#define  RRM_OAM_RECONNECT_MSG_IND_INCLUDED_PRESENT      0x004000
#define RRM_OAM_RER_MODE_SUPPORTED_INCLUDED_PRESENT      0x008000
#define RRM_OAM_PILOT_REPORT_INCLUDED_PRESENT            0x010000
#define RRM_OAM_SDB_SUPPORTED_INCLUDED_PRESENT           0x020000
#define RRM_OAM_AUTO_FCSO_ALLOWED_INCLUDED_PRESENT       0x040000
#define RRM_OAM_SDB_IN_RCNM_IND_INCLUDED_PRESENT         0x080000
#define RRM_OAM_DAYLT_INCLUDED_PRESENT                   0x100000
#define RRM_OAM_GCSNA_L2_ACK_TIMER_INCLUDED_PRESENT      0x200000
#define RRM_OAM_GCSNA_SEQUENCE_CONTEXT_TIMER_INCLUDED_PRESENT 0x400000
#define RRM_OAM_LP_SEC_INCLUDED_PRESENT                  0x800000
    /*ue generic*/
    U8      auth;
    /*^ O,RRM_OAM_AUTH_INCLUDED_PRESENT, H, 0, 3 ^*/
    U8      max_num_alt_so;
    /*^ O,RRM_OAM_MAX_NUM_ALT_SO_INCLUDED_PRESENT, H, 0, 7 ^*/
    U8      use_sync_id;
    /*^ O,RRM_OAM_USE_SYNC_ID_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      mob_qos;
    /*^ O,RRM_OAM_MOB_QOS_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      bypass_reg_ind;
    /*^ O,RRM_OAM_BYPASS_REG_IND_INCLUDED_PRESENT, H, 0, 31 ^*/
    U8      max_add_serv_instance;
    /*^ O,RRM_OAM_MAX_ADD_SERV_INSTANCE_INCLUDED_PRESENT, H, 0, 7 ^*/
    U8      parameter_reg;
    /*^ O,RRM_OAM_PARAMETER_REG_INCLUDED_PRESENT, H, 0, 1 ^*/
    U16     reg_dist;
    /*^ O,RRM_OAM_REG_DIST_INCLUDED_PRESENT, H, 0, 2047 ^*/
    U8      pref_msid_type;
    /*^ O,RRM_OAM_PREF_MSID_TYPE_INCLUDED_PRESENT, H, 0, 3 ^*/
    U8      ext_pref_msid_type;
    /*^ O,RRM_OAM_EXT_PREF_MSID_TYPE_INCLUDED_PRESENT, H, 0, 3 ^*/
    U8      meid_reqd;
    /*^ O,RRM_OAM_MEID_REQD_INCLUDED_PRESENT, H, 0, 1 ^*/
    U16     mcc;
    /*^ O,RRM_OAM_MCC_INCLUDED_PRESENT, H, 0, 1023 ^*/
    U8      imsi_11_12;
    /*^ O,RRM_OAM_IMSI_11_12_INCLUDED_PRESENT, H, 0, 127 ^*/
    U8      imsi_t_supported;
    /*^ O,RRM_OAM_IMSI_T_SUPPORTED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      reconnect_msg_ind;
    /*^ O,RRM_OAM_RECONNECT_MSG_IND_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      rer_mode_supported;
    /*^ O,RRM_OAM_RER_MODE_SUPPORTED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      pilot_report;
    /*^ O,RRM_OAM_PILOT_REPORT_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      sdb_supported;
    /*^ O,RRM_OAM_SDB_SUPPORTED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      auto_fcso_allowed;
    /*^ O,RRM_OAM_AUTO_FCSO_ALLOWED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      sdb_in_rcnm_ind;
    /*^ O,RRM_OAM_SDB_IN_RCNM_IND_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      daylt;
    /*^ O,RRM_OAM_DAYLT_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      gcsna_l2_ack_timer;
    /*^ O,RRM_OAM_GCSNA_L2_ACK_TIMER_INCLUDED_PRESENT, N, 0, 255 ^*/
    U8      gcsna_sequence_context_timer;
    /*^ O,RRM_OAM_GCSNA_SEQUENCE_CONTEXT_TIMER_INCLUDED_PRESENT, N, 0, 255 ^*/
    /*ue generic*/

    /* CDMA2000 updates */
    U8      lp_sec;
    /*^ O,RRM_OAM_LP_SEC_INCLUDED_PRESENT, N, 0, 255 ^*/
    /* CDMA2000 updates */
}rrm_oam_ue_generic_cdma2000_params_t;

#define RRMCM_RMIF_B1_THRESHOLD_UTRA_RSCP_PRESENT  0x0001
#define RRMCM_RMIF_B1_THRESHOLD_UTRA_ECN0_PRESENT  0x0002
#define RRMCM_RMIF_B1_THRESHOLD_GERAN_PRESENT      0x0004
#define RRM_OAM_Q_OFFSET_CDMA_PRESENT              0x0008
#define RRM_OAM_MEAS_QUANTITY_CDMA2000_PRESENT     0x0010
#define RRM_OAM_B1_THRESHOLD_CDMA2000_PRESENT      0x0020
#define RRMCM_RMIF_B1_THRESHOLD_2UTRA_RSCP_PRESENT 0x0100
#define RRMCM_RMIF_B1_THRESHOLD_2UTRA_ECN0_PRESENT 0x0200
#define RRMCM_RMIF_B1_THRESHOLD_2GERAN_PRESENT     0x0400
#define RRM_OAM_B2_THRESHOLD_2CDMA_PRESENT         0x0800
#define RRM_OAM_MEAS_QUANUTRA_FDD_PRESENT          0x1000
#define RRM_OAM_MEAS_QUANUTRA_TDD_PRESENT          0x2000
#define RRM_OAM_UE_GENERIC_PARAMS_PRESENT          0x4000
/*! \ rrm_oam_irat_t
 *  \brief This struct is used for Common parameters for Inter-RAT such as B1, B2 event configurations
 *  \param bitmask To check optional field is present or not
 *  \param qoffset_tutra Indicates a UTRA-specific offset tobe applied when evaluatingtriggering conditions formeasurement reporting in connected mode
 *  \param filter_coefficient_utra Filtering coefficient used for UTRA measurements
 *  \param meas_quantity_utra_fdd Measurement quantity used for fdd measurements
 *  \param meas_quantity_utra_tdd Measurement quantity used for tdd measurements
 *  \param b1_threshold_utra_rscp RSCP threshold to be used in UTRA measurement report triggering condition for event b1
 *  \param b1_threshold_utra_ecn0 ECN0 threshold to be used in UTRA measurement report triggering condition for event b1
 *  \param q_offset_geran GERAN-specific offset to be applied when evaluating triggering conditions for measurement reporting in connected mode
 *  \param filter_coefficient_geran Filtering coefficient used for GERAN measurements
 *  \param b1_threshold_geran Threshold to be usedin GERAN measurement report triggering condition for event b1
 *  \param q_offset_cdma2000 cdma -specific offset to be applied when evaluating triggering conditions for measurement reporting in connected mode
 *  \param meas_quantity_cdma2000 Measurement quantity used for cdma measurements
 *  \param b1_threshold_cdma2000 threshold to be used in CDMA  measurement report triggering condition for event b1
 *  \param b2_threshold_2utra_rscp RSRP threshold to be used in CDMA  measurement report triggering condition for event b2
 *  \param b2_threshold_2utra_ecn0 ecn0 threshold to be used in CDMA  measurement report triggering condition for event b2
 *  \param b2_threshold_2geran geran threshold to be used in CDMA  measurement report triggering condition for event b2
 *  \param b2_threshold_2cdma Threshold to be used in CDMA2000 measurement report triggering condition for event b2
 *  \param hysteresis applied to entry and leave condition of an IRAT report triggering event
 *  \param time_to_trigger Time during which measurement report triggering condition needs to be met in order to trigger meas report
 *  \param max_report_cells Maximum number of IRAT cells that can be included in a measurement report
 *  \param report_interval Interval between successive IRAT measurement reports
 *  \param report_amount Number of times an IRAT measurement report is sent
 *  \param ue_generic_cdma2000_params Parameters used by UEs for CDMA2000 cell
 */
typedef struct _rrm_oam_irat
{
        rrm_bitmask_t                           bitmask; /*^ BITMASK ^*/
        S8                                      qoffset_tutra;/*^ M, 0, B, -15, 15 ^*/  /*INTEGER (-15..15)*/
        rrm_filter_coefficient_et               filter_coefficient_utra;/*^ M, 0, H, 0, 14 ^*/
        rrm_irat_measquanutrafdd_et             meas_quantity_utra_fdd;/*^ O, RRM_OAM_MEAS_QUANUTRA_FDD_PRESENT, H, 0, 1 ^*/
        rrm_irat_measquanutratdd_et             meas_quantity_utra_tdd;/*^ O, RRM_OAM_MEAS_QUANUTRA_TDD_PRESENT, H, 0, 1 ^*/
        S8                                      b1_threshold_utra_rscp;/*^ O, RRMCM_RMIF_B1_THRESHOLD_UTRA_RSCP_PRESENT, B, -5, 91 ^*/
        U8                                      b1_threshold_utra_ecn0;/*^ O, RRMCM_RMIF_B1_THRESHOLD_UTRA_ECN0_PRESENT, H, 0, 49 ^*/
        S8                                      q_offset_geran;/*^ M, 0, H, 0, 30 ^*//*Integer [-15:15]*/
        rrm_filter_coefficient_et               filter_coefficient_geran;/*^ M, 0, H, 0, 14 ^*/
        U8                                      b1_threshold_geran;/*^ O, RRMCM_RMIF_B1_THRESHOLD_GERAN_PRESENT, H, 0, 63 ^*/
        S8                                      q_offset_cdma2000; /*^ O, RRM_OAM_Q_OFFSET_CDMA_PRESENT, N, 0, 0 ^*/ 
        U8                                      meas_quantity_cdma2000; /*^ O, RRM_OAM_MEAS_QUANTITY_CDMA2000_PRESENT, N, 0, 0 ^*/
        U8                                      b1_threshold_cdma2000; /*^ O, RRM_OAM_B1_THRESHOLD_CDMA2000_PRESENT, H, 0, 63 ^*/
        S8                                      b2_threshold_2utra_rscp;/*^ O, RRMCM_RMIF_B1_THRESHOLD_2UTRA_RSCP_PRESENT, B, -5, 91 ^*/
        U8                                      b2_threshold_2utra_ecn0;/*^ O, RRMCM_RMIF_B1_THRESHOLD_2UTRA_ECN0_PRESENT, H, 0, 49 ^*/
        U8                                      b2_threshold_2geran;/*^ O, RRMCM_RMIF_B1_THRESHOLD_2GERAN_PRESENT, H, 0, 63 ^*/
        U8                                      b2_threshold_2cdma;/*^ O, RRM_OAM_B2_THRESHOLD_2CDMA_PRESENT, H, 0, 63 ^*/   
        U8                                      hysteresis;/*^ M, 0, H, 0, 30 ^*/
        rrmc_time_to_trigger_et                 time_to_trigger;/*^ M, 0, H, 0, 15 ^*/
        U8                                      max_report_cells;/*^ M, 0, B, 1, 8 ^*/
        rrmc_report_interval_et                 report_interval;/*^ M, 0, H, 0, 12 ^*/
        rrmc_report_amount_et                   report_amount;/*^ M, 0, H, 0, 7 ^*/
        rrm_oam_ue_generic_cdma2000_params_t        ue_generic_cdma2000_params;
        /*^ O, RRM_OAM_UE_GENERIC_PARAMS_PRESENT, N, 0, 0 ^*/
}rrm_oam_irat_t;

#define RRM_OAM_COMMON_PARAMS_FOR_EUTRA_PRESENT           0x01
#define RRM_OAM_CONNECTED_MODE_MOBILITY_INTER_RAT_PRESENT 0x02
/*! \ rrm_oam_connected_mode_mobility_params_t
 *  \brief This struct is used for connected mode mobility parameters
 *  \param bitmask To check optional field is present or not
 *  \param common_params_for_eutra common parameters for eutra
 *  \param irat Common parameters for Inter-RAT 
 */
typedef struct _rrm_oam_connected_mode_mobility_params
{
        rrm_bitmask_t                           bitmask; /*^ BITMASK ^*/
        rrm_oam_common_params_for_eutra_t       common_params_for_eutra;/*^ O, RRM_OAM_COMMON_PARAMS_FOR_EUTRA_PRESENT, N, 0, 0 ^*/
        rrm_oam_irat_t                          irat;/*^ O, RRM_OAM_CONNECTED_MODE_MOBILITY_INTER_RAT_PRESENT, N, 0, 0 ^*/
}rrm_oam_connected_mode_mobility_params_t;

/*MEAS_CONFIG End */
#define RRM_OAM_SPEED_STATE_PARAMS_PRESENT  0x01
/*! \ rrm_oam_common_params_t
 *  \brief This struct is used for common parameters for oam
 *  \param bitmask To check optional field is present or not
 *  \param q_hyst Hysteresis value applied to serving cell for evaluating cell ranking criteria
 *  \param speed_state_params speed state parameters
 */
typedef struct _rrm_oam_common_params
{
	rrm_bitmask_t 			bitmask;/*^ BITMASK ^*/
	rrm_oam_q_hyst_et		q_hyst;/*^ M, 0, H, 0, 15 ^*/
	rrm_oam_speed_state_params_t  	speed_state_params;/*^ O, RRM_OAM_SPEED_STATE_PARAMS_PRESENT, N, 0, 0 ^*/
}rrm_oam_common_params_t;

#define RRM_OAM_EUTRA_UTRA_RESELECTION_SPEED_SCALE_FACTOR_PRESENT    0x01
/*! \  rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t
 *  \brief This struct is used for idle mode mobility irat eutra to utra reselection parameters
 *  \brief This struct is used for common parameters for oam
 *  \param t_reselection_utra Cell reselection timer for reselection to a UTRA frequency carrier
 *  \param speed_scale_factors speed scale factors
 */
typedef struct _rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t
{
	rrm_bitmask_t                  bitmask;/*^ BITMASK ^*/
	U8	                       t_reselection_utra;/*^ M, 0, H, 0, 7 ^*/
        rrm_oam_speed_scale_factors_t  speed_scale_factors; /*^ O, RRM_OAM_EUTRA_UTRA_RESELECTION_SPEED_SCALE_FACTOR_PRESENT, N, 0, 0 ^*/ 
}rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t;
/*! \ rrm_oam_thresx_rsrq_r9_t
 *  \brief This struct is used for thresx rsrq r9 parameters
 *  \param thresh_serving_highq_r9 thresh serving highq r9
 *  \param thresh_serving_lowq_r9 thresh serving lowq r9
 */
typedef struct _rrm_oam_thresx_rsrq_r9_t
{
  U8	thresh_serving_highq_r9;/*^ M, 0, H, 0, 31 ^*/				 
  U8	thresh_serving_lowq_r9;	/*^ M, 0, H, 0, 31 ^*/  
}rrm_oam_thresx_rsrq_r9_t;


#define RRM_OAM_CELL_RESELECT_PRIORITY_PRESENT   0x01
#define RRM_OAM_OFFSET_FREQ_PRESENT              0x02
#define RRM_OAM_THRESHOLD_Q_R9_T_PRESENT         0x04 
/*! \ rrm_oam_irat_eutran_to_utran_fdd_carriers_t
 *  \brief This struct is used for eutran to utran fdd carriers parameter initialization
 *  \param bitmask To check optional field is present or not
 *  \param utra_carrier_arfcn Indicates the ARFCN of the frequency carrier
 *  \param q_rx_lev_min Required minimum received RSCP level on this UTRA frequency carrier
 *  \param q_qual_min Required minimum received EcIo level on this UTRA FDD carrier
 *  \param cell_reselection_priority Absolute priority of this UTRA FDD frequency carrier, as used by the inter-frequency cell reselection procedure
 *  \param thresh_x_high Threshold used when reselecting towards a higher priority UTRA FDDfrequency
 *  \param thresh_x_low Threshold used when reselecting towards a lower priority UTRA FDD frequency
 *  \param p_max_utra limit the allowed UE uplink transmission power on this UTRA FDD carrier frequency
 *  \param threshx_q_r9 Containing two IEs corresponding to the reselection parameters
 *  \param offset_freq offset frequency
 */
typedef struct _rrm_oam_irat_eutran_to_utran_fdd_carriers_t 
{
  rrm_bitmask_t  bitmask; /*^ BITMASK ^*/
  U16 	utra_carrier_arfcn;/*^ M, 0, H, 0, 16383 ^*/
  S8  	q_rx_lev_min;/*^ M, 0, B, -60, -13 ^*/
  S8	q_qual_min;/*^ M, 0, B, -24, 0 ^*/ 
  U8 	cell_reselection_priority; /*^ O, RRM_OAM_CELL_RESELECT_PRIORITY_PRESENT, H, 0, 7 ^*/
  U8 	thresh_x_high; /*^ M, 0, H, 0, 31 ^*/
  U8 	thresh_x_low;/*^ M, 0, H, 0, 31 ^*/ 
  S8 	p_max_utra;/*^ M, 0, B, -50, 33 ^*/
  S8    offset_freq; /*^ O, RRM_OAM_OFFSET_FREQ_PRESENT, B, -15, 15 ^*/
  rrm_oam_thresx_rsrq_r9_t threshx_q_r9;/*^ O, RRM_OAM_THRESHOLD_Q_R9_T_PRESENT, N, 0, 0 ^*/ 
}rrm_oam_irat_eutran_to_utran_fdd_carriers_t;
/*! \ rrm_oam_irat_eutran_to_utran_fdd_list_t
 *  \brief This struct is used for eutran to utran fdd list 
 *  \param num_irat_eutran_to_utran_fdd_carriers Number of UTRA carrier information
 *  \param irat_eutran_to_utran_fdd_carriers[RRM_MAX_NUM_UTRA_FDD_CARRIERS] UTRA Parameters to be sent in SIB6
 */
typedef struct _rrm_oam_irat_eutran_to_utran_fdd_list_t
{
     U8                                           num_irat_eutran_to_utran_fdd_carriers; /*^ M, 0, B, 1, 16 ^*/
     rrm_oam_irat_eutran_to_utran_fdd_carriers_t  irat_eutran_to_utran_fdd_carriers[RRM_MAX_NUM_UTRA_FDD_CARRIERS]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_irat_eutran_to_utran_fdd_list_t;

#define RRM_OAM_IRAT_CELL_RESELECTION_PRIORITY_PRESENT  0x01
/*! \ rrm_oam_irat_eutran_to_utran_tdd_carriers_t
 *  \brief This struct is used for Information about UTRA TDD frequency carriers relevant for inter-RAT cell re-selection from E-UTRA to UTRAN TDD 
 *  \param bitmask To check optional field is present or not
 *  \param utra_carrier_arfcn Indicates the ARFCN of the frequency carrier
 *  \param q_rx_lev_min Required minimum received RSCP level on this UTRA frequency carrier
 *  \param cell_reselection_priority Absolute priority of this UTRA TDD frequency carrier, as used by the inter-frequency cell reselection procedure
 *  \param threshold_x_high Threshold used when reselecting towards a higher priority UTRA TDD frequency
 *  \param threshold_x_low Threshold used when reselecting towards a lower priority UTRA TDD frequency
 *  \param p_max_utra limit the allowed UE uplink transmission power on this UTRA TDD carrier frequency
 */
typedef struct _rrm_oam_irat_eutran_to_utran_tdd_carriers_t
{
  rrm_bitmask_t    bitmask;    /*^ BITMASK ^*/
  U16              utra_carrier_arfcn;  /*^ M, 0, N, 0, 0 ^*/ 
  S8               q_rx_lev_min;   /*^ M, 0, N, 0, 0 ^*/ 
  U8               cell_reselection_priority;  /*^ O, RRM_OAM_IRAT_CELL_RESELECTION_PRIORITY_PRESENT, N, 0, 0 ^*/
  U8               threshold_x_high;  /*^ M, 0, N, 0, 0 ^*/
  U8               threshold_x_low;  /*^ M, 0, N, 0, 0 ^*/
  S8               p_max_utra; /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_irat_eutran_to_utran_tdd_carriers_t;

/*! \  rrm_oam_irat_eutran_to_utran_tdd_list_t
 *  \brief This struct is used for eutran to utran tdd list
 *  \param num_irat_eutran_to_utran_tdd_carriers Number of eutran to utran TDD carrier information
 *  \param irat_eutran_to_utran_tdd_carriers[RRM_MAX_NUM_UTRA_TDD_CARRIERS] array of eutran to utran tdd carriers
 */
typedef struct _rrm_oam_irat_eutran_to_utran_tdd_list_t
{
  U8   num_irat_eutran_to_utran_tdd_carriers;  /*^ M, 0, N, 0, 0 ^*/
  rrm_oam_irat_eutran_to_utran_tdd_carriers_t  irat_eutran_to_utran_tdd_carriers[RRM_MAX_NUM_UTRA_TDD_CARRIERS]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/ 
}rrm_oam_irat_eutran_to_utran_tdd_list_t;
/*! \  rrm_oam_inter_frequency_params_list_t
 *  \brief This struct is used for inter frequency parameters list 
 *  \param bitmask To check optional field is present or not
 *  \param num_valid_inter_freq_list indicates the number of elements in inter frequency list array
 *  \param idle_mode_mobility_inter_freq_params array of rrm_oam_inter_freq_params_t count depends upon num_valid_inter_freq_list
 */
typedef struct _rrm_oam_inter_frequency_params_list
{
     U8                                 num_valid_inter_freq_list;/*^ M, 0, N, 0, 0 ^*/
     rrm_oam_inter_freq_params_t	idle_mode_mobility_inter_freq_params[RRM_OAM_MAX_NUM_INTER_FREQ_CARRIERS];  /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_inter_frequency_params_list_t;

#define RRM_OAM_IRAT_EUTRAN_UTRAN_FDD_LIST_PRESENT    0x01
#define RRM_OAM_IRAT_EUTRAN_UTRAN_TDD_LIST_PRESENT    0x02
/*! \ rrm_oam_idle_mode_mobility_inter_rat_utra_params_t
 *  \brief This struct is used for idle mode mobility inter rat utra params
 *  \param bitmask To check optional field is present or not
 *  \param irat_eutra_to_utra_reselection_params inter rat eutran to utran reselection parameters
 *  \param irat_eutran_to_utran_fdd_list inter rat eutran to utran FDD list
 *  \param irat_eutran_to_utran_tdd_list inter rat eutran to utran TDD list
 */
typedef struct _rrm_oam_idle_mode_mobility_inter_rat_utra_params_t
{
  rrm_bitmask_t                      bitmask; /*^ BITMASK ^*/ 
  rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t  irat_eutra_to_utra_reselection_params; /*^ M, 0, N, 0, 0 ^*/
  rrm_oam_irat_eutran_to_utran_fdd_list_t         irat_eutran_to_utran_fdd_list; /*^ O, RRM_OAM_IRAT_EUTRAN_UTRAN_FDD_LIST_PRESENT, N, 0, 0 ^*/
  rrm_oam_irat_eutran_to_utran_tdd_list_t         irat_eutran_to_utran_tdd_list; /*^ O, RRM_OAM_IRAT_EUTRAN_UTRAN_TDD_LIST_PRESENT, N, 0, 0 ^*/
}rrm_oam_idle_mode_mobility_inter_rat_utra_params_t;

#define OCTATE_SIZE 1 
#define RRM_OAM_CARRIER_GERAN_CELL_RESEL_PRI_PRESENCE_FLAG 0x01 
#define RRM_OAM_CARRIER_GERAN_P_MAX_GERAN_PRESENCE_FLAG 0x02 
#define RRM_OAM_CARRIER_GERAN_OFFSET_FREQ_PRESENCE_FLAG 0x04
/*! \  rrm_oam_carrier_freq_comman_info
 *  \brief This struct is used for carrier frequency common information
 *  \param present_bitmask To check optional field is present or not
 *  \param cell_reselection_priority Absolute priority of the concerned carrier frequency/set of freq as used by cell reselection procedure
 *  \param ncc_peritted[OCTATE_SIZE] encoded as a bit map
 *  \param q_rx_lev_min Minimum required RX level in the cell 
 *  \param p_max_geran Maximum allowed transmission power for GERAN on an uplink carrier frequency
 *  \param thres_x_high specifies the Srxlev threshold used by the UE when reselecting towards a higher priority RAT/frequency than the current serving frequency
 *  \param thres_x_low specifies the Srxlev threshold used by the UE when reselecting towards a lower priority RAT/frequency than the current serving frequency
 *  \param offset_freq offset frequency
 */
typedef struct 
{
	rrm_bitmask_t  present_bitmask;             /*^ BITMASK ^*/
	U8             cell_reselection_priority;  /*^ O, RRM_OAM_CARRIER_GERAN_CELL_RESEL_PRI_PRESENCE_FLAG, H, 0, 7 ^*/
	U8             ncc_peritted[OCTATE_SIZE];  /*^ M, 0, OCTET_STRING, FIXED ^*/
	U8             q_rx_lev_min;               /*^ M, 0, H, 0, 45 ^*/
	U8             p_max_geran;		  /*^ O, RRM_OAM_CARRIER_GERAN_P_MAX_GERAN_PRESENCE_FLAG, H, 0, 39 ^*/
	U8             thres_x_high;		  /*^ M, 0, H, 0, 31 ^*/
	U8             thres_x_low;		  /*^ M, 0, H, 0, 31 ^*/
    S8             offset_freq;        /*^ O, RRM_OAM_CARRIER_GERAN_OFFSET_FREQ_PRESENCE_FLAG, B, -15, 15 ^*/
}rrm_oam_carrier_freq_comman_info;
/*! \ rrm_oam_explicit_list_arfcns_t
 *  \brief This struct is used for list of explicit arfcn
 *  \param count_explicit_arfcn Number of explicit arfcn
 *  \param data_explicit_arfcn[MAX_EXPL_ARFCNS] specify the remaining ARFCN values in the set are explicitly listed one by one
 */
typedef struct
{
    U8                  count_explicit_arfcn;                 /*^ M, 0, H, 0, 31 ^*/
    U16 data_explicit_arfcn[MAX_EXPL_ARFCNS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_oam_explicit_list_arfcns_t;

/*! \ rrm_oam_equally_spaced_arfcn s_t
 *  \brief This struct is used for equally spaced arfcns
 *  \param arfcn_spacing Space, d, between a set of equally spaced ARFCN values
 *  \param num_of_following_arfcns The number, n, of the remaining equally spaced ARFCN values in the set
 */
typedef struct
{
    U8  arfcn_spacing;          /*^ M, 0, B, 1, 8 ^*/
    U8  num_of_following_arfcns;/*^ M, 0, H, 0, 31 ^*/
} rrm_oam_equally_spaced_arfcns_t;

/*! \ rrm_oam_var_bitmap_of_arfcns_t
 *  \brief This struct is used for bitmap of arfcns
 *  \param count_var_bit_map Number of var bit map
 *  \param data_var_bitmap[MAX_VAR_BITMAP_OF_ARFCNS] Bitmap field indicating remaining ARFCN values in the set
 */
typedef struct
{
    U8        count_var_bit_map;                          /*^ M, 0, B, 1, 16 ^*/
    U8        data_var_bitmap[MAX_VAR_BITMAP_OF_ARFCNS];
/*^ M, 0, OCTET_STRING, VARIABLE ^*/

} rrm_oam_var_bitmap_of_arfcns_t;

#define RRM_OAM_GERAN_EXPL_LIST_OF_ARFCNS_PRESENCE_FLAG    0x01 
#define RRM_OAM_GERAN_EQ_SPACED_ARFCNS_PRESENCE_FLAG       0x02 
#define RRM_OAM_GERAN_VAR_BITMAP_ARFCNS_PRESENCE_FLAG      0x04 
/*! \ rrm_oam_geran_following_arfcn_t
 *  \brief This struct is used for GERAN following ARFCN information
 *  \param presence_bitmask To check optional field is present or not
 *  \param explicit_list_of_arfcns  used for list of explicit arfcn
 *  \param equally_spaced_arfcns  used for equally spaced arfcns
 *  \param var_bitmap_of_arfcns  used for bitmap of arfcns
 */
typedef struct 
{
	rrm_bitmask_t                   presence_bitmask;       /*^ BITMASK ^*/
    rrm_oam_explicit_list_arfcns_t   explicit_list_of_arfcns; 
/*^ O, RRM_OAM_GERAN_EXPL_LIST_OF_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_equally_spaced_arfcns_t  equally_spaced_arfcns; 
/*^ O, RRM_OAM_GERAN_EQ_SPACED_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/ 

    rrm_oam_var_bitmap_of_arfcns_t   var_bitmap_of_arfcns;
/*^ O, RRM_OAM_GERAN_VAR_BITMAP_ARFCNS_PRESENCE_FLAG, N, 0, 0 ^*/ 
}rrm_oam_geran_following_arfcn_t;

/*! \enum  rrm_oam_carrier_freq_geran_band_indicator_et
 *  \brief An enum for carrier frequency geran band indicator
 */
typedef enum
{
  RRM_OAM_DCS1800,
  RRM_OAM_PCS1900
}rrm_oam_carrier_freq_geran_band_indicator_et;

/*! \ rrm_oam_carrier_freq_info_geran_t
 *  \brief This struct is used for carrier frequency information of geran
 *  \param starting_arfcn first ARFCN value in the set
 *  \param band_indicator Indicates how to interpret the ARFCN of the BCCH carrier
 *  \param following_arfcn Indicates remaining ARFCN values in the set
 */
typedef struct 
{
	U16 starting_arfcn; 		/*^ M, 0, H, 0, 1023 ^*/
	rrm_oam_carrier_freq_geran_band_indicator_et band_indicator;		/*^ M, 0, H, 0, 1 ^*/ 
	rrm_oam_geran_following_arfcn_t following_arfcn; /*^ M, 0, N, 0, 0 ^*/ 
}rrm_oam_carrier_freq_info_geran_t;

/*! \ rrm_oam_carrier_freq_geran_param_t
 *  \brief This struct is used to provide one or more GERAN ARFCN values, which represents a list of GERAN BCCH carrier freq
 *  \param carrier_freq carrier frequency
 *  \param common_info common information
 */
typedef struct 
{
	rrm_oam_carrier_freq_info_geran_t carrier_freq;/*^ M, 0, N, 0, 0 ^*/ 
	rrm_oam_carrier_freq_comman_info common_info; /*^ M, 0, N, 0, 0 ^*/ 
}rrm_oam_carrier_freq_geran_param_t;

/*! \ rrm_oam_carrier_freq_geran_param_list_t
 *  \brief This struct is used for carrier frequency geran parameter list
 *  \param count_geran_carrier Number of geran RFCN values
 *  \param carrier_list[MAX_GERAN_FREQ] provide one or more GERAN ARFCN values
 */
typedef struct 
{
	U8 count_geran_carrier;								 /*^ M, 0, B, 1, 16 ^*/
	rrm_oam_carrier_freq_geran_param_t carrier_list[MAX_GERAN_FREQ];    /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_carrier_freq_geran_param_list_t;


#define RRM_OAM_T_RESELECTION_GERAN_SPEED_SCALE_FACTOR_PRESENT 0x01

/*! \ rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t
 *  \brief This struct is used for idle mode mobility inter rat eutran to geran reselection parameters
 *  \param bitmask To check optional field is present or not
 *  \param t_reselection_geran specifies the cell reselection timer value for GERAN
 *  \param speed_scale_factors speed scale factors
 */
typedef struct 
{
        rrm_bitmask_t                  bitmask;    /*^ BITMASK ^*/
        U8                             t_reselection_geran; /*^ M, 0, H, 0, 7 ^*/
        rrm_oam_speed_scale_factors_t  speed_scale_factors; /*^ O, RRM_OAM_T_RESELECTION_GERAN_SPEED_SCALE_FACTOR_PRESENT, N, 0, 0 ^*/
}rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t;

#define RRM_OAM_GERAN_CARRIER_FREQ_PARAMETER 0x01
/*! \ rrm_oam_idle_mode_mobility_inter_rat_geran_params_t
 *  \brief This struct is used for idle mode mobility inter rat geran parameters
 *  \param bitmask To check optional field is present or not
 *  \param geran_reselection_params geran reselection parameters
 *  \param carrier_freq_info_list carrier frequency information list
 */
typedef struct rrm_oam_idle_mode_mobility_inter_rat_geran_params
{
        rrm_bitmask_t				bitmask;    /*^ BITMASK ^*/
	rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t  geran_reselection_params; /*^ M, 0, N, 0, 0 ^*/ 
	rrm_oam_carrier_freq_geran_param_list_t                              carrier_freq_info_list; /*^ O, RRM_OAM_GERAN_CARRIER_FREQ_PARAMETER, N, 0, 0 ^*/ 
}rrm_oam_idle_mode_mobility_inter_rat_geran_params_t;



#define RRM_OAM_IDLE_MODE_MOBILITY_IRAT_UTRA_PRESENT  0x01
#define RRM_OAM_BAND_CLASS_INFO_CDMA2000_CELL_RESELECT_PRI_PRESENCE_FLAG  0x01
/*! \ rrm_oam_band_class_info_cdma2000_t
 *  \brief This struct is used for band class information for cdma2000
 *  \param bitmask To check optional field is present or not
 *  \param band_class Identifies the Frequency Band in which the Carrier can be found
 *  \param cell_reselection_priority Cell reselection priority of CDMA2000 cell
 *  \param thresh_x_high specifies the high threshold used in reselection towards this CDMA2000 band class
 *  \param thresh_x_low specifies the low  threshold used in reselection towards this CDMA2000 band class
 */
typedef struct rrm_oam_band_class_info_cdma2000
{
    rrm_bitmask_t    presence_bitmask;          /*^ BITMASK ^*/
    U8     band_class;
    /*^ M, 0, H, 0, 31 ^*/   /* rrm_oam_rrm_bandclass_cdma2000_et */

    U8     cell_reselection_priority;
    /*^ O, RRM_OAM_BAND_CLASS_INFO_CDMA2000_CELL_RESELECT_PRI_PRESENCE_FLAG, H, 1, 7 ^*/

    U8     thresh_x_high;             /*^ M, 0, H, 0, 63 ^*/
    U8     thresh_x_low;              /*^ M, 0, H, 0, 63 ^*/
}rrm_oam_band_class_info_cdma2000_t;

/*! \ rrm_oam_band_class_list_cdma2000_t
 *  \brief This struct is used for band class list cdma 2000 info
 *  \param count Valid count for  band_class_info_cdma2000
 *  \param band_class_info_cdma2000[RRM_MAX_CDMA_BAND_CLASS] array of band class information cdma 2000
 */
typedef struct rrm_oam_band_class_list_cdma2000
{
    U8                          count;                  /*^ M, 0, H, 1, 32 ^*/
    rrm_oam_band_class_info_cdma2000_t  band_class_info_cdma2000[RRM_MAX_CDMA_BAND_CLASS];
    /*^ M, 0, OCTET_STRING, VARIABLE ^*/

}rrm_oam_band_class_list_cdma2000_t;

/*! \ rrm_oam_pz_hyst_parameters_included_t
 *  \brief This struct is used for packet zone hysteresis parameters 
 *  \param bitmask To check optional field is present or not
 *  \param pz_hyst_enabled If the packet zone hysteresis feature is to be enabled at the mobile station,BS shall set this to 1 else 0
 *  \param pz_hyst_info_incl this is included depending upon bitmask value by base station
 *  \param pz_hyst_list_len this is included depending upon bitmask value by base station
 *  \param pz_hyst_act_timer this is included depending upon bitmask value by base station
 *  \param pz_hyst_timer_mul this is included depending upon bitmask value by base station
 *  \param pz_hyst_timer_exp Packet zone hysteresis timer exponent
 */
typedef struct
{
        rrm_bitmask_t                      bitmask;  /*^ BITMASK ^*/
#define RRM_OAM_PZ_HYST_ENABLD_PRESENT                      0x01
#define RRM_OAM_PZ_HYST_INFO_INCL_PRESENT                   0x02
#define RRM_OAM_PZ_HYST_LIST_LEN_PRESENT                    0x04
#define RRM_OAM_PZ_HYST_ACT_TIMER_PRESENT                   0x08
#define RRM_OAM_PZ_HYST_TIMER_MUL_PRESENT                   0x10
#define RRM_OAM_PZ_HYST_TIMER_EXP_PRESENT                   0x20
        U8                                pz_hyst_enabled;   
        /*^ O, RRM_OAM_PZ_HYST_ENABLD_PRESENT, H, 0, 1 ^*/
        U8                                pz_hyst_info_incl; 
        /*^ O, RRM_OAM_PZ_HYST_INFO_INCL_PRESENT, H, 0, 1 ^*/
        U8                                pz_hyst_list_len;  
        /*^ O, RRM_OAM_PZ_HYST_LIST_LEN_PRESENT, H, 0, 1 ^*/
        U8                                pz_hyst_act_timer; 
        /*^ O, RRM_OAM_PZ_HYST_ACT_TIMER_PRESENT, N, 0, 255 ^*/
        U8                                pz_hyst_timer_mul; 
        /*^ O, RRM_OAM_PZ_HYST_TIMER_MUL_PRESENT, H, 0, 7 ^*/
        U8                                pz_hyst_timer_exp; 
        /*^ O, RRM_OAM_PZ_HYST_TIMER_EXP_PRESENT, H, 0, 31 ^*/
}rrm_oam_pz_hyst_parameters_included_t;

/*! \ rrm_oam_fpc_fch_included_t
 *  \brief This struct is used for
 *  \param bitmask To check optional field is present or not
 *  \param fpc_fch_init_setpt_rc3 The base station shall set this field to initial Fundamental Channel outer loop Eb/Nt setpoint, in units of 0.125 dB
 *  \param fpc_fch_init_setpt_rc4 The base station shall set this field to initial Fundamental Channel outer loop Eb/Nt setpoint, in units of 0.125 dB
 *  \param fpc_fch_init_setpt_rc5 The base station shall set this field to initial Fundamental Channel outer loop Eb/Nt setpoint, in units of 0.125 dB
 */
typedef struct
{
        rrm_bitmask_t                      bitmask;  /*^ BITMASK ^*/
#define RRM_OAM_FPC_FCH_INIT_SETPT_RC3_PRESENT              0x01
#define RRM_OAM_FPC_FCH_INIT_SETPT_RC4_PRESENT              0x02
#define RRM_OAM_FPC_FCH_INIT_SETPT_RC5_PRESENT               0x04
        U8                                 fpc_fch_init_setpt_rc3; 
        /*^ O, RRM_OAM_FPC_FCH_INIT_SETPT_RC3_PRESENT, N, 0, 255 ^*/
        U8                                 fpc_fch_init_setpt_rc4; 
        /*^ O, RRM_OAM_FPC_FCH_INIT_SETPT_RC4_PRESENT, N, 0, 255 ^*/
        U8                                 fpc_fch_init_setpt_rc5; 
        /*^ O, RRM_OAM_FPC_FCH_INIT_SETPT_RC5_PRESENT, N, 0, 255 ^*/
}rrm_oam_fpc_fch_included_t;

#define RRM_OAM_PZ_ID_HYST_PARAMETERS_INCLUDED_PRESENT      0x00001
#define RRM_OAM_P_REV_INCLUDED_PRESENT                      0x00002
#define RRM_OAM_MIN_P_REV_INCLUDED_PRESENT                  0x00004
#define RRM_OAM_NEG_SLOT_CYCLE_INDEX_SUP_INCLUDED_PRESENT   0x00008
#define RRM_OAM_ENCRYPT_MODE_INCLUDED_PRESENT               0x00010
#define RRM_OAM_ENC_SUPPORTED_INCLUDED_PRESENT              0x00020
#define RRM_OAM_SIG_ENCRYPT_SUP_INCLUDED_PRESENT            0x00040
#define RRM_OAM_MSG_INTEGRITY_SUP_INCLUDED_PRESENT          0x00080
#define RRM_OAM_SIG_INTEGRITY_SUP_INCL_INCLUDED_PRESENT     0x00100
#define RRM_OAM_SIG_INTEGRITY_SUP_INCLUDED_PRESENT          0x00200
#define RRM_OAM_MS_INIT_POS_LOC_SUP_IND_INCLUDED_PRESENT    0x00400
#define RRM_OAM_BAND_CLASS_INFO_REQ_INCLUDED_PRESENT        0x00800
#define RRM_OAM_BAND_CLASS_INCLUDED_PRESENT                 0x01000
#define RRM_OAM_ALT_BAND_CLASS_INCLUDED_PRESENT             0x02000
#define RRM_OAM_TKZ_MODE_SUPPORTED_INCLUDED_PRESENT         0x04000
#define RRM_OAM_TKZ_ID_INCLUDED_PRESENT                     0x08000
#define RRM_OAM_FPC_FCH_INCLUDED_PRESENT                    0x10000
#define RRM_OAM_T_ADD_INCLUDED_PRESENT                      0x20000
#define RRM_OAM_PILOT_INC_INCLUDED_PRESENT                  0x40000

/*! \ rrm_oam_cell_specific_params_t
 *  \brief This struct is used for cell specific parameters
 *  \param bitmask To check optional field is present or not
 *  \param pz_hyst_parameters_included denote power zone hyst parmas if present
 *  \param p_rev The base station shall set this field to the base station protocol revision level 
 *               that the mobile station is to use after completion of the handoff
 *  \param min_p_rev Minimum mobile station protocol revision level required for access to the CDMA system
 *  \param neg_slot_cycle_index_sup The base station shall set this field to 1 if it 
 *                                   supports negative values of the preferred slot cycle index
 *  \param encrypt_mode Message encryption mode
 *  \param enc_supported The base station shall set this field to 1 if the encryption related fields are included
 *  \param sig_encrypt_sup indicates which signaling encryption algorithms are supported by the base station
 *  \param msg_integrity_sup If the base station supports message integrity, the base station shall set this field to 1
 *  \param sig_integrity_sup_incl If the base station supports other integrity algorithm(s) in addition 
 *                                to the default integrity algorithm, the base station shall set this field to 1
 *  \param sig_integrity_sup The base station shall set this field to indicate the supported message integrity 
 *                           algorithms in addition to the default integrity algorithm
 *  \param ms_init_pos_loc_sup_ind If the base station supports mobile station initiated position determination, 
 *                                 the base station shall set this field to 1
 *  \param band_class_info_req The base station shall set this field to 1 if the ALT_BAND_CLASS 
 *                             field is included in this message
 *  \param band_class represents the bandclass 
 *  \param alt_band_class The base station shall set this field to an alternate CDMA band class 
 *                        supported by the base station
 *  \param tkz_mode_supported The base station shall set this field to 1 if the tracking zone mode is supported
 *  \param tkz_id if flag is set then the base station shall set this field to its tracking zone identifier
 *  \param fpc_fch_included FPC and FCH included
 *  \param t_add This value is used by the mobile station to trigger the transfer of a pilot from the 
 *               Neighbor Set or Remaining Set to the Candidate Set and to trigger the sending of the 
 *               Pilot Strength Measurement Message or Extended Pilot Strength Measurement Message 
 *               initiating the handoff process
 *  \param pilot_inc A mobile station searches for Remaining-Set pilots at pilot PN sequence 
 *                   index values that are multiples of this value
 */
typedef struct _rrm_oam_cell_specific_params_t
{
    rrm_bitmask_t                      bitmask; /*^ BITMASK ^*/
    /*base station*/
    rrm_oam_pz_hyst_parameters_included_t 
        pz_hyst_parameters_included;
    /*^ O,RRM_OAM_PZ_ID_HYST_PARAMETERS_INCLUDED_PRESENT , N, 0, 0 ^*/
    U8      p_rev;
    /*^ O,RRM_OAM_P_REV_INCLUDED_PRESENT , N, 0, 255 ^*/
    U8      min_p_rev;
    /*^ O,RRM_OAM_MIN_P_REV_INCLUDED_PRESENT , N, 0, 255 ^*/
    U8      neg_slot_cycle_index_sup;
    /*^ O,RRM_OAM_NEG_SLOT_CYCLE_INDEX_SUP_INCLUDED_PRESENT , H, 0, 1 ^*/
    U8      encrypt_mode;
    /*^ O,RRM_OAM_ENCRYPT_MODE_INCLUDED_PRESENT , N, 0, 255 ^*/
    U8      enc_supported;
    /*^ O,RRM_OAM_ENC_SUPPORTED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      sig_encrypt_sup;
    /*^ O,RRM_OAM_SIG_ENCRYPT_SUP_INCLUDED_PRESENT, N, 0, 255 ^*/
    U8      msg_integrity_sup;
    /*^ O,RRM_OAM_MSG_INTEGRITY_SUP_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      sig_integrity_sup_incl;
    /*^ O,RRM_OAM_SIG_INTEGRITY_SUP_INCL_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      sig_integrity_sup;
    /*^ O,RRM_OAM_SIG_INTEGRITY_SUP_INCLUDED_PRESENT, N, 0, 255 ^*/
    U8      ms_init_pos_loc_sup_ind;
    /*^ O,RRM_OAM_MS_INIT_POS_LOC_SUP_IND_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      band_class_info_req;
    /*^ O,RRM_OAM_BAND_CLASS_INFO_REQ_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      band_class;
    /*^ O,RRM_OAM_BAND_CLASS_INCLUDED_PRESENT, H, 0, 31 ^*/
    U8      alt_band_class;
    /*^ O,RRM_OAM_ALT_BAND_CLASS_INCLUDED_PRESENT, H, 0, 31 ^*/
    U8      tkz_mode_supported;
    /*^ O,RRM_OAM_TKZ_MODE_SUPPORTED_INCLUDED_PRESENT, H, 0, 1 ^*/
    U8      tkz_id;
    /*^ O,RRM_OAM_TKZ_ID_INCLUDED_PRESENT, H, 0, 1 ^*/
    rrm_oam_fpc_fch_included_t
        fpc_fch_included;
    /*^ O,RRM_OAM_FPC_FCH_INCLUDED_PRESENT, N, 0, 0 ^*/
    U8      t_add;
    /*^ O,RRM_OAM_T_ADD_INCLUDED_PRESENT, H, 0, 63 ^*/
    U8      pilot_inc;
    /*^ O,RRM_OAM_PILOT_INC_INCLUDED_PRESENT, H, 0, 15 ^*/
    /*base station*/
}rrm_oam_cell_specific_params_t;

/*! \ rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t
 *  \brief This struct is used to control when the UE should re-register
 *  \param count Valid number of  pre_reg_zone_id
 *  \param pre_reg_zone_id[RRM_PRE_REG_ZONE_ID] Used to control when the UE should register or re-register
 */
typedef struct rrm_oam_secondary_pre_reg_zone_id_list_hrpd
{
    U8 count;              /*^ M, 0, B, 1, 2 ^*/
    U8 pre_reg_zone_id[RRM_PRE_REG_ZONE_ID]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t;

#define RRM_OAM_PRE_REG_INFO_HRPD_ZONE_ID_PRESENCE_FLAG         0x01
#define RRM_OAM_PRE_REG_INFO_HRPD_SECONDARY_LST_PRESENCE_FLAG   0x02
/*! \ rrm_oam_pre_reg_info_hrpd_t
 *  \brief This struct is used for the CDMA2000 HRPD Pre-Registration Information tells the UE if it should 
 *         pre-register with the CDMA2000 HRPD network and identifies the Pre-registration zone to the UE
 *  \param presence_bitmask To check optional field is present or not
 *  \param pre_reg_allowed TRUE indicates that a UE shall perform a CDMA2000 HRPD pre-registration 
 *                          if the UE does not have a valid / current pre-registration
 *  \param pre_reg_zone_id Used to control when the UE should register or re-register
 *  \param secondary_list used to control when the UE should re-register
 */
typedef struct rrm_oam_pre_reg_info_hrpd
{
    rrm_bitmask_t                         presence_bitmask; /*^ BITMASK ^*/
    U8                                    pre_reg_allowed;
    /*^ M, 0, H, 0, 1 ^*/    /* rrm_bool_et */

    U8                                    pre_reg_zone_id;
    /*^ O, RRM_OAM_PRE_REG_INFO_HRPD_ZONE_ID_PRESENCE_FLAG, N, 0, 255 ^*/

    rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t secondary_list;
    /*^ O, RRM_OAM_PRE_REG_INFO_HRPD_SECONDARY_LST_PRESENCE_FLAG, N, 0, 0 ^*/

}rrm_oam_pre_reg_info_hrpd_t;

/*! \ rrm_oam_ac_barring_config_1_xrtt_r9_t
 *  \brief This struct is used for access barring config params
 *  \param ac_barring_0_to_9_r9 Parameter used for calculating the access class barring factor 
 *                              for access overload classes 0 through 9
 *  \param ac_barring_10_r9 Parameter used for calculating the access class barring factor for access overload class 10
 *  \param ac_barring_11_r9 Parameter used for calculating the access class barring factor for access overload class 11
 *  \param ac_barring_12_r9 Parameter used for calculating the access class barring factor for access overload class 12
 *  \param ac_barring_13_r9 Parameter used for calculating the access class barring factor for access overload class 13
 *  \param ac_barring_14_r9 Parameter used for calculating the access class barring factor for access overload class 14
 *  \param ac_barring_15_r9 Parameter used for calculating the access class barring factor for access overload class 15
 *  \param ac_barring_msg_r9 Parameter used for modifying the access class barring factor for message transmissions
 *  \param ac_barring_reg_r9 Parameter used for modifying the access class barring factor for autonomous registrations
 *  \param ac_barring_emg_r9 Parameter used for calculating the access class barring factor for 
 *                         emergency calls and emergency message transmissions for access overload classes 0 through 9
 */
typedef struct rrm_oam_ac_barring_config_1_xrtt_r9
{
    U8   ac_barring_0_to_9_r9; /*^ M, 0, H, 0, 63 ^*/
    U8   ac_barring_10_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_11_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_12_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_13_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_14_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_15_r9;   /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_msg_r9;  /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_reg_r9;  /*^ M, 0, H, 0, 7 ^*/
    U8   ac_barring_emg_r9;  /*^ M, 0, H, 0, 7 ^*/

}rrm_oam_ac_barring_config_1_xrtt_r9_t;


/*! \ rrm_oam_mobility_sib_8_params_t
 *  \brief This struct is used for mobility parameters for SIB 8
 *  \param bitmask To check optional field is present or not
 *  \param sid[RRM_XRTT_SID_OCTET_SIZE] System Identification, A number uniquely identifying a wireless system
 *  \param nid[RRM_XRTT_NID_OCTET_SIZE] Network identification
 *  \param multiple_sid Multiple SID storage indicator
 *  \param multiple_nid Multiple NID storage indicator
 *  \param reg_zone[RRM_XRTT_REG_ZONE_OCTET_SIZE] Registration zone,The base station shall set this field to its registration zone number
 *  \param total_zone[RRM_XRTT_TOTAL_ZONE_OCTET_SIZE] Number of registration zones to be retained
 *  \param zone_timer[RRM_XRTT_ZONE_TIMER_OCTET_SIZE] The base station shall set this field to the ZONE_TIMER 
 *          value corresponding to the length of the zone registration timer to be used by mobile stations
 *  \param packet_zone_id packet data service zone
 *  \param home_reg If mobile stations that are not roaming and have MOB_TERM_HOME equal to 1
 *         are to be enabled for autonomous registrations, the base station shall set this field to 1
 *  \param foreign_sid_reg If mobile stations that are foreign SID roamers and have MOB_TERM_FOR_SID 
 *        equal to 1 are to be enabled for autonomous registration,the base station shall set this field to 1
 *  \param foreign_nid_reg If mobile stations that are foreign NID roamers and have MOB_TERM_FOR_NID equal to 1 are to 
 *          be enabled for autonomous registration BS set this field to 1
 *  \param parame_reg If mobile stations are to register on parameter change events, 
 *        the base station shall set this field to 1
 *  \param power_up_reg If mobile stations enabled for autonomous registration are to register 
 *         immediately after powering on and receiving the system overhead messages,the base station shall set this field to 1
 *  \param reg_prd reg prd value
 *  \param power_down_reg If mobile stations enabled for autonomous registration are to 
 *              register immediately before powering down,the base station shall set this field to 1
 */
typedef struct _rrm_oam_sib_type_8_params_t
{
    rrm_bitmask_t                      bitmask; /*^ BITMASK ^*/
#define RRM_OAM_PACKET_ZONE_ID_INCLUDED_PRESENT             0x01
#define RRM_OAM_POWER_DOWN_REG_INCLUDED_PRESENT             0x02
    /* for Sib-8*/
    U8  sid[RRM_XRTT_SID_OCTET_SIZE]; /*^ M, 0, OCTET_STRING, FIXED ^*/
    U8  nid[RRM_XRTT_NID_OCTET_SIZE]; /*^ M, 0, OCTET_STRING, FIXED ^*/
    U8  multiple_sid;             /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  multiple_nid;             /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  reg_zone[RRM_XRTT_REG_ZONE_OCTET_SIZE];
    /*^ M, 0, OCTET_STRING, FIXED ^*/

    U8  total_zone[RRM_XRTT_TOTAL_ZONE_OCTET_SIZE];
    /*^ M, 0, OCTET_STRING, FIXED ^*/

    U8  zone_timer[RRM_XRTT_ZONE_TIMER_OCTET_SIZE];
    /*^ M, 0, OCTET_STRING, FIXED ^*/
    U8      packet_zone_id;
    /*^ O,RRM_OAM_PACKET_ZONE_ID_INCLUDED_PRESENT , N, 0, 255 ^*/
    U8  home_reg;                 /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  foreign_sid_reg;          /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  foreign_nid_reg;          /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  parame_reg;               /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */
    U8  power_up_reg;             /*^ M, 0, H, 0, 1 ^*/     /* rrm_bool_et */

    /* changes CDMA2000 after review starts */
    U8      reg_prd;              /*^ M, 0, N, 0, 0 ^*/
    /* changes CDMA2000 after review ends */

    U8      power_down_reg;
    /*^ O,RRM_OAM_POWER_DOWN_REG_INCLUDED_PRESENT, H, 0, 1 ^*/
    /* for Sib-8*/
}rrm_oam_mobility_sib_8_params_t;

/*! \ rrm_oam_cdma2000_rand_t
 *  \brief This struct is used for cdma random parameters
 *  \param rand_seed Initial Random Seed given by RRM to L3
 *  \param rand_min Minimun value of Rand
 *  \param rand_max Maximum value of Rand
 *  \param rand_regenerate_timer Timer duration in seconds to regenerate new Random Value
 */
typedef struct
{
    U32              rand_seed;     /*^ M, 0, H, 0, 4294967295 ^*/
    U32              rand_min;     /*^ M, 0, H, 0, 4294967295 ^*/
    U32              rand_max;     /*^ M, 0, H, 0, 4294967295 ^*/
    /* timer duration in seconds to regenerate new Random Value*/
    U32              rand_regenerate_timer;     /*^ M, 0, B, 1, 4294967296 ^*/
}rrm_oam_cdma2000_rand_t;

/*! \ rrm_oam_cdma2000_1xrtt_cell_identifier_t
 *  \brief This struct is used for 1xrtt cell identifier parameters
 *  \param cdma2000_1xrtt_cell_id[RRM_CDMA2000_1XRTT_CELL_ID_LENGTH] Cell Id of CDMA2000 1XRTT DAHO Cell. 
 */
typedef struct
{
    U8 cdma2000_1xrtt_cell_id[RRM_CDMA2000_1XRTT_CELL_ID_LENGTH];
    /*^ M,0,OCTET_STRING,FIXED ^*/
}rrm_oam_cdma2000_1xrtt_cell_identifier_t;

/*! \ rrm_oam_cdma2000_hrpd_cell_identifier_t
 *  \brief This struct is used for hrpd cell identifier parameters
 *  \param cdma2000_hrpd_cell_id[RRM_CDMA2000_HRPD_CELL_ID_LENGTH] Cell Id of CDMA2000 HRPD DAHO cell
 */
typedef struct
{
    U8 cdma2000_hrpd_cell_id_length; /*^ M,0,H,0,16 ^*/
    U8 cdma2000_hrpd_cell_id[RRM_CDMA2000_HRPD_CELL_ID_LENGTH]; /*^ M,0,OCTET_STRING, FIXED ^*/
}rrm_oam_cdma2000_hrpd_cell_identifier_t;

/*! \  rrm_oam_cdma2000_cell_param_t
 *  \brief This struct is used for cdma2000 cell parameters
 *  \param bitmask To check optional field is present or not
 *  \param cdma2000_rand cdma2000 random parameters
 *  \param cell_id_1xrtt cell id of 1xrtt
 *  \param cell_id_hrpd cell id of hrpd
 */
typedef struct _rrm_oam_cdma2000_cell_param_t
{
    rrm_bitmask_t    bitmask; /*^ BITMASK ^*/
#define RRM_OAM_CDMA2000_PARAM_1XRTT_CELL_ID_PRESENCE_FLAG             0x01
#define RRM_OAM_CDMA2000_PARAM_HRPD_SECTOR_ID_PRESENCE_FLAG              0x02
    rrm_oam_cdma2000_rand_t    cdma2000_rand;     /*^ M, 0, N, 0, 0 ^*/
    rrm_oam_cdma2000_1xrtt_cell_identifier_t     
                               cell_id_1xrtt;     
    /*^ O, RRM_OAM_CDMA2000_PARAM_1XRTT_CELL_ID_PRESENCE_FLAG, N, 0, 0 ^*/
    rrm_oam_cdma2000_hrpd_cell_identifier_t    
                               cell_id_hrpd;    
    /*^ O, RRM_OAM_CDMA2000_PARAM_HRPD_SECTOR_ID_PRESENCE_FLAG, N, 0, 0 ^*/
}rrm_oam_cdma2000_cell_param_t;

/*! \  rrm_oam_irat_parameters_cdma2000_v920_t
 *  \brief This struct is used for inter rat parameters cdma2000 v920 parameters
 *  \param eCSFB_1xrtt_r9 Indicates whether the UE supports enhanced CS fallback to CDMA2000 1xRTT or not
 *  \param eCSFB_conc_ps_mobility_1xrtt_r9 Indicates whether the UE supports concurrent enhanced CS fallback to 
 *                                         CDMA2000 1xRTT and PS handover/ redirection to CDMA2000 HRPD
 */
typedef struct _rrm_oam_irat_parameters_cdma2000_v920_t
{
#define RRM_OAM_CDMA2000_PARAM_CONC_PS_MOBILITY_PRESENCE_FLAG     0x01
    rrm_bitmask_t    bitmask; /*^ BITMASK ^*/
    U8                    eCSFB_1xrtt_r9;/*^ M, 0, N, 0, 0 ^*/
    /*rrm_oam_eCSFB_1xrtt_r9_et*/

    U8                    eCSFB_conc_ps_mobility_1xrtt_r9;
/*^O, RRM_OAM_CDMA2000_PARAM_CONC_PS_MOBILITY_PRESENCE_FLAG, N, 0, 0 ^*/
    /*rrm_oam_eCSFB_conc_ps_mobility_1xrtt_r9_et*/
}rrm_oam_irat_parameters_cdma2000_v920_t;

#define RRM_OAM_CELL_RESELECT_CDMA2000_SF_PRESENCE_FLAG         0x01
/*! \  rrm_oam_cell_reselection_params_cdma2000_t
 *  \brief This struct is used for cell reselection params for CDMA 2000
 *  \param presence_bitmask To check optional field is present or not
 *  \param band_class_list band class list parameters
 *  \param t_reselection_cdma2000 Parameter TreselectionCDMA_HRPD or TreselectionCDMA_1xRTT in TS 36.304
 *  \param t_reselection_cdma2000_sf SpeedStateScaleFactors concerns factors, to be applied when the 
 *              UE is in medium or high speed state, used for scaling a mobility control related parameter
 */
typedef struct _rrm_oam_cell_reselection_params_cdma2000_t
{
    rrm_bitmask_t                     presence_bitmask;    /*^ BITMASK ^*/
    rrm_oam_band_class_list_cdma2000_t  band_class_list;   
    /*^ M, 0, N, 0, 0 ^*/

    U8                          t_reselection_cdma2000;
    /*^ M, 0, H, 0, 7 ^*/

    rrm_oam_speed_scale_factors_t t_reselection_cdma2000_sf;
    /*^ O, RRM_OAM_CELL_RESELECT_CDMA2000_SF_PRESENCE_FLAG, N, 0, 0 ^*/

}rrm_oam_cell_reselection_params_cdma2000_t;

#define RRM_OAM_SEARCH_WIN_SIZE_PRESENCE_FLAG                   0x01
#define RRM_OAM_CSFB_SUPPORT_FOR_DUAL_RX_UES_R9_PRESENCE_FLAG   0x02
#define RRM_OAM_CSFB_REG_PARAM_1XRTT_V920_PRESENCE_FLAG         0x04
#define RRM_OAM_AC_BARRING_CONFIG_1_XRTT_R9_PRESENCE_FLAG       0x08
#define RRM_OAM_PRE_REG_INFO_HRPD_PRESENCE_FLAG                 0x10
#define RRM_OAM_MOBILITY_SIB_8_PARAMS_PRESENCE_FLAG             0x20
#define RRM_OAM_CDMA2000_CELL_PARAMS_PRESENCE_FLAG              0x40
#define RRM_OAM_IRAT_PARAMS_CDMA2000_V920_PRESENCE_FLAG         0x80
#define RRM_OAM_CELL_RESEL_PARAMS_HRPD_CDMA2000_PRESENCE_FLAG   0x100
#define RRM_OAM_CELL_RESEL_PARAMS_1XRTT_CDMA2000_PRESENCE_FLAG  0x200
#define RRM_OAM_SYSTEM_TIME_INFO_PRESENCE_FLAG                  0x400
/*! \  rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t
 *  \brief This struct is used for Inter-RAT cell re-selection parameters from E-UTRA to CDMA
 *  \param presence_bitmask To check optional field is present or not
 *  \param search_window_size The search window size is a CDMA2000 parameter to be used to assist in 
 *                             searching for the neighbouring pilots
 *  \param csfb_support_for_dual_rx_ues_r9 Value TRUE indicates that the network supports dual Rx CSFB
 *  \param csfb_registration_param_1xrtt_v920 Used to indicate whether or not the UE shall perform a CDMA2000 
 *                   1xRTT pre-registration if the UE does not have a valid / current pre-registration
 *  \param ac_barring_config_1_xrtt_r9 access barring config 1 xrtt parameters
 *  \param pre_reg_info_hrpd The CDMA2000 HRPD Pre-Registration Information tells the UE if it should 
 *         pre-register with the CDMA2000 HRPD network and identifies the Pre-registration zone to the UE
 *  \param mobility_sib_8_params SIB 8 paramteres
 *  \param cdma2000_cell_param cdma2000 cell parameters
 *  \param inter_rat_parameters_cdma2000_v920 inter rat parameters cdma2000 parameters
 *  \param cell_reselection_params_hrpd cell reselection parameters for hrpd
 *  \param cell_reselection_params_1xrtt cell reselection parameters for 1xrtt
 *  \param system_time_info It tells whether the system time is synchronous or asynchronous
 */
typedef struct rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params
{
    rrm_bitmask_t                     presence_bitmask;    /*^ BITMASK ^*/

    U8                        search_window_size;
    /*^ O, RRM_OAM_SEARCH_WIN_SIZE_PRESENCE_FLAG, H, 0, 15 ^*/

    U8                csfb_support_for_dual_rx_ues_r9;
    /*^ O, RRM_OAM_CSFB_SUPPORT_FOR_DUAL_RX_UES_R9_PRESENCE_FLAG, H, 0, 1 ^*/ /* rrm_bool_et */

    rrm_oam_csfb_registration_param_1xrtt_v920_et    csfb_registration_param_1xrtt_v920;
    /*^ O, RRM_OAM_CSFB_REG_PARAM_1XRTT_V920_PRESENCE_FLAG, N,  0, 0 ^*/
    /* rrm_oam_csfb_registration_param_1xrtt_v920_et */

    rrm_oam_ac_barring_config_1_xrtt_r9_t    ac_barring_config_1_xrtt_r9;
    /*^ O, RRM_OAM_AC_BARRING_CONFIG_1_XRTT_R9_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_pre_reg_info_hrpd_t              pre_reg_info_hrpd;
    /*^ O, RRM_OAM_PRE_REG_INFO_HRPD_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_mobility_sib_8_params_t              mobility_sib_8_params;
    /*^ O, RRM_OAM_MOBILITY_SIB_8_PARAMS_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_cdma2000_cell_param_t            cdma2000_cell_param;
    /*^ O, RRM_OAM_CDMA2000_CELL_PARAMS_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_irat_parameters_cdma2000_v920_t  
                                  inter_rat_parameters_cdma2000_v920;
    /*^ O, RRM_OAM_IRAT_PARAMS_CDMA2000_V920_PRESENCE_FLAG, N, 0, 0 ^*/

    /* changes CDMA2000 after review starts */
    rrm_oam_cell_reselection_params_cdma2000_t  cell_reselection_params_hrpd;
    /*^ O, RRM_OAM_CELL_RESEL_PARAMS_HRPD_CDMA2000_PRESENCE_FLAG, N, 0, 0 ^*/

    rrm_oam_cell_reselection_params_cdma2000_t  cell_reselection_params_1xrtt;
    /*^ O, RRM_OAM_CELL_RESEL_PARAMS_1XRTT_CDMA2000_PRESENCE_FLAG, N, 0, 0 ^*/
    /* changes CDMA2000 after review ends */

    /* CDMA2000 updates */
    rrm_oam_system_time_info_et      system_time_info;
    /*^ O, RRM_OAM_SYSTEM_TIME_INFO_PRESENCE_FLAG, N, 0, 0 ^*/
    /* CDMA2000 updates */
}rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t;


#define RRM_OAM_IDLE_MODE_MOBILITY_COMMON_PARAMS_PRESENT    0x0001
#define RRM_OAM_IDLE_MODE_MOBILITY_INTRA_FREQ_PRESENT       0x0002
#define RRM_OAM_IDLE_MODE_MOBILITY_INTER_FREQ_PRESENT       0x0004
#define RRM_OAM_IDLE_MODE_MOBILITY_IRAT_GERAN_PRESENT       0x0008
#define RRM_OAM_IDLE_MODE_MOBILITY_IRAT_CDMA2000_PRESENT    0x0010
#define RRM_OAM_EUTRAN_UTRAN_TDD_LIST_PRESENT               0x0020
/*! \ rrm_oam_idle_mode_mobility_params_t
 *  \brief This struct is used for idle mode mobility parameters
 *  \param bitmask To check optional field is present or not
 *  \param idle_mode_mobility_common_params idle mode mobility common parameters
 *  \param idle_mode_mobility_intra_freq_params idle mode mobility intra frequency cells parameters
 *  \param idle_mode_inter_freq_params_list inter frequency parameters list
 *  \param irat_eutran_to_utran_tdd_list eutran to utran TDD list
 *  \param idle_mode_mobility_inter_rat_utra_params inter rat utran parameters
 *  \param idle_mode_mobility_inter_rat_geran_params inter rat geran parameters
 *  \param idle_mode_mobility_inter_rat_cdma2000_params inter rat cdma2000 parameters
 */
typedef struct _rrm_oam_idle_mode_mobility_params
{
     rrm_bitmask_t                              bitmask; /*^ BITMASK ^*/
     rrm_oam_common_params_t    		idle_mode_mobility_common_params;/*^ M, 0, N, 0, 0 ^*/
     rrm_oam_intra_freq_params_t        	idle_mode_mobility_intra_freq_params;/*^ M, 0, N, 0, 0 ^*/
     rrm_oam_inter_frequency_params_list_t 	idle_mode_inter_freq_params_list; /*^ M, 0, N, 0, 0 ^*/
     rrm_oam_idle_mode_mobility_inter_rat_utra_params_t  idle_mode_mobility_inter_rat_utra_params;/*^ O, RRM_OAM_IDLE_MODE_MOBILITY_IRAT_UTRA_PRESENT, N, 0, 0 ^*/
     rrm_oam_idle_mode_mobility_inter_rat_geran_params_t idle_mode_mobility_inter_rat_geran_params;/*^ O, RRM_OAM_IDLE_MODE_MOBILITY_IRAT_GERAN_PRESENT, N, 0, 0 ^*/
     rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t idle_mode_mobility_inter_rat_cdma2000_params;/*^ O, RRM_OAM_IDLE_MODE_MOBILITY_IRAT_CDMA2000_PRESENT, N, 0, 0 ^*/
}rrm_oam_idle_mode_mobility_params_t;

#define RRM_OAM_IDLE_MODE_MOBILITY_PARAMS_PRESENT    0x01
/*! \ rrm_oam_mobility_params_t
 *  \brief This struct is used for mobility parameters information
 *  \param bitmask To check optional field is present or not
 *  \param idle_mode_mobility_params indicate idle mode mobility parameters
 */
typedef struct _rrm_oam_mobility_params
{
     rrm_bitmask_t                              bitmask; /*^ BITMASK ^*/
     rrm_oam_idle_mode_mobility_params_t 	idle_mode_mobility_params;/*^ O, RRM_OAM_IDLE_MODE_MOBILITY_PARAMS_PRESENT, N, 0, 0 ^*/
}rrm_oam_mobility_params_t;

#define RRM_OAM_MAC_LAYER_PARAM_RACH_PRESENT    0x01
#define RRM_OAM_MAC_LAYER_PARAM_DRX_PRESENT     0x02
#define RRM_OAM_UL_SYNC_LOSS_TIMER_PRESENT      0x04
#define RRM_OAM_N_GAP_PRESENT                   0x08
/*! \  rrm_oam_mac_layer_params_t
 *  \brief This struct is used for MAC layer parameters
 *  \param bitmask To check optional field is present or not
 *  \param mac_layer_param_rach RACH parameters
 *  \param mac_layer_param_drx This parameter provides information about  DRXconfiguration
 *  \param ul_sync_loss_timer The UE sync loss is detected based on the expiry of the timerValue configured for this IE
 *  \param n_gap For system bandwidth <10Mhz, NGAP2 is not defined
 */
typedef struct _rrm_oam_mac_layer_params
{
	    rrm_bitmask_t		bitmask; /*^ BITMASK ^*/
	    rrm_oam_rach_t	        mac_layer_param_rach; /*^ O, RRM_OAM_MAC_LAYER_PARAM_RACH_PRESENT, N, 0, 0 ^*/
	    rrm_oam_drx_t		mac_layer_param_drx;/*^ O, RRM_OAM_MAC_LAYER_PARAM_DRX_PRESENT, N, 0, 0 ^*/ 
        S32                     ul_sync_loss_timer; /*^ O, RRM_OAM_UL_SYNC_LOSS_TIMER_PRESENT, N, 0, 0 ^*/
        S32                     n_gap; /*^ O, RRM_OAM_N_GAP_PRESENT, N, 0, 0 ^*/  
}rrm_oam_mac_layer_params_t;

/*! \ rrm_oam_rlc_layer_params_t
 *  \brief This struct is used for RLC layer parameters
 *  \param num_valid_srb_info Indicates the number of elements in the following array
 *  \param rlc_layer_param_srb[RRM_OAM_MAX_NUM_SRBS] The first member of the array is for the RLC layer 
 *        configuration for the SRB1 and the second member is for the RLC layer configuration for the SRB2
 */
typedef struct _rrm_oam_rlc_layer_params
{
	U8 		num_valid_srb_info;/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_srb_t 	rlc_layer_param_srb[RRM_OAM_MAX_NUM_SRBS]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/     /* array of 2 */	
}rrm_oam_rlc_layer_params_t;

/*! \  rrm_oam_rrc_timers_t
 *  \brief This struct is used for RRC timers information
 *  \param t300 Possible timer values:  100 millisecond,200 ms, 300 ms,400 ms, 600 ms, 1000 ms,1500 ms,2000 ms
 *  \param t301 Possible timer values:  100 millisecond,200 ms, 300 ms,400 ms, 600 ms, 1000 ms,1500 ms,2000 ms
 *  \param t302 Possible timer values:  100 millisecond,200 ms, 300 ms,400 ms, 600 ms, 1000 ms,1500 ms,2000 ms
 *  \param t304_eutra Possible timer values: 
*                    50 ms, 100 ms,150 ms, 200 ms,500 ms, ms1000 ms,2000 ms,

 *  \param t304_irat Possible timer values:  100 millisecond,200 ms, 500 ms, 1000 ms, 2000 ms, 4000 ms, 8000 ms
 *  \param t310 Possible timer values:  
*               0 millisecond, 50 ms, 100 ms, 200 ms, 500 ms, 1000 ms, 2000 ms
 *  \param t311 Possible timer values : 1000 millisecond, 3000 ms, 5000 ms, 10000 ms, 15000 ms, 20000 ms, 30000 ms
 *  \param t320 Possible timer values: 5 minutes,10 mins, 20 mins, 30 mins, 60  mins, 120 mins, 180 mins
 */
typedef struct _rrm_oam_rrc_timers
{
	rrm_oam_timer_300_301_et	t300;	        /*^ M, 0, N, 0, 0 ^*/		/* from ue_timers_and_constants_t */
	rrm_oam_timer_300_301_et	t301;		/*^ M, 0, N, 0, 0 ^*/		/* from ue_timers_and_constants_t */
        rrm_oam_timer_t302_et	        t302;		/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_timer_t304_eutra_et	t304_eutra;	/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_timer_t304_irat_et	t304_irat;	/*^ M, 0, N, 0, 0 ^*/
	rrm_oam_timer_310_et	        t310; 		/*^ M, 0, N, 0, 0 ^*/		/* from ue_timers_and_constants_t */
	rrm_oam_timer_311_et	        t311;		/*^ M, 0, N, 0, 0 ^*/		/* from ue_timers_and_constants_t */
	rrm_oam_timer_t320_et	        t320;	        /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_rrc_timers_t;

/*! \  rrm_oam_rrc_constants_t 
 *  \brief This struct is used for RRC constants value
 *  \param n310 Possible Number of consecutive "out-of-sync"indications received from lower layers thattriggers 
 *              timer T310 : 1, 2, 3, 4, 6, 8, 10,20
 *  \param n311 Possible Number of consecutive "in-sync"indications received from lower layers thatstops timer 
 *              T310 : 1, 2, 3, 4, 5, 6, 8, 10
 */
typedef struct _rrm_oam_rrc_constants
{
	rrm_oam_out_of_sync_n310_et	n310;	/*^ M, 0, N, 0, 0 ^*/	/* from ue_timers_and_constants_t */
	rrm_oam_in_sync_n311_et		n311;	/*^ M, 0, N, 0, 0 ^*/	/* from ue_timers_and_constants_t */
} rrm_oam_rrc_constants_t;

#define RRM_OAM_RRC_TIMERS_PRESENT   0x01
#define RRM_OAM_RRC_CONSTANTS_PRESENT   0x02
/*! \  rrm_oam_rrc_timers_and_constants_t
 *  \brief This struct is used for RRC timers and constants parameters
 *  \param bitmask To check optional field is present or not
 *  \param rrc_timers RRC timers parameters
 *  \param rrc_constants RRC constants values
 */
typedef struct _rrm_oam_rrc_timers_and_constants
{
	rrm_bitmask_t 			bitmask; 	/*^ BITMASK ^*/
	rrm_oam_rrc_timers_t	rrc_timers; /*^ O, RRM_OAM_RRC_TIMERS_PRESENT, N, 0, 0 ^*/
	rrm_oam_rrc_constants_t	rrc_constants; /*^ O, RRM_OAM_RRC_CONSTANTS_PRESENT, N, 0, 0 ^*/
}rrm_oam_rrc_timers_and_constants_t;

#define RRM_OAM_RF_CONFIGURATION_UL_EARFCN_PRESENT   0x01
#define RRM_OAM_RF_CONFIGURATION_UL_BW_PRESENT       0x02
#define RRM_OAM_MAX_RS_EPRE_PRESENT                  0x04
/*! \  rrm_oam_rf_configurations_t
 *  \brief This struct is used for RF configurations parameters
 *  \param bitmask To check optional field is present or not
 *  \param frequency_band_indicator Frequency  Operating Band
 *  \param dl_earfcn Indicates the DL ARFCN of this frequency carrier
 *  \param dl_bandwidth DL-Bandwidth:
 *                      Possible values : 6, 15, 25, 50, 75, 100 RBs
 *  \param ul_earfcn Indicates the uplink carrier frequency
 *  \param ul_bandwidth UL-Bandwidth:
 *                      Possible values : 6, 15, 25, 50, 75, 100 RBs
 *  \param reference_signal_power The downlink reference-signal transmit power
 *  \param phy_cell_id The physical cell identity of the cell
 *  \param psch_power_offset Power offset of the PrimarySynchronization Channel with respect to theReferenceSignalPower
 *  \param ssch_power_offset Power offset of the Secondary Synchronization Channel with respect to the Reference Signal Power
 *  \param pbch_power_offset Power offset of the Physical Broadcast Channel with respect to the ReferenceSignalPower
 *  \param max_rs_epre Max enb tx power
 */
typedef struct _rrm_oam_rf_configurations
{
	rrm_bitmask_t 			bitmask; 	/*^ BITMASK ^*/
	U8				frequency_band_indicator;   /*^ M, 0, B, 1, 40 ^*/  /* sib_type_1_Info_t */
	U16				dl_earfcn; /*^ M, 0, N, 0, 65535 ^*/
	rrm_oam_band_width_et	        dl_bandwidth;	 /*^ M, 0, H, 0, 5 ^*/        /*mib_info_t*/
	U16				ul_earfcn; /*^ O, RRM_OAM_RF_CONFIGURATION_UL_EARFCN_PRESENT, N, 0, 65535 ^*/
	rrm_oam_band_width_et	        ul_bandwidth;	 /*^ O, RRM_OAM_RF_CONFIGURATION_UL_BW_PRESENT, H, 0, 5 ^*/	/*freq_info_t*/ 
	S8				reference_signal_power;  /*^ M, 0, B, -60, 50 ^*/ /*int[-60..50]*/
	U16				phy_cell_id;	 /*^ M, 0, H, 0, 503 ^*/	/* 0 to 503 */
	S16				psch_power_offset;/*^ M, 0, B, -60, 40 ^*/	/*-60 to 40*/
	S16				ssch_power_offset;/*^ M, 0, B, -60, 40 ^*/
	S16				pbch_power_offset; /*^ M, 0, B, -60, 40 ^*/	/*-60 to 40*/
    S16             max_rs_epre; /*^ O, RRM_OAM_MAX_RS_EPRE_PRESENT, B, -256, 256^*/
}rrm_oam_rf_configurations_t;

/*! \  rrm_oam_rf_params_t
 *  \brief This struct is used for RF parameters
 *  \param rf_configurations variable of rrm_oam_rf_configurations_t
 */
typedef struct _rrm_oam_rf_params
{
	rrm_oam_rf_configurations_t	rf_configurations; /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_rf_params_t;
 
/*! \  rrm_oam_s1ap_params_t
 *  \brief This struct is used for s1ap parameters information
 *  \param t_reloc_prep Specifies the maximum time for the Handover Preparation procedure in the source eNB
 *  \param t_reloc_overall Specifies the maximum time for the protection of the overall handover procedure in the source eNB
 */
typedef struct _rrm_oam_s1ap_params
{
	U8	t_reloc_prep;	/*^ M, 0, N, 0, 0 ^*/
	U8	t_reloc_overall;/*^ M, 0, H, 0, 60 ^*/
}rrm_oam_s1ap_params_t;

#define RRM_OAM_INTRA_FREQ_GLOBAL_CELL_ID_PRESENT  	   0x0001
#define RRM_OAM_INTRA_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT  0x0002 
#define RRM_OAM_INTRA_FREQ_R_STX_POWER_PRESENT             0x0004
#define RRM_OAM_INTRA_FREQ_CSG_ID_PRESENT                  0x0008
#define RRM_OAM_INTRA_FREQ_CELL_ACCESS_MODE_PRESENT        0x0010
#define RRM_OAM_INTRA_FREQ_HO_STATUS_PRESENT               0x0020
#define RRM_OAM_INTRA_FREQ_X2_STATUS_PRESENT               0x0040
#define RRM_OAM_INTRA_FREQ_BROADCAST_STATUS_PRESENT        0x0080
#define RRM_OAM_INTRA_FREQ_CELL_DAHO_IND_PRESENT           0x0100
/*! \ rrm_oam_intra_freq_cells_t
 *  \brief This struct is used for intra frequency cell parameters
 *  \param bitmask To check optional field is present or not
 *  \param cell_id global_c ell_id of the neighbouring cells including the PLMN Id and the 28 bit Cell Id
 *  \param phy_cell_id Physical cell ID
 *  \param q_offset Cell-specific offsetapplicable to a specific neighboring cell
 *  \param cell_individual_offset Cell individual offset applicableto a specific neighboring cell
 *  \param r_stx_power The downlink reference-signaltransmit power of the neighbouring cell specified indBM
 *  \param blacklisted indicate if cell is blacklisted or not 
 *  \param csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS] Identity of the Closed Subscriber Group the cell belongs to
 *  \param cell_access_mode Indicates if the cell access mode is HYBRID
 *  \param ho_status Indicates whether HO is allowed or not to this target cell
 *  \param x2_status Indicates whether X2 connection can be used for HO or not with the corresponding eNB
 *  \param broadcast_status Indicates if the cell to be broadcasted in the SIB or not 
 *  \param tac[RRM_OAM_MAX_NUM_TAC_OCTETS] the tracking area code  of the neighbour cell 
 *  \param daho_indication whether the cell is daho or not 
 */
typedef struct _rrm_oam_intra_freq_cells
{
        rrm_bitmask_t 		 	  bitmask;  /*^ BITMASK ^*/
	rrm_oam_eutran_global_cell_id_t	  cell_id;  /*^ O, RRM_OAM_INTRA_FREQ_GLOBAL_CELL_ID_PRESENT, N, 0, 0 ^*/ 
	U16                               phy_cell_id;/*^ M, 0, H, 0, 503 ^*/
	rrm_oam_q_offset_range_et	  q_offset; /*^ M, 0, H, 0, 30 ^*/   /* inter_freq_carrier_freq_t */
	rrm_oam_q_offset_range_et	  cell_individual_offset; /*^ O, RRM_OAM_INTRA_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT, N, 0, 0 ^*/ /* inter_freq_carrier_freq_t */
        S8	              	          r_stx_power;/*^ O, RRM_OAM_INTRA_FREQ_R_STX_POWER_PRESENT, B, -60, 50 ^*/
	S32   		                    blacklisted;/*^ M, 0, N, 0, 0 ^*/
	U8                                csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS];  /*^ O, RRM_OAM_INTRA_FREQ_CSG_ID_PRESENT, OCTET_STRING, FIXED ^*/
        S32                               cell_access_mode;   /*^ O, RRM_OAM_INTRA_FREQ_CELL_ACCESS_MODE_PRESENT, N, 0, 0 ^*/
        S32                               ho_status;  /*^ O, RRM_OAM_INTRA_FREQ_HO_STATUS_PRESENT, N, 0, 0 ^*/
        S32                               x2_status;  /*^ O, RRM_OAM_INTRA_FREQ_X2_STATUS_PRESENT, N, 0, 0 ^*/
        S32                               broadcast_status;  /*^ O, RRM_OAM_INTRA_FREQ_BROADCAST_STATUS_PRESENT, N, 0, 0 ^*/
        U8                                tac[RRM_OAM_MAX_NUM_TAC_OCTETS]; /*^ M, 0, OCTET_STRING, FIXED ^*/
        U8                                daho_indication; /*^ O, RRM_OAM_INTRA_FREQ_CELL_DAHO_IND_PRESENT, H, 0, 1 ^*/
}rrm_oam_intra_freq_cells_t;


#define RRM_OAM_INTER_FREQ_GLOBAL_CELL_ID_PRESENT  	    0x0001
#define RRM_OAM_INTER_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT   0x0002
#define RRM_OAM_INTER_FREQ_RSTX_POWER_PRESENT  		    0x0004
#define RRM_OAM_CELL_ACCESS_MODE_PRESENT                    0x0008
#define RRM_OAM_INTER_FREQ_CSG_ID_PRESENT   				0x0010
#define RRM_OAM_INTER_FREQ_HO_STATUS_PRESENT                0x0020  
#define RRM_OAM_INTER_FREQ_X2_STATUS_PRESENT                0x0040
#define RRM_OAM_INTER_FREQ_BROADCAST_STATUS_PRESENT         0x0080
/*! \ rrm_oam_inter_freq_cells_t
 *  \brief This struct is used for inter frequency cells 
 *  \param bitmask To check optional field is present or not
 *  \param cell_id  global_c ell_id of the neighbouring cells including the PLMN Id and the 28 bit CellId
 *  \param eutra_carrier_arfcn The EARFCN on which the neighbouring cell is transmitting
 *  \param phy_cell_id The physical cell identity of the neighbouring cell
 *  \param q_offset Cell-specific offsetapplicable to a specific neighboring cell
 *  \param cell_individual_offset Cell individual offset applicableto a specific neighboring cell
 *  \param r_stx_power The downlink reference-signaltransmit power of the neighbouring cell , specified indBM
 *  \param blacklisted 0 for false and 1 for true
 *  \param cell_access_mode Indicates if the cell access mode is HYBRID
 *  \param csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS] Identity of the Closed Subscriber Group the cell belongs to
 *  \param ho_status Indicates whether HO is allowed or not to this target cell
 *  \param x2_status Indicates whether X2 connection can be used for HO or not with the corresponding eNB
 *  \param broadcast_status Indicates if the cell to be broadcasted in the SIB or not 
 */
typedef struct _rrm_oam_inter_freq_cells
{
        rrm_bitmask_t 			bitmask; /*^ BITMASK ^*/
	rrm_oam_eutran_global_cell_id_t	cell_id; /*^ O, RRM_OAM_INTER_FREQ_GLOBAL_CELL_ID_PRESENT, N, 0, 0 ^*/
	U16				eutra_carrier_arfcn; /*^ M, 0, N, 0, 65535^*/
	U16				phy_cell_id;/*^ M, 0, H, 0, 503 ^*/
	rrm_oam_q_offset_range_et	q_offset; /*^ M, 0, H, 0, 30 ^*//* inter_freq_carrier_freq_t */
	rrm_oam_q_offset_range_et	cell_individual_offset; /*^ O, RRM_OAM_INTER_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT, N, 0, 0 ^*//* inter_freq_carrier_freq_t */
 	S8				r_stx_power;/*^ O, RRM_OAM_INTER_FREQ_RSTX_POWER_PRESENT, N, -60, 50 ^*/
	S32			blacklisted; /*^ M, 0, N, 0, 0 ^*/
	S32                             cell_access_mode; /*^ O, RRM_OAM_CELL_ACCESS_MODE_PRESENT, N, 0, 0 ^*/
    U8                                csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS];  /*^ O, RRM_OAM_INTER_FREQ_CSG_ID_PRESENT, OCTET_STRING, FIXED ^*/
        S32                             ho_status;  /*^ O, RRM_OAM_INTER_FREQ_HO_STATUS_PRESENT, N, 0, 0 ^*/
        S32                             x2_status;  /*^ O, RRM_OAM_INTER_FREQ_X2_STATUS_PRESENT, N, 0, 0 ^*/
        S32                             broadcast_status;  /*^ O, RRM_OAM_INTER_FREQ_BROADCAST_STATUS_PRESENT, N, 0, 0 ^*/
        U8                              tac[RRM_OAM_MAX_NUM_TAC_OCTETS]; /*^ M, 0, OCTET_STRING, FIXED ^*/
}rrm_oam_inter_freq_cells_t;

/*! \  rrm_lai_t
 *  \brief This struct is used for location area identity params
 *  \param plmn_id public land mobile network identity
 *  \param lac[RRM_OAM_MAX_NUM_LAC_OCTETS] location area code 
 */
typedef struct _rrm_lai
{
   rrm_oam_cell_plmn_info_t      plmn_id; /*^ M, 0, N, 0, 0 ^*/
    U8                           lac[RRM_OAM_MAX_NUM_LAC_OCTETS];/*^  M, 0, OCTET_STRING, FIXED ^*/
}rrm_lai_t;

/*! \  rrm_rai_t
 *  \brief This struct is used for Routing Area ID (RAI) params 
 *  \param lai Location area identity
 *  \param rac routing area code
 */
typedef struct _rrm_rai
{
    rrm_lai_t                 lai; /*^ M, 0, N, 0, 0 ^*/
    U8                        rac; /*^ M, 0, N, 0, 255 ^*/    
}rrm_rai_t;

#define RRM_OAM_GERAN_FREQ_CELL_NW_CTRL_ORDER_PRESENT 		0x01
#define RRM_OAM_GERAN_FREQ_HO_STATUS_PRESENT                    0x02
#define RRM_OAM_GERAN_FREQ_CELL_DTM_SUPPORTED_PRESENT 		0x04
#define RRM_OAM_GERAN_FREQ_CELL_DTM_HO_SUPPORTED_PRESENT 	0x08
#define RRM_OAM_GERAN_FREQ_CELL_VOIP_CAPABLE_PRESENT		0x10 
#define RRM_OAM_GERAN_FREQ_DAHO_IND_PRESENT                 0x20 
/*! \ rrm_oam_geran_freq_cells_t
 *  \brief This struct is used for GERAN frequency cell information
 *  \param bitmask To check optional field is present or not
 *  \param lai loaction area identity
 *  \param cell_id Global cell id 
 *  \param bandindicator bandindicator information
 *  \param bccharfcn ARFCN of this cell
 *  \param pci Physical Cell Id of GERAN.
 *  \param network_control_order enum type for network control order
 *  \param daho_indication Indicates this is a daho cel or not
 */
typedef struct _rrm_oam_geran_freq_cells
{
    rrm_bitmask_t          bitmask; /*^ BITMASK ^*/
    rrm_lai_t              lai;  /*^ M, 0, N, 0, 0 ^*/
    U16                    cell_id; /*^ M, 0, N, 0, 0 ^*/
    rrm_oam_band_ind_et    bandindicator; /*^ M, 0, H, 0, 3 ^*/
    U16                    bccharfcn; /*^ M, 0, H, 0, 1023 ^*/
    U16                    pci;  /*^ M, 0, H, 0, 512 ^*/
    /*RIM Changes begin*/
    rrm_oam_nco_ind_et     network_control_order;  /*^ O, RRM_OAM_GERAN_FREQ_CELL_NW_CTRL_ORDER_PRESENT, H, 0, 3 ^*/
    /*RIM Changes end*/
    S32                    ho_status; /*^ O, RRM_OAM_GERAN_FREQ_HO_STATUS_PRESENT, N, 0, 0 ^*/
     /*srvcc start*/
    U8			   dtm_supported; /*^ O, RRM_OAM_GERAN_FREQ_CELL_DTM_SUPPORTED_PRESENT, H, 0, 1 ^*/
    U8 			   dtm_ho_supported; /*^ O, RRM_OAM_GERAN_FREQ_CELL_DTM_HO_SUPPORTED_PRESENT, H, 0, 1 ^*/
    U8 			   voip_capable; /*^ O, RRM_OAM_GERAN_FREQ_CELL_VOIP_CAPABLE_PRESENT, H, 0, 1 ^*/
    /*srvcc start*/
    U8           daho_indication; /*^ O, RRM_OAM_GERAN_FREQ_DAHO_IND_PRESENT, H, 0, 1 ^*/
}rrm_oam_geran_freq_cells_t;
 
/*! \ rrm_utran_cell_id_t
 *  \brief This struct is used for UTRAN cell id information
 *  \param bitmask To check optional field is present or not
 *  \param cell_id[RRM_MAX_NUM_CELL_IDENTITY_OCTETS] physical cell id 
 *  \param rnc_id RNC-ID
 *  \param extended_rnc_id Extended RNC-ID 
 */
typedef struct _rrm_utran_cell_id
{
    #define RRM_OAM_UTRAN_EXTN_RNC_ID_PRESENT   0x01
    rrm_bitmask_t                    bitmask; /*^ BITMASK ^*/
    U8        cell_id[RRM_MAX_NUM_CELL_IDENTITY_OCTETS];/*^  M, 0, OCTET_STRING, FIXED ^*/
    U16       rnc_id; /*^ M, 0, H, 0, 4095 ^*/
    U16       extended_rnc_id; /*^ O,RRM_OAM_UTRAN_EXTN_RNC_ID_PRESENT , L, 4096, 65535 ^*/     
}rrm_utran_cell_id_t;  


/*! \ rrm_oam_utran_freq_cells_t
 *  \brief This struct is used for UTRAN frequency cells parameters
 *  \param bitmask To check optional field is present or not
 *  \param rai Routing Area Identity
 *  \param uc_id UTRAN Cell ID is used to identify a cell uniquely within UTRAN
 *  \param ura UTRAN Registration Area (URA) 
 *  \param uarfcnul The UL UTRA Absolute Radio Frequency Channel Number in an FDD mode cell
 *  \param uarfcndl The DL UTRA Absolute Radio Frequency Channel Number in an FDD mode cell
 *  \param pcpich_scrambling_code Primary CPICH scrambling code
 *  \param pcpich_tx_power Primary CPICH Tx power in dBm
 *  \param offset_freq offset frequency
 *  \param cell_access_mode Indicates if the cell access mode is HYBRID 
 *  \param blacklisted  1 for true and 0 for false
 *  \param csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS] Identity of the Closed Subscriber Group the cell belongs to
 *  \param ho_status Indicates whether HO is allowed or not to this target cell
 *  \param daho_indication Indicates this is a daho cel or not
 */
typedef struct _rrm_oam_utran_freq_cells
{
#define RRM_OAM_UTRAN_FREQ_UARFCNUL_PRESENT  		0x01
#define RRM_OAM_UTRAN_FREQ_CELL_ACCESS_MODE_PRESENT     0x02
#define RRM_OAM_UTRAN_FREQ_CSG_ID_PRESENT               0x04
#define RRM_OAM_UTRAN_HO_STATUS_PRESENT                 0x08
#define RRM_OAM_UTRAN_PS_HO_SUPPORTED_PRESENT 		0x10
#define RRM_OAM_UTRAN_VOIP_CAPABLE_PRESENT		0x20
#define RRM_OAM_UTRAN_DAHO_IND_PRESENT          0x40 
    rrm_bitmask_t        bitmask; /*^ BITMASK ^*/
    rrm_rai_t            rai; /*^ M, 0, N, 0, 0 ^*/  
    rrm_utran_cell_id_t  uc_id; /*^ M, 0, N, 0, 0 ^*/ 
    U16                  ura; /*^ M, 0, L, 1,65535 ^*/
    U16                  uarfcnul; /*^ O, RRM_OAM_UTRAN_FREQ_UARFCNUL_PRESENT, H , 0, 16383 ^*/ 
    U16                  uarfcndl; /*^ M, 0, H, 0, 16383 ^*/ 
    U16                  pcpich_scrambling_code; /*^ M, 0, H, 0, 511 ^*/
    S16                  pcpich_tx_power; /*^ M, 0, B, -100, 500 ^*/
    S8                   offset_freq;/*^ M, 0, H, -15, 15 ^*/
    S32                  cell_access_mode; /*^ O, RRM_OAM_UTRAN_FREQ_CELL_ACCESS_MODE_PRESENT, N, 0, 0 ^*/
    S32                  blacklisted; /*^ M, 0, N, 0, 0 ^*/
    U8                   csg_identity[RRM_OAM_MAX_NUM_CSG_OCTETS];  /*^ O, RRM_OAM_UTRAN_FREQ_CSG_ID_PRESENT, OCTET_STRING, FIXED ^*/
    S32                  ho_status; /*^ O, RRM_OAM_UTRAN_HO_STATUS_PRESENT, N, 0, 0 ^*/
     /*srvcc start*/
    U8 			 ps_ho_supported; /*^ O, RRM_OAM_UTRAN_PS_HO_SUPPORTED_PRESENT, H, 0, 1 ^*/
    U8 			 voip_capable; /*^ O, RRM_OAM_UTRAN_VOIP_CAPABLE_PRESENT, H, 0, 1 ^*/
    /*srvcc end*/
    U8           daho_indication; /*^ O, RRM_OAM_UTRAN_DAHO_IND_PRESENT, H, 0, 1 ^*/
}rrm_oam_utran_freq_cells_t;

/*! \ rrm_oam_lte_ncl_t
 *  \brief This struct is used for Intra frequency neighbour cell information
 *  \param num_valid_intra_freq_cell Total Number of neighbouring intra frequency cells, up to 64 including the black listed cells
 *  \param intra_freq_cells[RRM_OAM_MAX_NUM_INTRA_FREQ_CELLS] array of intra frequency cells parameters
 *  \param num_valid_inter_freq_cell Total Number of neighbouring inter frequency cells
 *  \param inter_freq_cells[RRM_OAM_MAX_NUM_INTER_FREQ_CELLS] array of inter frequency cells parameters
 */
typedef struct _rrm_oam_lte_ncl
{
	U8 				num_valid_intra_freq_cell;/*^ M, 0, H, 0, 32 ^*/
	rrm_oam_intra_freq_cells_t	intra_freq_cells[RRM_OAM_MAX_NUM_INTRA_FREQ_CELLS/*Currently its 16*/]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
	U8 				num_valid_inter_freq_cell; /*^ M, 0, H, 0, 32 ^*/
	rrm_oam_inter_freq_cells_t	inter_freq_cells[RRM_OAM_MAX_NUM_INTER_FREQ_CELLS/*Currently its 48*/];/*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_lte_ncl_t;

/*! \ rrm_oam_cdma2000_freq_cells_t
 *  \brief This struct is used for cdma 2000 frequency cell parameters
 *  \param presence_bitmask To check optional field is present or not
 *  \param band_class Used to define the CDMA2000 band in which the CDMA2000 carrier frequency can be found
 *  \param arfcn ARFCN value
 *  \param pn_offset Corresponds to PCI of Sib-8 in RRC
 *  \param type Specifies which type of cell info is present 1XRTT/HRPD
 *  \param num_valid_count_cid count value for the CID array 
 *  \param CID[RRM_MAX_CGI_CDMA2000] The Cell Id of the cell 1XRTT/HRPD
 *  \param cell_specific_params cell specific parameters
 *  \param daho_indication Indicates this is a daho cel or not
 */
typedef struct _rrm_oam_cdma2000_freq_cells_t
{
    rrm_bitmask_t  presence_bitmask;  /*^ BITMASK ^*/
#define RRM_OAM_CELL_SPECIFIC_PARAMS_PRESENCE_FLAG          0x01
#define RRM_OAM_CDMA_CELL_DAHO_IND_PRESENT                  0x02
    U8    band_class; /*^ M, 0, H, 0, 31 ^*/   /* rrm_oam_bandclass_cdma2000_et */
    U16   arfcn; /*^ M, 0, H, 0, 2047 ^*/
    /* Corresponds to phys_cell_id_cdma2000 of Sib-8 */
    U16   pn_offset; /*^M, 0, H ,0, 511 ^*/
    rrm_oam_ncl_type_et    type; /*^M, 0, B, 0, 1^*/
    /* Corresponds to cell_global_id_cdma2000 of Sib-8 */
    U8    num_valid_count_cid; /*^M, 0, B, 6, 16^*/
    U8    CID[RRM_MAX_CGI_CDMA2000]; /*^M, 0, OCTET_STRING, FIXED ^*/
    rrm_oam_cell_specific_params_t             cell_specific_params;
    /*^ O, RRM_OAM_CELL_SPECIFIC_PARAMS_PRESENCE_FLAG, N, 0, 0 ^*/
    U8    daho_indication;/*^ O, RRM_OAM_CDMA_CELL_DAHO_IND_PRESENT, H, 0, 1 ^*/
}rrm_oam_cdma2000_freq_cells_t;

#define RRM_OAM_GERAN_NEIGHBOR_INFO_PRESENT             0x0001
/*! \ rrm_oam_inter_rat_ncl_t
 *  \brief This struct is used for inter rat Neighbor cell list parameters
 *  \param presence_bitmask To check optional field is present or not
 *  \param num_valid_utran_freq_cell count value for utran freq cells array
 *  \param utran_freq_cells[RRM_OAM_MAX_NUM_UTRAN_FREQ_CELLS] utran freq cells array 
 *  \param num_valid_geran_freq_cell count for geran frequency cell array
 *  \param geran_freq_cells[RRM_OAM_MAX_NUM_GERAN_FREQ_CELLS] GERAN frequency cells array
 *  \param num_valid_cdma2000_freq_cells count value for cdma2000 freq cells array
 *  \param cdma2000_freq_cells[RRM_OAM_NUM_CDMA2000_FREQ_CELLS] cdma2000 freq cells array
 */
typedef struct _rrm_oam_inter_rat_ncl
{
        rrm_bitmask_t                   bitmask; /*^ BITMASK ^*/
	U8 				num_valid_utran_freq_cell;/*^ M, 0, H, 0, 32 ^*/
	rrm_oam_utran_freq_cells_t	utran_freq_cells[RRM_OAM_MAX_NUM_UTRAN_FREQ_CELLS/*Currently its 16 */];/*^M, 0, OCTET_STRING ,VARIABLE ^*/
    U8              num_valid_geran_freq_cell;/*^ M, 0, H, 0, 3 ^*/
    rrm_oam_geran_freq_cells_t  geran_freq_cells[RRM_OAM_MAX_NUM_GERAN_FREQ_CELLS/*Currently its 3 */];/*^M, 0, OCTET_STRING ,VARIABLE ^*/

    /* cdma2000 changes start */
    U8              num_valid_cdma2000_freq_cells;/*^ M, 0, H, 0, 71 ^*/
    rrm_oam_cdma2000_freq_cells_t  cdma2000_freq_cells[RRM_OAM_NUM_CDMA2000_FREQ_CELLS];
    /*^M, 0, OCTET_STRING ,VARIABLE ^*/
    /* cdma2000 changes end */

}rrm_oam_inter_rat_ncl_t;

/*! \ rrm_oam_sps_config_dl_t
 *  \brief This struct is used for SPS config downlink params
 *  \param bitmask To check optional field is present or not
 *  \param semi_persist_sched_interval_dl Semi-persistent scheduling interval in downlink
 *  \param number_of_conf_sps_processes The number of configured HARQ processes for Semi-Persistent Scheduling
 *  \param max_sps_harq_retx maximum value of SPS HARQ retx 
 *  \param explicit_release_after Number of empty transmissions before explicit release
 */
typedef struct _rrm_oam_sps_config_dl_t
{
    rrm_bitmask_t     bitmask; /*^ BITMASK ^*/
    U8                semi_persist_sched_interval_dl;    /*^ M, 0, H, 0, 9 ^*/     /* rrm_oam_semi_persist_sched_interval_et */
    U8                number_of_conf_sps_processes;      /*^ M, 0, B, 1, 8 ^*/
    U8                max_sps_harq_retx;                 /*^ M, 0, B, 1, 8 ^*/
    U8                explicit_release_after;            /*^ M, 0, B, 2, 8 ^*/
}rrm_oam_sps_config_dl_t;

#define RRM_OAM_P_ZERO_NOMINAL_PUSCH_PERSISTENT_PRESENT  0x0001
/*! \ rrm_oam_sps_config_ul_t
 *  \brief This struct is used for SPS config uplink parameters
 *  \param bitmask To check optional field is present or not
 *  \param semi_persist_sched_interval_ul Semi-persistent scheduling interval in uplink
 *  \param implicit_release_after Number of empty transmissions before implicit release
 *  \param p_zero_nominal_pusch_persistent Parameter: P0,NOMINAL_PUSCH (0)
 */
typedef struct _rrm_oam_sps_config_ul_t
{
    rrm_bitmask_t     bitmask; /*^ BITMASK ^*/
    U8                semi_persist_sched_interval_ul;    /*^ M, 0, H, 0, 9 ^*/      /* rrm_oam_semi_persist_sched_interval_et */
    U8                implicit_release_after;            /*^ M, 0, H, 0, 3 ^*/      /* rrm_oam_implicit_release_after_et */
    S8                p_zero_nominal_pusch_persistent;   /*^ O, RRM_OAM_P_ZERO_NOMINAL_PUSCH_PERSISTENT_PRESENT, B, -126, 24 ^*/
}rrm_oam_sps_config_ul_t;

#define RRM_OAM_SPS_CONFIG_DL_PRESENT  0x01
#define RRM_OAM_SPS_CONFIG_UL_PRESENT  0x02
/*! \ rrm_oam_sps_config_data_t
 *  \brief This struct is used for SPS config data
 *  \param bitmask To check optional field is present or not
 *  \param sps_config_dl SPS config data for downlink
 *  \param sps_config_ul SPS config data for uplink
 */
typedef struct _rrm_oam_sps_config_data_t
{
    rrm_bitmask_t                 bitmask; /*^ BITMASK ^*/
    rrm_oam_sps_config_dl_t       sps_config_dl;  /*^ O, RRM_OAM_SPS_CONFIG_DL_PRESENT, N, 0, 0 ^*/
    rrm_oam_sps_config_ul_t       sps_config_ul;  /*^ O, RRM_OAM_SPS_CONFIG_UL_PRESENT, N, 0, 0 ^*/
}rrm_oam_sps_config_data_t;

#define RRM_OAM_ROHC_PROFILE_1_PRESENT 0x0001
#define RRM_OAM_ROHC_PROFILE_2_PRESENT 0x0002
#define RRM_OAM_ROHC_PROFILE_3_PRESENT 0x0004
#define RRM_OAM_ROHC_PROFILE_4_PRESENT 0x0008
#define RRM_OAM_ROHC_PROFILE_6_PRESENT 0x0010
#define RRM_OAM_ROHC_PROFILE_101_PRESENT 0x0020
#define RRM_OAM_ROHC_PROFILE_102_PRESENT 0x0040
#define RRM_OAM_ROHC_PROFILE_103_PRESENT 0x0080
#define RRM_OAM_ROHC_PROFILE_104_PRESENT 0x0100
/*! \  rrm_oam_rohc_pofiles_t
 *  \brief This struct is used for ROHC parameters
 *  \param bitmask To check optional field is present or not
 *  \param rohc_profile0x0001 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0002 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0003 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0004 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0006 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0101 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0102 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0103 Indicates whether this Header Compression profile can be used for this QCI
 *  \param rohc_profile0x0104 Indicates whether this Header Compression profile can be used for this QCI
 */
typedef struct _rrm_oam_rohc_pofiles_t
{
  rrm_bitmask_t   bitmask; /*^ BITMASK ^*/
  U8              rohc_profile0x0001; /*^ O, RRM_OAM_ROHC_PROFILE_1_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0002; /*^ O, RRM_OAM_ROHC_PROFILE_2_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0003; /*^ O, RRM_OAM_ROHC_PROFILE_3_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0004; /*^ O, RRM_OAM_ROHC_PROFILE_4_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0006; /*^ O, RRM_OAM_ROHC_PROFILE_6_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0101; /*^ O, RRM_OAM_ROHC_PROFILE_101_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0102; /*^ O, RRM_OAM_ROHC_PROFILE_102_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0103; /*^ O, RRM_OAM_ROHC_PROFILE_103_PRESENT, N, 0, 0^*/
  U8              rohc_profile0x0104; /*^ O, RRM_OAM_ROHC_PROFILE_104_PRESENT, N, 0, 0^*/
}rrm_oam_rohc_pofiles_t;

#define   RRM_OAM_ROHC_ENABLE_PRESENT     0x0001
#define   RRM_OAM_ROHC_PROFILE_PRESENT    0x0002
#define   RRM_OAM_ROHC_MAX_CID_PRESENT    0x0004 
/*! \ rrm_oam_pdcp_rohc_params_t
 *  \brief This struct is used for PDCP ROHC parameters information
 *  \param bitmask To check optional field is present or not
 *  \param enable_rohc Enable/Disable ROHC profiles
 *  \param rohc_pofiles ROHC profiles information
 *  \param max_cid This is the maximum CID value that can be used for this QOS class
 */
typedef struct _rrm_oam_pdcp_rohc_params_t
{
  rrm_bitmask_t            bitmask;  /*^ BITMASK ^*/
  U8                       enable_rohc; /*^ O, RRM_OAM_ROHC_ENABLE_PRESENT, N, 0, 0^*/
  rrm_oam_rohc_pofiles_t   rohc_pofiles; /*^ O, RRM_OAM_ROHC_PROFILE_PRESENT, N, 0, 0^*/
  U16                      max_cid; /*^ O, RRM_OAM_ROHC_MAX_CID_PRESENT, N, 0, 0^*/ 
}rrm_oam_pdcp_rohc_params_t;

#define RRM_OAM_SN_FIELD_LEN_DL_RLC_PRESENT     0x0001
#define RRM_OAM_SN_FIELD_LEN_UL_RLC_PRESENT     0x0002
#define RRM_OAM_SN_FIELD_LEN_DL_PDCP_PRESENT    0x0004
#define RRM_OAM_SN_FIELD_LEN_UL_PDCP_PRESENT    0x0008
/*! \ rrm_oam_sn_field_len_t
 *  \brief This struct is used for SN field length information
 *  \param bitmask To check optional field is present or not
 *  \param dl_rlc Sequence number field length in dl for RLC
 *  \param ul_rlc Sequence number field length in ul for RLC
 *  \param dl_pdcp Sequence number field length in dl for PDCP
 *  \param ul_pdcp Sequence number field length in ul for PDCP
 */
typedef struct _rrm_oam_sn_field_len_t 
{
  rrm_bitmask_t     bitmask;  /*^ BITMASK ^*/
  U8                dl_rlc; /*^ O, RRM_OAM_SN_FIELD_LEN_DL_RLC_PRESENT, N, 0, 0^*/
  U8                ul_rlc; /*^ O, RRM_OAM_SN_FIELD_LEN_UL_RLC_PRESENT, N, 0, 0^*/
  U8                dl_pdcp; /*^O, RRM_OAM_SN_FIELD_LEN_DL_PDCP_PRESENT, N, 0, 0^*/
  U8                ul_pdcp; /*^O, RRM_OAM_SN_FIELD_LEN_UL_PDCP_PRESENT, N, 0, 0^*/
}rrm_oam_sn_field_len_t;

#define RRM_OAM_TMR_POLL_PDU_PRESENT            0x01
#define RRM_OAM_TMR_REORDER_PRESENT             0x02
#define RRM_OAM_TMR_RETRSMIT_PRESENT            0x04
#define RRM_OAM_TMR_STATUS_PROHIBIT_PRESENT     0x08
/*! \  rrm_oam_addl_rlc_params_t
 *  \brief This struct is used for additional RLC parameters
 *  \param bitmask To check optional field is present or not
 *  \param t_poll_pdu Counter of PDUs between successive poll transmissions
 *  \param t_reordering This timer is used by the receiving sideof an RLC entity in order to detect lossof RLC PDUs at lower layer
 *  \param t_poll_retransmit Timer value between successive poll transmissions 
 *  \param t_status_prohibit This timer is used by the receiving side of an AM RLC entity in order to prohibit transmission of a STATUS PDU
 */
typedef struct _rrm_oam_addl_rlc_params_t
{
  rrm_bitmask_t                 bitmask; /*^ BITMASK ^*/
  rrm_oam_poll_pdu_et           t_poll_pdu;/*^ O, RRM_OAM_TMR_POLL_PDU_PRESENT, N, 0, 0 ^*/
  rrm_oam_t_reordering_et		t_reordering;/*^ O, RRM_OAM_TMR_REORDER_PRESENT, N, 0, 0 ^*/
  rrm_oam_t_poll_retransmit_et	t_poll_retransmit;/*^ O, RRM_OAM_TMR_RETRSMIT_PRESENT, N, 0, 0 ^*/
  rrm_oam_t_status_prohibit_et	t_status_prohibit;/*^ O, RRM_OAM_TMR_STATUS_PROHIBIT_PRESENT, N, 0, 0 ^*/
}rrm_oam_addl_rlc_params_t;

#define RRM_OAM_PERIODIC_PHR_TMR_PRESENT    0x01
#define RRM_OAM_PROHIBIT_PHR_TMR_PRESENT    0x02
#define RRM_OAM_DL_PATHLOSS_TMR_PRESENT     0x04 
/*! \  rrm_oam_phr_config_t
 *  \brief This struct is used for PHR config params
 *  \param bitmask To check optional field is present or not
 *  \param t_periodic_phr Periodic PHR-Timer, possible values as per 3GPP spec 
 *  \param t_prohibit_phr ProhibitPHR-Timer possible values as per 3GPP spec  
 *  \param t_pathloss_chng DL pathloss change possible values as per 3GPP spec 
 */
typedef struct _rrm_oam_phr_config_t
{
  rrm_bitmask_t                     bitmask; /*^ BITMASK ^*/
  rrm_oam_periodic_phr_tmr_et       t_periodic_phr;/*^ O, RRM_OAM_PERIODIC_PHR_TMR_PRESENT, H, 0, 7 ^*/
  rrm_oam_prohibit_phr_tmr_et       t_prohibit_phr;/*^ O, RRM_OAM_PROHIBIT_PHR_TMR_PRESENT, H, 0, 7 ^*/
  rrm_oam_dl_pathloss_tmr_et        t_pathloss_chng;/*^ O, RRM_OAM_DL_PATHLOSS_TMR_PRESENT, H, 0, 3 ^*/
}rrm_oam_phr_config_t;

#define RRM_OAM_PERIODIC_TMR_BSR_PRESENT    0x01
#define RRM_OAM_RETX_TMR_BSR_PRESENT        0x02
/*! \  rrm_oam_bsr_config_t
 *  \brief This struct is used for BSR config parameters
 *  \param bitmask To check optional field is present or not
 *  \param t_periodic_bsr Periodic BSR-Timer, possible values as per 3GPP spec 
 *  \param t_retx_bsr Retransmission BSR Timer ,possible values as per 3GPP spec
 */
typedef struct _rrm_oam_bsr_config_t
{
  rrm_bitmask_t                     bitmask;         /*^ BITMASK ^*/
  rrm_oam_periodic_tmr_bsr_et       t_periodic_bsr;  /*^ O, RRM_OAM_PERIODIC_TMR_BSR_PRESENT, H, 0, 14 ^*/
  rrm_oam_retx_tmr_bsr_et           t_retx_bsr;      /*^ O, RRM_OAM_RETX_TMR_BSR_PRESENT, H, 0, 5 ^*/
}rrm_oam_bsr_config_t;


#define RRM_OAM_PHR_CONFIG_PRESENT  0x01
#define RRM_OAM_BSR_CONFIG_PRESENT  0x02
/*! \  rrm_oam_addl_mac_params_t
 *  \brief This struct is used for additional MAC parameters
 *  \param bitmask To check optional field is present or not
 *  \param phr_config used for PHR config parameters
 *  \param bsr_config used for BSR config parameters
 */
typedef struct _rrm_oam_addl_mac_params_t
{
  rrm_bitmask_t                 bitmask; /*^ BITMASK ^*/
  rrm_oam_phr_config_t          phr_config;/*^ O, RRM_OAM_PHR_CONFIG_PRESENT, N, 0, 0 ^*/
  rrm_oam_bsr_config_t          bsr_config;/*^ O, RRM_OAM_BSR_CONFIG_PRESENT, N, 0, 0 ^*/
}rrm_oam_addl_mac_params_t;

#define RRM_OAM_PACKET_ERROR_LOSS_RATE_PRESENT  0x000001
#define RRM_OAM_DSCP_PRESENT                    0x000002
#define RRM_OAM_RLC_MODE_PRESENT                0x000004
#define RRM_OAM_LOSSLESS_HO_REQ_PRESENT         0x000008
#define RRM_OAM_UE_INACTIVE_TIMER_PRESENT       0x000010
#define RRM_OAM_MAX_HARQ_TX_PRESENT             0x000020
#define RRM_OAM_ARQ_TX_RETRANS_PRESENT          0x000040
#define RRM_OAM_LOGICAL_GRP_ON_OFF_PRESENT      0x000080
#define RRM_OAM_MAX_RLC_TRANS_PRESENT           0x000100
#define RRM_OAM_PDCP_ROHC_PARAMS_PRESENT        0x000200
#define RRM_OAM_SN_FIELD_LEN_PRESENT            0x000400
#define RRM_OAM_SPS_CONFIG_ENABLED_PRESENT      0x000800
#define RRM_OAM_SPS_CONFIG_DATA_PRESENT         0x001000
#define RRM_OAM_SUPPORTED_RAT_PRESENT           0x002000
#define RRM_OAM_NGBR_DL_MIN_BITRATE_PRESENT     0x004000
#define RRM_OAM_NGBR_UL_MIN_BITRATE_PRESENT     0x008000
#define RRM_OAM_ADDL_RLC_PARAM_PRESENT          0x008000
#define RRM_OAM_ADDL_MAC_PARAM_PRESENT          0x010000
/*! \  rrm_oam_qos_config_params_t
 *  \brief This struct is used for QOS config parameters information
 *  \param bitmask To check optional field is present or not
 *  \param qci QCI class identifier
 *  \param type Service Type : Guaranteed Bit Rate (GBR) type service or Non-GBR type service
 *  \param priority Denotes the priority of the QoS class
 *  \param packet_delay_budget Possible values: 50ms, 100 ms, 150ms, 200 ms, 300ms, 400 ms, 500 ms, 600  ms, 700ms, 800 ms, 900ms, 1000ms, 1500ms, 2000 ms
 *  \param packet_error_loss_rate denote packet error loss rate values
 *  \param dscp diffserv code point mapping corresponding to the qc
 *  \param rlc_mode To be used when the OAM wants to control the RLC Mode selection for individual QCIs
 *  \param lossless_ho_required Indicates whether the bearers having this QCI need to support loss less HO or not
 *  \param ue_inactivity_timer_config Maximum time for which a connected UE may remain inactive before it is released
 *  \param max_harq_tx Used to set Maximum number of transmissions for UL HARQ
 *  \param max_harq_retrans Maximum number of re-transmissions for DL-HARQ 
 *  \param logical_channel_grouping_on_off '0' indicates logical channel grouping is not allowed 
 *  \param max_rlc_transmissions The maximum number of RLC retransmissions/qos class
 *  \param rohc_params ROHC parameters
 *  \param sn_field_len sn field length
 *  \param sps_config_enabled This field indicates that sps-configuration is present or not
 *  \param sps_data It consists of the DL and UL sps parameters
 *  \param supported_rat  denote the type :eutran,utran,geran,cdma1xrtt,cdmahrpd
 *  \param dl_min_bitrate Minimum bitrate for non GBR bearers
 *  \param ul_min_bitrate Minimum bitrate for non GBR bearers
 *  \param addl_rlc_param Additional rlc layer parameters 
 *  \param addl_mac_param Additional mac layer parameters 
 */
typedef struct _rrm_oam_qos_config_params
{
    rrm_bitmask_t                     bitmask; /*^ BITMASK ^*/
    U8				      qci; /*^M, 0, B, 1, 9^*/
    rrm_oam_qos_type_et		      type;	/*^M, 0, N, 0, 0^*/
    U8				      priority; /*^M, 0, N, 1, 20^*/
    rrm_oam_packet_delay_budget_et    packet_delay_budget; /*^M, 0, B, 0, 13^*/
    rrm_oam_packet_error_loss_rate_et packet_error_loss_rate; /*^O, RRM_OAM_PACKET_ERROR_LOSS_RATE_PRESENT, B, 0, 6^*/
    U8                                dscp; /*^ O, RRM_OAM_DSCP_PRESENT, N, 0, 0^*/
    U8                                rlc_mode; /*^ O, RRM_OAM_RLC_MODE_PRESENT, B, 1, 2^*/
    S32                               lossless_ho_required;/*^ O, RRM_OAM_LOSSLESS_HO_REQ_PRESENT, B, 0, 1^*/
    U32                               ue_inactivity_timer_config;/*^ O, RRM_OAM_UE_INACTIVE_TIMER_PRESENT, N, 0, 0^*/
    U8                                max_harq_tx;  /*^ O, RRM_OAM_MAX_HARQ_TX_PRESENT, N, 0, 0^*/
    U8                                max_harq_retrans; /*^ O, RRM_OAM_ARQ_TX_RETRANS_PRESENT, N, 0, 0^*/
    U8                                logical_channel_grouping_on_off; /*^ O, RRM_OAM_LOGICAL_GRP_ON_OFF_PRESENT, N, 0, 0^*/
    U8                                max_rlc_transmissions; /*^ O, RRM_OAM_MAX_RLC_TRANS_PRESENT, N, 0, 0^*/
    rrm_oam_pdcp_rohc_params_t        rohc_params;  /*^ O, RRM_OAM_PDCP_ROHC_PARAMS_PRESENT , N, 0, 0^*/
    rrm_oam_sn_field_len_t            sn_field_len; /*^ O, RRM_OAM_SN_FIELD_LEN_PRESENT, N, 0, 0^*/
    rrm_bool_et                       sps_config_enabled; /*^ O, RRM_OAM_SPS_CONFIG_ENABLED_PRESENT, N, 0, 0^*/
    rrm_oam_sps_config_data_t         sps_data; /*^ O, RRM_OAM_SPS_CONFIG_DATA_PRESENT, N, 0, 0^*/
    U8                                supported_rat;/*^ O, RRM_OAM_SUPPORTED_RAT_PRESENT, N, 0, 0^*/
    U32                               dl_min_bitrate; /*^O, RRM_OAM_NGBR_DL_MIN_BITRATE_PRESENT, N, 0, 10^*/
    U32                               ul_min_bitrate; /*^O, RRM_OAM_NGBR_UL_MIN_BITRATE_PRESENT, N, 0, 10^*/
    rrm_oam_addl_rlc_params_t         addl_rlc_param;/*^O, RRM_OAM_ADDL_RLC_PARAM_PRESENT, N, 0, 0^*/
    rrm_oam_addl_mac_params_t         addl_mac_param;/*^O, RRM_OAM_ADDL_MAC_PARAM_PRESENT, N, 0, 0^*/
}rrm_oam_qos_config_params_t;

/*! \ rrm_oam_plmn_access_info_t
 *  \brief This struct is used for PLMN access information parameters
 *  \param plmn_info PLMN information
 *  \param reserve_operator_use reserve for operator use
 */
typedef struct _rrm_oam_plmn_access_info
{
	rrm_oam_cell_plmn_info_t 		   plmn_info; /*^ M, 0, N, 0, 0 ^*/
	rrm_oam_cell_reserved_for_operatoruse_et   reserve_operator_use; /*^ M, 0, H, 0, 1 ^*/	
}rrm_oam_plmn_access_info_t;


#define RRM_OAM_EMERGENCY_AREA_ID_PRESENT  0x01
/*! \  rrm_oam_general_epc_params_t
 *  \brief This struct is used for general EPC parameters information
 *  \param bitmask To check optional field is present or not
 *  \param num_valid_plmn count value for plmn list array
 *  \param plmn_list[RRM_OAM_MAX_NUM_PLMNS] plmn list array
 *  \param tac[RRM_OAM_MAX_NUM_TAC_OCTETS] trackin area code
 *  \param eaid[RRM_OAM_MAX_NUM_EAID_OCTETS] eaid array
 */
typedef struct _rrm_oam_general_epc_params
{
	rrm_bitmask_t 			bitmask; /*^ BITMASK ^*/ 
	U8 				num_valid_plmn; /*^M, 0, B, 1, 6 ^*/ 
	rrm_oam_plmn_access_info_t 	plmn_list[RRM_OAM_MAX_NUM_PLMNS/*its 6 now*/]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
	U8				tac[RRM_OAM_MAX_NUM_TAC_OCTETS];  /*^ M, 0, OCTET_STRING, FIXED ^*/ 
	U8				eaid[RRM_OAM_MAX_NUM_EAID_OCTETS]; /*^ O, RRM_OAM_EMERGENCY_AREA_ID_PRESENT, OCTET_STRING, FIXED ^*/
}rrm_oam_general_epc_params_t;

#define RRM_OAM_GENERAL_EPC_PARAMS_PRESENT  0x0001
/*! \ rrm_oam_epc_params_t
 *  \brief This struct is used for EPC parameters 
 *  \param bitmask To check optional field is present or not
 *  \param general_epc_params rrm_oam_general_epc_params_t
 *  \param num_valid_qos_profiles count value for valid profiles
 *  \param qos_config_params[RRM_OAM_MAX_NUM_QCI_CLASSES] array of QOS config parameters
 */
typedef struct _rrm_oam_epc_params
{
	rrm_bitmask_t			bitmask; /*^ BITMASK ^*/
	rrm_oam_general_epc_params_t	general_epc_params;  /*^ O, RRM_OAM_GENERAL_EPC_PARAMS_PRESENT, N, 0, 0 ^*/
	U8 				num_valid_qos_profiles;  /*^ M, 0, N, 0, 0 ^*/
	rrm_oam_qos_config_params_t	qos_config_params[RRM_OAM_MAX_NUM_QCI_CLASSES]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
        U8                              emergency_erab_arp; /*M, 0, N, 1, 7*/
}rrm_oam_epc_params_t;


#define RRM_OAM_LTE_NCL_PRESENT  0x01
#define RRM_OAM_INTER_RAT_NCL_PRESENT 0x02
/*! \  rrm_oam_ncl_params_t
 *  \brief This struct is used for NCL params  
 *  \param bitmask To check optional field is present or not
 *  \param lte_ncl intra rat ncl params
 *  \param inter_rat_ncl inter rat ncl params
 */
typedef struct _rrm_oam_ncl_params
{
	rrm_bitmask_t 		bitmask; /*^ BITMASK ^*/ 
	rrm_oam_lte_ncl_t	lte_ncl; /*^ O, RRM_OAM_LTE_NCL_PRESENT, N, 0, 0 ^*/
        rrm_oam_inter_rat_ncl_t inter_rat_ncl;/*^ O, RRM_OAM_INTER_RAT_NCL_PRESENT, N, 0, 0 ^*/
}rrm_oam_ncl_params_t;

#define RRM_OAM_PHY_LAYER_PARAMS_PRESENT         0x0001
#define RRM_OAM_MAC_LAYER_PARAMS_PRESENT         0x0002
#define RRM_OAM_RLC_LAYER_PARAMS_PRESENT         0x0004
#define RRM_OAM_MOBILITY_LAYER_PARAMS_PRESENT    0x0008
#define RRM_OAM_RRC_TIMERS_CONST_PARAMS_PRESENT  0x0010
#define RRM_OAM_RF_PARAMS_PRESENT                0x0020
#define RRM_OAM_S1AP_PARAMS_PRESENT              0x0040
#define RRM_OAM_NCL_PARAMS_PRESENT		 0x0080
#define RRM_OAM_CONNECTED_MODE_MOBILITY_PRESENT  0x0100
/*! \ rrm_oam_ran_t
 *  \brief This struct is used for RAN information parameters
 *  \param bitmask To check optional field is present or not
 *  \param physical_layer_params physical layer parameters
 *  \param mac_layer_params mac layer parameters
 *  \param rlc_layer_params RLC layer parameters
 *  \param mobility_params mobility parameters
 *  \param rrc_timers_and_constants RRC timers and constants parameters
 *  \param rf_params RF parameters 
 *  \param s1ap_params s1ap parameters
 *  \param ncl_params neighbor cell list parameters
 *  \param connected_mode_mobility_params connected mode mobility parameters
 */
typedef struct _rrm_oam_ran
{
	rrm_bitmask_t 				bitmask; /*^ BITMASK ^*/
	rrm_oam_physical_layer_params_t		physical_layer_params;/*^ O, RRM_OAM_PHY_LAYER_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_mac_layer_params_t		mac_layer_params;/*^ O, RRM_OAM_MAC_LAYER_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_rlc_layer_params_t		rlc_layer_params;/*^ O, RRM_OAM_RLC_LAYER_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_mobility_params_t		mobility_params;/*^ O, RRM_OAM_MOBILITY_LAYER_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_rrc_timers_and_constants_t	rrc_timers_and_constants;/*^ O, RRM_OAM_RRC_TIMERS_CONST_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_rf_params_t			rf_params;/*^ O,  RRM_OAM_RF_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_s1ap_params_t			s1ap_params;/*^ O, RRM_OAM_S1AP_PARAMS_PRESENT, N, 0, 0 ^*/
	rrm_oam_ncl_params_t			ncl_params;/*^ O, RRM_OAM_NCL_PARAMS_PRESENT, N, 0, 0 ^*/
        rrm_oam_connected_mode_mobility_params_t  connected_mode_mobility_params;/*^ O, RRM_OAM_CONNECTED_MODE_MOBILITY_PRESENT, N, 0, 0 ^*/
}rrm_oam_ran_t;

/*! \  rrm_oam_epc_t
 *  \brief This struct is used for EPC parameters 
 *  \param epc_params EPC parameters
 */
typedef struct _rrm_oam_epc 
{
	rrm_oam_epc_params_t	epc_params;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_epc_t;

/*! \ rrm_oam_phy_phich_configuration_t
 *  \brief This struct is used for PHICH configuration parameters
 *  \param phich_resource Possible  values as per the 3GPP 36.331 specifications
 *  \param phich_duration Possible  values as per the 3GPP 36.331 specifications
 */
typedef struct _rrm_oam_phy_phich_configuration_t
{
    U8  phich_resource;     /*^ M, 0, H, 0, 3 ^*/ /* phich_resource_et */
    U8  phich_duration;     /*^ M, 0, H, 0, 1 ^*/ /* phich_duration_et */
} rrm_oam_phy_phich_configuration_t;

/*! \  rrm_oam_rrmc_mac_config_t
 *  \brief This struct is used for RRM MAC config parameters
 *  \param start_rarnti_range The start value of the Random Access RNTI range to be used by MAC
 *  \param end_rarnti_range the end value of the Random Access RNTI range to be used by MAC
 *  \param ue_inactivity_timer_config maximum time for which UE may remain inactive without sending/receiving UL/DL data
 */
typedef struct _rrm_oam_rrmc_mac_config
{
	U8	start_rarnti_range; /*^ M, 0, N, 1, 60 ^*/
	U8	end_rarnti_range;/*^ M, 0, N, 1, 60 ^*/
        U32     ue_inactivity_timer_config;/*^ M, 0, N, 0, 0^*/ 
}rrm_oam_rrmc_mac_config_t;


#define RRM_OAM_Q_QUAL_MIN_OFFSET_R9_PRESENT  0X01
/*! \ rrm_oam_cell_selection_info_v920_t
 *  \brief This struct is used for cell selection information
 *  \param bitmask To check optional field is present or not
 *  \param q_qual_min_r9 Integer Value range -34 to -3
 *  \param q_qual_min_offset_r9_present Integer Value range 1-8
 */
typedef struct _rrm_oam_cell_selection_info_v920
{
	rrm_bitmask_t 			bitmask;/*^ BITMASK ^*/ 
	S8 				q_qual_min_r9; /*^ M, 0, B, -34, -3 ^*/
	U8 				q_qual_min_offset_r9_present;/*^ O, RRM_OAM_Q_QUAL_MIN_OFFSET_R9_PRESENT, B, 1, 8 ^*/				
}rrm_oam_cell_selection_info_v920_t;

/*! \  rrm_oam_sib_mapping_info_t
 *  \brief This struct is used for sib maping information 
 *  \param sib_type type of sib
 */
typedef struct _rrm_oam_sib_mapping_info_t
{
  S32  sib_type; /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_sib_mapping_info_t;

/*! \  rrm_oam_scheduling_info_t
 *  \brief This struct is used for scheduling information
 *  \param si_periodicity Periodicity of the SI-message in radio frames
 *  \param sib_mapping_info[RRM_OAM_MAX_SIB] List of the SIBs mapped to this SystemInformation message
 */
typedef struct _rrm_oam_scheduling_info_t
{
  S32                          si_periodicity; /*^ M, 0, N, 0, 0 ^*/
  rrm_oam_sib_mapping_info_t   sib_mapping_info[RRM_OAM_MAX_SIB]; /*^ M, 0, OCTET_STRING, FIXED ^*/
}rrm_oam_scheduling_info_t;

#define RRM_OAM_IMS_EMERGENCY_SUPPORT_R9_PRESENT 0x0001
#define RRM_OAM_CELL_SELECTION_INFO_R9_PRESENT   0x0002
#define RRM_OAM_SI_WINDOW_SIZE_PRESENT           0x0004
/*! \ rrm_oam_sib_type_1_info_t
 *  \brief This struct is used for sib type 1 information
 *  \param bitmask To check optional field is present or not
 *  \param ims_emergency_support_r9 Possible value as per the 3GPP spec 36.331
 *  \param cell_selection_info rrm_oam_cell_selection_info_v920_t
 *  \param si_window_length  Common SI scheduling window for all sIs
 *  \param si_count No. of SI messages
 *  \param scheduling_info[RRM_OAM_MAX_NUM_SI] SchedulingInfo as defined in 3GPP spec 36.331
 */
typedef struct _rrm_oam_sib_type_1_info
{
	rrm_bitmask_t 			        bitmask;/*^ BITMASK ^*/
	rrm_oam_ims_emergency_support_r9_et 	ims_emergency_support_r9;/*^ O, RRM_OAM_IMS_EMERGENCY_SUPPORT_R9_PRESENT, N, 0, 0 ^*/
	rrm_oam_cell_selection_info_v920_t 	cell_selection_info;/*^ O, RRM_OAM_CELL_SELECTION_INFO_R9_PRESENT, H, 0, 1 ^*/   
	S32					si_window_length;  /*^ O, RRM_OAM_SI_WINDOW_SIZE_PRESENT, N, 0, 0 ^*/
        U8 					si_count; /*^ M, 0, N, 1, 32 ^*/
        rrm_oam_scheduling_info_t               scheduling_info[RRM_OAM_MAX_NUM_SI]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/ 
}rrm_oam_sib_type_1_info_t;

/*! \  rrm_oam_access_class_barring_information_t
 *  \brief This struct is used for access class barring information
 *  \param ac_barring_factor If the random number drawn by the UE is lower than this value, access is allowed
 *  \param ac_barring_time Mean access barring time value in seconds
 *  \param ac_barring_for_special_ac Access class barring for the Access Classes 11-15
 */
typedef struct _rrm_oam_access_class_barring_information_t
{
        rrm_oam_ac_barring_factor_et    ac_barring_factor;/*^ M, 0, H, 0, 15 ^*/
        rrm_oam_ac_barring_time_et      ac_barring_time;/*^ M, 0, H, 0, 7 ^*/
        U8                              ac_barring_for_special_ac;/*^ M, 0, H, 0, 248 ^*/
}rrm_oam_access_class_barring_information_t;

#define RRM_OAM_SSAC_BARRING_MMTEL_VOICE_R9_PRESENT   0x01
#define RRM_OAM_SSAC_BARRING_MMTEL_VIDEO_R9_PRESENT   0x02
/*! \  rrm_oam_ssac_barring_for_mmtel_r9_t
 *  \brief This struct is used for ss access barring for mmtel info
 *  \param bitmask To check optional field is present or not
 *  \param ssac_barring_for_mmtel_voice_r9 Access class barring for the Access Classes 11-15
 *  \param ssac_barring_for_mmtel_video_r9 Access class barring for the Access Classes 11-15
 */
typedef struct _rrm_oam_ssac_barring_for_mmtel_r9
{
   rrm_bitmask_t                               bitmask;/*^ BITMASK ^*/     
   rrm_oam_access_class_barring_information_t  ssac_barring_for_mmtel_voice_r9;/*^ O, RRM_OAM_SSAC_BARRING_MMTEL_VOICE_R9_PRESENT, N, 0, 0 ^*/
   rrm_oam_access_class_barring_information_t  ssac_barring_for_mmtel_video_r9;/*^ O, RRM_OAM_SSAC_BARRING_MMTEL_VIDEO_R9_PRESENT, N, 0, 0 ^*/
}rrm_oam_ssac_barring_for_mmtel_r9_t;

#define RRM_OAM_AC_BARRING_MO_SIGNALLING_PRESENT   0x01
#define RRM_OAM_AC_BARRING_MO_DATA_PRESENT         0x02
#define RRM_OAM_SSAC_BARRING_FOR_MMTEL_PRESENT     0x04
/*! \  rrm_oam_access_barring_info_t
 *  \brief This struct is used for access barring information
 *  \param bitmask To check optional field is present or not
 *  \param ac_barring_for_mo_signalling Access class barring for mobile originating signaling
 *  \param ac_barring_for_mo_data Access class barring for the Access Classes 11-15
 *  \param ssac_barring_r9  rrm_oam_ssac_barring_for_mmtel_r9_t
 */
typedef struct _rrm_oam_access_barring_info
{
    rrm_bitmask_t                                bitmask;/*^ BITMASK ^*/
    rrm_oam_access_class_barring_information_t   ac_barring_for_mo_signalling;/*^ O, RRM_OAM_AC_BARRING_MO_SIGNALLING_PRESENT, N, 0, 0 ^*/
    rrm_oam_access_class_barring_information_t   ac_barring_for_mo_data;  /*^ O, RRM_OAM_AC_BARRING_MO_DATA_PRESENT, N, 0, 0 ^*/
    rrm_oam_ssac_barring_for_mmtel_r9_t          ssac_barring_r9; /*^ O, RRM_OAM_SSAC_BARRING_FOR_MMTEL_PRESENT, N, 0, 0 ^*/  
}rrm_oam_access_barring_info_t;


#define RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT   0x01
#define RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT        0x02
#define RRM_OAM_NB_PRESENT                          0x04
#define RRM_OAM_UL_CYCLIC_PREFIX_LEN_PRESENT        0x08
#define RRM_OAM_BARRING_INFO_PRESENT                0x10
/*! \  rrm_oam_radio_resource_config_common_sib_t
 *  \brief This struct is used for radio resource config common sib parameters
 *  \param bitmask To check optional field is present or not
 *  \param modification_period_coeff SIB Modification Period Coefficient
 *  \param default_paging_cycle Default Paging Cycle in terms of radio frames
 *  \param nB Possible Values as per the 3GPP spec:
 *           4T, 2T, T, T/2, T/4, T/8, T/16, T/32
 *  \param ul_cyclic_prefix_length Uplink cyclic prefix length as per spec 36.211 
 *  \param access_barring_info Access barring information to be broadcasted in SIB2
 */
typedef struct _rrm_oam_radio_resource_config_common_sib
{
        rrm_bitmask_t                           bitmask;/*^ BITMASK ^*/
        rrm_oam_modification_period_coeff_et    modification_period_coeff; /*^ O, RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT, N, 0, 0 ^*/
        rrm_oam_default_paging_cycle_et         default_paging_cycle; /*^ O, RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT, N, 0, 0 ^*/
        rrm_oam_nB_et                           nB; /*^ O, RRM_OAM_NB_PRESENT, N, 0, 0 ^*/
	rrm_oam_ul_cyclic_prefix_length_et      ul_cyclic_prefix_length;/*^ O, RRM_OAM_UL_CYCLIC_PREFIX_LEN_PRESENT, N, 0, 0 ^*/
        rrm_oam_access_barring_info_t           access_barring_info;   /*^ O, RRM_OAM_BARRING_INFO_PRESENT, N, 0, 0 ^*/ 
}rrm_oam_radio_resource_config_common_sib_t;


/*! \  rrm_oam_sib_type_2_info_t
 *  \brief This struct is used for sib type 2 information
 *  \param presence_bitmask To check optional field is present or not
 *  \param radio_res_config_common_sib radio resource config common sib param
 *  \param additional_spectrum_emission additional spectrum emission param
 *  \param time_alignment_timer_common time alignment timer
 *  \param ac_barring_for_csfb_r10 access barring for CSFB r10 parameter
 */
typedef struct _rrm_oam_sib_type_2_info
{
    rrm_bitmask_t              presence_bitmask; /*^ BITMASK ^*/
#define RRM_OAM_AC_BARRING_PARAM_CSFB_R10_PRESENCE_FLAG  0x01
    rrm_oam_radio_resource_config_common_sib_t 	radio_res_config_common_sib;/*^ M, 0, N, 0, 0 ^*/
    U8                                          additional_spectrum_emission; /*^ M, 0, B, 1, 32 ^*/
    U8						time_alignment_timer_common; /*^ M, 0, N, 0, 7 ^*/
    rrm_oam_access_class_barring_information_t  ac_barring_for_csfb_r10; 
    /*^ O, RRM_OAM_AC_BARRING_PARAM_CSFB_R10_PRESENCE_FLAG, N, 0, 0 ^*/
}rrm_oam_sib_type_2_info_t;


#define RRM_OAM_MEAS_BW_PRESENT 0x01
/*! \  rrm_oam_intra_freq_cell_reselection_info_t
 *  \brief This struct is used for intra frequency reselection information parameters
 *  \param presence_bitmask To check optional field is present or not
 *  \param measurement_bandwidth maximum allowed measurement bandwidth on a carrier frequency
 *  \param presence_antenna_port1 indicate whether all the neighbouring cells use Antenna Port 1
 */
typedef struct _rrm_oam_intra_freq_cell_reselection_info
{
	rrm_bitmask_t                           bitmask;/*^ BITMASK ^*/
	rrm_oam_measurement_bandwidth_et	measurement_bandwidth;/*^ O, RRM_OAM_MEAS_BW_PRESENT, H, 0, 5 ^*/
	U8	                                presence_antenna_port1;/*^ M, 0, H, 0, 1 ^*/
}rrm_oam_intra_freq_cell_reselection_info_t;

/*! \ rrm_oam_s_intra_search_v920_t
 *  \brief This struct is used for s intra search v920 information
 *  \param s_intra_search_p_r9 The IE is used to indicate an Rx level threshold for cell reselection
 *  \param s_intra_search_q_r9 The IE is used to indicate a quality level threshold for cell reselection
 */
typedef struct _rrm_oam_s_intra_search_v920
{
	U8 		s_intra_search_p_r9;    /*^ M, 0, H, 0, 31 ^*/
	U8 		s_intra_search_q_r9;	/*^ M, 0, H, 0, 31 ^*/
}rrm_oam_s_intra_search_v920_t;

/*! \  rrm_oam_s_non_intra_search_v920_t
 *  \brief This struct is used for s non intra search v920 params
 *  \param s_non_intra_search_p_r9 indicate an Rx level threshold for cell reselection
 *  \param s_non_intra_search_q_r9 indicate a quality level threshold for cell reselection
 */
typedef struct _rrm_oam_s_non_intra_search_v920
{
	U8 		s_non_intra_search_p_r9;/*^ M, 0, H, 0, 31 ^*/
	U8 		s_non_intra_search_q_r9;/*^ M, 0, H, 0, 31 ^*/	
}rrm_oam_s_non_intra_search_v920_t;


#define RRM_OAM_S_INTRA_SEARCH_V920_PRESENT        0x0001
#define RRM_OAM_S_NON_INTRA_SEARCH_V920_PRESENT    0x0002
#define RRM_OAM_Q_QUAL_MIN_R9_PRESENT1             0x0004
#define RRM_OAM_THRESHOLD_SERVING_LOW_PRESENT      0x0008
/*! \  rrm_oam_sib_type_3_info_t
 *  \brief This struct is used for sib type 3 information
 *  \param bitmask To check optional field is present or not
 *  \param intra_freq_reselection_info intra frequency reselection parameters
 *  \param s_intra_search  Threshold for intra-frequency measurements
 *  \param s_non_intra_search Thisparameter is used to indicate an Rx level threshold for cell reselection
 *  \param q_qual_min_r9 integer value range -34 to -3 
 *  \param thresh_serving_lowq_r9 value from 0 to 31
 */
typedef struct _rrm_oam_sib_type_3_info
{
	rrm_bitmask_t                               bitmask; /*^ BITMASK ^*/
	rrm_oam_intra_freq_cell_reselection_info_t  intra_freq_reselection_info; /*^ M, 0, N, 0, 0 ^*/
	rrm_oam_s_intra_search_v920_t               s_intra_search; /*^ O, RRM_OAM_S_INTRA_SEARCH_V920_PRESENT, N, 0, 0 ^*/
	rrm_oam_s_non_intra_search_v920_t           s_non_intra_search; /*^ O, RRM_OAM_S_NON_INTRA_SEARCH_V920_PRESENT, N, 0, 0 ^*/
	S8 	         	              	    q_qual_min_r9;/*^ O, RRM_OAM_Q_QUAL_MIN_R9_PRESENT1, B, -34, -3 ^*/
	U8	                                    thresh_serving_lowq_r9; /*^ O, RRM_OAM_THRESHOLD_SERVING_LOW_PRESENT, H, 0, 31 ^*/		 
}rrm_oam_sib_type_3_info_t;


#define RRM_OAM_CELL_ID_RANGE_PRESENT        0x01
/*! \ rrm_oam_csg_cell_id_range_t
 *  \brief This struct is used for CSG Cell ID range params
 *  \param bitmask To check optional field is present or not
 *  \param start indicate start of range
 *  \param range range values
 */
typedef struct _rrm_oam_csg_cell_id_range
{
	rrm_bitmask_t     	   bitmask;/*^ BITMASK ^*/
	U16			   start;/*^ M, 0, H, 0, 503 ^*/
	rrm_oam_cell_id_range_et   range;/*^ O, RRM_OAM_CELL_ID_RANGE_PRESENT, H, 0, 13 ^*/
}rrm_oam_csg_cell_id_range_t;

/*! \  rrm_oam_sib_type_4_info_t
 *  \brief This struct is used for System Information Broadcast type 4 parameters
 *  \param csg_id_range CSG identity range
 */
typedef struct _rrm_oam_sib_type_4_info
{
	rrm_oam_csg_cell_id_range_t csg_id_range;/*^ M, 0, N, 0, 0 ^*/
}rrm_oam_sib_type_4_info_t;

/*GBR LIMIT START */
/*! \  available_gbr_limit_t
 *  \brief This struct is used for available GBR information parameters
 *  \param dl_gbr_limit Downlink GBR limit
 *  \param ul_gbr_limit Uplink GBR limit
 */
typedef struct _available_gbr_limit
{

	U16                           dl_gbr_limit; /*^ M, 0, N, 0, 0 ^*/
	U16                           ul_gbr_limit; /*^ M, 0, N, 0, 0 ^*/
}available_gbr_limit_t;
/* GBR LIMIT END*/

#define  RRM_OAM_EUTRA_PRIORITY_INFO_PRESENT   0x01
#define  RRM_OAM_UTRAN_PRIORITY_INFO_PRESENT   0x02
#define  RRM_OAM_GERAN_PRIORITY_INFO_PRESENT   0x04
/*! \  rrm_oam_spid_configuration_t
 *  \brief This struct is used for SPID cinfiguration parameters
 *  \param bitmask To check optional field is present or not
 *  \param sp_id SP identifier
 *  \param eutran_freq_priority_info Eutran frequency priority information
 *  \param utran_freq_priority_info utran frequency priority information
 *  \param geran_freq_priority_info geran frequency priority information
 */
typedef struct _rrm_oam_spid_configuration_t
{
        rrm_bitmask_t                     bitmask;                   /*^ BITMASK ^*/
        U16                               sp_id;                     /*^ M, 0, B, 1, 256 ^*/
        rrm_oam_freq_priority_info_et     eutran_freq_priority_info; /*^ O, RRM_OAM_EUTRA_PRIORITY_INFO_PRESENT, N, 0, 0 ^*/
        rrm_oam_freq_priority_info_et     utran_freq_priority_info;  /*^ O, RRM_OAM_UTRAN_PRIORITY_INFO_PRESENT, N, 0, 0 ^*/
        rrm_oam_freq_priority_info_et     geran_freq_priority_info;  /*^ O, RRM_OAM_GERAN_PRIORITY_INFO_PRESENT, N, 0, 0 ^*/
}rrm_oam_spid_configuration_t;


/*! \  rrm_oam_spid_table_t
 *  \brief This struct is used for SPID table parameters info
 *  \param spid_count  count determining the size of array
 *  \param spid_config[RRM_OAM_MAX_SPID] array of SPID configuration
 */
typedef struct _rrm_oam_spid_table_t
{
        U16                             spid_count; /*^ M, 0, B, 1, 256 ^*/
        rrm_oam_spid_configuration_t    spid_config[RRM_OAM_MAX_SPID]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_spid_table_t;

#define RRM_OAM_MAX_NUM_UE_PER_CELL_PRESENT 		0x0001
#define RRM_OAM_MAX_NUM_DRBS_PER_UE_PRESENT 		0x0002
#define RRM_OAM_MAX_NUM_GBR_DRBS_PER_UE_PRESENT 	0x0004
#define RRM_OAM_MAX_NUM_NGBR_DRBS_PER_UE_PRESENT 	0x0008
#define RRM_OAM_MAX_TOTAL_DL_PRB_BUDGET 		0x0010
#define RRM_OAM_MAX_TOTAL_UL_PRB_BUDGET 		0x0020
#define RRM_OAM_MAX_TOTAL_DL_GBR_PRB_BUDGET 		0x0040
#define RRM_OAM_MAX_TOTAL_UL_GBR_PRB_BUDGET 		0x0080
#define RRM_OAM_MAX_TOTAL_DL_NGBR_PRB_BUDGET 	        0x0100
#define RRM_OAM_MAX_TOTAL_UL_NGBR_PRB_BUDGET 	        0x0200
/*GBR LIMIT START */
#define RRM_OAM_AVAILABLE_GBR_LIMIT_PRESENT             0x0400
/* GBR LIMIT END*/
#define RRM_OAM_RESOURCE_RESERVED_PRESENT               0x0800
#define RRM_OAM_SPID_TABLE_PRESENT                      0x1000
#define RRM_OAM_PREEMPTION_ALLOWED_PRESENT              0x2000
#define RRM_OAM_PREEMPTION_STATUS_PRESENT               0x4000
#define RRM_OAM_PROXIMITY_IND_STATUS_PRESENT            0x8000
/*! \ rrm_oam_admission_control_info_t
 *  \brief This struct is used for admission control parameters information
 *  \param bitmask To check optional field is present or not
 *  \param max_num_ue_per_cell maximum no of ues that can be connected at a time
 *  \param max_sps_ues maximum no of ues that can be connected at a time
 *  \param max_num_gbr_drbs_per_ue Maximum number of GBR bearers that can be supported at a time for a ue
 *  \param max_num_non_gbr_drbs_per_ue Maximum number of non GBR bearers that can be supported at a time for a ue
 *  \param dl_prb_budget maximum number of DL PRBs that can be allocated to all radio bearers at a time in the cell
 *  \param ul_prb_budget maximum number of UL PRBs that can be allocated to all radio bearers at a time in the cell
 *  \param dl_prb_budget_gbr  maximum number of DL PRBs that can be allocated to GBR type bearers
 *  \param ul_prb_budget_gbr maximum number of UL PRBs that can be allocated to GBR type bearers
 *  \param dl_prb_budget_ngbr maximum number of DL PRBs that can be allocated to nonGBR type bearers
 *  \param ul_prb_budget_ngbr maximum number of UL PRBs that can be allocated to nonGBR type bearers
 *  \param available_gbr_limit available gbr limit
 *  \param resource_reserved_for_existing_users percentage of resource reserved for existing users
 *  \param total_backhaul_capacity Total backhaul capacity in Mbps
 *  \param capacity_threshold percentage of  Total backhaul capacity to be used for data traffic
 *  \param spid_table spid table
 *  \param preemption_allowed preemption allowed or not
 *  \param preemption_status preemption_status is ON/OFF
 *  \param proximity_indication_status that the proximity indication feature is ON/OFF
 */
typedef struct _rrm_oam_admission_control_info
{
    rrm_bitmask_t 	    	  bitmask; /*^ BITMASK ^*/
    U16                           max_num_ue_per_cell; /*^ O, RRM_OAM_MAX_NUM_UE_PER_CELL_PRESENT, B, 1, 255 ^*/
    U16                           max_sps_ues; /*^ M, 0, B, 1, 255 ^*/
    U8                            max_num_gbr_drbs_per_ue; /*^ O, RRM_OAM_MAX_NUM_GBR_DRBS_PER_UE_PRESENT, B, 1, 8 ^*/
    U8                            max_num_non_gbr_drbs_per_ue; /*^ O, RRM_OAM_MAX_NUM_NGBR_DRBS_PER_UE_PRESENT, B, 1, 8 ^*/
    U8                            dl_prb_budget; /*^ O, RRM_OAM_MAX_TOTAL_DL_PRB_BUDGET, H, 0, 100 ^*/
    U8                            ul_prb_budget; /*^ O, RRM_OAM_MAX_TOTAL_UL_PRB_BUDGET, H, 0, 100 ^*/
    U8                            dl_prb_budget_gbr; /*^ O, RRM_OAM_MAX_TOTAL_DL_GBR_PRB_BUDGET, H, 0, 100 ^*/
    U8                            ul_prb_budget_gbr; /*^ O, RRM_OAM_MAX_TOTAL_UL_GBR_PRB_BUDGET, H, 0, 100 ^*/
    U8                            dl_prb_budget_ngbr; /*^ O, RRM_OAM_MAX_TOTAL_DL_NGBR_PRB_BUDGET, H, 0, 100 ^*/
    U8                            ul_prb_budget_ngbr; /*^ O, RRM_OAM_MAX_TOTAL_UL_NGBR_PRB_BUDGET, H, 0, 100 ^*/
    /*GBR LIMIT START */
    available_gbr_limit_t         available_gbr_limit;/*^ O, RRM_OAM_AVAILABLE_GBR_LIMIT_PRESENT, N, 0, 0 ^*/
    /* GBR LIMIT END*/
    U16                           resource_reserved_for_existing_users;/*^ O, RRM_OAM_RESOURCE_RESERVED_PRESENT, H, 0, 100 ^*/
    /* TNL Feature */
    U64                           total_backhaul_capacity;  /*^ M, 0, B, 1000, 10000 ^*/
    U8                            capacity_threshold;  /*^ M, 0, H, 0, 100 ^*/
    rrm_oam_spid_table_t              spid_table; /*^ O, RRM_OAM_SPID_TABLE_PRESENT, N, 0, 0 ^*/
    U8                                preemption_allowed; /*^ O, RRM_OAM_PREEMPTION_ALLOWED_PRESENT, N, 0, 0 ^*/
    rrm_bool_et                       preemption_status; /*^ O, RRM_OAM_PREEMPTION_STATUS_PRESENT, N, 0, 0 ^*/
    rrm_bool_et                       proximity_indication_status; /*^ O, RRM_OAM_PROXIMITY_IND_STATUS_PRESENT, N, 0, 0 ^*/
}rrm_oam_admission_control_info_t;

#define RRM_OAM_HARQ_BLER_CLPC_PUCCH_ENABLE_PRESENT  0x0001
#define RRM_OAM_CLPC_PUSCH_PRESENT                   0x0002
#define RRM_OAM_CQI_SINR_CLPC_PUCCH_ENABLE_PRESENT   0x0004
#define RRM_OAM_DCI_3_3A_PUCCH_PRESENT               0x0008
#define RRM_OAM_DCI_3_3A_PUSCH_PRESENT               0x0010
#define RRM_OAM_CLPC_PUSCH_FREQ_SELECTIVE_PRESENT    0x0020
#define RRM_OAM_DELTA_MCS_ENABLED_PRESENT            0x0040
#define RRM_OAM_ACCUMULATION_ENABLED_PRESENT         0x0080
#define RRM_OAM_DELTA_F_PUCCH_FORMAT_1_PRESENT       0x0100
#define RRM_OAM_DELTA_F_PUCCH_FORMAT_1B_PRESENT      0x0200
#define RRM_OAM_DELTA_F_PUCCH_FORMAT_2_PRESENT       0x0400
#define RRM_OAM_DELTA_F_PUCCH_FORMAT_2A_PRESENT      0x0800
#define RRM_OAM_DELTA_F_PUCCH_FORMAT_2B_PRESENT      0x1000
#define RRM_OAM_DELTA_PREAMBLE_MSG_PRESENT           0x2000
/*! \ rrm_oam_power_control_enable_t
 *  \brief This struct is used for power control enable parameters
 *  \param bitmask To check optional field is present or not
 *  \param harqBlerClpcPucchEnable indicates if the closed loop power control feature for PUCCH based on HARQs BLER is to be enabled or disabled
 *  \param cqiSinrClpcPucchEnable indicates if the closed loop power control feature for PUCCH based on DCIs SINR be enabled or disabled
 *  \param clpcPuschEnable indicates if the closed loop power control feature for PUCCH  be enabled or disabled
 *  \param dci_3_3a_based_power_control_for_pucch_enable enable/disable tpc_pdcch_ConfigPUCCH
 *  \param dci_3_3a_based_power_control_for_pusch_enable enable/disable tpc_pdcch_ConfigPUSCH
 *  \param clpcPuschfreqSelectiveEnable applicable when closed loop power control feature is enabled on PUSCH 
 *  \param pdcchPowOrAggregationEnable indicate whether power control or aggregation on PDCCH can be enabled or not
 *  \param delta_mcs_enabled delta mcs enabled or not
 *  \param accumulation_enabled accumulation enabled or not
 *  \param delta_f_pucch_format_1 range 0 - 2
 *  \param delta_f_pucch_format_1b range 0 - 2
 *  \param delta_f_pucch_format_2 range 0 - 3
 *  \param delta_f_pucch_format_2a range 0 - 2
 *  \param delta_f_pucch_format_2b range 0 - 2
 *  \param delta_preamble_msg_3 Used for Uplink Power Control
 */
typedef struct _rrm_oam_power_control_enable_t
{ 
  rrm_bitmask_t    bitmask; /*^ BITMASK ^*/
  U8	           harqBlerClpcPucchEnable; /*^ O, RRM_OAM_HARQ_BLER_CLPC_PUCCH_ENABLE_PRESENT, N, 0, 0^*/
  U8	           cqiSinrClpcPucchEnable; /*^ O, RRM_OAM_CQI_SINR_CLPC_PUCCH_ENABLE_PRESENT, N, 0, 0^*/
  U8	           clpcPuschEnable; /*^ O, RRM_OAM_CLPC_PUSCH_PRESENT, N, 0, 0^*/
  U8	           dci_3_3a_based_power_control_for_pucch_enable; /*^ O, RRM_OAM_DCI_3_3A_PUCCH_PRESENT, N, 0, 0^*/
  U8	           dci_3_3a_based_power_control_for_pusch_enable; /*^ O, RRM_OAM_DCI_3_3A_PUSCH_PRESENT, N, 0, 0^*/
  U8	           clpcPuschfreqSelectiveEnable; /*^ O, RRM_OAM_CLPC_PUSCH_FREQ_SELECTIVE_PRESENT, N, 0, 0^*/
  U8	           pdcchPowOrAggregationEnable;  /*^ M, 0, N, 0, 0^*/
  U8	           delta_mcs_enabled; /*^ O, RRM_OAM_DELTA_MCS_ENABLED_PRESENT, N, 0, 0^*/
  U8	           accumulation_enabled; /*^ O, RRM_OAM_ACCUMULATION_ENABLED_PRESENT, N, 0, 0^*/
  S32	           delta_f_pucch_format_1; /*^ O, RRM_OAM_DELTA_F_PUCCH_FORMAT_1_PRESENT, N, 0, 0^*/
  S32	           delta_f_pucch_format_1b; /*^ O, RRM_OAM_DELTA_F_PUCCH_FORMAT_1B_PRESENT, N, 0, 0^*/
  S32	           delta_f_pucch_format_2; /*^ O, RRM_OAM_DELTA_F_PUCCH_FORMAT_2_PRESENT, N, 0, 0^*/
  S32	           delta_f_pucch_format_2a; /*^ O, RRM_OAM_DELTA_F_PUCCH_FORMAT_2A_PRESENT, N, 0, 0^*/
  S32	           delta_f_pucch_format_2b; /*^ O, RRM_OAM_DELTA_F_PUCCH_FORMAT_2B_PRESENT, N, 0, 0^*/
  S8	           delta_preamble_msg_3; /*^ O, RRM_OAM_DELTA_PREAMBLE_MSG_PRESENT, N, 0, 0^*/
}rrm_oam_power_control_enable_t;

/*! \ rrm_oam_tpc_rnti_range_t
 *  \brief This struct is used for Transmit Power Control rnti range params
 *  \param startTpcRntiPucch Starting value of TPC Physical Uplink Control Channel-RNTI of PUCCH
 *  \param endTpcRntiPucch End value of TPC Physical Uplink Control Channel-RNTI of PUCCH
 *  \param startTpcRntiPusch start value of TPC Physical Uplink Control Channel-RNTI of PUSCH
 *  \param endTpcRntiPusch end value of TPC Physical Uplink Control Channel-RNTI of PUSCH
 */
typedef struct _rrm_oam_tpc_rnti_range_t
{
  U16     startTpcRntiPucch; /*^ M, 0, N, 0, 0^*/
  U16     endTpcRntiPucch; /*^ M, 0, N, 0, 0^*/
  U16     startTpcRntiPusch; /*^ M, 0, N, 0, 0^*/
  U16     endTpcRntiPusch; /*^ M, 0, N, 0, 0^*/
}rrm_oam_tpc_rnti_range_t;

/*! \ rrm_oam_sps_crnti_range_t
 *  \brief This struct is used for SPS CRNTI range params
 *  \param start_sps_crnti_range Describes the Starting value of SPS-CRNTI
 *  \param end_sps_crnti_range Describes the end value of SPS-CRNTI
 */
typedef struct _rrm_oam_sps_crnti_range_t
{
  U16   start_sps_crnti_range; /*^ M, 0, L, 61, 0 ^*/
  U16   end_sps_crnti_range;   /*^ M, 0, L, 61, 0 ^*/
}rrm_oam_sps_crnti_range_t;

#define RRM_OAM_DL_MCS_PRESENT   0x0001
#define RRM_OAM_UL_MCS_PRESENT   0x0002

/*! \ rrm_oam_adl_pkt_scheduling_params_t
 *  \brief This struct is used for additional packet scheduling parameters
 *  \param bitmask To check optional field is present or not
 *  \param dl_mcs Indicates the highest mcs index that can be used for Modulation & Coding Scheme for Downlink
 *  \param ul_mcs Indicates the highest mcs index that can be used for Modulation & Coding Scheme for uplink
 *  \param frequency_selective_scheduling indicate frequency selective scheduling on/off
 *  \param cqi_reporting_mode indicate cqi reporting mode
 */
typedef struct _rrm_oam_adl_pkt_scheduling_params_t
{
  rrm_bitmask_t  bitmask; /*^ BITMASK ^*/
  U8             dl_mcs; /*^ O, RRM_OAM_DL_MCS_PRESENT, N, 0, 0^*/
  U8             ul_mcs; /*^ O, RRM_OAM_UL_MCS_PRESENT, N, 0, 0^*/
  S32            frequency_selective_scheduling; /*^ M, 0, N, 0, 0^*/
  S32            cqi_reporting_mode; /*^ M, 0, N, 0, 0^*/
}rrm_oam_adl_pkt_scheduling_params_t;

/*! \  rrm_oam_adl_cell_params_t
 *  \brief This struct is used for additional cell parameters information
 *  \param bitmask To check optional field is present or not
 *  \param sub_carrier_spacing indicate sub carrier spacing
 *  \param dl_cyclic_prefix  1 for normal cyclic prefix & 2 for extended cyclic prefix
 */
typedef struct _rrm_oam_adl_cell_params_t
{
  rrm_bitmask_t   bitmask; /*^ BITMASK ^*/
  U8	          sub_carrier_spacing;  /*^ M, 0, N, 0, 0^*/
  U8	          dl_cyclic_prefix; /*^ M, 0, N, 0, 0^*/
}rrm_oam_adl_cell_params_t;

#define RRM_OAM_WAIT_TIME_PRESENT   0x0001
/*! \ rrm_oam_load_params_t
 *  \brief This struct is used for load information
 *  \param bitmask To check optional field is present or not
 *  \param wait_time for RRC Connection Reject message
 */
typedef struct _rrm_oam_load_params_t
{
  rrm_bitmask_t   bitmask; /*^ BITMASK ^*/ 
  U8              wait_time; /*^ O, RRM_OAM_WAIT_TIME_PRESENT, N, 0, 0^*/
}rrm_oam_load_params_t;

#define RRM_OAM_ANTENNA_PORTS_COUNT_NO_PRESENT   0x0001
#define RRM_OAM_SUPPORTED_TX_MODE_PRESENT        0x0002
/*! \ rrm_oam_mimo_mode_params_t
 *  \brief This struct is used for mimo mode parameters
 *  \param bitmask To check optional field is present or not
 *  \param antenna_ports_count_number Indicates the no of antenna ports to be used
 *  \param supported_tx_mode Field encoded as a bit map
 */
typedef struct _rrm_oam_mimo_mode_params_t
{
   rrm_bitmask_t   bitmask; /*^ BITMASK ^*/
   U8		antenna_ports_count_number; /*^ O, RRM_OAM_ANTENNA_PORTS_COUNT_NO_PRESENT, N, 0, 0^*/
   U8		supported_tx_mode; /*^ O, RRM_OAM_SUPPORTED_TX_MODE_PRESENT, N, 0, 0^*/
}rrm_oam_mimo_mode_params_t;


#define  RRM_OAM_NEIGHBOUR_CELL_LOAD_HO_ENABLE_PRESENT      0x0001
#define  RRM_OAM_UE_HISTORY_BASED_HO_ENABLE_PRESENT         0x0002
#define  RRM_OAM_SPID_BASED_HO_ENABLE_PRESENT               0x0004
#define  RRM_OAM_UE_MEAS_BASED_HO_ENABLE_PRESENT            0x0008
#define  RRM_OAM_DAHO_CELL_BASED_HO_ENABLE_PRESENT          0x0010
/*! \  rrm_oam_target_cell_selection_params_t
 *  \brief This struct is used for target cell selection parameters 
 *  \param bitmask To check optional field is present or not
 *  \param neighboring_cell_load_based_ho_enable indicate if the  cell load based HO is to be enabled or not 
 *  \param ue_history_based_ho_enable indicate if the  UE history based HO is to be enabled or not 
 *  \param spid_based_ho_enable indicate if the  SPID based HO is to be enabled or not 
 *  \param ue_measurement_based_ho_enable indicate if the  UE measurements based HO is to be enabled or not 
 *  \param daho_cell_based_ho_enable indicate if the  DAHO cell based HO is to be enabled or not
 */
typedef struct _rrm_oam_target_cell_selection_params_t
{
  rrm_bitmask_t	 bitmask; /*^ BITMASK ^*/
  U8             neighboring_cell_load_based_ho_enable; /*^ O, RRM_OAM_NEIGHBOUR_CELL_LOAD_HO_ENABLE_PRESENT, N, 0, 0^*/
  U8             ue_history_based_ho_enable; /*^ O, RRM_OAM_UE_HISTORY_BASED_HO_ENABLE_PRESENT, N, 0, 0^*/
  U8             spid_based_ho_enable;  /*^ O, RRM_OAM_SPID_BASED_HO_ENABLE_PRESENT, N, 0, 0^*/
  U8             ue_measurement_based_ho_enable;  /*^ O, RRM_OAM_UE_MEAS_BASED_HO_ENABLE_PRESENT, N, 0, 0^*/
  U8             daho_cell_based_ho_enable; /*^ O, RRM_OAM_DAHO_CELL_BASED_HO_ENABLE_PRESENT, N, 0, 0^*/  
}rrm_oam_target_cell_selection_params_t;

#define  RRM_OAM_ENB_MEAS_FOR_HO_PRESENT           0x0001
#define  RRM_OAM_UE_MEAS_TRIGGER_QUAN_HO_PRESENT   0x0002
#define  RRM_OAM_COVERAGE_BASED_HO_PRESENT         0x0004
#define  RRM_OAM_INTRA_FREQ_HO_PRESENT             0x0008
#define  RRM_OAM_INTER_FREQ_HO_PRESENT             0x0010
#define  RRM_OAM_INTER_RAT_HO_PRESENT              0x0020
/*! \ rrm_oam_ho_algo_params_t
 *  \brief This struct is used for HO algorithm parameters
 *  \param bitmask To check optional field is present or not
 *  \param enb_measurements_for_ho indicates that eNB measurements are enabled or not
 *  \param ue_meas_trigger_quantity_for_ho indicates the triggering quantity for measurement reports
 *  \param coverage_based_ho Parameter indicates the HO based on coverage
 *  \param intra_freq_ho indicates if the intra LTE intra frequency HO is to be enabled 
 *  \param inter_freq_ho indicates if the intra LTE inter frequency HO is to be enabled
 *  \param inter_rat_ho indicates if the inter RAT HO is to be enabled
 */
typedef struct _rrm_oam_ho_algo_params_t
{
  rrm_bitmask_t	 bitmask; /*^ BITMASK ^*/
  S32            enb_measurements_for_ho;  /*^ O, RRM_OAM_ENB_MEAS_FOR_HO_PRESENT, N, 0, 0^*/
  S32            ue_meas_trigger_quantity_for_ho;  /*^ O, RRM_OAM_UE_MEAS_TRIGGER_QUAN_HO_PRESENT, N, 0, 0^*/
  S32            coverage_based_ho;  /*^ O, RRM_OAM_COVERAGE_BASED_HO_PRESENT, N, 0, 0^*/
  U8             intra_freq_ho;  /*^ O, RRM_OAM_INTRA_FREQ_HO_PRESENT, N, 0, 0^*/
  U8             inter_freq_ho; /*^ O, RRM_OAM_INTER_FREQ_HO_PRESENT, N, 0, 0^*/
  S32            inter_rat_ho; /*^ O, RRM_OAM_INTER_RAT_HO_PRESENT, N, 0, 0^*/
}rrm_oam_ho_algo_params_t;

#define  RRM_OAM_HO_RETRY_ENABLE_PRESENT  0x0001
#define  RRM_OAM_HO_RETRY_COUNT_PRESENT   0x0002
/*! \ rrm_oam_ho_retry_params_t
 *  \brief This struct is used for HO retry params
 *  \param bitmask To check optional field is present or not
 *  \param ho_retry_enable HO retry enabled
 *  \param ho_retry_count HO retry count
 */
typedef struct _rrm_oam_ho_retry_params_t
{
  rrm_bitmask_t	 bitmask; /*^ BITMASK ^*/
  U8             ho_retry_enable; /*^ O, RRM_OAM_HO_RETRY_ENABLE_PRESENT, N, 0, 0^*/
  U8             ho_retry_count; /*^ O, RRM_OAM_HO_RETRY_COUNT_PRESENT, N, 0, 0^*/
}rrm_oam_ho_retry_params_t;

#define RRM_OAM_TARGET_CELL_SELECTION_PARAMS_PRESENT  0x01
#define RRM_OAM_HO_ALGO_PARAMS_PRESENT                0x02
#define RRM_OAM_HO_RETRY_PARAMS_PRESENT               0x04
#define RRM_OAM_BLIND_HO_TIMER_PRESENT                0x08
/*! \  rrm_oam_ho_config_params_t
 *  \brief This struct is used for Handover configurations information
 *  \param bitmask To check optional field is present or not
 *  \param target_cell_selection_params target cell selection parameters
 *  \param ho_algo_params HO algo parameters
 *  \param ho_retry_params HO retry parameters
 *  \param blind_ho_timer Blind HO timer
 */
typedef struct rrm_oam_ho_config_params_t
{
  rrm_bitmask_t		bitmask; /*^ BITMASK ^*/
  rrm_oam_target_cell_selection_params_t  target_cell_selection_params; /*^ O, RRM_OAM_TARGET_CELL_SELECTION_PARAMS_PRESENT, N, 0, 0^*/
  rrm_oam_ho_algo_params_t     ho_algo_params;  /*^ O, RRM_OAM_HO_ALGO_PARAMS_PRESENT, N, 0, 0^*/
  rrm_oam_ho_retry_params_t    ho_retry_params; /*^ O, RRM_OAM_HO_RETRY_PARAMS_PRESENT, N, 0, 0^*/
  U16                          blind_ho_timer; /*^ O, RRM_OAM_BLIND_HO_TIMER_PRESENT, N, 0, 0^*/
}rrm_oam_ho_config_params_t;

#define  RRM_OAM_UTRAN_CSFB_TGT_SELECTION_PRESENT      0x01
#define  RRM_OAM_GERAN_CSFB_TGT_SELECTION_PRESENT      0x02
#define  RRM_OAM_CDMA2000_CSFB_TGT_SELECTION_PRESENT   0x04
/*! \ rrm_csfb_tgt_selection_t
 *  \brief This struct is used for CSFB target selection parameters
 *  \param bitmask To check optional field is present or not
 *  \param utran_csfb_tgt_selection Enum for utran csfb target selection
 *  \param geran_csfb_tgt_selection Enum for eutran csfb target selection
 *  \param cdma2000_csfb_tgt_selection Enum for geran csfb target selection
 */
typedef struct _rrm_csfb_tgt_selection_t
{
    rrm_bitmask_t  bitmask; /*^ BITMASK ^*/
    rrm_csfb_target_selection_et    utran_csfb_tgt_selection; /*^ O, RRM_OAM_UTRAN_CSFB_TGT_SELECTION_PRESENT, N, 0, 0^*/
    rrm_csfb_target_selection_et    geran_csfb_tgt_selection;  /*^ O, RRM_OAM_GERAN_CSFB_TGT_SELECTION_PRESENT, N, 0, 0^*/
    rrm_csfb_target_selection_et    cdma2000_csfb_tgt_selection;  /*^ O, RRM_OAM_CDMA2000_CSFB_TGT_SELECTION_PRESENT, N, 0, 0^*/
}rrm_csfb_tgt_selection_t;

#define  RRM_OAM_E_UTRAN_GAP_OFFSET_TYPE_PRESENT    0x01
#define  RRM_OAM_UTRAN_GAP_OFFSET_TYPE_PRESENT      0x02
#define  RRM_OAM_GERAN_GAP_OFFSET_TYPE_PRESENT      0x04
#define  RRM_OAM_CDMA2000_GAP_OFFSET_TYPE_PRESENT   0x08
/*! \  rrm_oam_meas_gap_config_t
 *  \brief This struct is used for specifying measurement gap configuration and controls setup/release of measurement gaps
 *  \param bitmask To check optional field is present or not
 *  \param eutran_gap_offset_type Gap offset of GAP pattern ID for eutran
 *  \param utran_gap_offset_type Gap offset of GAP pattern ID for utran
 *  \param geran_gap_offset_type Gap offset of GAP pattern ID geran
 *  \param cdma2000_gap_offset_type Gap offset of GAP pattern ID cdma2000
 */
typedef struct _rrm_oam_meas_gap_config_t
{
  rrm_bitmask_t  bitmask; /*^ BITMASK ^*/
  U8             eutran_gap_offset_type; /*^ O, RRM_OAM_E_UTRAN_GAP_OFFSET_TYPE_PRESENT, N, 0, 0^*/
  U8             utran_gap_offset_type;  /*^ O, RRM_OAM_UTRAN_GAP_OFFSET_TYPE_PRESENT, N, 0, 0^*/
  U8             geran_gap_offset_type;  /*^ O, RRM_OAM_GERAN_GAP_OFFSET_TYPE_PRESENT, N, 0, 0^*/
  U8             cdma2000_gap_offset_type;  /*^ O, RRM_OAM_CDMA2000_GAP_OFFSET_TYPE_PRESENT, N, 0, 0^*/
}rrm_oam_meas_gap_config_t;


#define RRM_OAM_REPORT_TRIGGER_TYPE_PRESENT  0x01
#define RRM_OAM_MEAS_GAP_CONFIG_PRESENT      0x02
#define RRM_OAM_SI_GAP_ENABLE_PRESENT        0x04
#define RRM_OAM_CSFB_TGT_SELECTION_PRESENT   0x08
/*! \ rrm_oam_meas_config_t
 *  \brief This struct is used for measurement configuration parameters
 *  \param bitmask To check optional field is present or not
 *  \param report_trigger_type indicates the triggering type for measurement reports
 *  \param meas_gap_config Specifies the measurement gap configuration and controls setup/ release of measurement gaps
 *  \param si_gap_enable indicates the SI gaps is to be enable or not
 *  \param csfb_tgt_selection Used for CSFB target selection
 */
typedef struct _rrm_oam_meas_config_t
{
  rrm_bitmask_t              bitmask; /*^ BITMASK ^*/
  S32	                     report_trigger_type; /*^ O, RRM_OAM_REPORT_TRIGGER_TYPE_PRESENT, N, 0, 0^*/
  rrm_oam_meas_gap_config_t  meas_gap_config; /*^ O, RRM_OAM_MEAS_GAP_CONFIG_PRESENT, N, 0, 0^*/
  S32	                     si_gap_enable; /*^ O, RRM_OAM_SI_GAP_ENABLE_PRESENT, N, 0, 0^*/
  rrm_csfb_tgt_selection_t   csfb_tgt_selection; /*^ O, RRM_OAM_CSFB_TGT_SELECTION_PRESENT, N, 0, 0^*/
}rrm_oam_meas_config_t;

/*  DYNAMIC ICIC CHANGES START  */


typedef struct _rrm_oam_resource_partition_t
{
    U32 start_rb;  /*^ M, 0, H, 0, 99^*/
    U32 num_of_rb;  /*^ M, 0, H, 0, 100^*/
}rrm_oam_resource_partition_t;

#define RRM_OAM_RESOURCE_PARTITION_CELL_EDGE_PRESENT 0x01
typedef struct _rrm_oam_rrm_oam_resource_partition_info_t
{
    rrm_bitmask_t              bitmask; /*^ BITMASK ^*/
    U32  num_of_cell_edge_region;  /*^ M, 0, N, 0, 0^*/
    U32  num_of_cell_center_region;  /*^ M, 0, B, 1, 2^*/
    rrm_oam_resource_partition_t cell_center_region[RRM_OAM_MAX_CC_REGION];  /*^ M, 0, OCTET_STRING, VARIABLE^*/
    rrm_oam_resource_partition_t cell_edge_region;  /*^ O, RRM_OAM_RESOURCE_PARTITION_CELL_EDGE_PRESENT, N, 0, 0^*/
}rrm_oam_resource_partition_info_t;


typedef struct _rrm_oam_aggregation_level_and_power_offset_info_t
{
    U32 aggregation_level;  /*^ M, 0, H, 1, 8^*/
    U32 power_offset;  /*^ M, 0, H, 0, 10000^*/
}rrm_oam_aggregation_power_offset_info_t;

typedef struct _rrm_oam_aggregation_power_offset_t
{
    U32 count;  /*^ M, 0, B, 1, 4^*/
    rrm_oam_aggregation_power_offset_info_t  aggr_pwr_offset_tuples[RRM_OAM_MAX_AGGREGATION_LEVEL_POWER_OFFSET_COUNT];/*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_aggregation_power_offset_t;

typedef struct _rrm_oam_aggregation_power_offset_on_cqi_group_basis_t
{
    rrm_oam_aggregation_power_offset_t aggregation_power_offset_user[RRM_OAM_MAX_CQI_VALUE]; /*^ M, 0, OCTET_STRING, FIXED^*/
}rrm_oam_aggregation_power_offset_on_cqi_basis_t;

#define RRM_OAM_AGGREGATION_POWER_OFFSET_CE_USER_PRESENT 0x01
typedef struct _rrm_oam_pdcch_aggregation_power_offset_t
{
    rrm_bitmask_t                           bitmask; /*^ BITMASK ^*/
    rrm_oam_aggregation_power_offset_on_cqi_basis_t aggregation_power_offset_cc_user[RRM_OAM_NUM_DCI_SIZE_CATEGORY];  /*^ M, 0, OCTET_STRING, FIXED^*/
    rrm_oam_aggregation_power_offset_on_cqi_basis_t aggregation_power_offset_ce_user[RRM_OAM_NUM_DCI_SIZE_CATEGORY];  /*^ O, RRM_OAM_AGGREGATION_POWER_OFFSET_CE_USER_PRESENT, OCTET_STRING, FIXED^*/
}rrm_oam_pdcch_aggregation_power_offset_t;


typedef struct _cqi_to_phich_power_t
{
    U32    cqi_to_phich_power_info[RRM_OAM_MAX_CQI_VALUE]; /*^ M, 0, OCTET_STRING, FIXED^*/ 
}rrm_oam_cqi_to_phich_power_t;


typedef struct _rrm_oam_sps_dl_scheduling_Info_per_tti_t
{
    U32 max_dl_sps_dci_per_tti;  /*^ M, 0, B, 1, 10^*/
    U32 max_dl_sps_Occasion_Per_tti;  /*^ M, 1, H, 0, 20^*/
    U32 max_dl_sps_rbs_per_tti;  /*^ M, 0, B, 1, 100^*/
    U32 max_dl_sps_rbs_per_tti_per_interval[RRM_OAM_MAX_SPS_INTERVALS];  /*^ M, 0, OCTET_STRING, FIXED^*/
}rrm_oam_sps_dl_scheduling_Info_per_tti_t;


typedef struct _rrm_oam_sps_ul_scheduling_Info_per_tti_t
{
    U32 max_ul_sps_dci_per_tti;  /*^ M, 0, B, 1, 10^*/
    U32 max_ul_sps_occasion_per_tti;  /*^ M, 1, H, 0, 20^*/
    U32 max_ul_sps_rbs_per_tti;  /*^ M, 0, B, 1, 100^*/
    U32 max_ul_sps_rbs_tti_per_interval[RRM_OAM_MAX_SPS_INTERVALS];  /*^ M, 0, OCTET_STRING, FIXED^*/
}rrm_oam_sps_ul_scheduling_Info_per_tti_t;


typedef struct _rrm_oam_hd_reduced_mcs_table_t
{
    U8 reduced_msc[RRM_OAM_MAX_REDUCED_MSC];  /*^ M, 0, N, 0, 0^*/
}rrm_oam_hd_reduced_mcs_table_t;


typedef struct _rrm_oam_dynamic_cfi_extension_params_t
{
    U8 cce_correction_step_up_factor[RRM_OAM_MAX_POSSIBLE_AGGREGAITION_LEVELS];  /*^ M, 0, OCTET_STRING, FIXED^*/
    U8 cce_correction_step_down_factor[RRM_OAM_MAX_POSSIBLE_AGGREGAITION_LEVELS];  /*^ M, 0, OCTET_STRING, FIXED^*/
    U8 cce_adjust_factor[RRM_OAM_MAX_POSSIBLE_AGGREGAITION_LEVELS];  /*^ M, 0, OCTET_STRING, FIXED^*/
}rrm_oam_dynamic_cfi_extension_params_t;


/*  Will be supported in rel 5.2    */
typedef struct _rrm_oam_atb_config_t
{
    U16     min_mcs_index_for_atb;  /*^ M, 0, H, 0, 28^*/
    U16     min_prb_val_for_atb;  /*^ M, 0, H, 0, 100^*/
}rrm_oam_atb_config_t;


typedef struct _rrm_oam_path_loss_to_target_sinr_map_info_t
{
    S32 start_PL;  /*^ M, 0, B, -230, 460^*/
    S32 end_PL;  /*^ M, 0, B, -230, 460^*/
    U32 target_SINR;  /*^ M, 0, H, 0, 255^*/
}rrm_oam_path_loss_to_target_sinr_map_info_t;

typedef struct _rrm_oam_path_loss_to_target_sinr_map_t
{
    U32 count;  /*^ M, 0, B, 1, 2^*/
    rrm_oam_path_loss_to_target_sinr_map_info_t path_loss_to_target_sinr_map_info[RRM_OAM_MAX_NUM_PATHLOSS_TO_SINR_COUNT];  /*^ M, 0, OCTET_STRING, VARIABLE^*/
}rrm_oam_path_loss_to_target_sinr_map_t;

typedef struct _rrm_oam_alpha_based_pathloss_target_sinr_map_t
{
    U32  default_path_loss;  /*^ M, 0, N, 0, 0^*/
    rrm_oam_path_loss_to_target_sinr_map_t path_loss_target_sinr_map[RRM_OAM_MAX_NUM_ALPHA_COUNT];  /*^ M, 0, OCTET_STRING, FIXED^*/
}rrm_oam_alpha_based_pathloss_target_sinr_map_t;


/* flags not specified  */
typedef struct _rrm_oam_ul_power_mask_t 
{
    S32 cell_center_user_power_mask; /*^ M, 0, N, 0, 0^*/
    S32 cell_edge_user_power_mask; /*^ M, 0, N, 0, 0^*/
    S32 qci_delta_power_mask[RRM_OAM_MAX_QCI_VAL];  /*^ M, 0, OCTET_STRING, FIXED^*/ 
}rrm_oam_ul_power_mask_t;

#define RRM_OAM_RNTP_THRESHOLD_PRESENT          0x01
#define RRM_OAM_MAX_NOMINAL_EPRE_PRESENT        0x02
typedef struct _rrm_oam_rntp_report_config_info_t
{
    rrm_bitmask_t  bitmask;/*^ BITMASK ^*/
    U32 rntp_report_on_X2_required; /*^ M, 0, H, 0, 1^*/
    U32 rntp_threshold; /*^ O, RRM_OAM_RNTP_THRESHOLD_PRESENT, H, 0, 15^*/
    U32 max_nominal_epre;  /*^ O, RRM_OAM_MAX_NOMINAL_EPRE_PRESENT, H, 0, 15^*/
}rrm_oam_rntp_report_config_info_t;

typedef enum
{
    RRM_OAM_ICIC_SCHEME_FFR, 
    RRM_OAM_ICIC_SCHEME_SFR 
}rrm_oam_icic_scheme_type_et;



#define RRM_OAM_ICIC_SCHEME_TYPE_PRESENT                        0x000001
#define RRM_OAM_DL_RESOURCE_PARTITON_INFO_PRESENT               0x000002
#define RRM_OAM_UL_RESOURCE_PARTITION_INFO_PRESENT              0x000004
#define RRM_OAM_UL_POWER_MASK_PRESENT                           0x000008
#define RRM_OAM_RNTP_REPORT_CONFIG_INFO_PRESENT                 0x000010
#define RRM_OAM_ALPHA_BASED_PATH_LOSS_TO_SINR_MAP_PRESENT       0x000020  
#define RRM_OAM_PDCCH_AGG_AND_POW_OFFSET_PRESENT                0x000040  
#define RRM_OAM_CQI_TO_PHICH_POW_PRESENT                        0x000080  
#define RRM_OAM_MIN_RB_FOR_PL_PHR_CALC_BIT_PRESENT              0x000100  
#define RRM_OAM_SPS_DL_SCHEDULING_INFO_PER_TTI_PRESENT          0x000200 
#define RRM_OAM_SPS_UL_SCHEDULING_INFO_PER_TTI_PRESENT          0x000400  
#define RRM_OAM_ALPHA_BASED_PATH_LOSS_TO_SINR_MAP_SPS_PRESENT   0x000800
#define RRM_OAM_DYNAMIC_CFI_EXTENSION_PARAM_PRESENT             0x001000
#define RRM_OAM_ATB_CONFIG_PRESENT                              0x002000
#define RRM_OAM_UL_MU_MIMO_TYPE_PRESENT                         0x004000
#define RRM_OAM_MSC_THRESHOLD_UL_MU_MIMO_PRESENT                0x008000
#define RRM_OAM_X2AP_ICIC_REPORT_PRESENT                        0x010000
#define RRM_OAM_PA_FOR_CELL_EDGE_UE_PRESENT                     0x020000

typedef struct _rrm_oam_dynamic_icic_info_t
{
    rrm_bitmask_t                          bitmask; /*^ BITMASK ^*/
    U8                                     icic_scheme_type;  /*^ O, RRM_OAM_ICIC_SCHEME_TYPE_PRESENT, N, 0, 0^*/
    rrm_oam_resource_partition_info_t      dl_resource_partition_info;  /*^ O, RRM_OAM_DL_RESOURCE_PARTITON_INFO_PRESENT, N, 0, 0^*/
    rrm_oam_resource_partition_info_t      ul_resource_partition_info;  /*^ O, RRM_OAM_UL_RESOURCE_PARTITION_INFO_PRESENT, N, 0, 0^*/
    rrm_oam_ul_power_mask_t                ul_power_mask;  /*^ O, RRM_OAM_UL_POWER_MASK_PRESENT, N, 0, 0^*/
    rrm_oam_rntp_report_config_info_t      rntp_report_config_info;  /*^ O, RRM_OAM_RNTP_REPORT_CONFIG_INFO_PRESENT, N, 0, 0^*/  

    rrm_oam_alpha_based_pathloss_target_sinr_map_t      alpha_pathloss_target_sinr_map;  /*^ O, RRM_OAM_ALPHA_BASED_PATH_LOSS_TO_SINR_MAP_PRESENT , N, 0, 0^*/  
    rrm_oam_pdcch_aggregation_power_offset_t            pdcch_aggregation_power_offset;  /* O, RRM_OAM_PDCCH_AGG_AND_POW_OFFSET_PRESENT, N, 0, 0^*/
    rrm_oam_cqi_to_phich_power_t                        cqi_to_phich_power;  /*^ O, RRM_OAM_CQI_TO_PHICH_POW_PRESENT, N, 0, 0^*/
    
    U32     min_rb_for_pl_phr_calc;  /*^ O, RRM_OAM_MIN_RB_FOR_PL_PHR_CALC_BIT_PRESENT, N, 0, 0^*/

    rrm_oam_sps_dl_scheduling_Info_per_tti_t            sps_dl_scheduling_Info_per_tti;  /*^ O, RRM_OAM_SPS_DL_SCHEDULING_INFO_PER_TTI_PRESENT, N, 0, 0^*/
    rrm_oam_sps_ul_scheduling_Info_per_tti_t            sps_ul_scheduling_Info_per_tti;  /*^ O, RRM_OAM_SPS_UL_SCHEDULING_INFO_PER_TTI_PRESENT, N, 0, 0^*/

    rrm_oam_alpha_based_pathloss_target_sinr_map_t      alpha_pathloss_target_sinr_map_sps;  /*^ O, RRM_OAM_ALPHA_BASED_PATH_LOSS_TO_SINR_MAP_SPS_PRESENT , N, 0, 0^*/
    rrm_oam_dynamic_cfi_extension_params_t      dynamic_cfi_extension_params;  /*^ O, RRM_OAM_DYNAMIC_CFI_EXTENSION_PARAM_PRESENT, N, 0, 0^*/
    rrm_oam_atb_config_t                        atb_config;  /*^ O, RRM_OAM_ATB_CONFIG_PRESENT, N, 0, 0^*/

    U32     ul_mu_mimo_type;  /*^ O, RRM_OAM_UL_MU_MIMO_TYPE_PRESENT, H, 0, 1^*/
    U32     msc_threshold_ul_mu_mimo;  /*^ O, RRM_OAM_MSC_THRESHOLD_UL_MU_MIMO_PRESENT, B, 0, 28^*/

    U16     x2ap_icic_report_periodicity;    /*^ O, RRM_OAM_X2AP_ICIC_REPORT_PRESENT, L, 20, 0^*/
    U32     pa_for_ce_ue;   /*^ O, RRM_OAM_PA_FOR_CELL_EDGE_UE_PRESENT, B, 0, 28^*/
}rrm_oam_dynamic_icic_info_t;

/*  DYNAMIC ICIC CHANGES END  */

#define RRM_OAM_POWER_CONTROL_ENABLE_PRESENT   0x0001
#define RRM_OAM_TPC_RNTI_RANGE_PRESENT         0x0002
/*! \ rrm_oam_power_control_params_t
 *  \brief This struct is used for power control params 
 *  \param bitmask To check optional field is present or not
 *  \param rrm_power_control_enable for power control enable/disable 
 *  \param rrm_tpc_rnti_range TPC rnti range
 */
typedef struct _rrm_oam_power_control_params_t
{
   rrm_bitmask_t		     bitmask; /*^ BITMASK ^*/
   rrm_oam_power_control_enable_t    rrm_power_control_enable; /*^ O, RRM_OAM_POWER_CONTROL_ENABLE_PRESENT, N, 0, 0 ^*/
   rrm_oam_tpc_rnti_range_t          rrm_tpc_rnti_range; /*^ O, RRM_OAM_TPC_RNTI_RANGE_PRESENT, N, 0, 0 ^*/
}rrm_oam_power_control_params_t; 

/*! \ rrm_oam_eutran_access_point_pos_t
 *  \brief This struct is used for EUTRAN Access point position IE params
 *  \param bitmask To check optional field is present or not
 *  \param latitude_sign Sign of Latitude:North/South
 *  \param deg_of_latitude Degree of Latitude
 *  \param deg_of_longitude Degree of Longitude
 *  \param dir_of_altitude  Direction of altitude:Height/Depth
 *  \param altitude Altitude
 *  \param uncertainty_semi_major Uncertainity in semi-major
 *  \param uncertainty_semi_minor Uncertainity in semi-minor
 *  \param orientation_of_major_axis Orientation of major axis
 *  \param uncertainty_altitude Uncertainity in altitude
 *  \param confidence In percentage
 */
typedef struct _rrm_oam_eutran_access_point_pos_t
{
    rrm_bitmask_t   bitmask;                    /*^ BITMASK ^*/
    U32             latitude_sign;              /*^ M, 0, H, 0, 1 ^*/               /* rrm_oam_latitude_sign_et */
    U8              deg_of_latitude;            /*^ M, 0, H, 0, 90 ^*/
    S16             deg_of_longitude;           /*^ M, 0, B, -180, 180 ^*/
    U32             dir_of_altitude;            /*^ M, 0, H, 0, 1 ^*/               /* rrm_oam_altitude_dir_et */
    U16             altitude;                   /*^ M, 0, H, 0, 32767 ^*/
    U32             uncertainty_semi_major;     /*^ M, 0, H, 0, 1800000 ^*/         /* in metres */
    U32             uncertainty_semi_minor;     /*^ M, 0, H, 0, 1800000 ^*/         /* in metres */
    U8              orientation_of_major_axis;  /*^ M, 0, H, 0, 179 ^*/
    U16             uncertainty_altitude;       /*^ M, 0, H, 0, 990 ^*/             /* in metres */
    U8              confidence;                 /*^ M, 0, H, 0, 100 ^*/
}rrm_oam_eutran_access_point_pos_t;

#define RRM_OAM_MAC_CONFIG_PRESENT             0x0001
#define RRM_OAM_PHICH_CONFIG_PRESENT           0x0002
#define RRM_OAM_ADDL_SIB1_INFO_PRESENT         0x0004
#define RRM_OAM_ADDL_SIB2_INFO_PRESENT         0x0008
#define RRM_OAM_ADDL_SIB3_INFO_PRESENT         0x0010
#define RRM_OAM_ADDL_SIB4_INFO_PRESENT         0x0020
#define RRM_OAM_ADDMISION_CONTROL_INFO_PRESENT 0x0040
#define RRM_OAM_POWER_CONTROL_INFO_PRESENT     0x0080
#define RRM_OAM_SPS_CRNTI_RANGE_PRESENT        0x0100
#define RRM_OAM_ACK_NACK_CQI_PRESENT           0x0200
#define RRM_OAM_ADD_PACKET_SCH_PARAMS_PRESENT  0x0400
#define RRM_OAM_ADD_CELL_PARAMS_PRESENT        0x0800
#define RRM_OAM_LOAD_PARAMS_PRESENT            0x1000
#define RRM_OAM_MIMO_MODE_PARAMS_PRESENT       0x2000
#define RRM_OAM_HO_CONFIGURATION_PRESENT       0x4000
#define RRM_OAM_MEASUREMENT_CONFIG_PRESENT     0x8000
#define RRM_OAM_CELL_CAPACITY_CLASS_PRESENT    0x10000
#define RRM_OAM_CELL_TYPE_PRESENT              0x20000
/*  DYNAMIC ICIC CHANGES START  */
#define RRM_OAM_DYNAMIC_ICIC_INFO_PRESENT      0x40000
/*  DYNAMIC ICIC CHANGES END  */

#define RRM_OAM_EUTRAN_ACCESS_POINT_POS_PRESENT 0x80000
/*! \ rrm_oam_operator_info_t
 *  \brief This struct is used for
 *  \param bitmask To check optional field is present or not
 *  \param rrm_mac_config contains mac config
 *  \param phich_config phich configuration as broadcasted in RRC MIB
 *  \param sib_1_info Additional SIB1 information
 *  \param sib_2_info Additional SIB2 information
 *  \param sib_3_info Additional SIB3 information
 *  \param sib_4_info Additional SIB4 information
 *  \param admission_control_info Contains admission control information
 *  \param rrm_power_control_params Power control parameters
 *  \param rrm_sps_crnti_range SPS-CRNTI range for semi-persistent scheduling
 *  \param simultaneous_ack_nack_and_cqi 1 indicates that simultaneoustransmission of ACK/NACK and CQI can be configured in the cell else it is not allowed to be configured
 *  \param additional_packet_scheduling_params additional packet scheduling parameters
 *  \param additional_cell_params additional cell parameters
 *  \param load_params load parameters
 *  \param mimo_mode_params mimo mode parameters
 *  \param ho_configuration HO configuration params
 *  \param measurement_configuration measurement configuration
 *  \param cell_capacity_class cell capacity class
 *  \param cell_type type of cell
 *  \param rrm_eutran_access_point_pos EUTRAN Access point position IE used in UE positioning
 */
typedef struct _rrm_oam_operator_info_t
{
	rrm_bitmask_t 			        bitmask; /*^ BITMASK ^*/
	rrm_oam_rrmc_mac_config_t               rrm_mac_config;/*^ O, RRM_OAM_MAC_CONFIG_PRESENT, N, 0, 0 ^*/
	rrm_oam_phy_phich_configuration_t       phich_config;/*^ O, RRM_OAM_PHICH_CONFIG_PRESENT, N, 0, 0 ^*/
	rrm_oam_sib_type_1_info_t 		sib_1_info;/*^ O, RRM_OAM_ADDL_SIB1_INFO_PRESENT, N, 0, 0 ^*/
	rrm_oam_sib_type_2_info_t 		sib_2_info;/*^ O, RRM_OAM_ADDL_SIB2_INFO_PRESENT, N, 0, 0 ^*/
	rrm_oam_sib_type_3_info_t 		sib_3_info;/*^ O, RRM_OAM_ADDL_SIB3_INFO_PRESENT, N, 0, 0 ^*/
	rrm_oam_sib_type_4_info_t 		sib_4_info;/*^ O, RRM_OAM_ADDL_SIB4_INFO_PRESENT, N, 0, 0 ^*/
	rrm_oam_admission_control_info_t 	admission_control_info;/*^ O, RRM_OAM_ADDMISION_CONTROL_INFO_PRESENT, N, 0, 0 ^*/
	rrm_oam_power_control_params_t		rrm_power_control_params; /*^ O, RRM_OAM_POWER_CONTROL_INFO_PRESENT, N, 0, 0 ^*/
    rrm_oam_sps_crnti_range_t               rrm_sps_crnti_range;  /*^ O, RRM_OAM_SPS_CRNTI_RANGE_PRESENT, N, 0, 0 ^*/
    U8                                      simultaneous_ack_nack_and_cqi;   /*^ O, RRM_OAM_ACK_NACK_CQI_PRESENT, N, 0, 0 ^*/
    rrm_oam_adl_pkt_scheduling_params_t     additional_packet_scheduling_params; /*^ O, RRM_OAM_ADD_PACKET_SCH_PARAMS_PRESENT, N, 0, 0 ^*/
    rrm_oam_adl_cell_params_t               additional_cell_params; /*^ O, RRM_OAM_ADD_CELL_PARAMS_PRESENT, N, 0, 0 ^*/ 
    rrm_oam_load_params_t                   load_params;  /*^ O, RRM_OAM_LOAD_PARAMS_PRESENT, N, 0, 0 ^*/
    rrm_oam_mimo_mode_params_t              mimo_mode_params;  /*^ O, RRM_OAM_MIMO_MODE_PARAMS_PRESENT, N, 0, 0 ^*/
    rrm_oam_ho_config_params_t              ho_configuration; /*^ O, RRM_OAM_HO_CONFIGURATION_PRESENT, N, 0, 0 ^*/
    rrm_oam_meas_config_t                   measurement_configuration;  /*^ O, RRM_OAM_MEASUREMENT_CONFIG_PRESENT, N, 0, 0 ^*/
    U8                                      cell_capacity_class; /*^ O, RRM_OAM_CELL_CAPACITY_CLASS_PRESENT, B, 1, 100 ^*/
    U8                                      cell_type; /*^ O, RRM_OAM_CELL_TYPE_PRESENT, H, 0, 3 ^*/
/* DYNAMIC ICIC CHANGES START */
    rrm_oam_dynamic_icic_info_t             dynamic_icic_info;  /*^ O, RRM_OAM_DYNAMIC_ICIC_INFO_PRESENT, N, 0, 0 ^*/
/* DYNAMIC ICIC Change End */
    rrm_oam_eutran_access_point_pos_t       rrm_eutran_access_point_pos; /*^ O, RRM_OAM_EUTRAN_ACCESS_POINT_POS_PRESENT, N, 0, 0 ^*/
}rrm_oam_operator_info_t;

#define RRM_OAM_CSG_ID_PRESENT		0x0001
/*! \  rrm_oam_access_mgmt_params_t
 *  \brief This struct is used for Parameters applicable for CSG mode access
 *  \param bitmask To check optional field is present or not
 *  \param access_mode Possible values:Open, Closed, Hybrid
 *  \param max_csg_members Maximum csg members that are allowed at a time 
 *  \param max_non_csg_members Maximum non csg members that are allowed at a time
 *  \param csg_id[RRM_OAM_MAX_NUM_CSG_OCTETS] used to identify a Closed Subscriber Group
 *  \param hnb_name_size Indicates the size of the following array 
 *  \param hnb_name[RRM_OAM_MAX_NUM_HNB_NAME_OCTETS] Carries the name of the home eNB coded in UTF-8 with variable number of bytes per character
 */
typedef struct _rrm_oam_access_mgmt_params
{
	rrm_bitmask_t           bitmask;  /*^ BITMASK ^*/
	rrm_oam_access_mode_et 	access_mode;/*^ M, 0, H, 0, 2 ^*/
	S16 			max_csg_members; /*^ M, 0, N, 0, 255 ^*/
	S16 			max_non_csg_members;/*^ M, 0, N, 0, 255 ^*/
	U8 			csg_id[RRM_OAM_MAX_NUM_CSG_OCTETS];/*^ O, RRM_OAM_CSG_ID_PRESENT, OCTET_STRING, FIXED ^*/
	U8 			hnb_name_size;/*^ M, 0, N, 0, 0 ^*/
	U8 			hnb_name[RRM_OAM_MAX_NUM_HNB_NAME_OCTETS];/*^ M, 0, OCTET_STRING, VARIABLE ^*/	
}rrm_oam_access_mgmt_params_t;


/*! \  rrm_oam_updated_plmn_info_t
 *  \brief This struct is used for The updated primary PLMN Id information params of cell
 *  \param no_of_valid_plmns used for maintaining the count of PLMN
 *  \param plmn_list[RRM_OAM_MAX_NUM_PLMNS] list of PLMN 
 */
typedef struct _rrm_oam_plmn_access_info_t
{
   U8                            no_of_valid_plmns; /*^ M, 0, B, 1, 6 ^*/
   rrm_oam_cell_plmn_info_t      plmn_list[RRM_OAM_MAX_NUM_PLMNS]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_updated_plmn_info_t;

/*! \ rrm_oam_time_stamp_t
 *  \brief This struct is used for storing time at which event occured
 *  \param year for year
 *  \param month for month
 *  \param day for day 
 *  \param hour for hour
 *  \param min for min
 *  \param sec for sec
 */
typedef struct _rrm_oam_time_stamp_t
{
  U16      year;  /*^ M, 0, N, 0, 0 ^*/
  U16      month; /*^ M, 0, N, 0, 0 ^*/
  U16      day;   /*^ M, 0, N, 0, 0 ^*/
  U16      hour;  /*^ M, 0, N, 0, 0 ^*/
  U16      min;   /*^ M, 0, N, 0, 0 ^*/
  U16      sec;   /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_time_stamp_t;


/*! \  rrm_oam_event_header_t
 *  \brief This struct is used for event header params
 *  \param msg_len Length of the message including header and payload
 *  \param time_stamp Time at which event is raised
 *  \param event_id Event identifier
 *  \param core_id core identifier
 *  \param cell_id cell identifier
 *  \param ue_id UE identifier
 *  \param msg_direction Message direction(message is coming inside the RRM or going outside RRM)
 *  \param mom_id MOM Identification
 */
typedef struct _rrm_oam_event_header_t
{
  rrm_oam_time_stamp_t       time_stamp;  /*^ M, 0, N, 0, 0 ^*/ 
  rrm_oam_event_class_et     event_type; /*^ M, 0, N, 0, 0 ^*/ 
  rrm_oam_event_subclass_et  event_sub_type; /*^ M, 0, N, 0, 0 ^*/ 
  U16                        event_id;  /*^ M, 0, N, 0, 0 ^*/ 
}rrm_oam_event_header_t;

/*! \  rrm_oam_tac_t
 *  \brief This struct is used for tracking area code parameters
 *  \param tac[RRM_OAM_MAX_NUM_TAC_OCTETS] array of tracking area code
 *  \param cell_id Global Cell Id
 */
typedef struct _rrm_oam_tac_t
{
  U8                               tac[RRM_OAM_MAX_NUM_TAC_OCTETS]; /*^ M, 0, OCTET_STRING, FIXED ^*/
  rrm_oam_eutran_global_cell_id_t  cell_id; /*^ M, 0, N, 0, 0 ^*/
}rrm_oam_tac_t;

#define RRM_OAM_TAC_INFO_PRESENT              0x01
#define RRM_OAM_TNL_ADDR_LIST_SIZE_PRESENT    0x02
#define RRM_OAM_TNL_ADDR_LIST_PRESENT         0x04
#define RRM_OAM_X2_STATUS_PRESENT             0x08
#define RRM_OAM_X2_CONNECTION_STATUS_PRESENT  0x10
/*! \ rrm_neighbor_enb_info_t
 *  \brief This struct is used for List of neighbor eNBs and  attribute values of each neighbor
 *  \param bitmask To check optional field is present or not
 *  \param enb_id Global eNB Id
 *  \param num_cells Number of cells information present in the array
 *  \param tac_info[RRM_MAX_NUM_CELLS] Tracking Area Info list
 *  \param enb_tnl_address_list_size Size of enb_tnl_address_list
 *  \param enb_tnl_address_list[MAX_NO_ENB_X2_TLAS] Transport Layer Address
 *  \param x2_status Indicates whether X2 connection can be used for HO or not with the corresponding eNB
 *  \param x2_connection_status Indicates the status of the X2 Connection
 */
typedef struct _rrm_neighbor_enb_info_t
{
   rrm_bitmask_t		bitmask; /*^ BITMASK ^*/
   rrm_global_enb_id_t		enb_id; /*^ M, 0, N, 0, 0 ^*/
   U16	                        num_cells; /*^ M, 0, N, 0, 0 ^*/
   rrm_oam_tac_t                tac_info[RRM_MAX_NUM_CELLS]; /*^ O, RRM_OAM_TAC_INFO_PRESENT, OCTET_STRING, VARIABLE ^*/
   U8				enb_tnl_address_list_size; /*^ O, RRM_OAM_TNL_ADDR_LIST_SIZE_PRESENT, N, 0, 0 ^*/
   rrm_enb_tnl_address_t	enb_tnl_address_list[MAX_NO_ENB_X2_TLAS]; /*^ O, RRM_OAM_TNL_ADDR_LIST_PRESENT, OCTET_STRING, VARIABLE ^*/ 
   S32				x2_status; /*^ O, RRM_OAM_X2_STATUS_PRESENT, N, 0, 0 ^*/
   S32				x2_connection_status; /*^ O, RRM_OAM_X2_CONNECTION_STATUS_PRESENT, N, 0, 0 ^*/
}rrm_neighbor_enb_info_t;


/*! \  rrm_global_enb_status_t
 *  \brief This struct is used for list of the neighbor eNBs which could not be updated due to some internal errors
 *  \param enb_id Identity of the eNB for which the operation is being performed
 *  \param error_code Error Code 
 */
typedef struct _rrm_global_enb_status_t
{
 rrm_global_enb_id_t  enb_id; /*^ M, 0, N, 0, 0 ^*/
 S32				  error_code;  /*^ M, 0, N, 0, 0 ^*/
}rrm_global_enb_status_t;



/*! \rrm_oam_watermark_t
 *  \brief This Struct contains watermark that needs to be taken under various load
 *  condition
 *  \param high_watermark indicates upper threshold limit
 *  \param low_watermark indicates lower threshold limit
 */
typedef struct _rrm_oam_watermark_t
{
  U8                  high_watermark; /*^ M, 0, B, 1, 100 ^*/
  U8                  low_watermark; /*^ M, 0, B, 1, 100 ^*/
}rrm_oam_watermark_t;

/*! \ rrm_oam_load_def_t
 *  \brief This Struct contains action that needs to be taken under various load
 *  condition
 *  \param bitmask To check optional field is present or not
 *  \param load_perctg indicates the percentage which defines the particular
 *  load
 *  \param action indicates the action that needs to be taken
 *  \param num_usr indicates the number of users that are being impacted due to
 *  the action. 
 *  \param q_watermark indicates the threshold limit
 */
#define RRM_OAM_PERCNTG_PRESENT  0x01
#define RRM_OAM_ACTION_PRESENT   0x02
#define RRM_OAM_NUM_USR_PRESENT  0x04
#define RRM_OAM_Q_WATERMARK_PRESENT  0x08
#define RRM_OAM_LD_AC_BARRING_PRESENT 0x10

typedef struct _rrm_oam_load_def_t 
{
  rrm_bitmask_t                 bitmask;        /*^ BITMASK ^*/
  U8                            load_perctg;    /*^ O, RRM_OAM_PERCNTG_PRESENT, B, 1, 100 ^*/
  rrm_oam_action_t              action;         /*^ O, RRM_OAM_ACTION_PRESENT, L, 1, 0 ^*/
  U8                            num_usr;        /*^ O, RRM_OAM_NUM_USR_PRESENT, L, 1, 255 ^*/
  rrm_oam_watermark_t           q_watermark;    /*^ O, RRM_OAM_Q_WATERMARK_PRESENT, N, 0, 0 ^*/
  rrm_oam_access_barring_info_t ld_ac_bar;      /*^ O, RRM_OAM_LD_AC_BARRING_PRESENT, N, 0, 0 ^*/
}rrm_oam_load_def_t;




/*! \rrm_oam_resrc_info_t
 *  \brief  Struct contains resource information that needs
 *  to be taken under various load condition
 *  \param bitmask To check optional field is present or not
 *  \param resrc_type indicates the type of the resource 
 *  for which the load information needs to be changed
 *  \param  overload Contain information about the overload 
 *  \param  highload Contain information about the high load 
 *  \param  midload Contain information about the mid load 
 */
#define RRM_OAM_ACTION_OVERLD_PRESENT  0x01
#define RRM_OAM_ACTION_HIGHLD_PRESENT  0x02
#define RRM_OAM_ACTION_MIDLD_PRESENT  0x04
typedef struct _rrm_oam_resrc_info_t
{
  rrm_bitmask_t         bitmask;    /*^ BITMASK ^*/
  U32                   resrc_type; /*^ M, 0, N, 0, 0 ^*/
  rrm_oam_load_def_t    overload; /*^ O, RRM_OAM_ACTION_OVERLD_PRESENT, N, 0, 0 ^*/
  rrm_oam_load_def_t    highload; /*^ O, RRM_OAM_ACTION_HIGHLD_PRESENT, N, 0, 0 ^*/
  rrm_oam_load_def_t    midload; /*^ O, RRM_OAM_ACTION_MIDLD_PRESENT, N, 0, 0 ^*/
}rrm_oam_resrc_info_t;

/*! \ rrm_oam_resource_load_info_t
 *  \brief This Struct contains resource information that needs 
 *  to be taken under various load condition
 *  \param bitmask Bitmask value
 *  \param count indicates the number of the resource
 *  \param resrc_info[RRM_OAM_MAX_RESOURCE]  indicates the resource information
 */
typedef struct _rrm_oam_resource_load_info_t
{
  rrm_bitmask_t         bitmask;             /*^ BITMASK ^*/
  U8                    count; /*^ M, 0, B, 1, 4 ^*/
  rrm_oam_resrc_info_t  resrc_info[RRM_OAM_MAX_RESOURCE]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_oam_resource_load_info_t;


/*! \ rrm_oam_serving_enb_cell_info_t 
 *  \brief This Struct stores serving enodeB cell information
 *  \param bitmask To check optional field is present or not
 *  \param global_cell_id indicates globally unique cell identifier
 *  \param over_load_lvl_act indicates the action that needs to be taken at
 *  eNodeB when under overload condition
 *  \param high_load_lvl_act indicates the action that needs to be taken at
 *  eNodeB when under high load condition
 *  \param mid_load_lvl_act indicates the action that needs to be taken at
 *  eNodeB when under mid load condition
 *  \param resrc_spec contains resource specific information about load condition
 */

#define RRM_OAM_OVER_LOAD_LVL_ACT_PRESENT  0x01
#define RRM_OAM_HIGH_LOAD_LVL_ACT_PRESENT  0x02
#define RRM_OAM_MID_LOAD_LVL_ACT_PRESENT  0x04
#define RRM_OAM_RESRC_SPEC_PRESENT        0x08
typedef struct _rrm_oam_serving_enb_cell_info_t
{
  rrm_bitmask_t                     bitmask;             /*^ BITMASK ^*/
  rrm_oam_eutran_global_cell_id_t   global_cell_id;     /*^ M, 0, N, 0, 0 ^*/
  rrm_oam_load_def_t                over_load_lvl_act;  /*^ O, RRM_OAM_OVER_LOAD_LVL_ACT_PRESENT, N, 0, 0 ^*/
  rrm_oam_load_def_t                high_load_lvl_act;  /*^ O, RRM_OAM_HIGH_LOAD_LVL_ACT_PRESENT, N, 0, 0 ^*/
  rrm_oam_load_def_t                mid_load_lvl_act;   /*^ O, RRM_OAM_MID_LOAD_LVL_ACT_PRESENT, N, 0, 0 ^*/
  rrm_oam_resource_load_info_t      resrc_spec;     /*^ O, RRM_OAM_RESRC_SPEC_PRESENT, N, 0, 0 ^*/
}rrm_oam_serving_enb_cell_info_t;


/*! \  rrm_hw_load_ind_t 
 *  \brief This Struct contains hardware load information 
 *  \param dl indicates total load on hardware due to downlink traffic
 *  \param ul indicates total load on hardware due to uplink traffic
 */
typedef struct _rrm_hw_load_ind_t
{
  rrm_rs_load_lvl_et    dl; /*^ M, 0, N, 0, 0 ^*/
  rrm_rs_load_lvl_et    ul; /*^ M, 0, N, 0, 0 ^*/
}rrm_hw_load_ind_t;

/*! \ rrm_s1_tnl_load_ind_t 
 *  \brief This Struct contains load information on S1 TNL
 *  \param dl indicates load level on S1 tunnel in downlink
 *  \param ul indicates load level on S1 tunnel in uplink
 */
typedef struct _rrm_s1_tnl_load_ind_t
{
  rrm_rs_load_lvl_et    dl; /*^ M, 0, N, 0, 0 ^*/
  rrm_rs_load_lvl_et    ul; /*^ M, 0, N, 0, 0 ^*/
}rrm_s1_tnl_load_ind_t;

/*! \  rrm_rrs_load_ind_t 
 *  \brief This Struct contains information about the PRB load on a cell
 *  \param dl_gbr_prb_usage indicates GBR PRB usage in downlink
 *  \param ul_gbr_prb_usage indicates GBR PRB usage in uplink
 *  \param dl_non_gbr_prb_usage indicates Non GBR PRB usage in downlink
 *  \param ul_non_gbr_prb_usage indicates Non GBR PRB usage in uplink
 *  \param dl_total_prb_usage indicates Total PRB usage in downlink
 *  \param ul_total_prb_usage indicates Total PRB usage in uplink
 */
typedef struct _rrm_rrs_load_ind_t
{
  U8    dl_gbr_prb_usage; /*^ M, 0, N, 0, 0 ^*/
  U8    ul_gbr_prb_usage; /*^ M, 0, N, 0, 0 ^*/
  U8    dl_non_gbr_prb_usage; /*^ M, 0, N, 0, 0 ^*/
  U8    ul_non_gbr_prb_usage; /*^ M, 0, N, 0, 0 ^*/
  U8    dl_total_prb_usage; /*^ M, 0, N, 0, 0 ^*/
  U8    ul_total_prb_usage; /*^ M, 0, N, 0, 0 ^*/
}rrm_rrs_load_ind_t;

/*! \ rrm_comp_avl_cap_t 
 *  \brief This Struct contains available capacity information of the cell
 *  \param bitmask To check optional field is present or not
 *  \param cell_cap_class_val value 1 shall indicate the minimum cell
 *   capacity, and 100 shall indicate the maximum cell capacity. There should be
 *   linear relation between cell capacity and Cell Capacity Class Value
 *  \param cap_val value 0 shall indicate no available capacity, and 100 shall
 *   indicate maximum available capacity.
 */
typedef struct _rrm_comp_avl_cap_t
{
#define RRM_SON_CELL_CAP_CLASS_VAL_PRESENT  0x01 
  rrm_bitmask_t bitmask;  /*^ BITMASK ^*/
  U8    cell_cap_class_val; /*^ O, RRM_SON_CELL_CAP_CLASS_VAL_PRESENT, B, 1, 100 ^*/
  U8    cap_val; /*^ M, 0, H, 0, 100 ^*/
}rrm_comp_avl_cap_t;

/*! \ rrm_comp_avl_cap_grp_t 
 *  \brief This Struct contains composite availablity of the resource at the cell
 *  \param dl_comp_avl_cap shows availability of the resource in downlink
 *  \param ul_comp_avl_cap shows availability of the resource in uplink
 */
typedef struct _rrm_comp_avl_cap_grp_t
{
  rrm_comp_avl_cap_t    dl_comp_avl_cap; /*^ M, 0, N, 0, 0 ^*/
  rrm_comp_avl_cap_t    ul_comp_avl_cap; /*^ M, 0, N, 0, 0 ^*/
}rrm_comp_avl_cap_grp_t;

/*! \ rrm_cell_load_info_t 
 *  \brief This Struct contains load information of the cell 
 *  \param bitmask To check optional field is present or not
 *  \param g_cell_id Global Cell identifier 
 *  \param hw_load contains information about hardware load
 *  \param s1_tnl_load contains information about S1 TNL load
 *  \param rrs contains information about the radio resource
 *  \param comp_avl_cap_grp contain information about available capacity of the cell
 */
#define RRM_OAM_HW_LOAD_PRESENT     0x01
#define RRM_OAM_S1_TNL_LOAD_PRESENT 0x02
#define RRM_OAM_RRS_LOAD_PRESENT    0x04
#define RRM_OAM_COMP_LOAD_PRESENT   0x08
typedef struct _rrm_cell_load_info_t
{
  rrm_bitmask_t                     bitmask; /*^ BITMASK ^*/
  rrm_oam_eutran_global_cell_id_t   g_cell_id; /*^ M, 0, N, 0, 0 ^*/
  rrm_hw_load_ind_t                 hw_load; /*^ O, RRM_OAM_HW_LOAD_PRESENT, N, 0, 0 ^*/
  rrm_s1_tnl_load_ind_t             s1_tnl_load;/*^ O, RRM_OAM_S1_TNL_LOAD_PRESENT, N, 0, 0 ^*/
  rrm_rrs_load_ind_t                rrs;/*^ O, RRM_OAM_RRS_LOAD_PRESENT, N, 0, 0 ^*/
  rrm_comp_avl_cap_grp_t            comp_avl_cap_grp;/*^ O, RRM_OAM_COMP_LOAD_PRESENT, N, 0, 0 ^*/
}rrm_cell_load_info_t;

/*! \  rrm_bitrate_ul_dl_t
 *  \brief This struct is used for Bitrate for QCI in uplink params
 *  \param max_bitrate Maximum bitrate on which ECN need to be set
 *  \param min_bitrate Minimum bitrate on which ECN need to be unset
 */
typedef struct _rrm_bitrate_ul_dl_t
{
    U64 max_bitrate; /*^ M, 0, N, 0, 0 ^*/
    U64 min_bitrate; /*^ M, 0, N, 0, 0 ^*/
}rrm_bitrate_ul_dl_t;
#define RRM_OAM_ECN_UL_BITRATE_PRESENT 0x01
#define RRM_OAM_ECN_DL_BITRATE_PRESENT 0x02
/*! \ rrm_configure_qci_bitrate_t
 *  \brief This struct is used for bitrates for QCI information
 *  \param bitmask To check optional field ispresent or not
 *  \param qci Qci number
 *  \param ul_bitrate Bitrate for QCI in uplink
 *  \param dl_bitrate Bitrate for QCI in downlink
 */
typedef struct  _rrm_configure_qci_bitrate_t
{
    rrm_bitmask_t bitmask; /*^ BITMASK ^*/
    U8 qci; /*^ M, 0, B, 1, 9 ^*/
    rrm_bitrate_ul_dl_t ul_bitrate; /*^ O, RRM_OAM_ECN_UL_BITRATE_PRESENT, N, 0, 0 ^*/
    rrm_bitrate_ul_dl_t dl_bitrate; /*^ O, RRM_OAM_ECN_DL_BITRATE_PRESENT, N, 0, 0 ^*/
}rrm_configure_qci_bitrate_t;

/*! \ rrm_qci_bitrate_info_t
 *  \brief This struct is used for Bitrate for UE params
 *  \param count number of qci for which bitrate is configured
 *  \param bitrate_for_qci[RRM_MAX_QCI] array of Bitrates for qci 
 */
typedef struct _rrm_qci_bitrate_config_t
{
    rrm_bitmask_t bitmask; /*^ BITMASK ^*/
    U8 count; /*^ M, 0, H, 0, 9 ^*/
    rrm_configure_qci_bitrate_t  bitrate_for_qci[RRM_MAX_QCI]; /*^ M, 0, OCTET_STRING, VARIABLE ^*/
}rrm_qci_bitrate_info_t;

/*! \ rrm_ecn_configure_cell_list_t 
 *  \brief This struct is used for Cells for which ECN bitrate has been provided
 *  \param bitmask BITMASK value
 *  \param global_cell_id Glabal Cell ID
 *  \param num_of_ue Number of ue on which ECN bit need to be set
 *  \param bitrate Bitrate for UE
 */
typedef struct _rrm_ecn_configure_cell_list_t
{
    rrm_bitmask_t bitmask; /*^ BITMASK ^*/
    rrm_oam_eutran_global_cell_id_t global_cell_id; /*^ M, 0, N, 0, 0 ^*/
    S8 num_of_ue; /*^ M, 0, B, -1, 100 ^*/
    rrm_qci_bitrate_info_t bitrate; /*^ M, 0, N, 0, 0 ^*/ 
}rrm_ecn_configure_cell_list_t;

typedef struct _rrm_oam_event_config_t
{
  rrm_oam_event_class_et       event_class; /*^ M, 0, H, 0, 1 ^*/
  rrm_oam_event_subclass_et    event_sub_class; /*^ M, 0,  H, 0, 10 ^*/ 
  rrm_oam_action_required_et   action_reqd; /*^ M, 0, H, 0, 3 ^*/
}rrm_oam_event_config_t;

#endif /* _RRM_OAM_TYPES_H */ 
