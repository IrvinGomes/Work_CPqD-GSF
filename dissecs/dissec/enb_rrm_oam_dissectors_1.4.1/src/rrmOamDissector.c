#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gmodule.h"
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <string.h>

#if 0
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int                  g_sockfd;
static struct sockaddr_in   g_serv_addr;
#endif

#include "rrmOamDissector.h"
#include "rrmOamCommonDissector.h"
#include "rrm_oam_intf.h"
#include "ueTags.h"
#include "rrm_ext_api_hdr.h"
#include "rrm_defines.h"

void dissect_rrmOamipr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define ARRSIZE(array_name) (sizeof(array_name) / sizeof(array_name[0]))

static dissector_handle_t iprRrmOamDissector_handle;
static int proto_iprRrmOamDissector =-1;

static int global_port0 =3222;     //RRM

#ifndef ENABLE_STATIC
#define ENABLE_STATIC
void proto_register_iprRrmOamDissector (void);

G_MODULE_EXPORT const gchar version[] = "0.0";

G_MODULE_EXPORT void plugin_register(void)
{  
    if (proto_iprRrmOamDissector == -1) 
    {

        proto_register_iprRrmOamDissector();

    }
}

void proto_reg_handoff_iprRrmOamDissector(void);
G_MODULE_EXPORT void plugin_reg_handoff(void)
{
    proto_reg_handoff_iprRrmOamDissector();
}

#endif


gint ett_rrm_oam = -1;
gint ett_rrm_oam_payload = -1;
int rrm_oam_header_count = -1;
gint ett_rrm_oam_header = -1; 

//RRM_OAM_INIT_IND
gint ett_RRM_OAM_INIT_IND = -1;
gint ett_RRM_OAM_INIT_IND_payload = -1;
int rrm_oam_init_ind_t_count = -1;
gint ett_rrm_oam_init_ind_t = -1;

//RRM_OAM_CELL_CONFIG_REQ
gint ett_RRM_OAM_CELL_CONFIG_REQ = -1;
gint ett_RRM_OAM_CELL_CONFIG_REQ_payload = -1;
int rrm_oam_cell_config_req_t_count = -1;
gint ett_rrm_oam_cell_config_req_t = -1;
gint ett_rrm_oam_cell_config_req_t_global_cell_info = -1;
gint ett_rrm_oam_cell_config_req_t_ran_info = -1;
gint ett_rrm_oam_cell_config_req_t_epc_info = -1;
gint ett_rrm_oam_cell_config_req_t_operator_info = -1;
gint ett_rrm_oam_cell_config_req_t_access_mgmt_params = -1;
int rrm_oam_cell_info_t_count = -1;
gint ett_rrm_oam_cell_info_t = -1;
gint ett_rrm_oam_cell_info_t_eutran_global_cell_id = -1;
gint ett_rrm_oam_cell_info_t_cell_access_restriction_params = -1;
int rrm_oam_eutran_global_cell_id_t_count = -1;
gint ett_rrm_oam_eutran_global_cell_id_t = -1;
gint ett_rrm_oam_eutran_global_cell_id_t_primary_plmn_id = -1;
int rrm_oam_cell_plmn_info_t_count = -1;
gint ett_myrrm_oam_cell_plmn_info_t = -1;
int rrm_oam_cell_access_restriction_params_t_count = -1;
gint ett_rrm_oam_cell_access_restriction_params_t = -1;
int rrm_oam_ran_t_count = -1;
gint ett_rrm_oam_ran_t = -1;
gint ett_rrm_oam_ran_t_physical_layer_params = -1;
gint ett_rrm_oam_ran_t_mac_layer_params = -1;
gint ett_rrm_oam_ran_t_rlc_layer_params = -1;
gint ett_rrm_oam_ran_t_mobility_params = -1;
gint ett_rrm_oam_ran_t_rrc_timers_and_constants = -1;
gint ett_rrm_oam_ran_t_rf_params = -1;
gint ett_rrm_oam_ran_t_s1ap_params = -1;
gint ett_rrm_oam_ran_t_ncl_params = -1;
gint ett_rrm_oam_ran_t_connected_mode_mobility_params = -1;
int rrm_oam_physical_layer_params_t_count = -1;
gint ett_rrm_oam_physical_layer_params_t = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_srs = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_prach = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pucch = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pusch = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_prs = -1;
gint ett_rrm_oam_physical_layer_params_t_addl_physical_layer_params = -1;
gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure = -1;
gint ett_rrm_oam_tdd_frame_structure_t = -1;
gint ett_rrm_oam_addl_phy_params_t = -1;
gint ett_rrm_oam_addl_phy_params_t_addl_pucch_parameters = -1;
gint ett_rrm_oam_addl_phy_params_t_additional_pusch_parameters = -1;
gint ett_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params = -1;
gint ett_rrm_oam_addl_pucch_config_t = -1;
gint ett_rrm_oam_addl_pusch_config_t = -1;
gint ett_rrm_oam_addl_ul_reference_signal_params_t = -1;
int rrm_oam_pdsch_t_count = -1;
gint ett_rrm_oam_pdsch_t = -1;
int rrm_oam_srs_t_count = -1;
gint ett_rrm_oam_srs_t = -1;
int rrm_oam_prach_t_count = -1;
gint ett_rrm_oam_prach_t = -1;
int rrm_oam_pucch_t_count = -1;
gint ett_rrm_oam_pucch_t = -1;
int rrm_oam_pusch_t_count = -1;
gint ett_rrm_oam_pusch_t = -1;
int rrm_oam_ul_reference_signal_t_count = -1;
gint ett_rrm_oam_ul_reference_signal_t = -1;
int rrm_oam_uplink_power_control_t_count = -1;
gint ett_rrm_oam_uplink_power_control_t = -1;
int rrm_oam_prs_t_count = -1;
gint ett_rrm_oam_prs_t = -1;
int rrm_oam_mac_layer_params_t_count = -1;
gint ett_rrm_oam_mac_layer_params_t = -1;
gint ett_rrm_oam_mac_layer_params_t_mac_layer_param_rach = -1;
gint ett_rrm_oam_mac_layer_params_t_mac_layer_param_drx = -1;
int rrm_oam_rach_t_count = -1;
gint ett_rrm_oam_rach_t = -1;
gint ett_rrm_oam_rach_t_preamble_info = -1;
int rrm_oam_preamble_info_t_count = -1;
gint ett_rrm_oam_preamble_info_t = -1;
gint ett_rrm_oam_preamble_info_t_ra_preamble_groupA_info = -1;
int rrm_oam_preamble_groupA_info_t_count = -1;
gint ett_rrm_oam_preamble_groupA_info_t = -1;
int rrm_oam_drx_t_count = -1;
gint ett_rrm_oam_drx_t = -1;
gint ett_rrm_oam_drx_t_drx_config = -1;
int rrm_oam_drx_config_t_count = -1;
gint ett_rrm_oam_drx_config_t = -1;
gint ett_rrm_oam_drx_config_t_short_drx_cycle = -1;
int rrm_oam_short_drx_cycle_config_t_count = -1;
gint ett_rrm_oam_short_drx_cycle_config_t = -1;
int rrm_oam_rlc_layer_params_t_count = -1;
gint ett_rrm_oam_rlc_layer_params_t = -1;
gint ett_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb = -1;
int rrm_oam_srb_t_count = -1;
gint ett_rrm_oam_srb_t = -1;
gint ett_rrm_oam_srb_t_srb_params = -1;
int rrm_oam_srb_info_t_count = -1;
gint ett_rrm_oam_srb_info_t = -1;
int rrm_oam_mobility_params_t_count = -1;
gint ett_rrm_oam_mobility_params_t = -1;
gint ett_rrm_oam_mobility_params_t_idle_mode_mobility_params = -1;
int rrm_oam_idle_mode_mobility_params_t_count = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9 = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9 = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920 = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000 = -1;
gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t = -1;
int rrm_oam_common_params_t_count = -1;
gint ett_rrm_oam_common_params_t = -1;
gint ett_rrm_oam_common_params_t_speed_state_params = -1;
int rrm_oam_speed_state_params_t_count = -1;
gint ett_rrm_oam_speed_state_params_t = -1;
int rrm_oam_intra_freq_params_t_count = -1;
gint ett_rrm_oam_intra_freq_params_t = -1;
gint ett_rrm_oam_intra_freq_params_t_speed_scale_factors = -1;
int rrm_oam_speed_scale_factors_t_count = -1;
gint ett_rrm_oam_speed_scale_factors_t = -1;
int rrm_oam_inter_frequency_params_list_t_count = -1;
gint ett_rrm_oam_inter_frequency_params_list_t = -1;
gint ett_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params = -1;
int rrm_oam_inter_freq_params_t_count = -1;
gint ett_rrm_oam_inter_freq_params_t = -1;
gint ett_rrm_oam_inter_freq_params_t_speed_scale_factors = -1;
gint ett_rrm_oam_inter_freq_params_t_threshx_q_r9 = -1;
int rrm_oam_thresholdx_q_r9_t_count = -1;
gint ett_rrm_oam_thresholdx_q_r9_t = -1;
int rrm_oam_rrc_timers_and_constants_t_count = -1;
gint ett_rrm_oam_rrc_timers_and_constants_t = -1;
gint ett_rrm_oam_rrc_timers_and_constants_t_rrc_timers = -1;
gint ett_rrm_oam_rrc_timers_and_constants_t_rrc_constants = -1;
int rrm_oam_rrc_timers_t_count = -1;
gint ett_rrm_oam_rrc_timers_t = -1;
int rrm_oam_rrc_constants_t_count = -1;
gint ett_rrm_oam_rrc_constants_t = -1;
int rrm_oam_rf_params_t_count = -1;
gint ett_rrm_oam_rf_params_t = -1;
gint ett_rrm_oam_rf_params_t_rf_configurations = -1;
int rrm_oam_rf_configurations_t_count = -1;
gint ett_rrm_oam_rf_configurations_t = -1;
int rrm_oam_s1ap_params_t_count = -1;
gint ett_rrm_oam_s1ap_params_t = -1;
int rrm_oam_ncl_params_t_count = -1;
gint ett_rrm_oam_ncl_params_t = -1;
gint ett_rrm_oam_ncl_params_t_lte_ncl = -1;
gint ett_rrm_oam_ncl_params_t_inter_rat_ncl = -1;
gint ett_rrm_oam_inter_rat_ncl_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_payload = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_utran_freq_cells = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_geran_freq_cells = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t = -1;
gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_payload = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params = -1;
gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t = -1;
gint ett_rrm_utran_cell_id_t  = -1;
int rrm_oam_lte_ncl_t_count = -1;
gint ett_rrm_oam_lte_ncl_t = -1;
gint ett_rrm_oam_lte_ncl_t_intra_freq_cells = -1;
gint ett_rrm_oam_lte_ncl_t_inter_freq_cells = -1;
int rrm_oam_intra_freq_cells_t_count = -1;
gint ett_rrm_oam_intra_freq_cells_t = -1;
gint ett_rrm_oam_intra_freq_cells_t_cell_id = -1;
int rrm_oam_inter_freq_cells_t_count = -1;
gint ett_rrm_oam_inter_freq_cells_t = -1;
gint ett_rrm_oam_inter_freq_cells_t_cell_id = -1;
int rrm_oam_epc_t_count = -1;
gint ett_rrm_oam_epc_t = -1;
gint ett_rrm_oam_epc_t_epc_params = -1;
int rrm_oam_epc_params_t_count = -1;
gint ett_rrm_oam_epc_params_t = -1;
gint ett_rrm_oam_epc_params_t_general_epc_params = -1;
gint ett_rrm_oam_epc_params_t_qos_config_params = -1;
int rrm_oam_general_epc_params_t_count = -1;
gint ett_rrm_oam_general_epc_params_t = -1;
gint ett_rrm_oam_general_epc_params_t_plmn_list = -1;
int rrm_oam_plmn_access_info_t_count = -1;
gint ett_rrm_oam_plmn_access_info_t = -1;
gint ett_rrm_oam_plmn_access_info_t_plmn_info = -1;
int rrm_oam_qos_config_params_t_count = -1;
gint ett_rrm_oam_qos_config_params_t = -1;
gint ett_rrm_oam_qos_config_params_t_rohc_params = -1;
gint ett_rrm_oam_qos_config_params_t_sn_field_len = -1;
gint ett_rrm_oam_qos_config_params_t_sps_data = -1;
gint ett_rrm_oam_qos_config_params_t_addl_rlc_param = -1;
gint ett_rrm_oam_qos_config_params_t_addl_mac_param = -1;
gint ett_rrm_oam_pdcp_rohc_params_t = -1;
gint ett_rrm_oam_pdcp_rohc_params_t_rohc_pofiles = -1;
gint ett_rrm_oam_rohc_pofiles_t = -1;
gint ett_rrm_oam_sn_field_len_t = -1;
gint ett_rrm_oam_sps_config_data_t = -1;
gint ett_rrm_oam_sps_config_data_t_sps_config_dl = -1;
gint ett_rrm_oam_sps_config_data_t_sps_config_ul = -1;
gint ett_rrm_oam_sps_config_dl_t = -1;
gint ett_rrm_oam_sps_config_ul_t = -1;
gint ett_rrm_oam_addl_rlc_params_t = -1;
gint ett_rrm_oam_addl_mac_params_t = -1;
gint ett_rrm_oam_addl_mac_params_t_phr_config = -1;
gint ett_rrm_oam_addl_mac_params_t_bsr_config = -1;
gint ett_rrm_oam_phr_config_t = -1;
gint ett_rrm_oam_bsr_config_t = -1;
int rrm_oam_operator_info_t_count = -1;
gint ett_rrm_oam_operator_info_t = -1;
gint ett_rrm_oam_operator_info_t_rrm_mac_config = -1;
gint ett_rrm_oam_operator_info_t_phich_config = -1;
gint ett_rrm_oam_operator_info_t_sib_1_info = -1;
gint ett_rrm_oam_operator_info_t_sib_2_info = -1;
gint ett_rrm_oam_operator_info_t_sib_3_info = -1;
gint ett_rrm_oam_operator_info_t_sib_4_info = -1;
gint ett_rrm_oam_operator_info_t_admission_control_info = -1;
gint ett_rrm_oam_operator_info_t_additional_packet_scheduling_params = -1;
gint ett_rrm_oam_operator_info_t_additional_cell_params = -1;
gint ett_rrm_oam_operator_info_t_load_params = -1;
gint ett_rrm_oam_operator_info_t_mimo_mode_params = -1;
gint ett_rrm_oam_operator_info_t_ho_configuration = -1;
gint ett_rrm_oam_operator_info_t_measurement_configuration = -1;
gint ett_rrm_oam_operator_info_t_rrm_eutran_access_point_pos = -1;
gint ett_rrm_oam_adl_pkt_scheduling_params_t = -1;
gint ett_rrm_oam_adl_cell_params_t = -1;
gint ett_rrm_oam_load_params_t = -1;
gint ett_rrm_oam_mimo_mode_params_t = -1;
gint ett_rrm_oam_ho_config_params_t = -1;
gint ett_rrm_oam_ho_config_params_t_target_cell_selection_params = -1;
gint ett_rrm_oam_ho_config_params_t_ho_algo_params = -1;
gint ett_rrm_oam_ho_config_params_t_ho_retry_params = -1;
gint ett_rrm_oam_target_cell_selection_params_t = -1;
gint ett_rrm_oam_ho_algo_params_t = -1;
gint ett_rrm_oam_ho_retry_params_t = -1;
gint ett_rrm_oam_meas_config_t = -1;
gint ett_rrm_oam_meas_config_t_meas_gap_config = -1;
gint ett_rrm_oam_meas_config_t_csfb_tgt_selection = -1;
gint ett_rrm_oam_meas_gap_config_t = -1;
gint ett_rrm_csfb_tgt_selection_t = -1;
gint ett_rrm_oam_eutran_access_point_pos_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t = -1;
gint ett_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_ul_power_mask = -1;
gint ett_rrm_oam_dynamic_icic_info_t_rntp_report_config_info = -1;
gint ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map = -1;
gint ett_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset = -1;
gint ett_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power = -1;
gint ett_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti = -1;
gint ett_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti = -1;
gint ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps = -1;
gint ett_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params = -1;
gint ett_rrm_oam_dynamic_icic_info_t_atb_config = -1;
int rrm_oam_resource_partition_info_t_count = -1;
gint ett_rrm_oam_resource_partition_info_t = -1;
gint ett_rrm_oam_resource_partition_info_t_cell_center_region = -1;
gint ett_rrm_oam_resource_partition_info_t_cell_edge_region = -1;
int rrm_oam_ul_power_mask_t_count = -1;
gint ett_rrm_oam_ul_power_mask_t = -1;
int rrm_oam_rntp_report_config_info_t_count = -1;
gint ett_rrm_oam_rntp_report_config_info_t = -1;

int rrm_oam_pdcch_aggregation_power_offset_t_count = -1;
gint ett_rrm_oam_pdcch_aggregation_power_offset_t = -1;

int rrm_oam_path_loss_to_target_sinr_map_t_count = -1;
gint ett_rrm_oam_path_loss_to_target_sinr_map_t = -1;

int rrm_oam_cqi_to_phich_power_t_count = -1;
gint ett_rrm_oam_cqi_to_phich_power_t = -1;

int rrm_oam_aggregation_power_offset_t_count = -1;
gint ett_rrm_oam_aggregation_power_offset_t = -1;
int rrm_oam_aggregation_power_offset_info_t_count = -1;
gint ett_rrm_oam_aggregation_power_offset_info_t = -1;

int rrm_oam_alpha_based_pathloss_target_sinr_map_t_count = -1;
gint ett_rrm_oam_alpha_based_pathloss_target_sinr_map_t = -1;
int rrm_oam_path_loss_to_target_sinr_map_info_t_count = -1;
gint ett_rrm_oam_path_loss_to_target_sinr_map_info_t = -1;

int rrm_oam_resource_partition_t_count = -1;
gint ett_rrm_oam_resource_partition_t = -1;

int rrm_oam_rrmc_mac_config_t_count = -1;
gint ett_rrm_oam_rrmc_mac_config_t = -1;
gint ett_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch = -1;
int rrm_oam_mac_enable_frequency_selective_scheduling_t_count = -1;
gint ett_rrm_oam_mac_enable_frequency_selective_scheduling_t = -1;
int rrm_oam_phy_phich_configuration_t_count = -1;
gint ett_rrm_oam_phy_phich_configuration_t = -1;
int rrm_oam_sib_type_1_info_t_count = -1;
gint ett_rrm_oam_sib_type_1_info_t = -1;
gint ett_rrm_oam_sib_type_1_info_t_cell_selection_info = -1;
gint ett_rrm_oam_sib_type_1_info_t_scheduling_info = -1;
gint ett_rrm_oam_scheduling_info_t = -1;
gint ett_rrm_oam_sib_mapping_info_t  = -1;
int rrm_oam_cell_selection_info_v920_t_count = -1;
gint ett_rrm_oam_cell_selection_info_v920_t = -1;

int rrm_oam_sib_type_2_info_t_count = -1;
gint ett_rrm_oam_sib_type_2_info_t = -1;
gint ett_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib = -1;
gint ett_rrm_oam_sib_type_2_info_t_rrm_freq_info = -1;

int rrm_oam_radio_resource_config_common_sib_t_count = -1;
gint ett_rrm_oam_radio_resource_config_common_sib_t = -1;

gint ett_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config = -1;
gint ett_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config = -1;

int rrm_oam_bcch_config_t_count = -1;
gint ett_rrm_oam_bcch_config_t = -1;
int rrm_oam_pcch_config_t_count = -1;
gint ett_rrm_oam_pcch_config_t = -1;
int rrm_oam_freq_info_t_count = -1;
gint ett_rrm_oam_freq_info_t = -1;
int rrm_oam_sib_type_3_info_t_count = -1;
gint ett_rrm_oam_sib_type_3_info_t = -1;
gint ett_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info = -1;
gint ett_rrm_oam_sib_type_3_info_t_s_intra_search = -1;
gint ett_rrm_oam_sib_type_3_info_t_s_non_intra_search = -1;
int rm_oam_intra_freq_cell_reselection_info_t_count = -1;
gint ett_rrm_oam_intra_freq_cell_reselection_info_t = -1;
int rrm_oam_s_intra_search_v920_t_count = -1;
gint ett_rrm_oam_s_intra_search_v920_t = -1;
int rrm_oam_s_non_intra_search_v920_t_count = -1;
gint ett_rrm_oam_s_non_intra_search_v920_t = -1;
int rrm_oam_sib_type_4_info_t_count = -1;
gint ett_rrm_oam_sib_type_4_info_t = -1;
gint ett_rrm_oam_sib_type_4_info_t_csg_id_range = -1;
int rrm_oam_csg_cell_id_range_t_count = -1;
gint ett_rrm_oam_csg_cell_id_range_t = -1;
int rrm_oam_admission_control_info_t_count = -1;
gint ett_rrm_oam_admission_control_info_t = -1;
gint ett_rrm_oam_admission_control_info_t_available_gbr_limit = -1;
gint ett_rrm_oam_admission_control_info_t_spid_table = -1;
gint ett_available_gbr_limit_t = -1;
gint ett_rrm_oam_spid_table_t = -1;
gint ett_rrm_oam_spid_table_t_spid_config = -1;
gint ett_rrm_oam_spid_configuration_t = -1;
gint ett_rrm_power_control_params = -1;
gint ett_rrm_power_control_params_payload = -1;
gint ett_rrm_power_control_params_rrm_power_control_params = -1;
gint ett_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable = -1;
gint ett_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range = -1;
gint ett_rrm_power_control_params_rrm_oam_power_control_enable_t = -1;
gint ett_rrm_power_control_params_rrm_oam_tpc_rnti_range_t = -1;
gint ett_rrm_oam_sps_crnti_range_t = -1;
int rrm_oam_access_mgmt_params_t_count = -1;
gint ett_rrm_oam_access_mgmt_params_t = -1;


//RRM OAM SHUTDOWN REQ
gint ett_RRM_OAM_SHUTDOWN_REQ = -1;
gint ett_RRM_OAM_SHUTDOWN_REQ_payload = -1;
int rrm_oam_shutdown_req_t_count = -1;
gint ett_rrm_oam_shutdown_req_t = -1;


//RRM OAM SHUTDOWN RESP
gint ett_RRM_OAM_SHUTDOWN_RESP = -1;
gint ett_RRM_OAM_SHUTDOWN_RESP_payload = -1;
int rrm_oam_shutdown_resp_t_count = -1;
gint ett_rrm_oam_shutdown_resp_t = -1;

//RRM OAM SET LOG LEVEL REQ
gint ett_RRM_OAM_SET_LOG_LEVEL_REQ = -1;
gint ett_RRM_OAM_SET_LOG_LEVEL_REQ_payload = -1;
int rrm_oam_set_log_level_req_t_count = -1;
gint ett_rrm_oam_set_log_level_req_t = -1;

//RRM SET LOG LEVEL RESP
gint ett_RRM_OAM_SET_LOG_LEVEL_RESP = -1;
gint ett_RRM_OAM_SET_LOG_LEVEL_RESP_payload = -1;
int rrm_oam_set_log_level_resp_t_count = -1;
gint ett_rrm_oam_set_log_level_resp_t = -1;

//RRM OAM RESUME SERVICE REQ
gint ett_RRM_OAM_RESUME_SERVICE_REQ = -1;
gint ett_RRM_OAM_RESUME_SERVICE_REQ_payload = -1;
int rrm_oam_resume_service_req_t_count = -1;
gint ett_rrm_oam_resume_service_req_t = -1;

// RRM OAM RESUME SERVICE RESP
gint ett_RRM_OAM_RESUME_SERVICE_RESP = -1;
gint ett_RRM_OAM_RESUME_SERVICE_RESP_payload = -1;
int rrm_oam_resume_service_resp_t_count = -1;
gint ett_rrm_oam_resume_service_resp_t = -1;

// ready for shutdown ind
gint ett_RRM_OAM_READY_FOR_SHUTDOWN_IND = -1;
gint ett_RRM_OAM_READY_FOR_SHUTDOWN_IND_payload = -1;
int rrm_oam_ready_for_shutdown_ind_t_count = -1;
gint ett_rrm_oam_ready_for_shutdown_ind_t = -1;

//RRM OAM RAC ENABLE DISABLE REQ
gint ett_RRM_OAM_RAC_ENABLE_DISABLE_REQ = -1;
gint ett_RRM_OAM_RAC_ENABLE_DISABLE_REQ_payload = -1;
int rrm_oam_rac_enable_disable_req_t_count = -1;
gint ett_rrm_oam_rac_enable_disable_req_t = -1;
gint ett_rrm_oam_rac_enable_disable_req_t_global_cell_id = -1;

//RRM OAM RAC ENABLE DISABLE RESP
gint ett_RRM_OAM_RAC_ENABLE_DISABLE_RESP = -1;
gint ett_RRM_OAM_RAC_ENABLE_DISABLE_RESP_payload = -1;
int rrm_oam_rac_enable_disable_resp_t_count = -1;
gint ett_rrm_oam_rac_enable_disable_resp_t = -1;
gint ett_rrm_oam_rac_enable_disable_resp_t_global_cell_id = -1;

//RRM OAM LOG ENABLE DISABLE REQ
gint ett_RRM_OAM_LOG_ENABLE_DISABLE_REQ = -1;
gint ett_RRM_OAM_LOG_ENABLE_DISABLE_REQ_payload = -1;
int rrm_oam_log_enable_disable_req_t_count = -1;
gint ett_rrm_oam_log_enable_disable_req_t = -1;
gint ett_rrm_oam_log_enable_disable_req_t_log_config = -1;
int rrm_oam_log_config_t_count = -1;
gint ett_rrm_oam_log_config_t = -1;

//RRM OAM LOG ENABLE DISABLE RESP
gint ett_RRM_OAM_LOG_ENABLE_DISABLE_RESP = -1;
gint ett_RRM_OAM_LOG_ENABLE_DISABLE_RESP_payload = -1;
int rrm_oam_log_enable_disable_resp_t_count = -1;
gint ett_rrm_oam_log_enable_disable_resp_t = -1;

//RRM OAM INIT CONFIG REQ
gint ett_RRM_OAM_INIT_CONFIG_REQ = -1;
gint ett_RRM_OAM_INIT_CONFIG_REQ_payload = -1;
int rrm_oam_init_config_req_t_count = -1;
gint ett_rrm_oam_init_config_req_t = -1;
gint ett_rrm_oam_init_config_req_t_init_module_config = -1;
int rrm_oam_module_init_config_t_count = -1;
gint ett_rrm_oam_module_init_config_t = -1;
gint ett_rrm_oam_module_init_config_t_log_config = -1;

///RRM OAM INIT CONFIG RESP
gint ett_RRM_OAM_INIT_CONFIG_RESP = -1;
gint ett_RRM_OAM_INIT_CONFIG_RESP_payload = -1;
int rrm_oam_init_config_resp_t_count = -1;
gint ett_rrm_oam_init_config_resp_t = -1;

// RRM OAM CELL START REQ
gint ett_RRM_OAM_CELL_START_REQ = -1;
gint ett_RRM_OAM_CELL_START_REQ_payload = -1;
int rrm_oam_cell_start_req_t_count = -1;
gint ett_rrm_oam_cell_start_req_t = -1;
gint ett_rrm_oam_cell_start_req_t_global_cell_id = -1;

//RRM OAM CELL START RESP
gint ett_RRM_OAM_CELL_START_RESP = -1;
gint ett_RRM_OAM_CELL_START_RESP_payload = -1;
int rrm_oam_cell_start_resp_t_count = -1;
gint ett_rrm_oam_cell_start_resp_t = -1;
gint ett_rrm_oam_cell_start_resp_t_global_cell_id = -1;

//RRM OAM CELL STOP REQ
gint ett_RRM_OAM_CELL_STOP_REQ = -1;
gint ett_RRM_OAM_CELL_STOP_REQ_payload = -1;
int rrm_oam_cell_stop_req_t_count = -1;
gint ett_rrm_oam_cell_stop_req_t = -1;
gint ett_rrm_oam_cell_stop_req_t_global_cell_id = -1;

///RRM OAM CELL STOP RESP
gint ett_RRM_OAM_CELL_STOP_RESP = -1;
gint ett_RRM_OAM_CELL_STOP_RESP_payload = -1;
int rrm_oam_cell_stop_resp_t_count = -1;
gint ett_rrm_oam_cell_stop_resp_t = -1;
gint ett_rrm_oam_cell_stop_resp_t_global_cell_id = -1;

//RRM OAM CELL DELETE REQ
gint ett_RRM_OAM_CELL_DELETE_REQ = -1;
gint ett_RRM_OAM_CELL_DELETE_REQ_payload = -1;
int rrm_oam_cell_delete_req_t_count = -1;
gint ett_rrm_oam_cell_delete_req_t = -1;
gint ett_rrm_oam_cell_delete_req_t_global_cell_id = -1;

//RRM OAM CELL DELETE RESP
gint ett_RRM_OAM_CELL_DELETE_RESP = -1;
gint ett_RRM_OAM_CELL_DELETE_RESP_payload = -1;
int rrm_oam_cell_delete_resp_t_count = -1;
gint ett_rrm_oam_cell_delete_resp_t = -1;
gint ett_rrm_oam_cell_delete_resp_t_global_cell_id = -1;

//CELL CONFIG RESP
int ett_RRM_OAM_CELL_CONFIG_RESP = -1;
gint ett_RRM_OAM_CELL_CONFIG_RESP_payload = -1;
int rrm_oam_cell_config_resp_t_count = -1;
gint ett_rrm_oam_cell_config_resp_t = -1;
gint ett_rrm_oam_cell_config_resp_t_global_cell_id = -1;

//CELL RECONFIG REQ
gint ett_RRM_OAM_CELL_RECONFIG_REQ = -1;
gint ett_RRM_OAM_CELL_RECONFIG_REQ_payload = -1;
int rrm_oam_cell_reconfig_req_t_count = -1;
gint ett_rrm_oam_cell_reconfig_req_t = -1;
gint ett_rrm_oam_cell_reconfig_req_t_global_cell_id = -1;
gint ett_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params = -1;
gint ett_rrm_oam_cell_reconfig_req_t_ran_info = -1;
gint ett_rrm_oam_cell_reconfig_req_t_epc_info = -1;
gint ett_rrm_oam_cell_reconfig_req_t_operator_info = -1;
gint ett_rrm_oam_cell_reconfig_req_t_access_mgmt_params = -1;

//CELL RECONFIG RESP
gint ett_RRM_OAM_CELL_RECONFIG_RESP = -1;
gint ett_RRM_OAM_CELL_RECONFIG_RESP_payload = -1;
int rrm_oam_cell_reconfig_resp_t_count = -1;
gint ett_rrm_oam_cell_reconfig_resp_t = -1;
gint ett_rrm_oam_cell_reconfig_resp_t_global_cell_id = -1;

/******ADDED PT**********/
//CELL CONTEXT PRINT REQ
gint ett_rrm_oam_cell_context_print_req = -1;
gint ett_rrm_oam_cell_context_print_req_payload = -1;
int rrm_oam_cell_context_print_req_count = -1;
gint ett_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req = -1;

// CARRRIER FREQ DL TX PARAMS REQ
gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t = -1;
gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t_payload = -1;
int rrm_oam_carrier_freq_dl_tx_params_req_t_count = -1;
gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t = -1;

// CARRRIER FREQ DL TX PARAMS RESP
gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t = -1;
gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_payload = -1;
int rrm_oam_carrier_freq_dl_tx_params_resp_t_count = -1;
gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t = -1;

// RRM OAM UE RELEASE REQ
gint ett_rrm_oam_ue_release_req_t = -1;
gint ett_rrm_oam_ue_release_req_t_payload = -1;
int rrm_oam_ue_release_req_t_count = -1;
gint ett_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t = -1;

//RRM_OAM_BLOCK_CELL_REQ
gint ett_RRM_OAM_BLOCK_CELL_REQ = -1;
gint ett_RRM_OAM_BLOCK_CELL_REQ_payload = -1;
int rrm_oam_block_cell_req_t_count = -1;
gint ett_rrm_oam_block_cell_req_t = -1;
gint ett_rrm_oam_block_cell_req_t_global_cell_id = -1;

//RRM_OAM_BLOCK_CELL_RESP
gint ett_RRM_OAM_BLOCK_CELL_RESP = -1;
gint ett_RRM_OAM_BLOCK_CELL_RESP_payload = -1;
int rrm_oam_block_cell_resp_t_count = -1;
gint ett_rrm_oam_block_cell_resp_t = -1;
gint ett_rrm_oam_block_cell_resp_t_global_cell_id = -1;
gint ett_rrm_oam_cell_plmn_info_t = -1;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ
gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ = -1;
gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ_payload = -1;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP
gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP = -1;
gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP_payload = -1;

//RRM_OAM_READY_FOR_CELL_BLOCK_IND
gint ett_RRM_OAM_READY_FOR_CELL_BLOCK_IND = -1;
gint ett_RRM_OAM_READY_FOR_CELL_BLOCK_IND_payload = -1;
int rrm_oam_ready_for_cell_block_ind_t_count = -1;
gint ett_rrm_oam_ready_for_cell_block_ind_t = -1;
gint ett_rrm_oam_ready_for_cell_block_ind_t_global_cell_id = -1;

//RRM_OAM_UNBLOCK_CELL_CMD
gint ett_RRM_OAM_UNBLOCK_CELL_CMD = -1;
gint ett_RRM_OAM_UNBLOCK_CELL_CMD_payload = -1;
int rrm_oam_unblock_cell_cmd_t_count = -1;
gint ett_rrm_oam_unblock_cell_cmd_t = -1;
gint ett_rrm_oam_unblock_cell_cmd_t_global_cell_id = -1;

//RRM_OAM_GET_VER_ID_RESP

gint ett_RRM_OAM_GET_VER_ID_RESP = -1;
gint ett_ett_RRM_OAM_GET_VER_ID_RESP_payload = -1;
int rrm_oam_get_ver_id_resp_t_count = -1;
gint ett_rrm_oam_get_ver_id_resp_t = -1;


// PROC SUPERVISION RESP
gint ett_rrm_oam_proc_supervision_resp_t = -1;
gint ett_rrm_oam_proc_supervision_resp_t_payload = -1;
int rrm_oam_proc_supervision_resp_t_count = -1;
gint ett_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t = -1;

//RRM_OAM_CELL_UPDATE_REQ
gint ett_RRM_OAM_CELL_UPDATE_REQ = -1;
gint ett_RRM_OAM_CELL_UPDATE_REQ_payload = -1;
int rrm_oam_cell_update_req_t_count = -1 ;
gint ett_rrm_oam_cell_update_req_t = -1;
gint ett_rrm_oam_cell_update_req_t_global_cell_id = -1;

//RRM_OAM_UPDATED_PLMN_INFO
gint ett_RRM_OAM_UPDATED_PLMN_INFO = -1;
gint ett_RRM_OAM_UPDATED_PLMN_INFO_payload = -1;
int rrm_oam_updated_plmn_info_t_count = -1;
gint ett_rrm_oam_updated_plmn_info_t = -1;


//RRM_OAM_CELL_UPDATE_RESP
gint ett_RRM_OAM_CELL_UPDATE_RESP = -1;
gint ett_RRM_OAM_CELL_UPDATE_RESP_payload = -1;
int rrm_oam_cell_update_resp_t_count = -1;
gint ett_rrm_oam_cell_update_resp_t = -1;
gint ett_rrm_oam_cell_update_resp_t_global_cell_id = -1;

//RRM_OAM_EVENT_NOTIFICATION
gint ett_RRM_OAM_EVENT_NOTIFICATION = -1;
gint ett_RRM_OAM_EVENT_NOTIFICATION_payload = -1;
int rrm_oam_event_notification_t_count = -1;
gint ett_rrm_oam_event_notification_t = -1;
gint ett_rrm_oam_event_notification_t_msg_header = -1;

//RRM_OAM_LOAD_CONFIG_RESP
gint ett_RRM_OAM_LOAD_CONFIG_RESP = -1;
gint ett_RRM_OAM_LOAD_CONFIG_RESP_payload = -1;
int rrm_oam_load_config_resp_t_count = -1;
gint ett_rrm_oam_load_config_resp_t = -1;

//RRM_OAM_EVENT_HEADER
gint ett_RRM_OAM_EVENT_HEADER = -1;
gint ett_RRM_OAM_EVENT_HEADER_payload = -1;
int rrm_oam_event_header_t_count = -1;
gint ett_rrm_oam_event_header_t = -1;
gint ett_rrm_oam_event_header_t_time_stamp = -1;

//RRM_OAM_TIME_STAMP
gint ett_RRM_OAM_TIME_STAMP = -1;
gint ett_RRM_OAM_TIME_STAMP_payload = -1;
int rrm_oam_time_stamp_t_count = -1;
gint ett_rrm_oam_time_stamp_t = -1;

//RRM_OAM_LOAD_CONFIG_REQ
gint ett_RRM_OAM_LOAD_CONFIG_REQ = -1;
gint ett_RRM_OAM_LOAD_CONFIG_REQ_payload = -1;
int rrm_oam_load_config_req_t_count = -1 ;
gint ett_rrm_oam_load_config_req_t = -1;
gint ett_rrm_oam_load_config_req_t_serv_enb_cell_info = -1;
int rrm_oam_serving_enb_cell_info_count = -1;

//RRM_OAM_LOAD_REPORT_IND
gint ett_RRM_OAM_LOAD_REPORT_IND = -1;
gint ett_RRM_OAM_LOAD_REPORT_IND_payload = -1;
int rrm_oam_load_report_ind_t_count = -1;
gint ett_rrm_oam_load_report_ind_t = -1;
gint ett_rrm_oam_load_cell_info_t = -1;
gint ett_rrm_oam_hw_load_ind_t = -1;
gint ett_rrm_oam_s1_tnl_load_t = -1;
gint ett_rrm_oam_rrs_load_ind_t = -1;
gint ett_rrm_oam_comp_avl_grp_t = -1;
gint ett_rrm_oam_comp_avl_dl_t = -1;
gint ett_rrm_oam_comp_avl_ul_t = -1;

//RRM_OAM_SERVING_ENB_CELL_INFO
gint ett_RRM_OAM_SERVING_ENB_CELL_INFO = -1;
gint ett_RRM_OAM_SERVING_ENB_CELL_INFO_payload = -1;
int rrm_oam_serving_enb_cell_info_t_count = -1 ;
gint ett_rrm_oam_serving_enb_cell_info_t = -1;
gint ett_rrm_oam_serving_enb_cell_info_t_global_cell_id = -1;
gint ett_rrm_oam_serving_enb_cell_info_t_over_load_lvl_act = -1;
gint ett_rrm_oam_serving_enb_cell_info_t_high_load_lvl_act = -1;
gint ett_rrm_oam_serving_enb_cell_info_t_mid_load_lvl_act = -1;
gint ett_rrm_oam_serving_enb_cell_info_t_resrc_spec = -1;

//RRM_OAM_LOAD_DEF
gint ett_RRM_OAM_LOAD_DEF = -1;
gint ett_RRM_OAM_LOAD_DEF_payload = -1;
int rrm_oam_load_def_t_count = -1 ;
gint ett_rrm_oam_over_load_def_t = -1;
gint ett_rrm_oam_high_load_def_t = -1;
gint ett_rrm_oam_mid_load_def_t = -1;
gint ett_rrm_oam_load_def_t_q_watermark = -1;
gint ett_rrm_oam_load_def_t_ld_ac_bar = -1;

//RRM_OAM_WATERMARK
gint ett_RRM_OAM_WATERMARK = -1;
gint ett_RRM_OAM_WATERMARK_payload = -1;
int rrm_oam_watermark_t_count = -1;
gint ett_rrm_oam_watermark_t = -1;

//RRM_OAM_RESOURCE_LOAD_INFO
gint ett_RRM_OAM_RESOURCE_LOAD_INFO = -1;
gint ett_RRM_OAM_RESOURCE_LOAD_INFO_payload = -1;
int rrm_oam_resource_load_info_t_count = -1;
gint ett_rrm_oam_resource_load_info_t = -1;
gint ett_rrm_oam_resource_load_info_t_resrc_info = -1;

//RRM_OAM_RESRC_INFO
gint ett_RRM_OAM_RESRC_INFO = -1;
gint ett_RRM_OAM_RESRC_INFO_payload = -1;
int rrm_oam_resrc_info_t_count = -1;
guint ett_rrm_oam_resrc_info_t = -1;
guint ett_rrm_oam_resrc_info_t_overload = -1;
guint ett_rrm_oam_resrc_info_t_highload = -1;
guint ett_rrm_oam_resrc_info_t_midload = -1;


//RRM_OAM_ACCESS_BARRING_INFO
gint ett_RRM_OAM_ACCESS_BARRING_INFO = -1;
gint ett_RRM_OAM_ACCESS_BARRING_INFO_payload = -1;
int rrm_oam_access_barring_info_t_count = -1;
guint ett_rrm_oam_access_barring_info_t = -1;
guint ett_rrm_oam_access_barring_info_t_class_barring_info = -1;
guint ett_rrm_oam_access_barring_info_t_ssac_barring_r9 = -1;

//RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION
gint ett_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION = -1;
gint ett_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION_payload = -1;
int rrm_oam_access_class_barring_information_t_count = -1;
gint ett_rrm_oam_access_class_barring_information_t = -1;

//RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9
gint ett_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9 = -1;
gint ett_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9_payload = -1;
int rrm_oam_access_ssac_barring_for_mmtel_r9_t_count = -1;
guint ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t = -1;
guint ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t_class_barring_info = -1;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ
gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ = -1;
gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ_payload = -1;
int rrm_oam_cell_ecn_capacity_enhance_req_t_count = -1;
guint ett_rrm_oam_cell_ecn_capacity_enhance_req_t = -1;
guint ett_rrm_oam_cell_ecn_capacity_enhance_req_t_ecn_cells = -1;

//RRM_ECN_CONFIGURE_CELL_LIST
gint ett_RRM_ECN_CONFIGURE_CELL_LIST = -1;
gint ett_RRM_ECN_CONFIGURE_CELL_LIST_payload = -1;
int rrm_ecn_configure_cell_list_t_count = -1;
guint ett_rrm_ecn_configure_cell_list_t = -1;
guint ett_rrm_ecn_configure_cell_list_t_global_cell_id = -1;
guint ett_rrm_ecn_configure_cell_list_t_bitrate = -1;

//RRM_QCI_BITRATE_INFO
gint ett_RRM_QCI_BITRATE_INFO = -1;
gint ett_RRM_QCI_BITRATE_INFO_payload = -1;
int rrm_qci_bitrate_info_t_count = -1;
guint ett_rrm_qci_bitrate_info_t = -1;
guint ett_rrm_qci_bitrate_info_t_bitrate_for_qci = -1;

//RRM_CONFIGURE_QCI_BITRATE
gint ett_RRM_CONFIGURE_QCI_BITRATE = -1;
gint ett_RRM_CONFIGURE_QCI_BITRATE_payload = -1;
int rrm_configure_qci_bitrate_t_count = -1;
guint ett_rrm_configure_qci_bitrate_t = -1;
guint ett_rrm_configure_qci_bitrate_t_ul_bitrate = -1;
guint ett_rrm_configure_qci_bitrate_t_dl_bitrate = -1;


//RRM_BITRATE_UL_DL
gint ett_RRM_BITRATE_UL_DL = -1;
gint ett_RRM_BITRATE_UL_DL_payload = -1;
int rrm_bitrate_ul_dl_t_count = -1;
guint ett_rrm_bitrate_ul_dl_t = -1;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP
gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP = -1;
gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP_payload = -1;
int rrm_oam_cell_ecn_capacity_enhance_resp_t_count = -1;
gint ett_rrm_oam_cell_ecn_capacity_enhance_resp_t = -1;

//RRM_OAM_CONFIG_KPI_REQ
gint ett_RRM_OAM_CONFIG_KPI_REQ = -1;
gint ett_RRM_OAM_CONFIG_KPI_REQ_payload = -1;
int rrm_oam_config_kpi_req_t_count = -1;
guint ett_rrm_oam_config_kpi_req_t = -1;
guint ett_rrm_oam_config_kpi_req_t_kpi_to_report = -1;

//RRM_OAM_KPI
gint ett_RRM_OAM_KPI = -1;
gint ett_RRM_OAM_KPI_payload = -1;
int rrm_oam_kpi_t_count = -1;
guint ett_rrm_oam_kpi_t = -1;

//RRM_OAM_CONFIG_KPI_RESP
gint ett_RRM_OAM_CONFIG_KPI_RESP = -1;
gint ett_RRM_OAM_CONFIG_KPI_RESP_payload = -1;
int rrm_oam_config_kpi_resp_t_count = -1;
gint ett_rrm_oam_config_kpi_resp_t = -1;
gint ett_rrm_oam_config_kpi_resp_t_global_cell_id = -1;

//RRM_OAM_GET_KPI_REQ
gint ett_RRM_OAM_GET_KPI_REQ = -1;
gint ett_RRM_OAM_GET_KPI_REQ_payload = -1;
int rrm_oam_get_kpi_req_t_count = -1;
guint ett_rrm_oam_get_kpi_req_t = -1;
guint ett_rrm_oam_get_kpi_req_t_kpi_to_report = -1;

//RRM_OAM_GET_KPI_RESP
gint ett_RRM_OAM_GET_KPI_RESP = -1;
gint ett_RRM_OAM_GET_KPI_RESP_payload = -1;
int rrm_oam_get_kpi_resp_t_count = -1;
gint ett_rrm_oam_get_kpi_resp_t = -1;
gint ett_rrm_oam_get_kpi_resp_t_global_cell_id = -1;
gint ett_rrm_oam_get_kpi_resp_t_resp_t_kpi_data = -1;

//RRM_OAM_KPI_DATA
gint ett_RRM_OAM_KPI_DATA = -1;
gint ett_RRM_OAM_KPI_DATA_payload = -1;
int rrm_oam_kpi_data_t_count = -1;
guint ett_rrm_oam_kpi_data_t = -1;
guint ett_rrm_oam_kpi_data_t_kpi_to_report = -1;



static gint *ett[] = {
    &ett_rrm_oam,
    &ett_rrm_oam_payload,
    &ett_rrm_oam_init_ind_t,
    &ett_rrm_oam_cell_config_req_t,
    &ett_rrm_oam_cell_config_req_t_global_cell_info,
    &ett_rrm_oam_cell_config_req_t_ran_info,
    &ett_rrm_oam_cell_config_req_t_epc_info,
    &ett_rrm_oam_cell_config_req_t_operator_info,
    &ett_rrm_oam_cell_config_req_t_access_mgmt_params,
    &ett_rrm_oam_cell_info_t,
    &ett_rrm_oam_cell_info_t_eutran_global_cell_id,
    &ett_rrm_oam_cell_info_t_cell_access_restriction_params,
    &ett_rrm_oam_eutran_global_cell_id_t,
    &ett_rrm_oam_eutran_global_cell_id_t_primary_plmn_id,
    &ett_myrrm_oam_cell_plmn_info_t,
    &ett_rrm_oam_cell_access_restriction_params_t,
    &ett_rrm_oam_ran_t,
    &ett_rrm_oam_ran_t_physical_layer_params,
    &ett_rrm_oam_ran_t_mac_layer_params,
    &ett_rrm_oam_ran_t_rlc_layer_params,
    &ett_rrm_oam_ran_t_mobility_params,
    &ett_rrm_oam_ran_t_rrc_timers_and_constants,
    &ett_rrm_oam_ran_t_rf_params,
    &ett_rrm_oam_ran_t_s1ap_params,
    &ett_rrm_oam_ran_t_ncl_params,
    &ett_rrm_oam_ran_t_connected_mode_mobility_params,
    &ett_rrm_oam_physical_layer_params_t,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_srs,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_prach,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_pucch,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_pusch,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_prs,
    &ett_rrm_oam_physical_layer_params_t_addl_physical_layer_params,
    &ett_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure,
    &ett_rrm_oam_tdd_frame_structure_t,
    &ett_rrm_oam_addl_phy_params_t,
    &ett_rrm_oam_addl_phy_params_t_addl_pucch_parameters,
    &ett_rrm_oam_addl_phy_params_t_additional_pusch_parameters,
    &ett_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params,
    &ett_rrm_oam_addl_pucch_config_t,
    &ett_rrm_oam_addl_pusch_config_t,
    &ett_rrm_oam_addl_ul_reference_signal_params_t,
    &ett_rrm_oam_pdsch_t,
    &ett_rrm_oam_srs_t,
    &ett_rrm_oam_prach_t,
    &ett_rrm_oam_pucch_t,
    &ett_rrm_oam_pusch_t,
    &ett_rrm_oam_ul_reference_signal_t,
    &ett_rrm_oam_uplink_power_control_t,
    &ett_rrm_oam_prs_t,
    &ett_rrm_oam_mac_layer_params_t,
    &ett_rrm_oam_mac_layer_params_t_mac_layer_param_rach,
    &ett_rrm_oam_mac_layer_params_t_mac_layer_param_drx,
    &ett_rrm_oam_rach_t,
    &ett_rrm_oam_rach_t_preamble_info,
    &ett_rrm_oam_preamble_info_t,
    &ett_rrm_oam_preamble_info_t_ra_preamble_groupA_info,
    &ett_rrm_oam_preamble_groupA_info_t,
    &ett_rrm_oam_drx_t,
    &ett_rrm_oam_drx_t_drx_config,
    &ett_rrm_oam_drx_config_t,
    &ett_rrm_oam_drx_config_t_short_drx_cycle,
    &ett_rrm_oam_short_drx_cycle_config_t,
    &ett_rrm_oam_rlc_layer_params_t,
    &ett_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb,
    &ett_rrm_oam_srb_t,
    &ett_rrm_oam_srb_t_srb_params,
    &ett_rrm_oam_srb_info_t,
    &ett_rrm_oam_mobility_params_t,
    &ett_rrm_oam_mobility_params_t_idle_mode_mobility_params,
    &ett_rrm_oam_idle_mode_mobility_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000,
    &ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t,
    &ett_rrm_oam_common_params_t,
    &ett_rrm_oam_common_params_t_speed_state_params,
    &ett_rrm_oam_speed_state_params_t,
    &ett_rrm_oam_intra_freq_params_t,
    &ett_rrm_oam_intra_freq_params_t_speed_scale_factors,
    &ett_rrm_oam_speed_scale_factors_t,
    &ett_rrm_oam_inter_frequency_params_list_t,
    &ett_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params,
    &ett_rrm_oam_inter_freq_params_t,
    &ett_rrm_oam_inter_freq_params_t_speed_scale_factors,
    &ett_rrm_oam_inter_freq_params_t_threshx_q_r9,
    &ett_rrm_oam_thresholdx_q_r9_t,
    &ett_rrm_oam_rrc_timers_and_constants_t,
    &ett_rrm_oam_rrc_timers_and_constants_t_rrc_timers,
    &ett_rrm_oam_rrc_timers_and_constants_t_rrc_constants,
    &ett_rrm_oam_rrc_timers_t,
    &ett_rrm_oam_rrc_constants_t,
    &ett_rrm_oam_rf_params_t,
    &ett_rrm_oam_rf_params_t_rf_configurations,
    &ett_rrm_oam_rf_configurations_t,
    &ett_rrm_oam_s1ap_params_t,
    &ett_rrm_oam_ncl_params_t,
    &ett_rrm_oam_ncl_params_t_lte_ncl,
    &ett_rrm_oam_ncl_params_t_inter_rat_ncl,
    &ett_rrm_oam_inter_rat_ncl_t,
    &ett_rrm_oam_inter_rat_ncl_t_payload,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_utran_freq_cells,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_geran_freq_cells,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t,
    &ett_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t,
    &ett_rrm_oam_connected_mode_mobility_params_t,
    &ett_rrm_oam_connected_mode_mobility_params_t_payload,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params,
    &ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t,
    &ett_rrm_utran_cell_id_t,
    &ett_rrm_oam_lte_ncl_t,
    &ett_rrm_oam_lte_ncl_t_intra_freq_cells,
    &ett_rrm_oam_lte_ncl_t_inter_freq_cells,
    &ett_rrm_oam_intra_freq_cells_t,
    &ett_rrm_oam_intra_freq_cells_t_cell_id,
    &ett_rrm_oam_inter_freq_cells_t,
    &ett_rrm_oam_inter_freq_cells_t_cell_id,
    &ett_rrm_oam_epc_t,
    &ett_rrm_oam_epc_t_epc_params,
    &ett_rrm_oam_epc_params_t,
    &ett_rrm_oam_epc_params_t_general_epc_params,
    &ett_rrm_oam_epc_params_t_qos_config_params,
    &ett_rrm_oam_general_epc_params_t,
    &ett_rrm_oam_general_epc_params_t_plmn_list,
    &ett_rrm_oam_plmn_access_info_t,
    &ett_rrm_oam_plmn_access_info_t_plmn_info,
    &ett_rrm_oam_qos_config_params_t,
    &ett_rrm_oam_qos_config_params_t_rohc_params,
    &ett_rrm_oam_qos_config_params_t_sn_field_len,
    &ett_rrm_oam_qos_config_params_t_sps_data,
    &ett_rrm_oam_qos_config_params_t_addl_rlc_param,
    &ett_rrm_oam_qos_config_params_t_addl_mac_param,
    &ett_rrm_oam_pdcp_rohc_params_t,
    &ett_rrm_oam_pdcp_rohc_params_t_rohc_pofiles,
    &ett_rrm_oam_rohc_pofiles_t,
    &ett_rrm_oam_sn_field_len_t,
    &ett_rrm_oam_sps_config_data_t,
    &ett_rrm_oam_sps_config_data_t_sps_config_dl,
    &ett_rrm_oam_sps_config_data_t_sps_config_ul,
    &ett_rrm_oam_sps_config_dl_t,
    &ett_rrm_oam_sps_config_ul_t,
    &ett_rrm_oam_addl_rlc_params_t,
    &ett_rrm_oam_addl_mac_params_t,
    &ett_rrm_oam_addl_mac_params_t_phr_config,
    &ett_rrm_oam_addl_mac_params_t_bsr_config,
    &ett_rrm_oam_phr_config_t,
    &ett_rrm_oam_bsr_config_t,
    &ett_rrm_oam_operator_info_t,
    &ett_rrm_oam_operator_info_t_rrm_mac_config,
    &ett_rrm_oam_operator_info_t_phich_config,
    &ett_rrm_oam_operator_info_t_sib_1_info,
    &ett_rrm_oam_operator_info_t_sib_2_info,
    &ett_rrm_oam_operator_info_t_sib_3_info,
    &ett_rrm_oam_operator_info_t_sib_4_info,
    &ett_rrm_oam_operator_info_t_admission_control_info,
	&ett_rrm_oam_operator_info_t_additional_packet_scheduling_params,
	&ett_rrm_oam_operator_info_t_additional_cell_params,
	&ett_rrm_oam_operator_info_t_load_params,
	&ett_rrm_oam_operator_info_t_mimo_mode_params,
	&ett_rrm_oam_operator_info_t_ho_configuration,
	&ett_rrm_oam_operator_info_t_measurement_configuration,
	&ett_rrm_oam_operator_info_t_rrm_eutran_access_point_pos,
	&ett_rrm_oam_adl_pkt_scheduling_params_t,
	&ett_rrm_oam_adl_cell_params_t,
	&ett_rrm_oam_load_params_t,
	&ett_rrm_oam_mimo_mode_params_t,
	&ett_rrm_oam_ho_config_params_t,
	&ett_rrm_oam_ho_config_params_t_target_cell_selection_params,
	&ett_rrm_oam_ho_config_params_t_ho_algo_params,
	&ett_rrm_oam_ho_config_params_t_ho_retry_params,
	&ett_rrm_oam_target_cell_selection_params_t,
	&ett_rrm_oam_ho_algo_params_t,
	&ett_rrm_oam_ho_retry_params_t,
	&ett_rrm_oam_meas_config_t,
	&ett_rrm_oam_meas_config_t_meas_gap_config,
	&ett_rrm_oam_meas_config_t_csfb_tgt_selection,
	&ett_rrm_oam_meas_gap_config_t,
	&ett_rrm_csfb_tgt_selection_t,
	&ett_rrm_oam_eutran_access_point_pos_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t,
	&ett_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t,
	&ett_rrm_oam_path_loss_to_target_sinr_map_info_t,
    &ett_rrm_oam_dynamic_icic_info_t,
    &ett_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info,
    &ett_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info,
    &ett_rrm_oam_dynamic_icic_info_t_ul_power_mask,
    &ett_rrm_oam_dynamic_icic_info_t_rntp_report_config_info,
    &ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map,
    &ett_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset,
    &ett_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power,
    &ett_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti,
    &ett_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti,
    &ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps,
    &ett_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params,
    &ett_rrm_oam_dynamic_icic_info_t_atb_config,
    &ett_rrm_oam_resource_partition_info_t,
    &ett_rrm_oam_resource_partition_info_t_cell_center_region,
    &ett_rrm_oam_resource_partition_info_t_cell_edge_region,
    &ett_rrm_oam_ul_power_mask_t,
    &ett_rrm_oam_rntp_report_config_info_t,
    &ett_rrm_oam_rrmc_mac_config_t,
    &ett_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch,
    &ett_rrm_oam_mac_enable_frequency_selective_scheduling_t,
    &ett_rrm_oam_phy_phich_configuration_t,
    &ett_rrm_oam_sib_type_1_info_t,
    &ett_rrm_oam_sib_type_1_info_t_cell_selection_info,
    &ett_rrm_oam_sib_type_1_info_t_scheduling_info,
    &ett_rrm_oam_scheduling_info_t,
    &ett_rrm_oam_sib_mapping_info_t,
    &ett_rrm_oam_cell_selection_info_v920_t,
    &ett_rrm_oam_sib_type_2_info_t,
    &ett_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib,
    &ett_rrm_oam_sib_type_2_info_t_rrm_freq_info,
    &ett_rrm_oam_radio_resource_config_common_sib_t,
    &ett_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config,
    &ett_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config,
    &ett_rrm_oam_bcch_config_t,
    &ett_rrm_oam_pcch_config_t,
    &ett_rrm_oam_freq_info_t,
    &ett_rrm_oam_sib_type_3_info_t,
    &ett_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info,
    &ett_rrm_oam_sib_type_3_info_t_s_intra_search,
    &ett_rrm_oam_sib_type_3_info_t_s_non_intra_search,
    &ett_rrm_oam_intra_freq_cell_reselection_info_t,
    &ett_rrm_oam_s_intra_search_v920_t,
    &ett_rrm_oam_s_non_intra_search_v920_t,
    &ett_rrm_oam_sib_type_4_info_t,
    &ett_rrm_oam_sib_type_4_info_t_csg_id_range,
    &ett_rrm_oam_csg_cell_id_range_t,
    &ett_rrm_oam_admission_control_info_t,
    &ett_rrm_oam_admission_control_info_t_available_gbr_limit,
    &ett_rrm_oam_admission_control_info_t_spid_table,
    &ett_available_gbr_limit_t,
    &ett_rrm_oam_spid_table_t,
    &ett_rrm_oam_spid_table_t_spid_config,
    &ett_rrm_oam_spid_configuration_t,
    &ett_rrm_power_control_params,
    &ett_rrm_power_control_params_payload,
    &ett_rrm_power_control_params_rrm_power_control_params,
    &ett_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable,
    &ett_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range,
    &ett_rrm_power_control_params_rrm_oam_power_control_enable_t,
    &ett_rrm_power_control_params_rrm_oam_tpc_rnti_range_t,
    &ett_rrm_oam_sps_crnti_range_t,
    &ett_rrm_oam_access_mgmt_params_t,
    &ett_rrm_oam_shutdown_req_t,
    &ett_rrm_oam_shutdown_resp_t,
    &ett_rrm_oam_set_log_level_req_t,
    &ett_rrm_oam_set_log_level_resp_t,
    &ett_rrm_oam_resume_service_req_t,
    &ett_rrm_oam_resume_service_resp_t,
    &ett_rrm_oam_ready_for_shutdown_ind_t,
    &ett_rrm_oam_rac_enable_disable_req_t,
    &ett_rrm_oam_rac_enable_disable_req_t_global_cell_id,
    &ett_rrm_oam_rac_enable_disable_resp_t,
    &ett_rrm_oam_rac_enable_disable_resp_t_global_cell_id,
    &ett_rrm_oam_log_enable_disable_req_t,
    &ett_rrm_oam_log_enable_disable_req_t_log_config,
    &ett_rrm_oam_log_config_t,
    &ett_rrm_oam_log_enable_disable_resp_t,
    &ett_rrm_oam_init_config_req_t,
    &ett_rrm_oam_init_config_req_t_init_module_config,
    &ett_rrm_oam_module_init_config_t,
    &ett_rrm_oam_module_init_config_t_log_config,
    &ett_rrm_oam_init_config_resp_t,
    &ett_rrm_oam_cell_start_req_t,
    &ett_rrm_oam_cell_start_req_t_global_cell_id,
    &ett_rrm_oam_cell_start_resp_t,
    &ett_rrm_oam_cell_start_resp_t_global_cell_id,
    &ett_rrm_oam_cell_stop_req_t,
    &ett_rrm_oam_cell_stop_req_t_global_cell_id,
    &ett_rrm_oam_cell_stop_resp_t,
    &ett_rrm_oam_cell_stop_resp_t_global_cell_id,
    &ett_rrm_oam_cell_delete_req_t,
    &ett_rrm_oam_cell_delete_req_t_global_cell_id,
    &ett_rrm_oam_cell_delete_resp_t,
    &ett_rrm_oam_cell_delete_resp_t_global_cell_id,
    &ett_rrm_oam_cell_config_resp_t,
    &ett_rrm_oam_cell_config_resp_t_global_cell_id,
    &ett_rrm_oam_cell_reconfig_req_t,
    &ett_rrm_oam_cell_reconfig_req_t_global_cell_id,
    &ett_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params,
    &ett_rrm_oam_cell_reconfig_req_t_ran_info,
    &ett_rrm_oam_cell_reconfig_req_t_epc_info,
    &ett_rrm_oam_cell_reconfig_req_t_operator_info,
    &ett_rrm_oam_cell_reconfig_req_t_access_mgmt_params,
    &ett_rrm_oam_cell_reconfig_resp_t,
    &ett_rrm_oam_cell_reconfig_resp_t_global_cell_id,
    &ett_rrm_oam_block_cell_req_t,
    &ett_rrm_oam_block_cell_req_t_global_cell_id,
    &ett_rrm_oam_cell_plmn_info_t,
    &ett_rrm_oam_block_cell_resp_t,
    &ett_rrm_oam_block_cell_resp_t_global_cell_id,
    &ett_rrm_oam_ready_for_cell_block_ind_t,
    &ett_rrm_oam_ready_for_cell_block_ind_t_global_cell_id,
    &ett_rrm_oam_unblock_cell_cmd_t,
    &ett_rrm_oam_unblock_cell_cmd_t_global_cell_id,
    &ett_rrm_oam_get_ver_id_resp_t,
       
    
   //Added PT.
    &ett_rrm_oam_cell_context_print_req,
    &ett_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req,
    &ett_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t,
    &ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t,
    &ett_rrm_oam_ue_release_req_t,
    &ett_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t,
    &ett_rrm_oam_proc_supervision_resp_t,
    &ett_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t,
    //Added PD
    &ett_rrm_oam_cell_update_req_t,
    &ett_rrm_oam_cell_update_req_t_global_cell_id,
    &ett_rrm_oam_updated_plmn_info_t,
    &ett_rrm_oam_cell_update_resp_t,
    &ett_rrm_oam_cell_update_resp_t_global_cell_id,
    &ett_rrm_oam_event_notification_t,
    &ett_rrm_oam_event_notification_t_msg_header,
    &ett_rrm_oam_event_header_t,
    &ett_rrm_oam_event_header_t_time_stamp,
    &ett_rrm_oam_time_stamp_t,
    &ett_rrm_oam_load_config_req_t,
    &ett_rrm_oam_load_config_req_t_serv_enb_cell_info,
    &ett_rrm_oam_serving_enb_cell_info_t,
    &ett_rrm_oam_serving_enb_cell_info_t_global_cell_id,
    &ett_rrm_oam_serving_enb_cell_info_t_over_load_lvl_act,
    &ett_rrm_oam_serving_enb_cell_info_t_high_load_lvl_act,
    &ett_rrm_oam_serving_enb_cell_info_t_mid_load_lvl_act,
    &ett_rrm_oam_serving_enb_cell_info_t_resrc_spec,
    &ett_rrm_oam_over_load_def_t,
    &ett_rrm_oam_high_load_def_t,
    &ett_rrm_oam_mid_load_def_t,
    &ett_rrm_oam_load_def_t_q_watermark,
    &ett_rrm_oam_load_def_t_ld_ac_bar,
    &ett_rrm_oam_watermark_t,
    &ett_rrm_oam_resource_load_info_t,
    &ett_rrm_oam_resource_load_info_t_resrc_info,
    &ett_rrm_oam_resrc_info_t,
    &ett_rrm_oam_resrc_info_t_overload,
    &ett_rrm_oam_resrc_info_t_highload,
    &ett_rrm_oam_resrc_info_t_midload,
    &ett_rrm_oam_access_barring_info_t,
    &ett_rrm_oam_access_barring_info_t_class_barring_info,
    &ett_rrm_oam_access_barring_info_t_ssac_barring_r9,
    &ett_rrm_oam_access_class_barring_information_t,
    &ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t,
    &ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t_class_barring_info,
    &ett_rrm_oam_load_config_resp_t,
    &ett_rrm_oam_load_report_ind_t,
    &ett_rrm_oam_load_cell_info_t,
    &ett_rrm_oam_hw_load_ind_t,
    &ett_rrm_oam_s1_tnl_load_t,
    &ett_rrm_oam_rrs_load_ind_t,
    &ett_rrm_oam_comp_avl_grp_t,
    &ett_rrm_oam_comp_avl_dl_t,
    &ett_rrm_oam_cell_ecn_capacity_enhance_req_t,
    &ett_rrm_oam_cell_ecn_capacity_enhance_req_t_ecn_cells,
    &ett_rrm_ecn_configure_cell_list_t,
    &ett_rrm_ecn_configure_cell_list_t_global_cell_id,
    &ett_rrm_ecn_configure_cell_list_t_bitrate,
    &ett_rrm_qci_bitrate_info_t,
    &ett_rrm_qci_bitrate_info_t_bitrate_for_qci,
    &ett_rrm_bitrate_ul_dl_t,
    &ett_rrm_oam_cell_ecn_capacity_enhance_resp_t,
    &ett_rrm_oam_config_kpi_req_t,
    &ett_rrm_oam_config_kpi_req_t_kpi_to_report,
    &ett_rrm_oam_kpi_t,
    &ett_rrm_oam_config_kpi_resp_t,
    &ett_rrm_oam_config_kpi_resp_t_global_cell_id,
    &ett_rrm_oam_get_kpi_req_t,
    &ett_rrm_oam_get_kpi_req_t_kpi_to_report,
    &ett_rrm_oam_get_kpi_resp_t,
    &ett_rrm_oam_get_kpi_resp_t_global_cell_id ,
    &ett_rrm_oam_get_kpi_resp_t_resp_t_kpi_data,
    &ett_rrm_oam_kpi_data_t,
    &ett_rrm_oam_kpi_data_t_kpi_to_report,
};

//hfinfo
int hf_rrm_oam_header = -1;
int hf_rrm_oam_header_transactionId = -1;
int hf_rrm_oam_header_sourceModId = -1;
int hf_rrm_oam_header_destModId = -1;
int hf_rrm_oam_header_TypeOfAPI = -1;
int hf_rrm_oam_header_MsgBufferlen = -1;
int hf_rrm_oam_header_unparsed_data = -1;

// RRM OAM INIT IND
int hf_RRM_OAM_INIT_IND_unparsed_data = -1;
int hf_rrm_oam_init_ind_t = -1;


//Cell Config Req
int hf_rrm_oam_cell_config_req_t = -1;
int hf_rrm_oam_cell_config_req_t_bitmask = -1;
int hf_rrm_oam_cell_config_req_t_global_cell_info = -1;
int hf_rrm_oam_cell_config_req_t_ran_info = -1;
int hf_rrm_oam_cell_config_req_t_epc_info = -1;
int hf_rrm_oam_cell_config_req_t_operator_info = -1;
int hf_rrm_oam_cell_config_req_t_access_mgmt_params = -1;
int hf_rrm_oam_cell_config_req_t_immediate_start_needed = -1;
static const range_string immediate_start_needed_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_cell_info_t = -1;
int hf_rrm_oam_cell_info_t_eutran_global_cell_id = -1;
int hf_rrm_oam_cell_info_t_cell_access_restriction_params = -1;
int hf_rrm_oam_eutran_global_cell_id_t = -1;
int hf_rrm_oam_eutran_global_cell_id_t_primary_plmn_id = -1;
int hf_rrm_oam_eutran_global_cell_id_t_cell_identity = -1;
int hf_rrm_oam_cell_plmn_info_t = -1;
int hf_rrm_oam_cell_plmn_info_t_mcc = -1;
int hf_rrm_oam_cell_plmn_info_t_num_mnc_digit = -1;
int hf_rrm_oam_cell_plmn_info_t_mnc = -1;
int hf_rrm_oam_cell_access_restriction_params_t = -1;
int hf_rrm_oam_cell_access_restriction_params_t_cell_barred = -1;
static const range_string cell_barred_values [] = {
    {0,0,"RRMC_RRMC_CELL_BARRED"},
    {1,1,"RRMC_RRMC_CELL_NOT_BARRED"},
    {0,0,"NULL"}
};
int hf_rrm_oam_cell_access_restriction_params_t_intra_freq_reselection = -1;
static const range_string intra_freq_reselection_values [] = {
    {0,0,"RRMC_INTRA_FREQ_RESELECTION_ALLOWED"},
    {1,1,"RRMC_INTRA_FREQ_RESELECTION_NOT_ALLOWED"},
    {0,0,"NULL"}
};
int hf_rrm_oam_cell_access_restriction_params_t_barring_for_emergency = -1;
static const range_string barring_for_emergency_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_ran_t = -1;
int hf_rrm_oam_ran_t_bitmask = -1;
int hf_rrm_oam_ran_t_physical_layer_params = -1;
int hf_rrm_oam_ran_t_mac_layer_params = -1;
int hf_rrm_oam_ran_t_rlc_layer_params = -1;
int hf_rrm_oam_ran_t_mobility_params = -1;
int hf_rrm_oam_ran_t_rrc_timers_and_constants = -1;
int hf_rrm_oam_ran_t_rf_params = -1;
int hf_rrm_oam_ran_t_s1ap_params = -1;
int hf_rrm_oam_ran_t_ncl_params = -1;
int hf_rrm_oam_ran_t_connected_mode_mobility_params = -1;
int hf_rrm_oam_physical_layer_params_t = -1;
int hf_rrm_oam_physical_layer_params_t_bitmask = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_srs = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_prach = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pucch = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pusch = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_prs = -1;
int hf_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure = -1;
int hf_rrm_oam_physical_layer_params_t_addl_physical_layer_params = -1;
int hf_rrm_oam_addl_phy_params_t = -1;
int hf_rrm_oam_addl_phy_params_t_bitmask = -1;
int hf_rrm_oam_addl_phy_params_t_addl_pucch_parameters = -1;
int hf_rrm_oam_addl_phy_params_t_additional_pusch_parameters = -1;
int hf_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params = -1;
int hf_rrm_oam_addl_pucch_config_t = -1;
int hf_rrm_oam_addl_pucch_config_t_bitmask = -1;
int hf_rrm_oam_addl_pucch_config_t_n1_cs = -1;
int hf_rrm_oam_addl_pusch_config_t = -1;
int hf_rrm_oam_addl_pusch_config_t_bitmask = -1;
int hf_rrm_oam_addl_pusch_config_t_pusch_enable_64_qam = -1;
int hf_rrm_oam_addl_ul_reference_signal_params_t = -1;
int hf_rrm_oam_addl_ul_reference_signal_params_t_bitmask = -1;
int hf_rrm_oam_addl_ul_reference_signal_params_t_group_assignment_pusch = -1;
int hf_rrm_oam_addl_ul_reference_signal_params_t_ul_reference_signal_pusch_cyclicshift = -1;
int hf_rrm_oam_tdd_frame_structure_t = -1;
int hf_rrm_oam_tdd_frame_structure_t_sub_frame_assignment = -1;
int hf_rrm_oam_tdd_frame_structure_t_special_sub_frame_patterns = -1;
int hf_rrm_oam_pdsch_t = -1;
int hf_rrm_oam_pdsch_t_p_b = -1;
static const range_string p_b_values [] = {
    {0,0,"pb0"},
    {1,1,"pb1"},
    {2,2,"pb2"},
    {3,3,"pb3"},
    {0,0,"NULL"}
};
int hf_rrm_oam_pdsch_t_p_a = -1;
static const range_string p_a_values [] = {
    {0,0,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_6"},
    {1,1,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_4DOT77"},
    {2,2,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_3"},
    {3,3,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_1DOT77"},
    {4,4,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB0"},
    {5,5,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB1"},
    {6,6,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB2"},
    {7,7,"PDSCH_CONFIGURATION_DEDICATED_P_A_DB3"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srs_t = -1;
int hf_rrm_oam_srs_t_bitmask = -1;
int hf_rrm_oam_srs_t_srsEnabled = -1;
static const range_string srsEnabled_values [] = {
    {0,0,"RRMC_SRS_DISABLED"},
    {1,1,"RRMC_SRS_ENABLED"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srs_t_srs_bandwidth_config = -1;
static const range_string srs_bandwidth_config_values [] = {
    {0,0,"RRMC_SRS_BW_CONFIG_BW0"},
    {1,1,"RRMC_SRS_BW_CONFIG_BW1"},
    {2,2,"RRMC_SRS_BW_CONFIG_BW2"},
    {3,3,"RRMC_SRS_BW_CONFIG_BW3"},
    {4,4,"RRMC_SRS_BW_CONFIG_BW4"},
    {5,5,"RRMC_SRS_BW_CONFIG_BW5"},
    {6,6,"RRMC_SRS_BW_CONFIG_BW6"},
    {7,7,"RRMC_SRS_BW_CONFIG_BW7"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srs_t_srs_subframe_config = -1;
static const range_string srs_subframe_config_values [] = {
    {0,0,"RRMC_SRS_SUBFRAME_CONFIG_SC0"},
    {1,1,"RRMC_SRS_SUBFRAME_CONFIG_SC1"},
    {2,2,"RRMC_SRS_SUBFRAME_CONFIG_SC2"},
    {3,3,"RRMC_SRS_SUBFRAME_CONFIG_SC3"},
    {4,4,"RRMC_SRS_SUBFRAME_CONFIG_SC4"},
    {5,5,"RRMC_SRS_SUBFRAME_CONFIG_SC5"},
    {6,6,"RRMC_SRS_SUBFRAME_CONFIG_SC6"},
    {7,7,"RRMC_SRS_SUBFRAME_CONFIG_SC7"},
    {8,8,"RRMC_SRS_SUBFRAME_CONFIG_SC8"},
    {9,9,"RRMC_SRS_SUBFRAME_CONFIG_SC9"},
    {10,10,"RRMC_SRS_SUBFRAME_CONFIG_SC10"},
    {11,11,"RRMC_SRS_SUBFRAME_CONFIG_SC11"},
    {12,12,"RRMC_SRS_SUBFRAME_CONFIG_SC12"},
    {13,13,"RRMC_SRS_SUBFRAME_CONFIG_SC13"},
    {14,14,"RRMC_SRS_SUBFRAME_CONFIG_SC14"},
    {15,15,"RRMC_SRS_SUBFRAME_CONFIG_SC15"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srs_t_srs_max_up_pts = -1;
static const range_string srs_max_up_pts_values [] = {
    {0,0,"RRMC_SRS_MAX_UP_PTS_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srs_t_ack_nack_srs_simultaneous_transmission = -1;
static const range_string ack_nack_srs_simultaneous_transmission_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};

int hf_rrm_oam_prach_t = -1;
int hf_rrm_oam_prach_t_root_sequence_index = -1;
int hf_rrm_oam_prach_t_configuration_index = -1;
int hf_rrm_oam_prach_t_high_speed_flag = -1;
int hf_rrm_oam_prach_t_zero_correlation_zone_config = -1;
int hf_rrm_oam_prach_t_frequency_offset = -1;
int hf_rrm_oam_pucch_t = -1;
int hf_rrm_oam_pucch_t_delta_pucch_shift = -1;
int hf_rrm_oam_pucch_t_n_rb_cqi = -1;
int hf_rrm_oam_pucch_t_n1_pucch_an = -1;
int hf_rrm_oam_pucch_t_cqi_pucch_resource_index = -1;
int hf_rrm_oam_pucch_t_tdd_ack_nack_feedback_mode = -1;
int hf_rrm_oam_pucch_t_pucch_cqi_sinr_value = -1;
int hf_rrm_oam_pusch_t = -1;
int hf_rrm_oam_pusch_t_n_sb = -1;
int hf_rrm_oam_pusch_t_pusch_hopping_mode = -1;
static const range_string pusch_hopping_mode_values [] = {
    {0,0,"RRMC_HM_INTER_SF"},
    {1,1,"RRMC_HM_INTRA_AND_INTER_SF"},
    {0,0,"NULL"}
};
int hf_rrm_oam_pusch_t_hopping_offset = -1;
int hf_rrm_oam_ul_reference_signal_t = -1;
int hf_rrm_oam_ul_reference_signal_t_group_hopping_enabled = -1;
static const range_string group_hopping_enabled_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_ul_reference_signal_t_sequence_hopping_enabled = -1;
static const range_string sequence_hopping_enabled_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};

int hf_rrm_oam_uplink_power_control_t = -1;
int hf_rrm_oam_uplink_power_control_t_p_0_nominal_pusch = -1;
int hf_rrm_oam_uplink_power_control_t_alpha = -1;
static const range_string alpha_values [] = {
    {0,0,"RRMC_AL_0"},
    {1,1,"RRMC_AL_0_4"},
    {2,2,"RRMC_AL_0_5"},
    {3,3,"RRMC_AL_0_6"},
    {4,4,"RRMC_AL_0_7"},
    {5,5,"RRMC_AL_0_8"},
    {6,6,"RRMC_AL_0_9"},
    {7,7,"RRMC_AL_1"},
    {0,0,"NULL"}
};

int hf_rrm_oam_uplink_power_control_t_p_0_nominal_pucch = -1;
int hf_rrm_oam_prs_t = -1;
int hf_rrm_oam_prs_t_num_prs_resource_blocks = -1;
int hf_rrm_oam_prs_t_prs_configuration_index = -1;
int hf_rrm_oam_prs_t_num_consecutive_prs_subfames = -1;
static const range_string num_consecutive_prs_subfames_values [] = {
    {0,0,"NUM_CONS_PRS_SF_N1"},
    {1,1,"NUM_CONS_PRS_SF_N2"},
    {2,2,"NUM_CONS_PRS_SF_N4"},
    {3,3,"NUM_CONS_PRS_SF_N6"},
    {0,0,"NULL"}
};
int hf_rrm_oam_mac_layer_params_t = -1;
int hf_rrm_oam_mac_layer_params_t_mac_layer_param_rach = -1;
int hf_rrm_oam_mac_layer_params_t_mac_layer_param_drx = -1;
int hf_rrm_oam_rach_t = -1;
int hf_rrm_oam_rach_t_preamble_info = -1;
int hf_rrm_oam_rach_t_power_ramping_step = -1;
static const range_string power_ramping_step_values [] = {
    {0,0,"RRMC_POWER_RAMP_STEP_DB0"},
    {1,1,"RRMC_POWER_RAMP_STEP_DB2"},
    {2,2,"RRMC_POWER_RAMP_STEP_DB4"},
    {3,3,"RRMC_POWER_RAMP_STEP_DB6"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rach_t_preamble_initial_received_target_power = -1;
static const range_string preamble_initial_received_target_power_values [] = {
    {0,0,"RRMC_PREAMBLE_POWER_DBM_120"},
    {1,1,"RRMC_PREAMBLE_POWER_DBM_118"},
    {2,2,"RRMC_PREAMBLE_POWER_DBM_116"},
    {3,3,"RRMC_PREAMBLE_POWER_DBM_114"},
    {4,4,"RRMC_PREAMBLE_POWER_DBM_112"},
    {5,5,"RRMC_PREAMBLE_POWER_DBM_110"},
    {6,6,"RRMC_PREAMBLE_POWER_DBM_108"},
    {7,7,"RRMC_PREAMBLE_POWER_DBM_106"},
    {8,8,"RRMC_PREAMBLE_POWER_DBM_104"},
    {9,9,"RRMC_PREAMBLE_POWER_DBM_102"},
    {10,10,"RRMC_PREAMBLE_POWER_DBM_100"},
    {11,11,"RRMC_PREAMBLE_POWER_DBM_98"},
    {12,12,"RRMC_PREAMBLE_POWER_DBM_96"},
    {13,13,"RRMC_PREAMBLE_POWER_DBM_94"},
    {14,14,"RRMC_PREAMBLE_POWER_DBM_92"},
    {15,15,"RRMC_PREAMBLE_POWER_DBM_90"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rach_t_preamble_trans_max = -1;
static const range_string preamble_trans_max_values [] = {
    {0,0,"RRMC_PREAMBLE_TRANS_MAX_N3"},
    {1,1,"RRMC_PREAMBLE_TRANS_MAX_N4"},
    {2,2,"RRMC_PREAMBLE_TRANS_MAX_N5"},
    {3,3,"RRMC_PREAMBLE_TRANS_MAX_N6"},
    {4,4,"RRMC_PREAMBLE_TRANS_MAX_N7"},
    {5,5,"RRMC_PREAMBLE_TRANS_MAX_N8"},
    {6,6,"RRMC_PREAMBLE_TRANS_MAX_N10"},
    {7,7,"RRMC_PREAMBLE_TRANS_MAX_N20"},
    {8,8,"RRMC_PREAMBLE_TRANS_MAX_N50"},
    {9,9,"RRMC_PREAMBLE_TRANS_MAX_N100"},
    {10,10,"RRMC_PREAMBLE_TRANS_MAX_N200"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rach_t_response_window_size = -1;
static const range_string response_window_size_values [] = {
    {0,0,"RRMC_RA_RESP_WIN_SIZE_SF2"},
    {1,1,"RRMC_RA_RESP_WIN_SIZE_SF3"},
    {2,2,"RRMC_RA_RESP_WIN_SIZE_SF4"},
    {3,3,"RRMC_RA_RESP_WIN_SIZE_SF5"},
    {4,4,"RRMC_RA_RESP_WIN_SIZE_SF6"},
    {5,5,"RRMC_RA_RESP_WIN_SIZE_SF7"},
    {6,6,"RRMC_RA_RESP_WIN_SIZE_SF8"},
    {7,7,"RRMC_RA_RESP_WIN_SIZE_SF10"},
    {0,0,"NULL"}
};

int hf_rrm_oam_rach_t_contention_resolution_timer = -1;
static const range_string contention_resolution_timer_values [] = {
    {0,0,"RRMC_MAC_CONT_RES_TIMER_SF8"},
    {1,1,"RRMC_MAC_CONT_RES_TIMER_SF16"},
    {2,2,"RRMC_MAC_CONT_RES_TIMER_SF24"},
    {3,3,"RRMC_MAC_CONT_RES_TIMER_SF32"},
    {4,4,"RRMC_MAC_CONT_RES_TIMER_SF40"},
    {5,5,"RRMC_MAC_CONT_RES_TIMER_SF48"},
    {6,6,"RRMC_MAC_CONT_RES_TIMER_SF56"},
    {7,7,"RRMC_MAC_CONT_RES_TIMER_SF64"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rach_t_max_harq_msg_3tx = -1;
int hf_rrm_oam_preamble_info_t = -1;
int hf_rrm_oam_preamble_info_t_bitmask = -1;
int hf_rrm_oam_preamble_info_t_number_of_ra_preambles = -1;
static const range_string number_of_ra_preambles_values [] = {
    {0,0,"RRMC_RA_PREAMBLE_COUNT_N4"},
    {1,1,"RRMC_RA_PREAMBLE_COUNT_N8"},
    {2,2,"RRMC_RA_PREAMBLE_COUNT_N12"},
    {3,3,"RRMC_RA_PREAMBLE_COUNT_N16"},
    {4,4,"RRMC_RA_PREAMBLE_COUNT_N20"},
    {5,5,"RRMC_RA_PREAMBLE_COUNT_N24"},
    {6,6,"RRMC_RA_PREAMBLE_COUNT_N28"},
    {7,7,"RRMC_RA_PREAMBLE_COUNT_N32"},
    {8,8,"RRMC_RA_PREAMBLE_COUNT_N36"},
    {9,9,"RRMC_RA_PREAMBLE_COUNT_N40"},
    {10,10,"RRMC_RA_PREAMBLE_COUNT_N44"},
    {11,11,"RRMC_RA_PREAMBLE_COUNT_N48"},
    {12,12,"RRMC_RA_PREAMBLE_COUNT_N52"},
    {13,13,"RRMC_RA_PREAMBLE_COUNT_N56"},
    {14,14,"RRMC_RA_PREAMBLE_COUNT_N60"},
    {15,15,"RRMC_RA_PREAMBLE_COUNT_N64"},
    {0,0,"NULL"}
};
int hf_rrm_oam_preamble_info_t_ra_preamble_groupA_info = -1;
int hf_rrm_oam_preamble_groupA_info_t = -1;
int hf_rrm_oam_preamble_groupA_info_t_size_of_ra_group_a = -1;
static const range_string size_of_ra_group_a_values [] = {
    {0,0,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N4"},
    {1,1,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N8"},
    {2,2,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N12"},
    {3,3,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N16"},
    {4,4,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N20"},
    {5,5,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N24"},
    {6,6,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N28"},
    {7,7,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N32"},
    {8,8,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N36"},
    {9,9,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N40"},
    {10,10,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N44"},
    {11,11,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N48"},
    {12,12,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N52"},
    {13,13,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N56"},
    {14,14,"RRMC_RA_PREAMBLE_GROUP_A_SIZE_N60"},
    {0,0,"NULL"}
};
int hf_rrm_oam_preamble_groupA_info_t_message_size_group_a = -1;
static const range_string message_size_group_a_values [] = {
    {0,0,"RRMC_GROUP_A_MSG_SIZE_B56"},
    {1,1,"RRMC_GROUP_A_MSG_SIZE_B144"},
    {2,2,"RRMC_GROUP_A_MSG_SIZE_B208"},
    {3,3,"RRMC_GROUP_A_MSG_SIZE_B256"},
    {0,0,"NULL"}
};
int hf_rrm_oam_preamble_groupA_info_t_message_power_offset_group_b = -1;
static const range_string message_power_offset_group_b_values [] = {
    {0,0,"RRMC_GROUP_B_MSG_POWER_OFFSET_MINUSINFINITY"},
    {1,1,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB0"},
    {2,2,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB5"},
    {3,3,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB8"},
    {4,4,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB10"},
    {5,5,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB12"},
    {6,6,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB15"},
    {7,7,"RRMC_GROUP_B_MSG_POWER_OFFSET_DB18"},
    {0,0,"NULL"}
};
int hf_rrm_oam_drx_t = -1;
int hf_rrm_oam_drx_t_drx_enabled = -1;
static const range_string drx_enabled_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};

int hf_rrm_oam_drx_t_num_valid_drx_profiles = -1;
int hf_rrm_oam_drx_t_drx_config = -1;
int hf_rrm_oam_drx_config_t = -1;
int hf_rrm_oam_drx_config_t_bitmask = -1;
int hf_rrm_oam_drx_config_t_num_applicable_qci = -1;
int hf_rrm_oam_drx_config_t_applicable_qci_list = -1;
int hf_rrm_oam_drx_config_t_on_duration_timer = -1;
static const range_string on_duration_timer_values [] = {
    {0,0,"RRMC_ON_DURATION_TIMER_PSF_1"},
    {1,1,"RRMC_ON_DURATION_TIMER_PSF_2"},
    {2,2,"RRMC_ON_DURATION_TIMER_PSF_3"},
    {3,3,"RRMC_ON_DURATION_TIMER_PSF_4"},
    {4,4,"RRMC_ON_DURATION_TIMER_PSF_5"},
    {5,5,"RRMC_ON_DURATION_TIMER_PSF_6"},
    {6,6,"RRMC_ON_DURATION_TIMER_PSF_8"},
    {7,7,"RRMC_ON_DURATION_TIMER_PSF_10"},
    {8,8,"RRMC_ON_DURATION_TIMER_PSF_20"},
    {9,9,"RRMC_ON_DURATION_TIMER_PSF_30"},
    {10,10,"RRMC_ON_DURATION_TIMER_PSF_40"},
    {11,11,"RRMC_ON_DURATION_TIMER_PSF_50"},
    {12,12,"RRMC_ON_DURATION_TIMER_PSF_60"},
    {13,13,"RRMC_ON_DURATION_TIMER_PSF_80"},
    {14,14,"RRMC_ON_DURATION_TIMER_PSF_100"},
    {15,15,"RRMC_ON_DURATION_TIMER_PSF_200"},
    {0,0,"NULL"}
};
int hf_rrm_oam_drx_config_t_drx_inactivity_timer = -1;
static const range_string drx_inactivity_timer_values [] = {
    {0,0,"RRMC_DRX_INACTIVITY_TIMER_PSF_1"},
    {1,1,"RRMC_DRX_INACTIVITY_TIMER_PSF_2"},
    {2,2,"RRMC_DRX_INACTIVITY_TIMER_PSF_3"},
    {3,3,"RRMC_DRX_INACTIVITY_TIMER_PSF_4"},
    {4,4,"RRMC_DRX_INACTIVITY_TIMER_PSF_5"},
    {5,5,"RRMC_DRX_INACTIVITY_TIMER_PSF_6"},
    {6,6,"RRMC_DRX_INACTIVITY_TIMER_PSF_8"},
    {7,7,"RRMC_DRX_INACTIVITY_TIMER_PSF_10"},
    {8,8,"RRMC_DRX_INACTIVITY_TIMER_PSF_20"},
    {9,9,"RRMC_DRX_INACTIVITY_TIMER_PSF_30"},
    {10,10,"RRMC_DRX_INACTIVITY_TIMER_PSF_40"},
    {11,11,"RRMC_DRX_INACTIVITY_TIMER_PSF_50"},
    {12,12,"RRMC_DRX_INACTIVITY_TIMER_PSF_60"},
    {13,13,"RRMC_DRX_INACTIVITY_TIMER_PSF_80"},
    {14,14,"RRMC_DRX_INACTIVITY_TIMER_PSF_100"},
    {15,15,"RRMC_DRX_INACTIVITY_TIMER_PSF_200"},
    {16,16,"RRMC_DRX_INACTIVITY_TIMER_PSF_300"},
    {17,17,"RRMC_DRX_INACTIVITY_TIMER_PSF_500"},
    {18,18,"RRMC_DRX_INACTIVITY_TIMER_PSF_750"},
    {19,19,"RRMC_DRX_INACTIVITY_TIMER_PSF_1280"},
    {20,20,"RRMC_DRX_INACTIVITY_TIMER_PSF_1920"},
    {21,21,"RRMC_DRX_INACTIVITY_TIMER_PSF_2560"},
    {0,0,"NULL"}
};
int hf_rrm_oam_drx_config_t_drx_retransmission_timer = -1;
static const range_string drx_retransmission_timer_values [] = {
    {0,0,"RRMC_DRX_RETRANS_TIMER_PSF_1"},
    {1,1,"RRMC_DRX_RETRANS_TIMER_PSF_2"},
    {2,2,"RRMC_DRX_RETRANS_TIMER_PSF_4"},
    {3,3,"RRMC_DRX_RETRANS_TIMER_PSF_6"},
    {4,4,"RRMC_DRX_RETRANS_TIMER_PSF_8"},
    {5,5,"RRMC_DRX_RETRANS_TIMER_PSF_16"},
    {6,6,"RRMC_DRX_RETRANS_TIMER_PSF_24"},
    {7,7,"RRMC_DRX_RETRANS_TIMER_PSF_33"},
    {0,0,"NULL"}
};
int hf_rrm_oam_drx_config_t_long_drx_cycle = -1;
static const range_string long_drx_cycle_values [] = {
    {0,0,"sf10"},
    {1,1,"sf20"},
    {2,2,"sf32"},
    {3,3,"sf40"},
    {4,4,"sf64"},
    {5,5,"sf80"},
    {6,6,"sf128"},
    {7,7,"sf160"},
    {8,8,"sf256"},
    {9,9,"sf320"},
    {10,10,"sf512"},
    {11,11,"sf640"},
    {12,12,"sf1024"},
    {13,13,"sf1280"},
    {14,14,"sf2048"},
    {15,15,"sf2560"},
    {0,0,"NULL"}
};

int hf_rrm_oam_drx_config_t_drx_start_offset = -1;
int hf_rrm_oam_drx_config_t_short_drx_cycle = -1;
static const range_string short_drx_cycle_values [] = {
    {0,0,"RRMC_SHORT_DRX_CYCLE_SF_2"},
    {1,1,"RRMC_SHORT_DRX_CYCLE_SF_5"},
    {2,2,"RRMC_SHORT_DRX_CYCLE_SF_8"},
    {3,3,"RRMC_SHORT_DRX_CYCLE_SF_10"},
    {4,4,"RRMC_SHORT_DRX_CYCLE_SF_16"},
    {5,5,"RRMC_SHORT_DRX_CYCLE_SF_20"},
    {6,6,"RRMC_SHORT_DRX_CYCLE_SF_32"},
    {7,7,"RRMC_SHORT_DRX_CYCLE_SF_40"},
    {8,8,"RRMC_SHORT_DRX_CYCLE_SF_64"},
    {9,9,"RRMC_SHORT_DRX_CYCLE_SF_80"},
    {10,10,"RRMC_SHORT_DRX_CYCLE_SF_128"},
    {11,11,"RRMC_SHORT_DRX_CYCLE_SF_160"},
    {12,12,"RRMC_SHORT_DRX_CYCLE_SF_256"},
    {13,13,"RRMC_SHORT_DRX_CYCLE_SF_320"},
    {14,14,"RRMC_SHORT_DRX_CYCLE_SF_512"},
    {15,15,"RRMC_SHORT_DRX_CYCLE_SF_640"},
    {0,0,"NULL"}
};

int hf_rrm_oam_short_drx_cycle_config_t = -1;
int hf_rrm_oam_short_drx_cycle_config_t_short_drx_cycle = -1;
int hf_rrm_oam_short_drx_cycle_config_t_drx_short_cycle_timer = -1;
int hf_rrm_oam_mac_layer_params_t_ul_sync_loss_timer = -1;
int hf_rrm_oam_mac_layer_params_t_ul_ngap = -1;
int hf_rrm_oam_rlc_layer_params_t = -1;
int hf_rrm_oam_rlc_layer_params_t_num_valid_srb_info = -1;
int hf_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb = -1;
int hf_rrm_oam_srb_t = -1;
int hf_rrm_oam_srb_t_bitmask = -1;
int hf_rrm_oam_srb_t_default_configuration = -1;
static const range_string default_configuration_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srb_t_srb_params = -1;
int hf_rrm_oam_srb_info_t = -1;
int hf_rrm_oam_srb_info_t_t_poll_retransmit = -1;
static const range_string t_poll_retransmit_values [] = {
    {0,0,"RRMC_POLL_RETRAS_MS_5"},
    {1,1,"RRMC_POLL_RETRAS_MS_10"},
    {2,2,"RRMC_POLL_RETRAS_MS_15"},
    {3,3,"RRMC_POLL_RETRAS_MS_20"},
    {4,4,"RRMC_POLL_RETRAS_MS_25"},
    {5,5,"RRMC_POLL_RETRAS_MS_30"},
    {6,6,"RRMC_POLL_RETRAS_MS_35"},
    {7,7,"RRMC_POLL_RETRAS_MS_40"},
    {8,8,"RRMC_POLL_RETRAS_MS_45"},
    {9,9,"RRMC_POLL_RETRAS_MS_50"},
    {10,10,"RRMC_POLL_RETRAS_MS_55"},
    {11,11,"RRMC_POLL_RETRAS_MS_60"},
    {12,12,"RRMC_POLL_RETRAS_MS_65"},
    {13,13,"RRMC_POLL_RETRAS_MS_70"},
    {14,14,"RRMC_POLL_RETRAS_MS_75"},
    {15,15,"RRMC_POLL_RETRAS_MS_80"},
    {16,16,"RRMC_POLL_RETRAS_MS_85"},
    {17,17,"RRMC_POLL_RETRAS_MS_90"},
    {18,18,"RRMC_POLL_RETRAS_MS_95"},
    {19,19,"RRMC_POLL_RETRAS_MS_100"},
    {20,20,"RRMC_POLL_RETRAS_MS_105"},
    {21,21,"RRMC_POLL_RETRAS_MS_110"},
    {22,22,"RRMC_POLL_RETRAS_MS_115"},
    {23,23,"RRMC_POLL_RETRAS_MS_120"},
    {24,24,"RRMC_POLL_RETRAS_MS_125"},
    {25,25,"RRMC_POLL_RETRAS_MS_130"},
    {26,26,"RRMC_POLL_RETRAS_MS_135"},
    {27,27,"RRMC_POLL_RETRAS_MS_140"},
    {28,28,"RRMC_POLL_RETRAS_MS_145"},
    {29,29,"RRMC_POLL_RETRAS_MS_150"},
    {30,30,"RRMC_POLL_RETRAS_MS_155"},
    {31,31,"RRMC_POLL_RETRAS_MS_160"},
    {32,32,"RRMC_POLL_RETRAS_MS_165"},
    {33,33,"RRMC_POLL_RETRAS_MS_170"},
    {34,34,"RRMC_POLL_RETRAS_MS_175"},
    {35,35,"RRMC_POLL_RETRAS_MS_180"},
    {36,36,"RRMC_POLL_RETRAS_MS_185"},
    {37,37,"RRMC_POLL_RETRAS_MS_190"},
    {38,38,"RRMC_POLL_RETRAS_MS_195"},
    {39,39,"RRMC_POLL_RETRAS_MS_200"},
    {40,40,"RRMC_POLL_RETRAS_MS_205"},
    {41,41,"RRMC_POLL_RETRAS_MS_210"},
    {42,42,"RRMC_POLL_RETRAS_MS_215"},
    {43,43,"RRMC_POLL_RETRAS_MS_220"},
    {44,44,"RRMC_POLL_RETRAS_MS_225"},
    {45,45,"RRMC_POLL_RETRAS_MS_230"},
    {46,46,"RRMC_POLL_RETRAS_MS_235"},
    {47,47,"RRMC_POLL_RETRAS_MS_240"},
    {48,48,"RRMC_POLL_RETRAS_MS_245"},
    {49,49,"RRMC_POLL_RETRAS_MS_250"},
    {50,50,"RRMC_POLL_RETRAS_MS_300"},
    {51,51,"RRMC_POLL_RETRAS_MS_350"},
    {52,52,"RRMC_POLL_RETRAS_MS_400"},
    {53,53,"RRMC_POLL_RETRAS_MS_450"},
    {54,54,"RRMC_POLL_RETRAS_MS_500"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srb_info_t_poll_pdu = -1;
static const range_string poll_pdu_values [] = {
    {0,0,"RRMC_POLL_PDU_4"},
    {1,1,"RRMC_POLL_PDU_8"},
    {2,2,"RRMC_POLL_PDU_16"},
    {3,3,"RRMC_POLL_PDU_32"},
    {4,4,"RRMC_POLL_PDU_64"},
    {5,5,"RRMC_POLL_PDU_128"},
    {6,6,"RRMC_POLL_PDU_256"},
    {7,7,"RRMC_POLL_PDU_INFINITY"},
    {0,0,"NULL"}
};

int hf_rrm_oam_srb_info_t_poll_byte = -1;
static const range_string poll_byte_values [] = {
    {0,0,"RRMC_POLL_BYTE_KB_25"},
    {1,1,"RRMC_POLL_BYTE_KB_50"},
    {2,2,"RRMC_POLL_BYTE_KB_75"},
    {3,3,"RRMC_POLL_BYTE_KB_100"},
    {4,4,"RRMC_POLL_BYTE_KB_125"},
    {5,5,"RRMC_POLL_BYTE_KB_250"},
    {6,6,"RRMC_POLL_BYTE_KB_375"},
    {7,7,"RRMC_POLL_BYTE_KB_500"},
    {8,8,"RRMC_POLL_BYTE_KB_750"},
    {9,9,"RRMC_POLL_BYTE_KB_1000"},
    {10,10,"RRMC_POLL_BYTE_KB_1250"},
    {11,11,"RRMC_POLL_BYTE_KB_1500"},
    {12,12,"RRMC_POLL_BYTE_KB_2000"},
    {13,13,"RRMC_POLL_BYTE_KB_3000"},
    {14,14,"RRMC_POLL_BYTE_KB_INFINITY"},
    {0,0,"NULL"}
};

int hf_rrm_oam_srb_info_t_max_retx_threshold = -1;
static const range_string max_retx_threshold_values [] = {
    {0,0,"RRMC_MAX_RETRANS_THRESH_1"},
    {1,1,"RRMC_MAX_RETRANS_THRESH_2"},
    {2,2,"RRMC_MAX_RETRANS_THRESH_3"},
    {3,3,"RRMC_MAX_RETRANS_THRESH_4"},
    {4,4,"RRMC_MAX_RETRANS_THRESH_6"},
    {5,5,"RRMC_MAX_RETRANS_THRESH_8"},
    {6,6,"RRMC_MAX_RETRANS_THRESH_16"},
    {7,7,"RRMC_MAX_RETRANS_THRESH_32"},
    {0,0,"NULL"}
};

int hf_rrm_oam_srb_info_t_t_reordering = -1;
static const range_string t_reordering_values [] = {
    {0,0,"RRMC_T_REORDER_MS_0"},
    {1,1,"RRMC_T_REORDER_MS_5"},
    {2,2,"RRMC_T_REORDER_MS_10"},
    {3,3,"RRMC_T_REORDER_MS_15"},
    {4,4,"RRMC_T_REORDER_MS_20"},
    {5,5,"RRMC_T_REORDER_MS_25"},
    {6,6,"RRMC_T_REORDER_MS_30"},
    {7,7,"RRMC_T_REORDER_MS_35"},
    {8,8,"RRMC_T_REORDER_MS_40"},
    {9,9,"RRMC_T_REORDER_MS_45"},
    {10,10,"RRMC_T_REORDER_MS_50"},
    {11,11,"RRMC_T_REORDER_MS_55"},
    {12,12,"RRMC_T_REORDER_MS_60"},
    {13,13,"RRMC_T_REORDER_MS_65"},
    {14,14,"RRMC_T_REORDER_MS_70"},
    {15,15,"RRMC_T_REORDER_MS_75"},
    {16,16,"RRMC_T_REORDER_MS_80"},
    {17,17,"RRMC_T_REORDER_MS_85"},
    {18,18,"RRMC_T_REORDER_MS_90"},
    {19,19,"RRMC_T_REORDER_MS_95"},
    {20,20,"RRMC_T_REORDER_MS_100"},
    {21,21,"RRMC_T_REORDER_MS_110"},
    {22,22,"RRMC_T_REORDER_MS_120"},
    {23,23,"RRMC_T_REORDER_MS_130"},
    {24,24,"RRMC_T_REORDER_MS_140"},
    {25,25,"RRMC_T_REORDER_MS_150"},
    {26,26,"RRMC_T_REORDER_MS_160"},
    {27,27,"RRMC_T_REORDER_MS_170"},
    {28,28,"RRMC_T_REORDER_MS_180"},
    {29,29,"RRMC_T_REORDER_MS_190"},
    {30,30,"RRMC_T_REORDER_MS_200"},
    {0,0,"NULL"}
};
int hf_rrm_oam_srb_info_t_t_status_prohibit = -1;
static const range_string t_status_prohibit_values [] = {
    {0,0,"RRMC_T_STATUS_PROHB_MS_0"},
    {1,1,"RRMC_T_STATUS_PROHB_MS_5"},
    {2,2,"RRMC_T_STATUS_PROHB_MS_10"},
    {3,3,"RRMC_T_STATUS_PROHB_MS_15"},
    {4,4,"RRMC_T_STATUS_PROHB_MS_20"},
    {5,5,"RRMC_T_STATUS_PROHB_MS_25"},
    {6,6,"RRMC_T_STATUS_PROHB_MS_30"},
    {7,7,"RRMC_T_STATUS_PROHB_MS_35"},
    {8,8,"RRMC_T_STATUS_PROHB_MS_40"},
    {9,9,"RRMC_T_STATUS_PROHB_MS_45"},
    {10,10,"RRMC_T_STATUS_PROHB_MS_50"},
    {11,11,"RRMC_T_STATUS_PROHB_MS_55"},
    {12,12,"RRMC_T_STATUS_PROHB_MS_60"},
    {13,13,"RRMC_T_STATUS_PROHB_MS_65"},
    {14,14,"RRMC_T_STATUS_PROHB_MS_70"},
    {15,15,"RRMC_T_STATUS_PROHB_MS_75"},
    {16,16,"RRMC_T_STATUS_PROHB_MS_80"},
    {17,17,"RRMC_T_STATUS_PROHB_MS_85"},
    {18,18,"RRMC_T_STATUS_PROHB_MS_90"},
    {19,19,"RRMC_T_STATUS_PROHB_MS_95"},
    {20,20,"RRMC_T_STATUS_PROHB_MS_100"},
    {21,21,"RRMC_T_STATUS_PROHB_MS_105"},
    {22,22,"RRMC_T_STATUS_PROHB_MS_110"},
    {23,23,"RRMC_T_STATUS_PROHB_MS_115"},
    {24,24,"RRMC_T_STATUS_PROHB_MS_120"},
    {25,25,"RRMC_T_STATUS_PROHB_MS_125"},
    {26,26,"RRMC_T_STATUS_PROHB_MS_130"},
    {27,27,"RRMC_T_STATUS_PROHB_MS_135"},
    {28,28,"RRMC_T_STATUS_PROHB_MS_140"},
    {29,29,"RRMC_T_STATUS_PROHB_MS_145"},
    {30,30,"RRMC_T_STATUS_PROHB_MS_150"},
    {31,31,"RRMC_T_STATUS_PROHB_MS_155"},
    {32,32,"RRMC_T_STATUS_PROHB_MS_160"},
    {33,33,"RRMC_T_STATUS_PROHB_MS_165"},
    {34,34,"RRMC_T_STATUS_PROHB_MS_170"},
    {35,35,"RRMC_T_STATUS_PROHB_MS_175"},
    {36,36,"RRMC_T_STATUS_PROHB_MS_180"},
    {37,37,"RRMC_T_STATUS_PROHB_MS_185"},
    {38,38,"RRMC_T_STATUS_PROHB_MS_190"},
    {39,39,"RRMC_T_STATUS_PROHB_MS_195"},
    {40,40,"RRMC_T_STATUS_PROHB_MS_200"},
    {41,41,"RRMC_T_STATUS_PROHB_MS_205"},
    {42,42,"RRMC_T_STATUS_PROHB_MS_210"},
    {43,43,"RRMC_T_STATUS_PROHB_MS_215"},
    {44,44,"RRMC_T_STATUS_PROHB_MS_220"},
    {45,45,"RRMC_T_STATUS_PROHB_MS_225"},
    {46,46,"RRMC_T_STATUS_PROHB_MS_230"},
    {47,47,"RRMC_T_STATUS_PROHB_MS_235"},
    {48,48,"RRMC_T_STATUS_PROHB_MS_240"},
    {49,49,"RRMC_T_STATUS_PROHB_MS_245"},
    {50,50,"RRMC_T_STATUS_PROHB_MS_250"},
    {51,51,"RRMC_T_STATUS_PROHB_MS_300"},
    {52,52,"RRMC_T_STATUS_PROHB_MS_350"},
    {53,53,"RRMC_T_STATUS_PROHB_MS_400"},
    {54,54,"RRMC_T_STATUS_PROHB_MS_450"},
    {55,55,"RRMC_T_STATUS_PROHB_MS_500"},
    {0,0,"NULL"}
};
int hf_rrm_oam_mobility_params_t = -1;
int hf_rrm_oam_mobility_params_t_bitmask = -1;
int hf_rrm_oam_mobility_params_t_idle_mode_mobility_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_t_reselection_utra = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_num_irat_eutran_to_utran_fdd_carriers = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_utra_carrier_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_rx_lev_min = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_qual_min = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_cell_reselection_priority = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_high = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_low = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_p_max_utra = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_offset_freq = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_highq_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_lowq_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_preemption_vulnerability = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_num_irat_eutran_to_utran_tdd_carriers = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_utra_carrier_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_q_rx_lev_min = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_cell_reselection_priority = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_high = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_low = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_p_max_utra = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_t_reselection_geran = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_count_geran_carrier = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_starting_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_band_indicator = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_count_explicit_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_data_explicit_arfcn = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_arfcn_spacing = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_num_of_following_arfcns = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_count_var_bit_map = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_data_var_bitmap = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_cell_reselection_priority = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_ncc_peritted = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_q_rx_lev_min = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_p_max_geran = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_high = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_low = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_offset_freq = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_search_window_size = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_support_for_dual_rx_ues_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_registration_param_1xrtt_v920 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_system_time_info = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_0_to_9_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_10_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_11_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_12_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_13_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_14_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_15_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_msg_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_reg_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_emg_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_thresh_x_low = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_allowed = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_zone_id = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_count = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_pre_reg_zone_id = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_sid = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_nid = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_sid = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_nid = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_zone = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_total_zone = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_zone_timer = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_packet_zone_id = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_home_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_sid_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_nid_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_parame_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_up_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_prd = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_down_reg = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_seed = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_min = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_max = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_regenerate_timer = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t_cdma2000_1xrtt_cell_id = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id_length = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_1xrtt_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_conc_ps_mobility_1xrtt_r9 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_count = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000 = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_bitmask = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_band_class = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_cell_reselection_priority = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_high = -1;
int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_low = -1;
int hf_rrm_oam_common_params_t = -1;
int hf_rrm_oam_common_params_t_bitmask = -1;
int hf_rrm_oam_common_params_t_q_hyst = -1;
static const range_string q_hyst_values [] = {
    {0,0,"RRMC_Q_HYST_DB0"},
    {1,1,"RRMC_Q_HYST_DB1"},
    {2,2,"RRMC_Q_HYST_DB2"},
    {3,3,"RRMC_Q_HYST_DB3"},
    {4,4,"RRMC_Q_HYST_DB4"},
    {5,5,"RRMC_Q_HYST_DB5"},
    {6,6,"RRMC_Q_HYST_DB6"},
    {7,7,"RRMC_Q_HYST_DB8"},
    {8,8,"RRMC_Q_HYST_DB10"},
    {9,9,"RRMC_Q_HYST_DB12"},
    {10,10,"RRMC_Q_HYST_DB14"},
    {11,11,"RRMC_Q_HYST_DB16"},
    {12,12,"RRMC_Q_HYST_DB18"},
    {13,13,"RRMC_Q_HYST_DB20"},
    {14,14,"RRMC_Q_HYST_DB22"},
    {15,15,"RRMC_Q_HYST_DB24"},
    {0,0,"NULL"}
};

int hf_rrm_oam_common_params_t_speed_state_params = -1;
int hf_rrm_oam_speed_state_params_t = -1;
int hf_rrm_oam_speed_state_params_t_q_hyst_sf_medium = -1;
static const range_string q_hyst_sf_medium_values [] = {
    {0,0,"RRMC_Q_HYST_NEG_SIX"},
    {1,1,"RRMC_Q_HYST_NEG_FOUR"},
    {2,2,"RRMC_Q_HYST_NEG_TWO"},
    {3,3,"RRMC_Q_HYST_ZERO"},
    {0,0,"NULL"}
};

int hf_rrm_oam_speed_state_params_t_q_hyst_sf_high = -1;
static const range_string q_hyst_sf_high_values [] = {
    {0,0,"RRMC_Q_HYST_NEG_SIX"},
    {1,1,"RRMC_Q_HYST_NEG_FOUR"},
    {2,2,"RRMC_Q_HYST_NEG_TWO"},
    {3,3,"RRMC_Q_HYST_ZERO"},
    {0,0,"NULL"}
};
int hf_rrm_oam_speed_state_params_t_t_evaluation = -1;
static const range_string t_evaluation_values [] = {
    {0,0,"RRMC_T_EVAL_S_30"},
    {1,1,"RRMC_T_EVAL_S_60"},
    {2,2,"RRMC_T_EVAL_S_120"},
    {3,3,"RRMC_T_EVAL_S_180"},
    {4,4,"RRMC_T_EVAL_S_240"},
    {0,0,"NULL"}
};
int hf_rrm_oam_speed_state_params_t_t_hyst_normal = -1;
static const range_string t_hyst_normal_values [] = {
    {0,0,"RRMC_T_HYST_NORMAL_S_30"},
    {1,1,"RRMC_T_HYST_NORMAL_S_60"},
    {2,2,"RRMC_T_HYST_NORMAL_S_120"},
    {3,3,"RRMC_T_HYST_NORMAL_S_180"},
    {4,4,"RRMC_T_HYST_NORMAL_S_240"},
    {0,0,"NULL"}
};
int hf_rrm_oam_speed_state_params_t_n_cell_change_medium = -1;
int hf_rrm_oam_speed_state_params_t_n_cell_change_high = -1;
int hf_rrm_oam_intra_freq_params_t = -1;
int hf_rrm_oam_intra_freq_params_t_bitmask = -1;
int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_1 = -1;
int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_offset = -1;
int hf_rrm_oam_intra_freq_params_t_p_max_sib_1 = -1;
int hf_rrm_oam_intra_freq_params_t_p_max_sib_3 = -1;
int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_3 = -1;
int hf_rrm_oam_intra_freq_params_t_s_intra_search = -1;
int hf_rrm_oam_intra_freq_params_t_t_reselection_eutra = -1;
int hf_rrm_oam_intra_freq_params_t_speed_scale_factors = -1;
int hf_rrm_oam_intra_freq_params_t_s_non_intra_search = -1;
int hf_rrm_oam_intra_freq_params_t_cell_reselection_priority = -1;
int hf_rrm_oam_intra_freq_params_t_thresh_serving_low = -1;
int hf_rrm_oam_intra_freq_params_t_neigh_cell_config = -1;
int hf_rrm_oam_speed_scale_factors_t = -1;
int hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_medium = -1;
static const range_string t_reselection_eutra_sf_medium_values [] = {
    {0,0,"RRMC_O_DOT_25"},
    {1,1,"RRMC_O_DOT_5"},
    {2,2,"RRMC_O_DOT_75"},
    {3,3,"RRMC_l_DOT_0"},
    {0,0,"NULL"}
};
int hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_high = -1;
static const range_string t_reselection_eutra_sf_high_values [] = {
    {0,0,"RRMC_O_DOT_25"},
    {1,1,"RRMC_O_DOT_5"},
    {2,2,"RRMC_O_DOT_75"},
    {3,3,"RRMC_l_DOT_0"},
    {0,0,"NULL"}
};

int hf_rrm_oam_inter_frequency_params_list_t = -1;
int hf_rrm_oam_inter_frequency_params_list_t_num_valid_inter_freq_list = -1;
int hf_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params = -1;
int hf_rrm_oam_inter_freq_params_t = -1;
int hf_rrm_oam_inter_freq_params_t_bitmask = -1;
int hf_rrm_oam_inter_freq_params_t_eutra_carrier_arfcn = -1;
int hf_rrm_oam_inter_freq_params_t_q_rx_lev_min_sib_5 = -1;
int hf_rrm_oam_inter_freq_params_t_q_offset_freq = -1;
static const range_string q_offset_freq_values [] = {
    {0,0,"RRMC_Q_OFFESET_RANGE_DB_24"},
    {1,1,"RRMC_Q_OFFESET_RANGE_DB_22"},
    {2,2,"RRMC_Q_OFFESET_RANGE_DB_20"},
    {3,3,"RRMC_Q_OFFESET_RANGE_DB_18"},
    {4,4,"RRMC_Q_OFFESET_RANGE_DB_16"},
    {5,5,"RRMC_Q_OFFESET_RANGE_DB_14"},
    {6,6,"RRMC_Q_OFFESET_RANGE_DB_12"},
    {7,7,"RRMC_Q_OFFESET_RANGE_DB_10"},
    {8,8,"RRMC_Q_OFFESET_RANGE_DB_8"},
    {9,9,"RRMC_Q_OFFESET_RANGE_DB_6"},
    {10,10,"RRMC_Q_OFFESET_RANGE_DB_5"},
    {11,11,"RRMC_Q_OFFESET_RANGE_DB_4"},
    {12,12,"RRMC_Q_OFFESET_RANGE_DB_3"},
    {13,13,"RRMC_Q_OFFESET_RANGE_DB_2"},
    {14,14,"RRMC_Q_OFFESET_RANGE_DB_1"},
    {15,15,"RRMC_Q_OFFESET_RANGE_DB0"},
    {16,16,"RRMC_Q_OFFESET_RANGE_DB1"},
    {17,17,"RRMC_Q_OFFESET_RANGE_DB2"},
    {18,18,"RRMC_Q_OFFESET_RANGE_DB3"},
    {19,19,"RRMC_Q_OFFESET_RANGE_DB4"},
    {20,20,"RRMC_Q_OFFESET_RANGE_DB5"},
    {21,21,"RRMC_Q_OFFESET_RANGE_DB6"},
    {22,22,"RRMC_Q_OFFESET_RANGE_DB8"},
    {23,23,"RRMC_Q_OFFESET_RANGE_DB10"},
    {24,24,"RRMC_Q_OFFESET_RANGE_DB12"},
    {25,25,"RRMC_Q_OFFESET_RANGE_DB14"},
    {26,26,"RRMC_Q_OFFESET_RANGE_DB16"},
    {27,27,"RRMC_Q_OFFESET_RANGE_DB18"},
    {28,28,"RRMC_Q_OFFESET_RANGE_DB20"},
    {29,29,"RRMC_Q_OFFESET_RANGE_DB22"},
    {30,30,"RRMC_Q_OFFESET_RANGE_DB24"},
    {0,0,"NULL"}
};

int hf_rrm_oam_inter_freq_params_t_t_reselection_eutra = -1;
int hf_rrm_oam_inter_freq_params_t_cell_reselection_priority = -1;
int hf_rrm_oam_inter_freq_params_t_thresh_x_high = -1;
int hf_rrm_oam_inter_freq_params_t_thresh_x_low = -1;
int hf_rrm_oam_inter_freq_params_t_p_max = -1;
int hf_rrm_oam_inter_freq_params_t_measurement_bandwidth = -1;
static const range_string measurement_bandwidth_values [] = {
    {0,0,"RRM_RRC_BW_N_6"},
    {1,1,"RRM_RRC_BW_N_15"},
    {2,2,"RRM_RRC_BW_N_25"},
    {3,3,"RRM_RRC_BW_N_50"},
    {4,4,"RRM_RRC_BW_N_75"},
    {5,5,"RRM_RRC_BW_N_100"},
    {0,0,"NULL"}
};

int hf_rrm_oam_inter_freq_params_t_presence_antenna_port1 = -1;
int hf_rrm_oam_inter_freq_params_t_neigh_cell_config = -1;
int hf_rrm_oam_inter_freq_params_t_speed_scale_factors = -1;
int hf_rrm_oam_inter_freq_params_t_q_qual_min_r9 = -1;
int hf_rrm_oam_inter_freq_params_t_threshx_q_r9 = -1;

int hf_rrm_oam_thresholdx_q_r9_t = -1;
int hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_highq_r9 = -1;
int hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_lowq_r9 = -1;

int hf_rrm_oam_rrc_timers_and_constants_t = -1;
int hf_rrm_oam_rrc_timers_and_constants_t_rrc_timers = -1;
int hf_rrm_oam_rrc_timers_and_constants_t_rrc_constants = -1;
int hf_rrm_oam_rrc_timers_t = -1;
int hf_rrm_oam_rrc_timers_t_t300 = -1;
static const range_string t300_values [] = {
    {0,0,"RRMC_TIMER_300_301_MS100"},
    {1,1,"RRMC_TIMER_300_301_MS200"},
    {2,2,"RRMC_TIMER_300_301_MS300"},
    {3,3,"RRMC_TIMER_300_301_MS400"},
    {4,4,"RRMC_TIMER_300_301_MS600"},
    {5,5,"RRMC_TIMER_300_301_MS1000"},
    {6,6,"RRMC_TIMER_300_301_MS1500"},
    {7,7,"RRMC_TIMER_300_301_MS2000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t301 = -1;
static const range_string t301_values [] = {
    {0,0,"RRMC_TIMER_300_301_MS100"},
    {1,1,"RRMC_TIMER_300_301_MS200"},
    {2,2,"RRMC_TIMER_300_301_MS300"},
    {3,3,"RRMC_TIMER_300_301_MS400"},
    {4,4,"RRMC_TIMER_300_301_MS600"},
    {5,5,"RRMC_TIMER_300_301_MS1000"},
    {6,6,"RRMC_TIMER_300_301_MS1500"},
    {7,7,"RRMC_TIMER_300_301_MS2000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t302 = -1;
static const range_string t302_values [] = {
    {0,0,"RRM_TIMER_T302_MS100"},
    {1,1,"RRM_TIMER_T302_MS200"},
    {2,2,"RRM_TIMER_T302_MS300"},
    {3,3,"RRM_TIMER_T302_MS400"},
    {4,4,"RRM_TIMER_T302_MS600"},
    {5,5,"RRM_TIMER_T302_MS1000"},
    {6,6,"RRM_TIMER_T302_MS1500"},
    {7,7,"RRM_TIMER_T302_MS2000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t304_eutra = -1;
static const range_string t304_eutra_values [] = {
    {0,0,"RRM_TIMER_T304_EUTRA_MS50"},
    {1,1,"RRM_TIMER_T304_EUTRA_MS100"},
    {2,2,"RRM_TIMER_T304_EUTRA_MS150"},
    {3,3,"RRM_TIMER_T304_EUTRA_MS200"},
    {4,4,"RRM_TIMER_T304_EUTRA_MS500"},
    {5,5,"RRM_TIMER_T304_EUTRA_MS1000"},
    {6,6,"RRM_TIMER_T304_EUTRA_MS2000"},
    {7,7,"RRM_TIMER_T304_EUTRA_SPARE1"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t304_irat = -1;
static const range_string t304_irat_values [] = {
    {0,0,"RRM_TIMER_T304_IRAT_MS100"},
    {1,1,"RRM_TIMER_T304_IRAT_MS200"},
    {2,2,"RRM_TIMER_T304_IRAT_MS500"},
    {3,3,"RRM_TIMER_T304_IRAT_MS1000"},
    {4,4,"RRM_TIMER_T304_IRAT_MS2000"},
    {5,5,"RRM_TIMER_T304_IRAT_MS4000"},
    {6,6,"RRM_TIMER_T304_IRAT_MS8000"},
    {7,7,"RRM_TIMER_T304_IRAT_SPARE1"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t310 = -1;
static const range_string t310_values [] = {
    {0,0,"RRMC_TIMER_310_MS0"},
    {1,1,"RRMC_TIMER_310_MS50"},
    {2,2,"RRMC_TIMER_310_MS100"},
    {3,3,"RRMC_TIMER_310_MS200"},
    {4,4,"RRMC_TIMER_310_MS500"},
    {5,5,"RRMC_TIMER_310_MS1000"},
    {6,6,"RRMC_TIMER_310_MS2000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t311 = -1;
static const range_string t311_values [] = {
    {0,0,"RRMC_TIMER_311_MS1000"},
    {1,1,"RRMC_TIMER_311_MS3000"},
    {2,2,"RRMC_TIMER_311_MS5000"},
    {3,3,"RRMC_TIMER_311_MS10000"},
    {4,4,"RRMC_TIMER_311_MS15000"},
    {5,5,"RRMC_TIMER_311_MS20000"},
    {6,6,"RRMC_TIMER_311_MS30000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_timers_t_t320 = -1;
static const range_string t320_values [] = {
    {0,0,"RRM_TIMER_T320_MIN5"},
    {1,1,"RRM_TIMER_T320_MIN10"},
    {2,2,"RRM_TIMER_T320_MIN20"},
    {3,3,"RRM_TIMER_T320_MIN30"},
    {4,4,"RRM_TIMER_T320_MIN60"},
    {5,5,"RRM_TIMER_T320_MIN120"},
    {6,6,"RRM_TIMER_T320_MIN180"},
    {7,7,"RRM_TIMER_T320_SPARE1"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rrc_constants_t = -1;
int hf_rrm_oam_rrc_constants_t_n310 = -1;
static const range_string n310_values [] = {
    {0,0,"RRMC_TIMER_N310_N1"},
    {1,1,"RRMC_TIMER_N310_N2"},
    {2,2,"RRMC_TIMER_N310_N3"},
    {3,3,"RRMC_TIMER_N310_N4"},
    {4,4,"RRMC_TIMER_N310_N6"},
    {5,5,"RRMC_TIMER_N310_N8"},
    {6,6,"RRMC_TIMER_N310_N10"},
    {7,7,"RRMC_TIMER_N310_N20"},
    {0,0,"NULL"}
};

int hf_rrm_oam_rrc_constants_t_n311 = -1;
static const range_string n311_values [] = {
    {0,0,"RRMC_TIMER_N311_N1"},
    {1,1,"RRMC_TIMER_N311_N2"},
    {2,2,"RRMC_TIMER_N311_N3"},
    {3,3,"RRMC_TIMER_N311_N4"},
    {4,4,"RRMC_TIMER_N311_N6"},
    {5,5,"RRMC_TIMER_N311_N8"},
    {6,6,"RRMC_TIMER_N311_N10"},
    {0,0,"NULL"}
};

int hf_rrm_oam_rf_params_t = -1;
int hf_rrm_oam_rf_params_t_rf_configurations = -1;
int hf_rrm_oam_rf_configurations_t = -1;
int hf_rrm_oam_rf_configurations_t_bitmask = -1;
int hf_rrm_oam_rf_configurations_t_frequency_band_indicator = -1;
int hf_rrm_oam_rf_configurations_t_dl_earfcn = -1;
int hf_rrm_oam_rf_configurations_t_dl_bandwidth = -1;
static const range_string dl_bandwidth_values [] = {
    {0,0,"RRMC_BW_N_6"},
    {1,1,"RRMC_BW_N_15"},
    {2,2,"RRMC_BW_N_25"},
    {3,3,"RRMC_BW_N_50"},
    {4,4,"RRMC_BW_N_75"},
    {5,5,"RRMC_BW_N_100"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rf_configurations_t_ul_earfcn = -1;
int hf_rrm_oam_rf_configurations_t_ul_bandwidth = -1;
static const range_string ul_bandwidth_values [] = {
    {0,0,"RRMC_BW_N_6"},
    {1,1,"RRMC_BW_N_15"},
    {2,2,"RRMC_BW_N_25"},
    {3,3,"RRMC_BW_N_50"},
    {4,4,"RRMC_BW_N_75"},
    {5,5,"RRMC_BW_N_100"},
    {0,0,"NULL"}
};
int hf_rrm_oam_rf_configurations_t_reference_signal_power = -1;
int hf_rrm_oam_rf_configurations_t_phy_cell_id = -1;
int hf_rrm_oam_rf_configurations_t_psch_power_offset = -1;
int hf_rrm_oam_rf_configurations_t_ssch_power_offset = -1;
int hf_rrm_oam_rf_configurations_t_pbch_power_offset = -1;
int hf_rrm_oam_rf_configurations_t_max_rs_epre = -1;
int hf_rrm_oam_s1ap_params_t = -1;
int hf_rrm_oam_s1ap_params_t_t_reloc_prep = -1;
int hf_rrm_oam_s1ap_params_t_t_reloc_overall = -1;
int hf_rrm_oam_ncl_params_t = -1;
int hf_rrm_oam_ncl_params_t_bitmask = -1;
int hf_rrm_oam_ncl_params_t_lte_ncl = -1;
int hf_rrm_oam_ncl_params_t_inter_rat_ncl = -1;
int hf_rrm_oam_inter_rat_ncl_t_unparsed_data = -1;
int hf_rrm_oam_inter_rat_ncl_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_num_valid_utran_freq_cell = -1;
int hf_rrm_oam_inter_rat_ncl_t_utran_freq_cells = -1;
int hf_rrm_oam_inter_rat_ncl_t_num_valid_geran_freq_cell = -1;
int hf_rrm_oam_inter_rat_ncl_t_geran_freq_cells = -1;
int hf_rrm_oam_inter_rat_ncl_t_num_valid_cdma2000_freq_cells = -1;
int hf_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ura = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcnul = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcndl = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_scrambling_code = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_tx_power = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_offset_freq = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_cell_access_mode = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_blacklisted = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_csg_identity = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ho_status = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ps_ho_supported = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_voip_capable = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_daho_indication = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_rac = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_lac = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_cell_id = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bandindicator = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bccharfcn = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_pci = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_network_control_order = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_ho_status = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_supported = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_ho_supported = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_voip_capable = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_daho_indication = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_band_class = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_arfcn = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_pn_offset = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_type = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_num_valid_count_cid = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_CID = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_daho_indication = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_p_rev = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_min_p_rev = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_neg_slot_cycle_index_sup = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_encrypt_mode = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_enc_supported = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_encrypt_sup = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_msg_integrity_sup = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup_incl = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_ms_init_pos_loc_sup_ind = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class_info_req = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_alt_band_class = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_mode_supported = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_id = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_t_add = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pilot_inc = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_enabled = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_info_incl = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_list_len = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_act_timer = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_mul = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_exp = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_bitmask = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc3 = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc4 = -1;
int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc5 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_unparsed_data = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_bitmask = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_bitmask = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a3_offset = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_on_leave = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrq = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_hysteresis = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_time_to_trigger = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_trigger_quantity = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_quantity = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_interval = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_amount = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_ps_ho_enabled = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_bitmask = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_qoffset_tutra = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_utra = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_fdd = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_tdd = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_rscp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_ecn0 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_geran = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_geran = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_geran = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_cdma2000 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_cdma2000 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_cdma2000 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_rscp = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_ecn0 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2geran = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2cdma = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_hysteresis = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_time_to_trigger = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_max_report_cells = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_interval = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_amount = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ps_ho_enabled = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bitmask = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auth = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_num_alt_so = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_use_sync_id = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mob_qos = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bypass_reg_ind = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_add_serv_instance = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_parameter_reg = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reg_dist = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pref_msid_type = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_ext_pref_msid_type = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_meid_reqd = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mcc = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_11_12 = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_t_supported = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reconnect_msg_ind = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_rer_mode_supported = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pilot_report = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_supported = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auto_fcso_allowed = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_in_rcnm_ind = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_daylt = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_l2_ack_timer = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_sequence_context_timer = -1;
int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_lp_sec = -1;
int hf_rrm_utran_cell_id_t = -1;
int hf_rrm_utran_cell_id_t_bitmask = -1;
int hf_rrm_utran_cell_id_t_cell_id = -1;
int hf_rrm_utran_cell_id_t_rnc_id = -1;
int hf_rrm_utran_cell_id_t_extended_rnc_id = -1;
int hf_rrm_oam_lte_ncl_t = -1;
int hf_rrm_oam_lte_ncl_t_num_valid_intra_freq_cell = -1;
int hf_rrm_oam_lte_ncl_t_intra_freq_cells = -1;
int hf_rrm_oam_lte_ncl_t_num_valid_inter_freq_cell = -1;
int hf_rrm_oam_lte_ncl_t_inter_freq_cells = -1;
int hf_rrm_oam_intra_freq_cells_t = -1;
int hf_rrm_oam_intra_freq_cells_t_bitmask = -1;
int hf_rrm_oam_intra_freq_cells_t_cell_id = -1;

int hf_rrm_oam_intra_freq_cells_t_phy_cell_id = -1;
int hf_rrm_oam_intra_freq_cells_t_q_offset = -1;
int hf_rrm_oam_intra_freq_cells_t_cell_individual_offset = -1;
static const range_string cio_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_intra_freq_cells_t_r_stx_power = -1;
int hf_rrm_oam_intra_freq_cells_t_blacklisted = -1;
int hf_rrm_oam_intra_freq_cells_t_cell_access_mode = -1;
int hf_rrm_oam_intra_freq_cells_t_csg_identity = -1;
int hf_rrm_oam_intra_freq_cells_t_ho_status = -1;
int hf_rrm_oam_intra_freq_cells_t_x2_status = -1;
int hf_rrm_oam_intra_freq_cells_t_broadcast_status = -1;
int hf_rrm_oam_intra_freq_cells_t_tac = -1;
int hf_rrm_oam_intra_freq_cells_t_daho_indication = -1;
static const range_string blacklisted_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_inter_freq_cells_t = -1;
int hf_rrm_oam_inter_freq_cells_t_bitmask = -1;
int hf_rrm_oam_inter_freq_cells_t_cell_id = -1;
int hf_rrm_oam_inter_freq_cells_t_eutra_carrier_arfcn = -1;
int hf_rrm_oam_inter_freq_cells_t_phy_cell_id = -1;
int hf_rrm_oam_inter_freq_cells_t_q_offset = -1;
static const range_string q_offset_values [] = {
    {0,0,"RRMC_Q_OFFESET_RANGE_DB_24"},
    {1,1,"RRMC_Q_OFFESET_RANGE_DB_22"},
    {2,2,"RRMC_Q_OFFESET_RANGE_DB_20"},
    {3,3,"RRMC_Q_OFFESET_RANGE_DB_18"},
    {4,4,"RRMC_Q_OFFESET_RANGE_DB_16"},
    {5,5,"RRMC_Q_OFFESET_RANGE_DB_14"},
    {6,6,"RRMC_Q_OFFESET_RANGE_DB_12"},
    {7,7,"RRMC_Q_OFFESET_RANGE_DB_10"},
    {8,8,"RRMC_Q_OFFESET_RANGE_DB_8"},
    {9,9,"RRMC_Q_OFFESET_RANGE_DB_6"},
    {10,10,"RRMC_Q_OFFESET_RANGE_DB_5"},
    {11,11,"RRMC_Q_OFFESET_RANGE_DB_4"},
    {12,12,"RRMC_Q_OFFESET_RANGE_DB_3"},
    {13,13,"RRMC_Q_OFFESET_RANGE_DB_2"},
    {14,14,"RRMC_Q_OFFESET_RANGE_DB_1"},
    {15,15,"RRMC_Q_OFFESET_RANGE_DB0"},
    {16,16,"RRMC_Q_OFFESET_RANGE_DB1"},
    {17,17,"RRMC_Q_OFFESET_RANGE_DB2"},
    {18,18,"RRMC_Q_OFFESET_RANGE_DB3"},
    {19,19,"RRMC_Q_OFFESET_RANGE_DB4"},
    {20,20,"RRMC_Q_OFFESET_RANGE_DB5"},
    {21,21,"RRMC_Q_OFFESET_RANGE_DB6"},
    {22,22,"RRMC_Q_OFFESET_RANGE_DB8"},
    {23,23,"RRMC_Q_OFFESET_RANGE_DB10"},
    {24,24,"RRMC_Q_OFFESET_RANGE_DB12"},
    {25,25,"RRMC_Q_OFFESET_RANGE_DB14"},
    {26,26,"RRMC_Q_OFFESET_RANGE_DB16"},
    {27,27,"RRMC_Q_OFFESET_RANGE_DB18"},
    {28,28,"RRMC_Q_OFFESET_RANGE_DB20"},
    {29,29,"RRMC_Q_OFFESET_RANGE_DB22"},
    {30,30,"RRMC_Q_OFFESET_RANGE_DB24"},
    {0,0,"NULL"}
};

int hf_rrm_oam_inter_freq_cells_t_cell_individual_offset = -1;
int hf_rrm_oam_inter_freq_cells_t_r_stx_power = -1;
int hf_rrm_oam_inter_freq_cells_t_blacklisted = -1;
int hf_rrm_oam_epc_t = -1;
int hf_rrm_oam_epc_t_epc_params = -1;
int hf_rrm_oam_epc_params_t = -1;
int hf_rrm_oam_epc_params_t_bitmask = -1;
int hf_rrm_oam_epc_params_t_general_epc_params = -1;
int hf_rrm_oam_epc_params_t_num_valid_qos_profiles = -1;
int hf_rrm_oam_epc_params_t_emergency_erab_arp = -1;
int hf_rrm_oam_epc_params_t_qos_config_params = -1;
int hf_rrm_oam_general_epc_params_t = -1;
int hf_rrm_oam_general_epc_params_t_bitmask = -1;
int hf_rrm_oam_general_epc_params_t_num_valid_plmn = -1;
int hf_rrm_oam_general_epc_params_t_plmn_list = -1;
int hf_rrm_oam_general_epc_params_t_tac = -1;
int hf_rrm_oam_general_epc_params_t_eaid = -1;
int hf_rrm_oam_plmn_access_info_t = -1;
int hf_rrm_oam_plmn_access_info_t_plmn_info = -1;
int hf_rrm_oam_plmn_access_info_t_reserve_operator_use = -1;
int hf_rrm_oam_qos_config_params_t = -1;
int hf_rrm_oam_qos_config_params_t_bitmask = -1;
int hf_rrm_oam_qos_config_params_t_qci = -1;
int hf_rrm_oam_qos_config_params_t_type = -1;
static const range_string type_values [] = {
    {0,0,"gbr"},
    {1,1,"non_gbr"},
    {0,0,"NULL"}
};

int hf_rrm_oam_qos_config_params_t_priority = -1;
int hf_rrm_oam_qos_config_params_t_packet_delay_budget = -1;
int hf_rrm_oam_qos_config_params_t_packet_error_loss_rate = -1;
int hf_rrm_oam_qos_config_params_t_dscp = -1;
int hf_rrm_oam_qos_config_params_t_rlc_mode = -1;
int hf_rrm_oam_qos_config_params_t_lossless_ho_required = -1;
int hf_rrm_oam_qos_config_params_t_ue_inactivity_timer_config = -1;
int hf_rrm_oam_qos_config_params_t_max_harq_tx = -1;
int hf_rrm_oam_qos_config_params_t_max_harq_retrans = -1;
int hf_rrm_oam_qos_config_params_t_logical_channel_grouping_on_off = -1;
int hf_rrm_oam_qos_config_params_t_max_rlc_transmissions = -1;
int hf_rrm_oam_qos_config_params_t_rohc_params = -1;
int hf_rrm_oam_qos_config_params_t_sn_field_len = -1;
int hf_rrm_oam_qos_config_params_t_sps_config_enabled = -1;
int hf_rrm_oam_qos_config_params_t_sps_data = -1;
int hf_rrm_oam_qos_config_params_t_supported_rat = -1;
int hf_rrm_oam_qos_config_params_t_dl_min_bitrate = -1;
int hf_rrm_oam_qos_config_params_t_ul_min_bitrate = -1;
int hf_rrm_oam_qos_config_params_t_addl_rlc_param = -1;
int hf_rrm_oam_qos_config_params_t_addl_mac_param = -1;
int hf_rrm_oam_pdcp_rohc_params_t = -1;
int hf_rrm_oam_pdcp_rohc_params_t_bitmask = -1;
int hf_rrm_oam_pdcp_rohc_params_t_enable_rohc = -1;
int hf_rrm_oam_pdcp_rohc_params_t_rohc_pofiles = -1;
int hf_rrm_oam_pdcp_rohc_params_t_max_cid = -1;
int hf_rrm_oam_rohc_pofiles_t = -1;
int hf_rrm_oam_rohc_pofiles_t_bitmask = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0001 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0002 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0003 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0004 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0006 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0101 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0102 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0103 = -1;
int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0104 = -1;
int hf_rrm_oam_sn_field_len_t = -1;
int hf_rrm_oam_sn_field_len_t_bitmask = -1;
int hf_rrm_oam_sn_field_len_t_dl_rlc = -1;
int hf_rrm_oam_sn_field_len_t_ul_rlc = -1;
int hf_rrm_oam_sn_field_len_t_dl_pdcp = -1;
int hf_rrm_oam_sn_field_len_t_ul_pdcp = -1;
int hf_rrm_oam_sps_config_data_t = -1;
int hf_rrm_oam_sps_config_data_t_bitmask = -1;
int hf_rrm_oam_sps_config_data_t_sps_config_dl = -1;
int hf_rrm_oam_sps_config_data_t_sps_config_ul = -1;
int hf_rrm_oam_sps_config_dl_t = -1;
int hf_rrm_oam_sps_config_dl_t_bitmask = -1;
int hf_rrm_oam_sps_config_dl_t_semi_persist_sched_interval_dl = -1;
int hf_rrm_oam_sps_config_dl_t_number_of_conf_sps_processes = -1;
int hf_rrm_oam_sps_config_dl_t_max_sps_harq_retx = -1;
int hf_rrm_oam_sps_config_dl_t_explicit_release_after = -1;
int hf_rrm_oam_sps_config_ul_t = -1;
int hf_rrm_oam_sps_config_ul_t_bitmask = -1;
int hf_rrm_oam_sps_config_ul_t_semi_persist_sched_interval_ul = -1;
int hf_rrm_oam_sps_config_ul_t_implicit_release_after = -1;
int hf_rrm_oam_sps_config_ul_t_p_zero_nominal_pusch_persistent = -1;
int hf_rrm_oam_addl_rlc_params_t = -1;
int hf_rrm_oam_addl_rlc_params_t_bitmask = -1;
int hf_rrm_oam_addl_rlc_params_t_t_poll_pdu = -1;
int hf_rrm_oam_addl_rlc_params_t_t_reordering = -1;
int hf_rrm_oam_addl_rlc_params_t_t_poll_retransmit = -1;
int hf_rrm_oam_addl_rlc_params_t_t_status_prohibit = -1;
int hf_rrm_oam_addl_mac_params_t = -1;
int hf_rrm_oam_addl_mac_params_t_bitmask = -1;
int hf_rrm_oam_addl_mac_params_t_phr_config = -1;
int hf_rrm_oam_addl_mac_params_t_bsr_config = -1;
int hf_rrm_oam_phr_config_t = -1;
int hf_rrm_oam_phr_config_t_bitmask = -1;
int hf_rrm_oam_phr_config_t_t_periodic_phr = -1;
int hf_rrm_oam_phr_config_t_t_prohibit_phr = -1;
int hf_rrm_oam_phr_config_t_t_pathloss_chng = -1;
int hf_rrm_oam_bsr_config_t = -1;
int hf_rrm_oam_bsr_config_t_bitmask = -1;
int hf_rrm_oam_bsr_config_t_t_periodic_bsr = -1;
int hf_rrm_oam_bsr_config_t_t_retx_bsr = -1;


static const range_string packet_delay_budget_values [] = {
    {0,0,"PACKET_DELAY_BUDGET_MS50"},
    {1,1,"PACKET_DELAY_BUDGET_MS100"},
    {2,2,"PACKET_DELAY_BUDGET_MS150"},
    {3,3,"PACKET_DELAY_BUDGET_MS200"},
    {4,4,"PACKET_DELAY_BUDGET_MS300"},
    {5,5,"PACKET_DELAY_BUDGET_MS400"},
    {6,6,"PACKET_DELAY_BUDGET_MS500"},
    {7,7,"PACKET_DELAY_BUDGET_MS600"},
    {8,8,"PACKET_DELAY_BUDGET_MS700"},
    {9,9,"PACKET_DELAY_BUDGET_MS800"},
    {10,10,"PACKET_DELAY_BUDGET_MS900"},
    {11,11,"PACKET_DELAY_BUDGET_MS1000"},
    {12,12,"PACKET_DELAY_BUDGET_MS1500"},
    {13,13,"PACKET_DELAY_BUDGET_MS2000"},
    {0,0,"NULL"}
};
int hf_rrm_oam_operator_info_t = -1;
int hf_rrm_oam_operator_info_t_bitmask = -1;
int hf_rrm_oam_operator_info_t_simultaneous_ack_nack_and_cqi = -1;
int hf_rrm_oam_operator_info_t_rrm_mac_config = -1;
int hf_rrm_oam_operator_info_t_phich_config = -1;
int hf_rrm_oam_operator_info_t_sib_1_info = -1;
int hf_rrm_oam_operator_info_t_sib_2_info = -1;
int hf_rrm_oam_operator_info_t_sib_3_info = -1;
int hf_rrm_oam_operator_info_t_sib_4_info = -1;
int hf_rrm_oam_operator_info_t_admission_control_info = -1;
int hf_rrm_oam_operator_info_t_additional_packet_scheduling_params = -1;
int hf_rrm_oam_operator_info_t_additional_cell_params = -1;
int hf_rrm_oam_operator_info_t_load_params = -1;
int hf_rrm_oam_operator_info_t_mimo_mode_params = -1;
int hf_rrm_oam_operator_info_t_ho_configuration = -1;
int hf_rrm_oam_operator_info_t_measurement_configuration = -1;
int hf_rrm_oam_operator_info_t_cell_capacity_class = -1;
int hf_rrm_oam_operator_info_t_cell_type = -1;
int hf_rrm_oam_operator_info_t_rrm_eutran_access_point_pos = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t_bitmask = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t_dl_mcs = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t_ul_mcs = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t_frequency_selective_scheduling = -1;
int hf_rrm_oam_adl_pkt_scheduling_params_t_cqi_reporting_mode = -1;
int hf_rrm_oam_adl_cell_params_t = -1;
int hf_rrm_oam_adl_cell_params_t_bitmask = -1;
int hf_rrm_oam_adl_cell_params_t_sub_carrier_spacing = -1;
int hf_rrm_oam_adl_cell_params_t_dl_cyclic_prefix = -1;
int hf_rrm_oam_load_params_t = -1;
int hf_rrm_oam_load_params_t_bitmask = -1;
int hf_rrm_oam_load_params_t_wait_time = -1;
int hf_rrm_oam_mimo_mode_params_t = -1;
int hf_rrm_oam_mimo_mode_params_t_bitmask = -1;
int hf_rrm_oam_mimo_mode_params_t_antenna_ports_count_number = -1;
int hf_rrm_oam_mimo_mode_params_t_supported_tx_mode = -1;
int hf_rrm_oam_ho_config_params_t = -1;
int hf_rrm_oam_ho_config_params_t_bitmask = -1;
int hf_rrm_oam_ho_config_params_t_target_cell_selection_params = -1;
int hf_rrm_oam_ho_config_params_t_ho_algo_params = -1;
int hf_rrm_oam_ho_config_params_t_ho_retry_params = -1;
int hf_rrm_oam_ho_config_params_t_blind_ho_timer = -1;
int hf_rrm_oam_target_cell_selection_params_t = -1;
int hf_rrm_oam_target_cell_selection_params_t_bitmask = -1;
int hf_rrm_oam_target_cell_selection_params_t_neighboring_cell_load_based_ho_enable = -1;
int hf_rrm_oam_target_cell_selection_params_t_ue_history_based_ho_enable = -1;
int hf_rrm_oam_target_cell_selection_params_t_spid_based_ho_enable = -1;
int hf_rrm_oam_target_cell_selection_params_t_ue_measurement_based_ho_enable = -1;
int hf_rrm_oam_target_cell_selection_params_t_daho_cell_based_ho_enable = -1;
int hf_rrm_oam_ho_algo_params_t = -1;
int hf_rrm_oam_ho_algo_params_t_bitmask = -1;
int hf_rrm_oam_ho_algo_params_t_enb_measurements_for_ho = -1;
int hf_rrm_oam_ho_algo_params_t_ue_meas_trigger_quantity_for_ho = -1;
int hf_rrm_oam_ho_algo_params_t_coverage_based_ho = -1;
int hf_rrm_oam_ho_algo_params_t_intra_freq_ho = -1;
int hf_rrm_oam_ho_algo_params_t_inter_freq_ho = -1;
int hf_rrm_oam_ho_algo_params_t_inter_rat_ho = -1;
int hf_rrm_oam_ho_retry_params_t = -1;
int hf_rrm_oam_ho_retry_params_t_bitmask = -1;
int hf_rrm_oam_ho_retry_params_t_ho_retry_enable = -1;
int hf_rrm_oam_ho_retry_params_t_ho_retry_count = -1;
int hf_rrm_oam_meas_config_t = -1;
int hf_rrm_oam_meas_config_t_bitmask = -1;
int hf_rrm_oam_meas_config_t_report_trigger_type = -1;
int hf_rrm_oam_meas_config_t_meas_gap_config = -1;
int hf_rrm_oam_meas_config_t_si_gap_enable = -1;
int hf_rrm_oam_meas_config_t_csfb_tgt_selection = -1;
int hf_rrm_oam_meas_gap_config_t = -1;
int hf_rrm_oam_meas_gap_config_t_bitmask = -1;
int hf_rrm_oam_meas_gap_config_t_eutran_gap_offset_type = -1;
int hf_rrm_oam_meas_gap_config_t_utran_gap_offset_type = -1;
int hf_rrm_oam_meas_gap_config_t_geran_gap_offset_type = -1;
int hf_rrm_oam_meas_gap_config_t_cdma2000_gap_offset_type = -1;
int hf_rrm_csfb_tgt_selection_t = -1;
int hf_rrm_csfb_tgt_selection_t_bitmask = -1;
int hf_rrm_csfb_tgt_selection_t_utran_csfb_tgt_selection = -1;
int hf_rrm_csfb_tgt_selection_t_geran_csfb_tgt_selection = -1;
int hf_rrm_csfb_tgt_selection_t_cdma2000_csfb_tgt_selection = -1;
int hf_rrm_oam_eutran_access_point_pos_t = -1;
int hf_rrm_oam_eutran_access_point_pos_t_bitmask = -1;
int hf_rrm_oam_eutran_access_point_pos_t_latitude_sign = -1;
int hf_rrm_oam_eutran_access_point_pos_t_deg_of_latitude = -1;
int hf_rrm_oam_eutran_access_point_pos_t_deg_of_longitude = -1;
int hf_rrm_oam_eutran_access_point_pos_t_dir_of_altitude = -1;
int hf_rrm_oam_eutran_access_point_pos_t_altitude = -1;
int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_major = -1;
int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_minor = -1;
int hf_rrm_oam_eutran_access_point_pos_t_orientation_of_major_axis = -1;
int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_altitude = -1;
int hf_rrm_oam_eutran_access_point_pos_t_confidence = -1;
int hf_rrm_oam_path_loss_to_target_sinr_map_info_t = -1;
int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_start_PL = -1;
int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_end_PL = -1;
int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_target_SINR = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_bitmask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_icic_scheme_type = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_min_rb_for_pl_phr_calc = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_mu_mimo_type = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_msc_threshold_ul_mu_mimo = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_x2ap_icic_report_periodicity = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pa_for_ce_ue = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_bitmask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_edge_region = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_center_region = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_start_rb = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_num_of_rb = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_center_user_power_mask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_edge_user_power_mask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_qci_delta_power_mask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_bitmask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_report_on_X2_required = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_threshold = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_max_nominal_epre = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_default_path_loss = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_count = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_bitmask = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_count = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_aggregation_level = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_power_offset = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t_cqi_to_phich_power_info = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_dci_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_Occasion_Per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti_per_interval = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_dci_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_Occasion_Per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti_per_interval = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_up_factor = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_down_factor = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_adjust_factor = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_mcs_index_for_atb = -1;
int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_prb_val_for_atb = -1;
int hf_rrm_oam_rrmc_mac_config_t = -1;
int hf_rrm_oam_rrmc_mac_config_t_start_rarnti_range = -1;
int hf_rrm_oam_rrmc_mac_config_t_end_rarnti_range = -1;
int hf_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch = -1;
int hf_rrm_oam_rrmc_mac_config_t_ue_inactive_time_config = -1;
int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t = -1;
int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_ul_freq_selective_enable = -1;
int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_dl_freq_selective_enable = -1;
int hf_rrm_oam_phy_phich_configuration_t = -1;
int hf_rrm_oam_phy_phich_configuration_t_phich_resource = -1;
int hf_rrm_oam_phy_phich_configuration_t_phich_duration = -1;
int hf_rrm_oam_sib_type_1_info_t = -1;
int hf_rrm_oam_sib_type_1_info_t_bitmask = -1;
int hf_rrm_oam_sib_type_1_info_t_ims_emergency_support_r9 = -1;
int hf_rrm_oam_sib_type_1_info_t_si_window_length = -1;
int hf_rrm_oam_sib_type_1_info_t_si_count = -1;
int hf_rrm_oam_sib_type_1_info_t_scheduling_info = -1;
int hf_rrm_oam_scheduling_info_t = -1;
int hf_rrm_oam_scheduling_info_t_si_periodicity = -1;
int hf_rrm_oam_scheduling_info_t_sib_mapping_info = -1;
int hf_rrm_oam_sib_mapping_info_t = -1;
int hf_rrm_oam_sib_mapping_info_t_sib_type = -1;
static const range_string ims_emergency_support_r9_values [] = {
    {0,0,"RRM_FALSE"},
    {1,1,"RRM_TRUE"},
    {0,0,"NULL"}
};
int hf_rrm_oam_sib_type_1_info_t_cell_selection_info = -1;
int hf_rrm_oam_cell_selection_info_v920_t = -1;
int hf_rrm_oam_cell_selection_info_v920_t_bitmask = -1;
int hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_r9 = -1;
int hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_offset_r9_present = -1;

int hf_rrm_oam_sib_type_2_info_t = -1;
int hf_rrm_oam_sib_type_2_info_t_bitmask = -1;
int hf_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib = -1;
int hf_rrm_oam_sib_type_2_info_t_additional_spectrum_emission = -1;
int hf_rrm_oam_sib_type_2_info_t_rrm_freq_info = -1;
int hf_rrm_oam_sib_type_2_info_t_time_alignment_timer_common = -1;

int hf_rrm_oam_radio_resource_config_common_sib_t = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_bitmask = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_modification_period_coeff = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_default_paging_cycle = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_nB = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config = -1;
int hf_rrm_oam_radio_resource_config_common_sib_t_ul_cyclic_prefix_length = -1;
static const range_string ul_cyclic_prefix_length_values [] = {
    {0,0,"RRM_RRC_UL_CYC_PREFIX_LEN_1"},
    {1,1,"RRM_RRC_UL_CYC_PREFIX_LEN_2"},
    {0,0,"NULL"}
};
int hf_rrm_oam_bcch_config_t = -1;
int hf_rrm_oam_bcch_config_t_bitmask = -1;
int hf_rrm_oam_bcch_config_t_modification_period_coeff = -1;
static const range_string modification_period_coeff_values [] = {
    {0,0,"RRM_RRC_MOD_PERIOD_COEFF_N2"},
    {1,1,"RRM_RRC_MOD_PERIOD_COEFF_N4"},
    {2,2,"RRM_RRC_MOD_PERIOD_COEFF_N8"},
    {3,3,"RRM_RRC_MOD_PERIOD_COEFF_N16"},
    {0,0,"NULL"}
};

int hf_rrm_oam_pcch_config_t = -1;
int hf_rrm_oam_pcch_config_t_bitmask = -1;
int hf_rrm_oam_pcch_config_t_default_paging_cycle = -1;
static const range_string default_paging_cycle_values [] = {
    {0,0,"RRM_RRC_DEF_PAG_CYCLE_RF32"},
    {1,1,"RRM_RRC_DEF_PAG_CYCLE_RF64"},
    {2,2,"RRM_RRC_DEF_PAG_CYCLE_RF128"},
    {3,3,"RRM_RRC_DEF_PAG_CYCLE_RF256"},
    {0,0,"NULL"}
};

int hf_rrm_oam_pcch_config_t_nB = -1;
static const range_string nB_values [] = {
    {0,0,"RRM_RRC_NB_FOUR_T"},
    {1,1,"RRM_RRC_NB_TWO_T"},
    {2,2,"RRM_RRC_NB_ONE_T"},
    {3,3,"RRM_RRC_NB_HALF_T"},
    {4,4,"RRM_RRC_NB_QUARTER_T"},
    {5,5,"RRM_RRC_NB_ONE_EIGHTH_T"},
    {6,6,"RRM_RRC_NB_ONE_SIXTEENTH_T"},
    {7,7,"RRM_RRC_NB_ONE_THIRTY_SECOND_T"},
    {0,0,"NULL"}
};

int hf_rrm_oam_freq_info_t = -1;
int hf_rrm_oam_freq_info_t_additional_spectrum_emission = -1;
int hf_rrm_oam_sib_type_3_info_t = -1;
int hf_rrm_oam_sib_type_3_info_t_bitmask = -1;
int hf_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info = -1;
int hf_rrm_oam_sib_type_3_info_t_s_intra_search = -1;
int hf_rrm_oam_sib_type_3_info_t_s_non_intra_search = -1;
int hf_rrm_oam_sib_type_3_info_t_q_qual_min_r9 = -1;
int hf_rrm_oam_sib_type_3_info_t_thresh_serving_lowq_r9 = -1;
int hf_rrm_oam_intra_freq_cell_reselection_info_t = -1;
int hf_rrm_oam_intra_freq_cell_reselection_info_t_bitmask = -1;
int hf_rrm_oam_intra_freq_cell_reselection_info_t_measurement_bandwidth = -1;
int hf_rrm_oam_intra_freq_cell_reselection_info_t_presence_antenna_port1 = -1;
int hf_rrm_oam_s_intra_search_v920_t = -1;
int hf_rrm_oam_s_intra_search_v920_t_s_intra_search_p_r9 = -1;
int hf_rrm_oam_s_intra_search_v920_t_s_intra_search_q_r9 = -1;
int hf_rrm_oam_s_non_intra_search_v920_t = -1;
int hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_p_r9 = -1;
int hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_q_r9 = -1;
int hf_rrm_oam_sib_type_4_info_t = -1;
int hf_rrm_oam_sib_type_4_info_t_csg_id_range = -1;
int hf_rrm_oam_csg_cell_id_range_t = -1;
int hf_rrm_oam_csg_cell_id_range_t_bitmask = -1;
int hf_rrm_oam_csg_cell_id_range_t_start = -1;
int hf_rrm_oam_csg_cell_id_range_t_range = -1;
static const range_string range_values [] = {
    {0,0,"n4"},
    {1,1,"n8"},
    {2,2,"n12"},
    {3,3,"n16"},
    {4,4,"n24"},
    {5,5,"n32"},
    {6,6,"n48"},
    {7,7,"n64"},
    {8,8,"n84"},
    {9,9,"n96"},
    {10,10,"n128"},
    {11,11,"n168"},
    {12,12,"n252"},
    {13,13,"spare2"},
    {14,14,"spare1"},
    {0,0,"NULL"}
};
int hf_rrm_oam_admission_control_info_t = -1;
int hf_rrm_oam_admission_control_info_t_bitmask = -1;
int hf_rrm_oam_admission_control_info_t_max_num_ue_per_cell = -1;
int hf_rrm_oam_admission_control_info_t_max_sps_ues = -1;
int hf_rrm_oam_admission_control_info_t_max_num_drbs_per_ue = -1;
int hf_rrm_oam_admission_control_info_t_max_num_gbr_drbs_per_ue = -1;
int hf_rrm_oam_admission_control_info_t_max_num_non_gbr_drbs_per_ue = -1;
int hf_rrm_oam_admission_control_info_t_dl_prb_budget = -1;
int hf_rrm_oam_admission_control_info_t_ul_prb_budget = -1;
int hf_rrm_oam_admission_control_info_t_dl_prb_budget_gbr = -1;
int hf_rrm_oam_admission_control_info_t_ul_prb_budget_gbr = -1;
int hf_rrm_oam_admission_control_info_t_dl_prb_budget_ngbr = -1;
int hf_rrm_oam_admission_control_info_t_ul_prb_budget_ngbr = -1;
int hf_rrm_oam_admission_control_info_t_available_gbr_limit ;
int hf_rrm_oam_admission_control_info_t_resource_reserved_for_existing_users ;
int hf_rrm_oam_admission_control_info_t_total_backhaul_capacity ;
int hf_rrm_oam_admission_control_info_t_capacity_threshold ;
int hf_rrm_oam_admission_control_info_t_spid_table ;
int hf_rrm_oam_admission_control_info_t_preemption_allowed ;
int hf_rrm_oam_admission_control_info_t_preemption_status ;
int hf_rrm_oam_admission_control_info_t_proximity_indication_status ;
int hf_available_gbr_limit_t ;
int hf_available_gbr_limit_t_dl_gbr_limit ;
int hf_available_gbr_limit_t_ul_gbr_limit ;
int hf_rrm_oam_spid_table_t ;
int hf_rrm_oam_spid_table_t_spid_count ;
int hf_rrm_oam_spid_table_t_spid_config ;
int hf_rrm_oam_spid_configuration_t ;
int hf_rrm_oam_spid_configuration_t_bitmask ;
int hf_rrm_oam_spid_configuration_t_sp_id ;
int hf_rrm_oam_spid_configuration_t_eutran_freq_priority_info ;
int hf_rrm_oam_spid_configuration_t_utran_freq_priority_info ;
int hf_rrm_oam_spid_configuration_t_geran_freq_priority_info ;
int hf_rrm_power_control_params_unparsed_data = -1;
int hf_rrm_power_control_params_rrm_power_control_params = -1;
int hf_rrm_power_control_params_rrm_power_control_params_bitmask = -1;
int hf_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable = -1;
int hf_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_bitmask = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_harqBlerClpcPucchEnable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_cqiSinrClpcPucchEnable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschEnable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pucch_enable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pusch_enable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschfreqSelectiveEnable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_pdcchPowOrAggregationEnable = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_mcs_enabled = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_accumulation_enabled = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1 = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1b = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2 = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2a = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2b = -1;
int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_preamble_msg_3 = -1;
int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t = -1;
int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPucch = -1;
int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPucch = -1;
int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPusch = -1;
int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPusch = -1;
int hf_rrm_oam_sps_crnti_range_t = -1;
int hf_rrm_oam_sps_crnti_range_t_start_sps_crnti_range = -1;
int hf_rrm_oam_sps_crnti_range_t_end_sps_crnti_range = -1;
int hf_rrm_oam_access_mgmt_params_t = -1;
int hf_rrm_oam_access_mgmt_params_t_access_mode = -1;
static const range_string access_mode_values [] = {
    {0,0,"access_mode_open"},
    {1,1,"access_mode_close"},
    {2,2,"access_mode_hybrid"},
    {0,0,"NULL"}
};
int hf_rrm_oam_access_mgmt_params_t_max_csg_members = -1;
int hf_rrm_oam_access_mgmt_params_t_max_non_csg_members = -1;
int hf_rrm_oam_access_mgmt_params_t_csg_id = -1;
int hf_rrm_oam_access_mgmt_params_t_hnb_name_size = -1;
int hf_rrm_oam_access_mgmt_params_t_hnb_name = -1;

static const range_string reserve_operator_use_values [] = {
    {0,0,"RRMC_RESERVED_FOR_OPERATOR"},
    {1,1,"RRMC_NOT_RESERVED_FOR_OPERATOR"},
    {0,0,"NULL"}
};

//SHUTDOWN REQ
int hf_RRM_OAM_SHUTDOWN_REQ_unparsed_data = -1;
int hf_rrm_oam_shutdown_req_t = -1;
int hf_rrm_oam_shutdown_req_t_shutdown_mode = -1;
static const range_string shutdown_mode_values [] = {
    {0,0,"SHUTDOWN_MODE_FORCED"},
    {1,1,"SHUTDOWN_MODE_GRACEFUL"},
    {0,0,"NULL"}
};
int hf_rrm_oam_shutdown_req_t_time_to_shutdown = -1;

//SHUTDOWN RESP
int hf_RRM_OAM_SHUTDOWN_RESP_unparsed_data = -1;
int hf_rrm_oam_shutdown_resp_t = -1;
int hf_rrm_oam_shutdown_resp_t_response = -1;
static const range_string response_values[] = 
{
    {-1,-1,"RRM_INDEX_ERR"},
    {0,0,"RRM_FAILURE"},
    {1,1,"RRM_SUCCESS"},
    {2,2,"RRM_PARTIAL_SUCCESS"},
};

int hf_rrm_oam_shutdown_resp_t_fail_cause = -1;
static const range_string fail_cause_values[] = 
{
    {0,0,"RRM_NO_ERROR"},
    {0,0,"NULL"},
};


//RRM OAM SET LOG LEVEL REQ
int hf_RRM_OAM_SET_LOG_LEVEL_REQ_unparsed_data = -1;
int hf_rrm_oam_set_log_level_req_t = -1;
int hf_rrm_oam_set_log_level_req_t_module_id = -1;
static const range_string module_id_values[]=
{
    {0,0,"RRM_OAM_MIF_MODULE_ID"},
    {1,1,"RRM_OAM_CM_MODULE_ID"},
    {2,2,"RRM_OAM_UEM_MODULE_ID"},
    {3,3,"RRM_OAM_MAX_INT_MODULE_ID"},
};
int hf_rrm_oam_set_log_level_req_t_log_level = -1;
static const range_string log_level_values [] = {
    {0,0,"RRM_OAM_LOG_LEVEL_BRIEF"},
    {1,1,"RRM_OAM_LOG_LEVEL_INFO"},
    {2,2,"RRM_OAM_LOG_LEVEL_INFO"},
    {3,3,"RRM_OAM_LOG_LEVEL_WARNING"},
    {4,4,"RRM_OAM_LOG_LEVEL_ERROR"},
    {5,5,"RRM_OAM_LOG_LEVEL_FATAL"},
    {0,0,"NULL"}
};

//set log level resp
int hf_RRM_OAM_SET_LOG_LEVEL_RESP_unparsed_data = -1;
int hf_rrm_oam_set_log_level_resp_t = -1;
int hf_rrm_oam_set_log_level_resp_t_response = -1;
int hf_rrm_oam_set_log_level_resp_t_fail_cause = -1;

//resume service req
int hf_RRM_OAM_RESUME_SERVICE_REQ_unparsed_data = -1;
int hf_rrm_oam_resume_service_req_t = -1;

//resume service resp
int hf_RRM_OAM_RESUME_SERVICE_RESP_unparsed_data = -1;
int hf_rrm_oam_resume_service_resp_t = -1;
int hf_rrm_oam_resume_service_resp_t_response = -1;
int hf_rrm_oam_resume_service_resp_t_fail_cause = -1;

//ready for shutdown ind
int hf_RRM_OAM_READY_FOR_SHUTDOWN_IND_unparsed_data = -1;
int hf_rrm_oam_ready_for_shutdown_ind_t = -1;

//RRM OAM RAC ENABLE DISABLE REQ
int hf_RRM_OAM_RAC_ENABLE_DISABLE_REQ_unparsed_data = -1;
int hf_rrm_oam_rac_enable_disable_req_t = -1;
int hf_rrm_oam_rac_enable_disable_req_t_bitmask = -1;
int hf_rrm_oam_rac_enable_disable_req_t_request_type = -1;
static const range_string request_type_values[]=
{
    {0,0,"RRM_OAM_RAC_ENABLE"},
    {1,1,"RRM_OAM_RAC_DISABLE"},
    {0,0,"NULL"}
};

int hf_rrm_oam_rac_enable_disable_req_t_global_cell_id = -1;


///RRM OAM RAC ENABLE DISABLE RESP
int hf_RRM_OAM_RAC_ENABLE_DISABLE_RESP_unparsed_data = -1;
int hf_rrm_oam_rac_enable_disable_resp_t = -1;
int hf_rrm_oam_rac_enable_disable_resp_t_bitmask = -1;
int hf_rrm_oam_rac_enable_disable_resp_t_global_cell_id = -1;
int hf_rrm_oam_rac_enable_disable_resp_t_response = -1;
int hf_rrm_oam_rac_enable_disable_resp_t_fail_cause = -1;

///RRM OAM LOG ENABLE DISABLE REQ
int hf_RRM_OAM_LOG_ENABLE_DISABLE_REQ_unparsed_data = -1;
int hf_rrm_oam_log_enable_disable_req_t = -1;
int hf_rrm_oam_log_enable_disable_req_t_module_id = -1;
int hf_rrm_oam_log_enable_disable_req_t_log_config = -1;
int hf_rrm_oam_log_config_t = -1;
int hf_rrm_oam_log_config_t_log_on_off = -1;
static const range_string log_on_off_values [] = {
    {0,0,"RRM_LOG_ON"},
    {1,1,"RRM_LOG_OFF"},
    {0,0,"NULL"}
};
int hf_rrm_oam_log_config_t_log_level = -1;

///RRM OAM LOG ENABLE DISABLE RESP
int hf_RRM_OAM_LOG_ENABLE_DISABLE_RESP_unparsed_data = -1;
int hf_rrm_oam_log_enable_disable_resp_t = -1;
int hf_rrm_oam_log_enable_disable_resp_t_response = -1;
int hf_rrm_oam_log_enable_disable_resp_t_fail_cause = -1;

//RRM OAM INIT CONFIG REQ
int hf_RRM_OAM_INIT_CONFIG_REQ_unparsed_data = -1;
int hf_rrm_oam_init_config_req_t = -1;
int hf_rrm_oam_init_config_req_t_bitmask = -1;
int hf_rrm_oam_init_config_req_t_init_module_config = -1;
int hf_rrm_oam_module_init_config_t = -1;
int hf_rrm_oam_module_init_config_t_module_id = -1;
int hf_rrm_oam_module_init_config_t_log_config = -1;

//RRM OAM INIT CONFIG RESP
int hf_RRM_OAM_INIT_CONFIG_RESP_unparsed_data = -1;
int hf_rrm_oam_init_config_resp_t = -1;
int hf_rrm_oam_init_config_resp_t_response = -1;
int hf_rrm_oam_init_config_resp_t_fail_cause = -1;

// RRM OAM CELL START REQ
int hf_RRM_OAM_CELL_START_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_start_req_t = -1;
int hf_rrm_oam_cell_start_req_t_global_cell_id = -1;

// RRM OAM CELL START RESP
int hf_RRM_OAM_CELL_START_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_start_resp_t = -1;
int hf_rrm_oam_cell_start_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_start_resp_t_response = -1;
int hf_rrm_oam_cell_start_resp_t_fail_cause = -1;

//RRM OAM CELL STOP REQ
int hf_RRM_OAM_CELL_STOP_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_stop_req_t = -1;
int hf_rrm_oam_cell_stop_req_t_global_cell_id = -1;

//RRM OAM CELL STOP RESP
int hf_RRM_OAM_CELL_STOP_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_stop_resp_t = -1;
int hf_rrm_oam_cell_stop_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_stop_resp_t_response = -1;
int hf_rrm_oam_cell_stop_resp_t_fail_cause = -1;

//RRM OAM CELL DELETE REQ
int hf_RRM_OAM_CELL_DELETE_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_delete_req_t = -1;
int hf_rrm_oam_cell_delete_req_t_global_cell_id = -1;

//RRM OAM CELL DELETE RESP
int hf_RRM_OAM_CELL_DELETE_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_delete_resp_t = -1;
int hf_rrm_oam_cell_delete_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_delete_resp_t_response = -1;
int hf_rrm_oam_cell_delete_resp_t_fail_cause = -1;

//RRM OAM CELL CONFIG RESP
int hf_RRM_OAM_CELL_CONFIG_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_config_resp_t = -1;
int hf_rrm_oam_cell_config_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_config_resp_t_response = -1;
int hf_rrm_oam_cell_config_resp_t_fail_cause = -1;

//CELL RECONFIG REQ
int hf_RRM_OAM_CELL_RECONFIG_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_reconfig_req_t = -1;
int hf_rrm_oam_cell_reconfig_req_t_bitmask = -1;
int hf_rrm_oam_cell_reconfig_req_t_global_cell_id = -1;
int hf_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params = -1;
int hf_rrm_oam_cell_reconfig_req_t_ran_info = -1;
int hf_rrm_oam_cell_reconfig_req_t_epc_info = -1;
int hf_rrm_oam_cell_reconfig_req_t_operator_info = -1;
int hf_rrm_oam_cell_reconfig_req_t_access_mgmt_params = -1;

//cell reconfig resp
int hf_RRM_OAM_CELL_RECONFIG_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_reconfig_resp_t = -1;
int hf_rrm_oam_cell_reconfig_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_reconfig_resp_t_response = -1;
int hf_rrm_oam_cell_reconfig_resp_t_fail_cause = -1;

//RRM_OAM_BLOCK_CELL_REQ
int hf_RRM_OAM_BLOCK_CELL_REQ_unparsed_data = -1;
int hf_rrm_oam_block_cell_req_t = -1;
int hf_rrm_oam_block_cell_req_t_bitmask = -1;
int hf_rrm_oam_block_cell_req_t_global_cell_id = -1;
int hf_rrm_oam_block_cell_req_t_cell_block_priority = -1;
int hf_rrm_oam_block_cell_req_t_cell_block_resource_cleanup_timer = -1;

//CELL BLOCK RESPONSE
int hf_RRM_OAM_BLOCK_CELL_RESP_unparsed_data = -1;
int hf_rrm_oam_block_cell_resp_t = -1;
int hf_rrm_oam_block_cell_resp_t_global_cell_id = -1;
int hf_rrm_oam_block_cell_resp_t_response = -1;
int hf_rrm_oam_block_cell_resp_t_fail_cause = -1;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ
int hf_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ_unparsed_data = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_meas_bandwidth = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_no_of_arfcn = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_arfcn_list = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_upp = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_low = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_p_offset_o = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_p_adjust = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_p_penetration_loss = -1;
         
      
//RRM_OAM_READY_FOR_CELL_BLOCK_IND
int hf_RRM_OAM_READY_FOR_CELL_BLOCK_IND_unparsed_data = -1;
int hf_rrm_oam_ready_for_cell_block_ind_t = -1;
int hf_rrm_oam_ready_for_cell_block_ind_t_global_cell_id = -1;

//RRM_OAM_UNBLOCK_CELL_CMD
int hf_RRM_OAM_UNBLOCK_CELL_CMD_unparsed_data = -1;
int hf_rrm_oam_unblock_cell_cmd_t = -1;
int hf_rrm_oam_unblock_cell_cmd_t_global_cell_id = -1;

//RRM_OAM_GET_VER_ID_REQ
int hf_RRM_OAM_GET_VER_ID_REQ_unspared_data = -1;
int hf_rrm_oam_get_ver_id_req_t = -1;

//RRM_OAM_GET_VER_ID_RESP
int hf_RRM_OAM_GET_VER_ID_RESP_unspared_data = -1;
int hf_rrm_oam_get_ver_id_resp_t = -1;
int hf_rrm_oam_get_ver_id_resp_t_response = -1;


//RRM_OAM_CELL_UPDATE_REQ
int hf_RRM_OAM_CELL_UPDATE_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_update_req_t = -1;
int hf_rrm_oam_cell_update_req_t_bitmask = -1;
int hf_rrm_oam_cell_update_req_t_global_cell_id = -1;
int hf_rrm_oam_cell_update_req_t_pci_value = -1;
int hf_rrm_oam_cell_update_req_t_updated_plmn_info = -1;
int hf_rrm_oam_cell_update_req_t_conn_mode_cell_spec_off = -1;
int hf_rrm_oam_cell_update_req_t_idle_mode_cell_spec_off = -1;

//RRM_OAM_UPDATED_PLMN_INFO
int hf_RRM_OAM_UPDATED_PLMN_INFO_unparsed_data = -1;
int hf_rrm_oam_updated_plmn_info_t = -1;
int hf_rrm_oam_updated_plmn_info_t_num_valid_plmn = -1;
int hf_rrm_oam_updated_plmn_info_t_cell_plmn_info = -1;

//CELL UPDATE RESPONSE
int hf_RRM_OAM__CELL_UPDATE_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_update_resp_t = -1;
int hf_rrm_oam_cell_update_resp_t_global_cell_id = -1;
int hf_rrm_oam_cell_update_resp_t_response = -1;
int hf_rrm_oam_cell_update_resp_t_fail_cause = -1;

//RRM_OAM_EVENT_NOTIFICATION
int hf_RRM_OAM_EVENT_NOTIFICATION_unparsed_data = -1;
int hf_rrm_oam_event_notification_t = -1;
int hf_rrm_oam_event_notification_t_bitmask = -1;
int hf_rrm_oam_event_notification_t_msg_header = -1;
int hf_rrm_oam_event_notification_t_api_data = -1;
     
//RRM_OAM_EVENT_HEADER
int hf_RRM_OAM_EVENT_HEADER_unparsed_data = -1;
int hf_rrm_oam_event_header_t = -1;
int hf_rrm_oam_event_header_t_time_stamp = -1;
int hf_rrm_oam_event_header_t_event_type = -1;
int hf_rrm_oam_event_header_t_event_subtype = -1;
int hf_rrm_oam_event_header_t_event_id = -1;

//RRM_OAM_TIME_STAMP
int hf_RRM_OAM_TIME_STAMP_unparsed_data = -1;
int hf_rrm_oam_time_stamp_t = -1;
int hf_rrm_oam_time_stamp_t_year = -1;
int hf_rrm_oam_time_stamp_t_month = -1;
int hf_rrm_oam_time_stamp_t_day = -1;
int hf_rrm_oam_time_stamp_t_hour = -1;
int hf_rrm_oam_time_stamp_t_min = -1;
int hf_rrm_oam_time_stamp_t_sec = -1;

//RRM_OAM_LOAD_CONFIG_REQ
int hf_RRM_OAM_LOAD_CONFIG_REQ_unparsed_data = -1;
int hf_rrm_oam_load_config_req_t = -1;
int hf_rrm_oam_load_config_req_t_bitmask = -1;
int hf_rrm_oam_load_config_req_t_ncl_load_ind_intrvl = -1;
int hf_rrm_oam_load_config_req_t_load_rpt_intrvl = -1;
int hf_rrm_oam_load_config_req_t_num_enb_cells = -1;
int hf_rrm_oam_load_config_req_t_serv_enb_cell_info = -1;

//RRM_OAM_LOAD_REPORT_IND
int hf_RRM_OAM_LOAD_REPORT_IND_unparsed_data = -1;
int hf_rrm_oam_load_report_ind_t = -1;
int hf_rrm_oam_load_cell_info_t = -1;
int hf_rrm_oam_load_cell_info_bitmask = -1;
int hf_rrm_oam_hw_load_ind_t = -1;
int hf_rrm_oam_rs_load_lvl_ul = -1;
int hf_rrm_oam_rs_load_lvl_dl = -1;
int hf_rrm_oam_s1_tnl_load_ind_t = -1;
int hf_rrm_oam_rrs_load_ind_t = -1;
int hf_rrm_oam_dl_gbr_prb_usage = -1;
int hf_rrm_oam_ul_gbr_prb_usage = -1;
int hf_rrm_oam_dl_non_gbr_prb_usage = -1;
int hf_rrm_oam_ul_non_gbr_prb_usage = -1;
int hf_rrm_oam_dl_total_prb_usage = -1;
int hf_rrm_oam_ul_total_prb_usage = -1;
int hf_rrm_oam_comp_avl_cap_grp_t = -1;
int hf_rrm_oam_comp_avl_cap_dl_t = -1;
int hf_rrm_oam_comp_avl_dl_bimask = -1;
int hf_rrm_oam_comp_avl_dl_cell_cap_class_val = -1;
int hf_rrm_oam_comp_avl_dl_cap_val = -1;
int hf_rrm_oam_comp_avl_cap_ul_t = -1;

//RRM_OAM_SERVING_ENB_CELL_INFO
int hf_RRM_OAM_SERVING_ENB_CELL_INFO_unparsed_data = -1;
int hf_rrm_oam_serving_enb_cell_info_t = -1;
int hf_rrm_oam_serving_enb_cell_info_t_bitmask = -1;
int hf_rrm_oam_serving_enb_cell_info_t_global_cell_id = -1;
int hf_rrm_oam_serving_enb_cell_info_t_over_load_lvl_act = -1;
int hf_rrm_oam_serving_enb_cell_info_t_high_load_lvl_act = -1;
int hf_rrm_oam_serving_enb_cell_info_t_mid_load_lvl_act = -1;
int hf_rrm_oam_serving_enb_cell_info_t_resrc_spec = -1;

//RRM_OAM_LOAD_DEF
int hf_RRM_OAM_LOAD_DEF_unparsed_data = -1;
int hf_rrm_oam_over_load_def_t = -1;
int hf_rrm_oam_high_load_def_t = -1;
int hf_rrm_oam_mid_load_def_t = -1;
int hf_rrm_oam_load_def_t_bitmask = -1;
int hf_rrm_oam_load_def_t_load_perctg = -1;
int hf_rrm_oam_load_def_t_action = -1;
int hf_rrm_oam_load_def_t_num_usr = -1;

//RRM_OAM_LOAD_WATERMARK
int hf_RRM_OAM_WATERMARK_unparsed_data = -1;
int hf_rrm_oam_watermark_t = -1;
int hf_rrm_oam_watermark_t_high_watermark = -1;
int hf_rrm_oam_watermark_t_low_watermark = -1;

//RRM_OAM_RESOURCE_LOAD_INFO
int hf_RRM_OAM_RESOURCE_LOAD_INFO_unparsed_data = -1;
int hf_rrm_oam_resource_load_info_t = -1;
int hf_rrm_oam_resource_load_info_t_bitmask = -1;
int hf_rrm_oam_resource_load_info_t_count = -1;
int hf_rrm_oam_resource_load_info_t_resrc_info = -1;

//RRM_OAM_RESRC_INFO
int hf_RRM_OAM_RESRC_INFO_unparsed_data = -1;
int hf_rrm_oam_resrc_info_t = -1;
int hf_rrm_oam_resrc_info_t_bitmask = -1;
int hf_rrm_oam_resrc_info_t_resrc_type = -1;
int hf_rrm_oam_resrc_info_t_overload = -1;
int hf_rrm_oam_resrc_info_t_highload = -1;
int hf_rrm_oam_resrc_info_t_midload = -1;


//RRM_OAM_ACCESS_BARRING_INFO
int hf_RRM_OAM_ACCESS_BARRING_INFO_unparsed_data = -1;
int hf_rrm_oam_access_barring_info_t = -1;
int hf_rrm_oam_access_barring_info_t_bitmask = -1;
int hf_rrm_oam_access_barring_info_t_class_barring_info = -1;
int hf_rrm_oam_access_barring_info_t_ssac_barring_r9 = -1;

//RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION
int hf_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION_unparsed_data = -1;
int hf_rrm_oam_access_class_barring_information_t = -1;
int hf_rrm_oam_access_class_barring_information_t_ac_barring_factor = -1;
int hf_rrm_oam_access_class_barring_information_t_ac_barring_time = -1;
int hf_rrm_oam_access_class_barring_information_t_ac_barring_for_special_ac = -1;

//RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9
int hf_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9_unparsed_data = -1;
int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t = -1;
int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_bitmask = -1;
int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_class_barring_info = -1;

//RRM_OAM_LOAD_CONFIG_RESP
int hf_RRM_OAM_LOAD_CONFIG_RESP_unparsed_data = -1;
int hf_rrm_oam_load_config_resp_t = -1;
int hf_rrm_oam_load_config_resp_t_response = -1;
int hf_rrm_oam_load_config_resp_t_fail_cause = -1;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ
int hf_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ_unparsed_data = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_req_t = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_bitmask = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_count = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_ecn_cells = -1;

//RRM_ECN_CONFIGURE_CELL_LIST
int hf_RRM_ECN_CONFIGURE_CELL_LIST_unparsed_data = -1;
int hf_rrm_ecn_configure_cell_list_t = -1;
int hf_rrm_ecn_configure_cell_list_t_bitmask = -1;
int hf_rrm_ecn_configure_cell_list_t_global_cell_id = -1;
int hf_rrm_ecn_configure_cell_list_t_num_of_ue = -1;
int hf_rrm_ecn_configure_cell_list_t_bitrate = -1;

//RRM_QCI_BITRATE_INFO
int hf_RRM_QCI_BITRATE_INFO_unparsed_data = -1;
int hf_rrm_qci_bitrate_info_t = -1;
int hf_rrm_qci_bitrate_info_t_bitmask = -1;
int hf_rrm_qci_bitrate_info_t_count = -1;
int hf_rrm_qci_bitrate_info_t_bitrate_for_qci = -1;

//RRM_CONFIGURE_QCI_BITRATE
int hf_RRM_CONFIGURE_QCI_BITRATE_unparsed_data = -1;
int hf_rrm_configure_qci_bitrate_t = -1;
int hf_rrm_configure_qci_bitrate_t_bitmask = -1;
int hf_rrm_configure_qci_bitrate_t_qci = -1;
int hf_rrm_configure_qci_bitrate_t_ul_bitrate = -1;
int hf_rrm_configure_qci_bitrate_t_dl_bitrate = -1;


//RRM_BITRATE_UL_DL
int hf_RRM_BITRATE_UL_DL_unparsed_data = -1;
int hf_rrm_bitrate_ul_dl_t = -1;
int hf_rrm_bitrate_ul_dl_t_max_bitrate = -1;
int hf_rrm_bitrate_ul_dl_t_min_bitrate = -1;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP
int hf_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP_unparsed_data = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_response = -1;
int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_fail_cause = -1;

//RRM_OAM_CONFIG_KPI_REQ
int hf_RRM_OAM_CONFIG_KPI_REQ_unparsed_data = -1;
int hf_rrm_oam_config_kpi_req_t = -1;
int hf_rrm_oam_config_kpi_req_t_bitmask = -1;
int hf_rrm_oam_config_kpi_req_t_cell_id = -1;
int hf_rrm_oam_config_kpi_req_t_duration = -1;
int hf_rrm_oam_config_kpi_req_t_periodic_reporting = -1;
int hf_rrm_oam_config_kpi_req_t_kpi_to_report = -1;

//RRM_OAM_KPI
int hf_RRM_OAM_KPI_unparsed_data = -1;
int hf_rrm_oam_kpi_t = -1;
int hf_rrm_oam_kpi_t_bitmap = -1;

//RRM_OAM_CONFIG_KPI_RESP
int hf_RRM_OAM_CONFIG_KPI_RESP_unparsed_data = -1;
int hf_rrm_oam_config_kpi_resp_t = -1;
int hf_rrm_oam_config_kpi_resp_t_bitmask = -1;
int hf_rrm_oam_config_kpi_resp_t_global_cell_id = -1;
int hf_rrm_oam_config_kpi_resp_t_response = -1;
int hf_rrm_oam_config_kpi_resp_t_fail_cause = -1;

//RRM_OAM_GET_KPI_REQ
int hf_RRM_OAM_GET_KPI_REQ_unparsed_data = -1;
int hf_rrm_oam_get_kpi_req_t = -1;
int hf_rrm_oam_get_kpi_req_t_bitmask = -1;
int hf_rrm_oam_get_kpi_req_t_cell_id = -1;
int hf_rrm_oam_get_kpi_req_t_reset = -1;
int hf_rrm_oam_get_kpi_req_t_kpi_to_report = -1;

//RRM_OAM_GET_KPI_RESP
int hf_RRM_OAM_GET_KPI_RESP_unparsed_data = -1;
int hf_rrm_oam_get_kpi_resp_t = -1;
int hf_rrm_oam_get_kpi_resp_t_bitmask = -1;
int hf_rrm_oam_get_kpi_resp_t_global_cell_id = -1;
int hf_rrm_oam_get_kpi_resp_t_response = -1;
int hf_rrm_oam_get_kpi_resp_t_fail_cause = -1;
int hf_rrm_oam_get_kpi_resp_t_kpi_data = -1;

//RRM_OAM_KPI_DATA
int hf_RRM_OAM_KPI_DATA_unparsed_data = -1;
int hf_rrm_oam_kpi_data_t = -1;
int hf_rrm_oam_kpi_data_t_num_of_admitted_csg_user = -1;
int hf_rrm_oam_kpi_data_t_num_of_admitted_non_csg_user = -1;
int hf_rrm_oam_kpi_data_t_num_of_ue_admission_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_ue_admission_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_setup_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_setup_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_modify_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_modify_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_release_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_erb_release_fail = -1;
int hf_rrm_oam_kpi_data_t_total_dl_allocated_gbr_prb = -1;
int hf_rrm_oam_kpi_data_t_total_ul_allocated_gbr_prb = -1;
int hf_rrm_oam_kpi_data_t_dl_allocated_ngbr_prb = -1;
int hf_rrm_oam_kpi_data_t_ul_allocated_ngbr_prb = -1;
int hf_rrm_oam_kpi_data_t_num_of_geran_ho_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_geran_ho_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_utran_ho_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_utran_ho_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_eutran_ho_attempt = -1;
int hf_rrm_oam_kpi_data_t_num_of_eutran_ho_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_geran_hi_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_geran_hi_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_utran_hi_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_utran_hi_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_eutran_hi_success = -1;
int hf_rrm_oam_kpi_data_t_num_of_eutran_hi_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_csg_usr = -1;
int hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_non_csg_usr = -1;
int hf_rrm_oam_kpi_data_t_num_of_enb_init_ue_release = -1;
int hf_rrm_oam_kpi_data_t_num_pucch_res_alloc_attempts = -1;
int hf_rrm_oam_kpi_data_t_num_of_sr_res_alloc_fail = -1;
int hf_rrm_oam_kpi_data_t_num_of_sr_cqi_alloc_fail = -1;




//ADDED PT.

//CELL CONTEXT PRINT REQ
int hf_rrm_oam_cell_context_print_req_unparsed_data = -1;
int hf_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req = -1;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER _REQ
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_unparsed_data = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_meas_bandwidth = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_no_of_arfcn = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_arfcn_list = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_upp = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_low = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_offset_o = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_adjust = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_penetration_loss = -1;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER _RESP
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_unparsed_data = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_bitmask = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_dl_earfcn = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_reference_signal_power = -1;
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_result = -1;
static const range_string result_values[] =
{
    {-1,-1,"RRM_INDEX_ERR"},
    {0,0,"RRM_FAILURE"},
    {1,1,"RRM_SUCCESS"},
    {2,2,"RRM_PARTIAL_SUCCESS"},
};
int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_error_code = -1;

int hf_rrm_oam_ue_release_req_t_unparsed_data = -1;
int hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t = -1;
int hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t_ue_index = -1;

int hf_rrm_oam_proc_supervision_resp_t_unparsed_data = -1;
int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t = -1;
int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_alive_status = -1;
static const range_string alive_status_values[] = 
{
    {0,0,"RRM_OAM_SUP_OK"},
    {1,1,"RRM_OAM_SUP_NOK"},
};
int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_fail_cause = -1;



static hf_register_info hf[] = {
    { &hf_rrm_oam_header_unparsed_data,
        { "Unparsed protocol data","rrm_oam_header.unparsed_data",BASE_NONE,BASE_NONE, NULL, 0x0,"Unparsed for protocol data", HFILL }},
    { &hf_rrm_oam_header,
        { "RRM OAM Ext API Header IE","rrm_ext_api_hdr_t",BASE_NONE, BASE_NONE, NULL, 0x0,"RRM OAM Ext API Header IE", HFILL }},
    { &hf_rrm_oam_header_transactionId,
        { "Transaction Id","rrm_ext_api_header_t.transactionId",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Transaction Id", HFILL }},
    { &hf_rrm_oam_header_sourceModId,
        { "Src Module Id","rrm_ext_api_header_t.sourceModId",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Src Module Id", HFILL }},
    { &hf_rrm_oam_header_destModId,
        { "Dest Module Id","rrm_ext_api_header_t.destModId",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"Dest Module Id", HFILL }},
    { &hf_rrm_oam_header_TypeOfAPI,
        { "ApiType","rrm_ext_api_header_t.TypeOfAPI",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"ApiType", HFILL }},
    { &hf_rrm_oam_header_MsgBufferlen,
        { "BuffLength","rrm_ext_api_header_t.MsgBufferlen",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"BuffLength", HFILL }},
    { &hf_rrm_oam_cell_config_req_t, 
        { "rrm_oam_cell_config_req_t","RRM_OAM_CELL_CONFIG_REQ.rrm_oam_cell_config_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_config_req_t", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_bitmask, 
        { "bitmask","rrm_oam_cell_config_req_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_global_cell_info, 
        { "global_cell_info","rrm_oam_cell_config_req_t.global_cell_info",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_info", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_ran_info, 
        { "ran_info","rrm_oam_cell_config_req_t.ran_info",FT_NONE,BASE_NONE ,NULL,0x0,"ran_info", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_epc_info, 
        { "epc_info","rrm_oam_cell_config_req_t.epc_info",FT_NONE,BASE_NONE ,NULL,0x0,"epc_info", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_operator_info, 
        { "operator_info","rrm_oam_cell_config_req_t.operator_info",FT_NONE,BASE_NONE ,NULL,0x0,"operator_info", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_access_mgmt_params, 
        { "access_mgmt_params","rrm_oam_cell_config_req_t.access_mgmt_params",FT_NONE,BASE_NONE ,NULL,0x0,"access_mgmt_params", HFILL }},
    { &hf_rrm_oam_cell_config_req_t_immediate_start_needed, 
        { "immediate_start_needed","rrm_oam_cell_config_req_t.immediate_start_needed",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&immediate_start_needed_values),0x0,"immediate_start_needed", HFILL }},
    { &hf_rrm_oam_cell_info_t, 
        { "rrm_oam_cell_info_t","rrm_oam_cell_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_info_t", HFILL }},
    { &hf_rrm_oam_cell_info_t_eutran_global_cell_id, 
        { "eutran_global_cell_id","rrm_oam_cell_info_t.eutran_global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"eutran_global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_info_t_cell_access_restriction_params, 
        { "cell_access_restriction_params","rrm_oam_cell_info_t.cell_access_restriction_params",FT_NONE,BASE_NONE ,NULL,0x0,"cell_access_restriction_params", HFILL }},
    { &hf_rrm_oam_eutran_global_cell_id_t, 
        { "rrm_oam_eutran_global_cell_id_t","rrm_oam_eutran_global_cell_id_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_eutran_global_cell_id_t", HFILL }},
    { &hf_rrm_oam_eutran_global_cell_id_t_primary_plmn_id, 
        { "primary_plmn_id","rrm_oam_eutran_global_cell_id_t.primary_plmn_id",FT_NONE,BASE_NONE ,NULL,0x0,"primary_plmn_id", HFILL }},
    { &hf_rrm_oam_eutran_global_cell_id_t_cell_identity, 
        { "cell_identity","rrm_oam_eutran_global_cell_id_t.cell_identity",FT_STRING,BASE_NONE ,NULL,0x0,"cell_identity", HFILL }},
    { &hf_rrm_oam_cell_plmn_info_t, 
        { "rrm_oam_cell_plmn_info_t","rrm_oam_cell_plmn_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_cell_plmn_info_t", HFILL }},
    { &hf_rrm_oam_cell_plmn_info_t_mcc, 
        { "mcc","rrm_oam_cell_plmn_info_t.mcc",FT_STRING,BASE_NONE ,NULL,0x0,"mcc", HFILL }},
    { &hf_rrm_oam_cell_plmn_info_t_num_mnc_digit, 
        { "num_mnc_digit","rrm_oam_cell_plmn_info_t.num_mnc_digit",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_mnc_digit", HFILL }},
    { &hf_rrm_oam_cell_plmn_info_t_mnc, 
        { "mnc","rrm_oam_cell_plmn_info_t.mnc",FT_STRING,BASE_NONE ,NULL,0x0,"mnc", HFILL }},
    { &hf_rrm_oam_cell_access_restriction_params_t, 
        { "rrm_oam_cell_access_restriction_params_t","rrm_oam_cell_access_restriction_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_cell_access_restriction_params_t", HFILL }},
    { &hf_rrm_oam_cell_access_restriction_params_t_cell_barred, 
        { "cell_barred","rrm_oam_cell_access_restriction_params_t.cell_barred",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&cell_barred_values),0x0,"cell_barred", HFILL }},
    { &hf_rrm_oam_cell_access_restriction_params_t_intra_freq_reselection, 
        { "intra_freq_reselection","rrm_oam_cell_access_restriction_params_t.intra_freq_reselection",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&intra_freq_reselection_values),0x0,"intra_freq_reselection", HFILL }},
    { &hf_rrm_oam_cell_access_restriction_params_t_barring_for_emergency, 
        { "barring_for_emergency","rrm_oam_cell_access_restriction_params_t.barring_for_emergency",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&barring_for_emergency_values),0x0,"barring_for_emergency", HFILL }},
    { &hf_rrm_oam_ran_t, 
        { "rrm_oam_ran_t","rrm_oam_ran_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_ran_t", HFILL }},
    { &hf_rrm_oam_ran_t_bitmask, 
        { "bitmask","rrm_oam_ran_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_ran_t_physical_layer_params, 
        { "physical_layer_params","rrm_oam_ran_t.physical_layer_params",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_params", HFILL }},
    { &hf_rrm_oam_ran_t_mac_layer_params, 
        { "mac_layer_params","rrm_oam_ran_t.mac_layer_params",FT_NONE,BASE_NONE ,NULL,0x0,"mac_layer_params", HFILL }},
    { &hf_rrm_oam_ran_t_rlc_layer_params, 
        { "rlc_layer_params","rrm_oam_ran_t.rlc_layer_params",FT_NONE,BASE_NONE ,NULL,0x0,"rlc_layer_params", HFILL }},
    { &hf_rrm_oam_ran_t_mobility_params, 
        { "mobility_params","rrm_oam_ran_t.mobility_params",FT_NONE,BASE_NONE ,NULL,0x0,"mobility_params", HFILL }},
    { &hf_rrm_oam_ran_t_rrc_timers_and_constants, 
        { "rrc_timers_and_constants","rrm_oam_ran_t.rrc_timers_and_constants",FT_NONE,BASE_NONE ,NULL,0x0,"rrc_timers_and_constants", HFILL }},
    { &hf_rrm_oam_ran_t_rf_params, 
        { "rf_params","rrm_oam_ran_t.rf_params",FT_NONE,BASE_NONE ,NULL,0x0,"rf_params", HFILL }},
    { &hf_rrm_oam_ran_t_s1ap_params, 
        { "s1ap_params","rrm_oam_ran_t.s1ap_params",FT_NONE,BASE_NONE ,NULL,0x0,"s1ap_params", HFILL }},
    { &hf_rrm_oam_ran_t_ncl_params, 
        { "nlc_params","rrm_oam_ran_t.ncl_params",FT_NONE,BASE_NONE ,NULL,0x0,"nlc_params", HFILL }},
    { &hf_rrm_oam_ran_t_connected_mode_mobility_params, 
        { "connected_mode_mobility_params","rrm_oam_ran_t.connected_mode_mobility_params",FT_NONE,BASE_NONE ,NULL,0x0,"connected_mode_mobility_params", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t, 
        { "rrm_oam_physical_layer_params_t","rrm_oam_physical_layer_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_physical_layer_params_t", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_bitmask, 
        { "bitmask","rrm_oam_physical_layer_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch, 
        { "physical_layer_param_pdsch","rrm_oam_physical_layer_params_t.physical_layer_param_pdsch",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_pdsch", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_srs, 
        { "physical_layer_param_srs","rrm_oam_physical_layer_params_t.physical_layer_param_srs",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_srs", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_prach, 
        { "physical_layer_param_prach","rrm_oam_physical_layer_params_t.physical_layer_param_prach",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_prach", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_pucch, 
        { "physical_layer_param_pucch","rrm_oam_physical_layer_params_t.physical_layer_param_pucch",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_pucch", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_pusch, 
        { "physical_layer_param_pusch","rrm_oam_physical_layer_params_t.physical_layer_param_pusch",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_pusch", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal, 
        { "physical_layer_param_ul_reference_signal","rrm_oam_physical_layer_params_t.physical_layer_param_ul_reference_signal",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_ul_reference_signal", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control, 
        { "physical_layer_param_ul_power_control","rrm_oam_physical_layer_params_t.physical_layer_param_ul_power_control",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_ul_power_control", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_prs, 
        { "physical_layer_param_prs","rrm_oam_physical_layer_params_t.physical_layer_param_prs",FT_NONE,BASE_NONE ,NULL,0x0,"physical_layer_param_prs", HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure, 
        { "tdd_frame_structure","rrm_oam_physical_layer_params_t.tdd_frame_structure",FT_NONE,BASE_NONE ,NULL,0x0,"tdd_frame_structure",HFILL }},
    { &hf_rrm_oam_physical_layer_params_t_addl_physical_layer_params, 
        { "addl_physical_layer_params","rrm_oam_physical_layer_params_t.addl_physical_layer_params",FT_NONE,BASE_NONE ,NULL,0x0,"addl_physical_layer_params", HFILL }},
    { &hf_rrm_oam_addl_phy_params_t, 
        { "rrm_oam_addl_phy_params_t","rrm_oam_addl_phy_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_addl_phy_params_t", HFILL }},
    { &hf_rrm_oam_addl_phy_params_t_bitmask, 
        { "Bitmask","rrm_oam_addl_phy_params_t.bitmask",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"Bitmask", HFILL }},
    { &hf_rrm_oam_addl_phy_params_t_addl_pucch_parameters, 
        { "addl_pucch_parameters","rrm_oam_addl_phy_params_t.addl_pucch_parameters",FT_NONE,BASE_NONE, NULL, 0x0,"addl_pucch_parameters", HFILL }},
    { &hf_rrm_oam_addl_phy_params_t_additional_pusch_parameters, 
        { "additional_pusch_parameters","rrm_oam_addl_phy_params_t.additional_pusch_parameters",FT_NONE,BASE_NONE, NULL, 0x0,"additional_pusch_parameters", HFILL }},
    { &hf_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params, 
        { "addl_pucch_parameters","rrm_oam_addl_phy_params_t.addl_pucch_parameters",FT_NONE,BASE_NONE, NULL, 0x0,"addl_pucch_parameters", HFILL }},
    { &hf_rrm_oam_addl_pucch_config_t, 
        { "rrm_oam_addl_pucch_config_t","rrm_oam_pdsch_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_pdsch_t", HFILL }},
    { &hf_rrm_oam_addl_pucch_config_t_bitmask,
        { "bitmask", "rrm_oam_addl_pucch_config_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask", HFILL }},
    { &hf_rrm_oam_addl_pucch_config_t_n1_cs,
        { "n1_cs", "rrm_oam_addl_pucch_config_t.n1_cs", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "n1_cs", HFILL }},
    { &hf_rrm_oam_addl_pusch_config_t,
        { "rrm_oam_addl_pusch_config_t", "rrm_oam_addl_pusch_config_t", FT_NONE, BASE_NONE, NULL, 0x0, "rrm_oam_addl_pusch_config_t", HFILL}},
    { &hf_rrm_oam_addl_pusch_config_t_bitmask,
        { "bitmask" , "rrm_oam_addl_pusch_config_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask", HFILL }},
    { &hf_rrm_oam_addl_pusch_config_t_pusch_enable_64_qam,
        { "pusch_enable_64_qam", "rrm_oam_addl_pusch_config_t.pusch_enable_64_qam", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "pusch_enable_64_qam", HFILL }},
    { &hf_rrm_oam_addl_ul_reference_signal_params_t,
        { "rrm_oam_addl_ul_reference_signal_params_t", "rrm_oam_addl_ul_reference_signal_params_t", FT_NONE, BASE_NONE, NULL, 0x0, "rrm_oam_addl_ul_reference_signal_params_t", HFILL }},
    { &hf_rrm_oam_addl_ul_reference_signal_params_t_bitmask,
        { "bitmask", "rrm_oam_addl_ul_reference_signal_params_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask", HFILL }},
    { &hf_rrm_oam_addl_ul_reference_signal_params_t_group_assignment_pusch,
        { "group_assignment_pusch", "rrm_oam_addl_ul_reference_signal_params_t.group_assignment_pusch" ,FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "group_assignment_pusch", HFILL }},
    { &hf_rrm_oam_addl_ul_reference_signal_params_t_ul_reference_signal_pusch_cyclicshift,
        { "ul_reference_signal_pusch_cyclicshift", "rrm_oam_addl_ul_reference_signal_params_t.ul_reference_signal_pusch_cyclicshift", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, "ul_reference_signal_pusch_cyclicshift", HFILL }},
    { &hf_rrm_oam_tdd_frame_structure_t, 
        { "rrm_oam_tdd_frame_structure_t","rrm_oam_tdd_frame_structure_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_tdd_frame_structure_t", HFILL }},
    { &hf_rrm_oam_tdd_frame_structure_t_sub_frame_assignment,
        { "sub_frame_assignment", "rrm_oam_tdd_frame_structure_t.sub_frame_assignment", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "sub_frame_assignment", HFILL }},
    { &hf_rrm_oam_tdd_frame_structure_t_special_sub_frame_patterns,
        { "special_sub_frame_patterns", "rrm_oam_tdd_frame_structure_t.special_sub_frame_patterns", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "special_sub_frame_patterns", HFILL }},
    { &hf_rrm_oam_pdsch_t, 
        { "rrm_oam_pdsch_t","rrm_oam_pdsch_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_pdsch_t", HFILL }},
    { &hf_rrm_oam_pdsch_t_p_b, 
        { "p_b","rrm_oam_pdsch_t.p_b",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&p_b_values),0x0,"p_b", HFILL }},
    { &hf_rrm_oam_pdsch_t_p_a, 
        { "p_a","rrm_oam_pdsch_t.p_a",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&p_a_values),0x0,"p_a", HFILL }},
    { &hf_rrm_oam_srs_t, 
        { "rrm_oam_srs_t","rrm_oam_srs_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_srs_t", HFILL }},
    { &hf_rrm_oam_srs_t_bitmask, 
        { "bitmask","rrm_oam_srs_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_srs_t_srsEnabled, 
        { "srsEnabled","rrm_oam_srs_t.srsEnabled",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&srsEnabled_values),0x0,"srsEnabled", HFILL }},
    { &hf_rrm_oam_srs_t_srs_bandwidth_config, 
        { "srs_bandwidth_config","rrm_oam_srs_t.srs_bandwidth_config",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&srs_bandwidth_config_values),0x0,"srs_bandwidth_config", HFILL }},
    { &hf_rrm_oam_srs_t_srs_subframe_config, 
        { "srs_subframe_config","rrm_oam_srs_t.srs_subframe_config",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&srs_subframe_config_values),0x0,"srs_subframe_config", HFILL }},
    { &hf_rrm_oam_srs_t_srs_max_up_pts, 
        { "srs_max_up_pts","rrm_oam_srs_t.srs_max_up_pts",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&srs_max_up_pts_values),0x0,"srs_max_up_pts", HFILL }},
    { &hf_rrm_oam_srs_t_ack_nack_srs_simultaneous_transmission, 
        { "ack_nack_srs_simultaneous_transmission","rrm_oam_srs_t.ack_nack_srs_simultaneous_transmission",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&ack_nack_srs_simultaneous_transmission_values),0x0,"ack_nack_srs_simultaneous_transmission", HFILL }},
    { &hf_rrm_oam_prach_t, 
        { "rrm_oam_prach_t","rrm_oam_prach_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_prach_t", HFILL }},
    { &hf_rrm_oam_prach_t_root_sequence_index, 
        { "root_sequence_index","rrm_oam_prach_t.root_sequence_index",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"root_sequence_index", HFILL }},
    { &hf_rrm_oam_prach_t_configuration_index, 
        { "configuration_index","rrm_oam_prach_t.configuration_index",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"configuration_index", HFILL }},
    { &hf_rrm_oam_prach_t_high_speed_flag, 
        { "high_speed_flag","rrm_oam_prach_t.high_speed_flag",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"high_speed_flag", HFILL }},
    { &hf_rrm_oam_prach_t_zero_correlation_zone_config, 
        { "zero_correlation_zone_config","rrm_oam_prach_t.zero_correlation_zone_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"zero_correlation_zone_config", HFILL }},
    { &hf_rrm_oam_prach_t_frequency_offset, 
        { "frequency_offset","rrm_oam_prach_t.frequency_offset",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"frequency_offset", HFILL }},
    { &hf_rrm_oam_pucch_t, 
        { "rrm_oam_pucch_t","rrm_oam_pucch_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_pucch_t", HFILL }},
    { &hf_rrm_oam_pucch_t_delta_pucch_shift, 
        { "delta_pucch_shift","rrm_oam_pucch_t.delta_pucch_shift",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"delta_pucch_shift", HFILL }},
    { &hf_rrm_oam_pucch_t_n_rb_cqi, 
        { "n_rb_cqi","rrm_oam_pucch_t.n_rb_cqi",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n_rb_cqi", HFILL }},
    { &hf_rrm_oam_pucch_t_n1_pucch_an, 
        { "n1_pucch_an","rrm_oam_pucch_t.n1_pucch_an",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"n1_pucch_an", HFILL }},
    { &hf_rrm_oam_pucch_t_cqi_pucch_resource_index, 
        { "cqi_pucch_resource_index","rrm_oam_pucch_t.cqi_pucch_resource_index",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"cqi_pucch_resource_index", HFILL }},
    { &hf_rrm_oam_pucch_t_tdd_ack_nack_feedback_mode, 
        { "tdd_ack_nack_feedback_mode","rrm_oam_pucch_t.tdd_ack_nack_feedback_mode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"tdd_ack_nack_feedback_mode", HFILL }},
    { &hf_rrm_oam_pucch_t_pucch_cqi_sinr_value, 
        { "pucch_cqi_sinr_value","rrm_oam_pucch_t.pucch_cqi_sinr_value",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pucch_cqi_sinr_value", HFILL }},
    { &hf_rrm_oam_pusch_t, 
        { "rrm_oam_pusch_t","rrm_oam_pusch_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_pusch_t", HFILL }},
    { &hf_rrm_oam_pusch_t_n_sb, 
        { "n_sb","rrm_oam_pusch_t.n_sb",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n_sb", HFILL }},
    { &hf_rrm_oam_pusch_t_pusch_hopping_mode, 
        { "pusch_hopping_mode","rrm_oam_pusch_t.pusch_hopping_mode",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&pusch_hopping_mode_values),0x0,"pusch_hopping_mode", HFILL }},
    { &hf_rrm_oam_pusch_t_hopping_offset, 
        { "hopping_offset","rrm_oam_pusch_t.hopping_offset",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"hopping_offset", HFILL }},
    { &hf_rrm_oam_ul_reference_signal_t, 
        { "rrm_oam_ul_reference_signal_t","rrm_oam_ul_reference_signal_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_ul_reference_signal_t", HFILL }},
    { &hf_rrm_oam_ul_reference_signal_t_group_hopping_enabled, 
        { "group_hopping_enabled","rrm_oam_ul_reference_signal_t.group_hopping_enabled",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&group_hopping_enabled_values),0x0,"group_hopping_enabled", HFILL }},
    { &hf_rrm_oam_ul_reference_signal_t_sequence_hopping_enabled, 
        { "sequence_hopping_enabled","rrm_oam_ul_reference_signal_t.sequence_hopping_enabled",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&sequence_hopping_enabled_values),0x0,"sequence_hopping_enabled", HFILL }},
    { &hf_rrm_oam_uplink_power_control_t, 
        { "rrm_oam_uplink_power_control_t","rrm_oam_uplink_power_control_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_uplink_power_control_t", HFILL }},
    { &hf_rrm_oam_uplink_power_control_t_p_0_nominal_pusch, 
        { "p_0_nominal_pusch","rrm_oam_uplink_power_control_t.p_0_nominal_pusch",FT_INT8,BASE_DEC ,NULL,0x0,"p_0_nominal_pusch", HFILL }},
    { &hf_rrm_oam_uplink_power_control_t_alpha, 
        { "alpha","rrm_oam_uplink_power_control_t.alpha",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&alpha_values),0x0,"alpha", HFILL }},
    { &hf_rrm_oam_uplink_power_control_t_p_0_nominal_pucch, 
        { "p_0_nominal_pucch","rrm_oam_uplink_power_control_t.p_0_nominal_pucch",FT_INT8,BASE_DEC ,NULL,0x0,"p_0_nominal_pucch", HFILL }},
    { &hf_rrm_oam_prs_t, 
        { "rrm_oam_prs_t","rrm_oam_prs_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_prs_t", HFILL }},
    { &hf_rrm_oam_prs_t_num_prs_resource_blocks, 
        { "num_prs_resource_blocks","rrm_oam_prs_t.num_prs_resource_blocks",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_prs_resource_blocks", HFILL }},
    { &hf_rrm_oam_prs_t_prs_configuration_index, 
        { "prs_configuration_index","rrm_oam_prs_t.prs_configuration_index",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"prs_configuration_index", HFILL }},
    { &hf_rrm_oam_prs_t_num_consecutive_prs_subfames, 
        { "num_consecutive_prs_subfames","rrm_oam_prs_t.num_consecutive_prs_subfames",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&num_consecutive_prs_subfames_values),0x0,"num_consecutive_prs_subfames", HFILL }},
    { &hf_rrm_oam_mac_layer_params_t, 
        { "rrm_oam_mac_layer_params_t","rrm_oam_mac_layer_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_mac_layer_params_t", HFILL }},
    { &hf_rrm_oam_mac_layer_params_t_mac_layer_param_rach, 
        { "mac_layer_param_rach","rrm_oam_mac_layer_params_t.mac_layer_param_rach",FT_NONE,BASE_NONE ,NULL,0x0,"mac_layer_param_rach", HFILL }},
    { &hf_rrm_oam_mac_layer_params_t_mac_layer_param_drx, 
        { "mac_layer_param_drx","rrm_oam_mac_layer_params_t.mac_layer_param_drx",FT_NONE,BASE_NONE ,NULL,0x0,"mac_layer_param_drx", HFILL }},
    { &hf_rrm_oam_rach_t, 
        { "rrm_oam_rach_t","rrm_oam_rach_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rach_t", HFILL }},
    { &hf_rrm_oam_rach_t_preamble_info, 
        { "preamble_info","rrm_oam_rach_t.preamble_info",FT_NONE,BASE_NONE ,NULL,0x0,"preamble_info", HFILL }},
    { &hf_rrm_oam_rach_t_power_ramping_step, 
        { "power_ramping_step","rrm_oam_rach_t.power_ramping_step",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&power_ramping_step_values),0x0,"power_ramping_step", HFILL }},
    { &hf_rrm_oam_rach_t_preamble_initial_received_target_power, 
        { "preamble_initial_received_target_power","rrm_oam_rach_t.preamble_initial_received_target_power",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&preamble_initial_received_target_power_values),0x0,"preamble_initial_received_target_power", HFILL }},
    { &hf_rrm_oam_rach_t_preamble_trans_max, 
        { "preamble_trans_max","rrm_oam_rach_t.preamble_trans_max",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&preamble_trans_max_values),0x0,"preamble_trans_max", HFILL }},
    { &hf_rrm_oam_rach_t_response_window_size, 
        { "response_window_size","rrm_oam_rach_t.response_window_size",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_window_size_values),0x0,"response_window_size", HFILL }},
    { &hf_rrm_oam_rach_t_contention_resolution_timer, 
        { "contention_resolution_timer","rrm_oam_rach_t.contention_resolution_timer",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&contention_resolution_timer_values),0x0,"contention_resolution_timer", HFILL }},
    { &hf_rrm_oam_rach_t_max_harq_msg_3tx, 
        { "max_harq_msg_3tx","rrm_oam_rach_t.max_harq_msg_3tx",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_harq_msg_3tx", HFILL }},
    { &hf_rrm_oam_preamble_info_t, 
        { "rrm_oam_preamble_info_t","rrm_oam_preamble_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_preamble_info_t", HFILL }},
    { &hf_rrm_oam_preamble_info_t_bitmask, 
        { "bitmask","rrm_oam_preamble_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_preamble_info_t_number_of_ra_preambles, 
        { "number_of_ra_preambles","rrm_oam_preamble_info_t.number_of_ra_preambles",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&number_of_ra_preambles_values),0x0,"number_of_ra_preambles", HFILL }},
    { &hf_rrm_oam_preamble_info_t_ra_preamble_groupA_info, 
        { "ra_preamble_groupA_info","rrm_oam_preamble_info_t.ra_preamble_groupA_info",FT_NONE,BASE_NONE ,NULL,0x0,"ra_preamble_groupA_info", HFILL }},
    { &hf_rrm_oam_preamble_groupA_info_t, 
        { "rrm_oam_preamble_info_t","rrm_oam_preamble_groupA_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_preamble_info_t", HFILL }},
    { &hf_rrm_oam_preamble_groupA_info_t_size_of_ra_group_a, 
        { "size_of_ra_group_a","rrm_oam_preamble_groupA_info_t.size_of_ra_group_a",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&size_of_ra_group_a_values),0x0,"size_of_ra_group_a", HFILL }},
    { &hf_rrm_oam_preamble_groupA_info_t_message_size_group_a, 
        { "message_size_group_a","rrm_oam_preamble_groupA_info_t.message_size_group_a",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&message_size_group_a_values),0x0,"message_size_group_a", HFILL }},
    { &hf_rrm_oam_preamble_groupA_info_t_message_power_offset_group_b, 
        { "message_power_offset_group_b","rrm_oam_preamble_groupA_info_t.message_power_offset_group_b",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&message_power_offset_group_b_values),0x0,"message_power_offset_group_b", HFILL }},
    { &hf_rrm_oam_drx_t, 
        { "rrm_oam_drx_t","rrm_oam_drx_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_drx_t", HFILL }},
    { &hf_rrm_oam_drx_t_drx_enabled, 
        { "drx_enabled","rrm_oam_drx_t.drx_enabled",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&drx_enabled_values),0x0,"drx_enabled", HFILL }},
    { &hf_rrm_oam_drx_t_num_valid_drx_profiles, 
        { "num_valid_drx_profiles","rrm_oam_drx_t.num_valid_drx_profiles",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_drx_profiles", HFILL }},
    { &hf_rrm_oam_drx_t_drx_config, 
        { "drx_config","rrm_oam_drx_t.drx_config",FT_NONE,BASE_NONE ,NULL,0x0,"drx_config", HFILL }},
    { &hf_rrm_oam_drx_config_t, 
        { "rrm_oam_drx_config_t","rrm_oam_drx_config_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_drx_config_t", HFILL }},
    { &hf_rrm_oam_drx_config_t_bitmask, 
        { "bitmask","rrm_oam_drx_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_drx_config_t_num_applicable_qci, 
        { "num_applicable_qci","rrm_oam_drx_config_t.num_applicable_qci",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_applicable_qci", HFILL }},
    { &hf_rrm_oam_drx_config_t_applicable_qci_list, 
        { "applicable_qci_list","rrm_oam_drx_config_t.applicable_qci_list",FT_BYTES,BASE_NONE ,NULL,0x0,"applicable_qci_list", HFILL }},
    { &hf_rrm_oam_drx_config_t_on_duration_timer, 
        { "on_duration_timer","rrm_oam_drx_config_t.on_duration_timer",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&on_duration_timer_values),0x0,"on_duration_timer", HFILL }},
    { &hf_rrm_oam_drx_config_t_drx_inactivity_timer, 
        { "drx_inactivity_timer","rrm_oam_drx_config_t.drx_inactivity_timer",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&drx_inactivity_timer_values),0x0,"drx_inactivity_timer", HFILL }},
    { &hf_rrm_oam_drx_config_t_drx_retransmission_timer, 
        { "drx_retransmission_timer","rrm_oam_drx_config_t.drx_retransmission_timer",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&drx_retransmission_timer_values),0x0,"drx_retransmission_timer", HFILL }},
    { &hf_rrm_oam_drx_config_t_long_drx_cycle, 
        { "long_drx_cycle","rrm_oam_drx_config_t.long_drx_cycle",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&long_drx_cycle_values),0x0,"long_drx_cycle", HFILL }},
    { &hf_rrm_oam_drx_config_t_drx_start_offset, 
        { "drx_start_offset","rrm_oam_drx_config_t.drx_start_offset",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"drx_start_offset", HFILL }},
    { &hf_rrm_oam_drx_config_t_short_drx_cycle, 
        { "short_drx_cycle","rrm_oam_drx_config_t.short_drx_cycle",FT_NONE,BASE_NONE ,NULL,0x0,"short_drx_cycle", HFILL }},
    { &hf_rrm_oam_short_drx_cycle_config_t, 
        { "rrm_oam_short_drx_cycle_config_t","rrm_oam_short_drx_cycle_config_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_short_drx_cycle_config_t", HFILL }},
    { &hf_rrm_oam_short_drx_cycle_config_t_short_drx_cycle, 
        { "short_drx_cycle","rrm_oam_short_drx_cycle_config_t.short_drx_cycle",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&short_drx_cycle_values),0x0,"short_drx_cycle", HFILL }},
    { &hf_rrm_oam_short_drx_cycle_config_t_drx_short_cycle_timer, 
        { "drx_short_cycle_timer","rrm_oam_short_drx_cycle_config_t.drx_short_cycle_timer",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"drx_short_cycle_timer", HFILL }},
    { &hf_rrm_oam_mac_layer_params_t_ul_sync_loss_timer,
        { "ul_sync_loss_timer", "rrm_oam_mac_layer_params_t.ul_sync_loss_timer", FT_INT32, BASE_HEX_DEC, NULL, 0x0, "ul_sync_loss_timer", HFILL }},
    { &hf_rrm_oam_mac_layer_params_t_ul_ngap,
        { "n_gap", "hf_rrm_oam_mac_layer_params_t.ul_ngap", FT_INT32, BASE_HEX_DEC, NULL, 0x0, "n_gap", HFILL }},
    { &hf_rrm_oam_rlc_layer_params_t, 
        { "rrm_oam_rlc_layer_params_t","rrm_oam_rlc_layer_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rlc_layer_params_t", HFILL }},
    { &hf_rrm_oam_rlc_layer_params_t_num_valid_srb_info, 
        { "num_valid_srb_info","rrm_oam_rlc_layer_params_t.num_valid_srb_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_srb_info", HFILL }},
    { &hf_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb, 
        { "rlc_layer_param_srb","rrm_oam_rlc_layer_params_t.rlc_layer_param_srb",FT_NONE,BASE_NONE ,NULL,0x0,"rlc_layer_param_srb", HFILL }},
    { &hf_rrm_oam_srb_t, 
        { "rrm_oam_srb_t","rrm_oam_srb_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_srb_t", HFILL }},
    { &hf_rrm_oam_srb_t_bitmask, 
        { "bitmask","rrm_oam_srb_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_srb_t_default_configuration, 
        { "default_configuration","rrm_oam_srb_t.default_configuration",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&default_configuration_values),0x0,"default_configuration", HFILL }},
    { &hf_rrm_oam_srb_t_srb_params, 
        { "srb_params","rrm_oam_srb_t.srb_params",FT_NONE,BASE_NONE ,NULL,0x0,"srb_params", HFILL }},
    { &hf_rrm_oam_srb_info_t, 
        { "rrm_oam_srb_info_t","rrm_oam_srb_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_srb_info_t", HFILL }},
    { &hf_rrm_oam_srb_info_t_t_poll_retransmit, 
        { "t_poll_retransmit","rrm_oam_srb_info_t.t_poll_retransmit",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_poll_retransmit_values),0x0,"t_poll_retransmit", HFILL }},
    { &hf_rrm_oam_srb_info_t_poll_pdu, 
        { "poll_pdu","rrm_oam_srb_info_t.poll_pdu",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&poll_pdu_values),0x0,"poll_pdu", HFILL }},
    { &hf_rrm_oam_srb_info_t_poll_byte, 
        { "poll_byte","rrm_oam_srb_info_t.poll_byte",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&poll_byte_values),0x0,"poll_byte", HFILL }},
    { &hf_rrm_oam_srb_info_t_max_retx_threshold, 
        { "max_retx_threshold","rrm_oam_srb_info_t.max_retx_threshold",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&max_retx_threshold_values),0x0,"max_retx_threshold", HFILL }},
    { &hf_rrm_oam_srb_info_t_t_reordering, 
        { "t_reordering","rrm_oam_srb_info_t.t_reordering",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_reordering_values),0x0,"t_reordering", HFILL }},
    { &hf_rrm_oam_srb_info_t_t_status_prohibit, 
        { "t_status_prohibit","rrm_oam_srb_info_t.t_status_prohibit",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_status_prohibit_values),0x0,"t_status_prohibit", HFILL }},
    { &hf_rrm_oam_mobility_params_t, 
        { "rrm_oam_mobility_params_t","rrm_oam_mobility_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_mobility_params_t", HFILL }},
    { &hf_rrm_oam_mobility_params_t_bitmask,
        { "bitmask", "hf_rrm_oam_mobility_params_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask", HFILL }},
    { &hf_rrm_oam_mobility_params_t_idle_mode_mobility_params, 
        { "idle_mode_mobility_params","rrm_oam_mobility_params_t.idle_mode_mobility_params",FT_NONE,BASE_NONE ,NULL,0x0,"idle_mode_mobility_params", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t, 
        { "rrm_oam_idle_mode_mobility_params_t","rrm_oam_idle_mode_mobility_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_params_t", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t_bitmask, 
        { "Bitmask","rrm_oam_idle_mode_mobility_params_t.bitmask",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"Bitmask", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params, 
        { "idle_mode_mobility_common_params","rrm_oam_idle_mode_mobility_params_t.idle_mode_mobility_common_params",FT_NONE,BASE_NONE ,NULL,0x0,"idle_mode_mobility_common_params", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params, 
        { "idle_mode_mobility_intra_freq_params","rrm_oam_idle_mode_mobility_params_t.idle_mode_mobility_intra_freq_params",FT_NONE,BASE_NONE ,NULL,0x0,"idle_mode_mobility_intra_freq_params", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list, 
        { "idle_mode_inter_freq_params_list","rrm_oam_idle_mode_mobility_params_t.idle_mode_inter_freq_params_list",FT_NONE,BASE_NONE ,NULL,0x0,"idle_mode_inter_freq_params_list", HFILL }},
    { &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params, 
	{ "idle_mode_mobility_inter_rat_utra_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_params_t.idle_mode_mobility_inter_rat_utra_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"idle_mode_mobility_inter_rat_utra_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params, 
	{ "idle_mode_mobility_inter_rat_geran_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_params_t.idle_mode_mobility_inter_rat_geran_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"idle_mode_mobility_inter_rat_geran_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params, 
	{ "idle_mode_mobility_inter_rat_cdma2000_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_params_t.idle_mode_mobility_inter_rat_cdma2000_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"idle_mode_mobility_inter_rat_cdma2000_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t, 
	{ "rrm_oam_idle_mode_mobility_inter_rat_utra_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_utra_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_inter_rat_utra_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_utra_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params, 
	{ "irat_eutra_to_utra_reselection_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_utra_params_t.irat_eutra_to_utra_reselection_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutra_to_utra_reselection_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list, 
	{ "irat_eutran_to_utran_fdd_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_utra_params_t.irat_eutran_to_utran_fdd_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutran_to_utran_fdd_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list, 
	{ "irat_eutran_to_utran_tdd_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_utra_params_t.irat_eutran_to_utran_tdd_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutran_to_utran_tdd_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t, 
	{ "rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_t_reselection_utra, 
	{ "t_reselection_utra","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t.t_reselection_utra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reselection_utra", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors, 
	{ "speed_scale_factors","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t.speed_scale_factors",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"speed_scale_factors", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t, 
	{ "rrm_oam_irat_eutran_to_utran_fdd_list_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_list_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_eutran_to_utran_fdd_list_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_num_irat_eutran_to_utran_fdd_carriers, 
	{ "num_irat_eutran_to_utran_fdd_carriers","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_list_t.num_irat_eutran_to_utran_fdd_carriers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_irat_eutran_to_utran_fdd_carriers", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers, 
	{ "irat_eutran_to_utran_fdd_carriers","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_list_t.irat_eutran_to_utran_fdd_carriers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutran_to_utran_fdd_carriers", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t, 
	{ "rrm_oam_irat_eutran_to_utran_fdd_carriers_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_eutran_to_utran_fdd_carriers_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_utra_carrier_arfcn, 
	{ "utra_carrier_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.utra_carrier_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"utra_carrier_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_rx_lev_min, 
	{ "q_rx_lev_min","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.q_rx_lev_min",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_rx_lev_min", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_qual_min, 
	{ "q_qual_min","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.q_qual_min",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_qual_min", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_cell_reselection_priority, 
	{ "cell_reselection_priority","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_high, 
	{ "thresh_x_high","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.thresh_x_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_high", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_low, 
	{ "thresh_x_low","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_p_max_utra, 
	{ "p_max_utra","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.p_max_utra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_max_utra", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_offset_freq, 
	{ "offset_freq","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.offset_freq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"offset_freq", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9, 
	{ "threshx_q_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_fdd_carriers_t.threshx_q_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"threshx_q_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t, 
	{ "rrm_oam_thresx_rsrq_r9_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_thresx_rsrq_r9_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_thresx_rsrq_r9_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_highq_r9, 
	{ "thresh_serving_highq_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_thresx_rsrq_r9_t.thresh_serving_highq_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_highq_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_lowq_r9, 
	{ "thresh_serving_lowq_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_thresx_rsrq_r9_t.thresh_serving_lowq_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_lowq_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_preemption_vulnerability, 
	{ "preemption_vulnerability","rrm_oam_idle_mode_mobility_params_t.rrm_oam_thresx_rsrq_r9_t.preemption_vulnerability",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"preemption_vulnerability", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t, 
	{ "rrm_oam_irat_eutran_to_utran_tdd_list_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_list_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_eutran_to_utran_tdd_list_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_num_irat_eutran_to_utran_tdd_carriers, 
	{ "num_irat_eutran_to_utran_tdd_carriers","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_list_t.num_irat_eutran_to_utran_tdd_carriers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_irat_eutran_to_utran_tdd_carriers", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers, 
	{ "irat_eutran_to_utran_tdd_carriers","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_list_t.irat_eutran_to_utran_tdd_carriers",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutran_to_utran_tdd_carriers", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t, 
	{ "rrm_oam_irat_eutran_to_utran_tdd_carriers_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_eutran_to_utran_tdd_carriers_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_utra_carrier_arfcn, 
	{ "utra_carrier_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.utra_carrier_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"utra_carrier_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_q_rx_lev_min, 
	{ "q_rx_lev_min","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.q_rx_lev_min",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_rx_lev_min", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_cell_reselection_priority, 
	{ "cell_reselection_priority","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_high, 
	{ "thresh_x_high","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.thresh_x_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_high", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_low, 
	{ "thresh_x_low","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_p_max_utra, 
	{ "p_max_utra","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_eutran_to_utran_tdd_carriers_t.p_max_utra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_max_utra", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t, 
	{ "rrm_oam_idle_mode_mobility_inter_rat_geran_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_geran_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_inter_rat_geran_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_geran_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params, 
	{ "irat_eutra_to_geran_reselection_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_geran_params_t.irat_eutra_to_geran_reselection_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat_eutra_to_geran_reselection_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list, 
	{ "carrier_freq_info_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_geran_params_t.carrier_freq_info_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"carrier_freq_info_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t, 
	{ "rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t.bitmask",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_t_reselection_geran, 
	{ "t_reselection_geran","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t.t_reselection_geran",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_reselection_geran", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors, 
	{ "speed_scale_factors","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t.speed_scale_factors",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"speed_scale_factors", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t, 
	{ "rrm_oam_carrier_freq_geran_param_list_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_list_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_geran_param_list_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_count_geran_carrier, 
	{ "count_geran_carrier","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_list_t.count_geran_carrier",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"count_geran_carrier", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list, 
	{ "carrier_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_list_t.carrier_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"carrier_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t, 
	{ "rrm_oam_carrier_freq_geran_param_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_geran_param_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq, 
	{ "carrier_freq","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_t.carrier_freq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"carrier_freq", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info, 
	{ "common_info","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_geran_param_t.common_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"common_info", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t, 
	{ "rrm_oam_carrier_freq_info_geran_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_info_geran_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_info_geran_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_starting_arfcn, 
	{ "starting_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_info_geran_t.starting_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"starting_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_band_indicator, 
	{ "band_indicator","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_info_geran_t.band_indicator",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"band_indicator", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn, 
	{ "following_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_info_geran_t.following_arfcn",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"following_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t, 
	{ "rrm_oam_geran_following_arfcn_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_geran_following_arfcn_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_geran_following_arfcn_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_geran_following_arfcn_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns, 
	{ "explicit_list_of_arfcns","rrm_oam_idle_mode_mobility_params_t.rrm_oam_geran_following_arfcn_t.explicit_list_of_arfcns",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"explicit_list_of_arfcns", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns, 
	{ "equally_spaced_arfcns","rrm_oam_idle_mode_mobility_params_t.rrm_oam_geran_following_arfcn_t.equally_spaced_arfcns",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"equally_spaced_arfcns", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns, 
	{ "var_bitmap_of_arfcns","rrm_oam_idle_mode_mobility_params_t.rrm_oam_geran_following_arfcn_t.var_bitmap_of_arfcns",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"var_bitmap_of_arfcns", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t, 
	{ "rrm_oam_explicit_list_arfcns_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_explicit_list_arfcns_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_explicit_list_arfcns_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_count_explicit_arfcn, 
	{ "count_explicit_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_explicit_list_arfcns_t.count_explicit_arfcn",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"count_explicit_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_data_explicit_arfcn, 
	{ "data_explicit_arfcn","rrm_oam_idle_mode_mobility_params_t.rrm_oam_explicit_list_arfcns_t.data_explicit_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"data_explicit_arfcn", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t, 
	{ "rrm_oam_equally_spaced_arfcns_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_equally_spaced_arfcns_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_equally_spaced_arfcns_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_arfcn_spacing, 
	{ "arfcn_spacing","rrm_oam_idle_mode_mobility_params_t.rrm_oam_equally_spaced_arfcns_t.arfcn_spacing",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"arfcn_spacing", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_num_of_following_arfcns, 
	{ "num_of_following_arfcns","rrm_oam_idle_mode_mobility_params_t.rrm_oam_equally_spaced_arfcns_t.num_of_following_arfcns",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_of_following_arfcns", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t, 
	{ "rrm_oam_var_bitmap_of_arfcns_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_var_bitmap_of_arfcns_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_var_bitmap_of_arfcns_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_count_var_bit_map, 
	{ "count_var_bit_map","rrm_oam_idle_mode_mobility_params_t.rrm_oam_var_bitmap_of_arfcns_t.count_var_bit_map",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"count_var_bit_map", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_data_var_bitmap, 
	{ "data_var_bitmap","rrm_oam_idle_mode_mobility_params_t.rrm_oam_var_bitmap_of_arfcns_t.data_var_bitmap",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"data_var_bitmap", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info, 
	{ "rrm_oam_carrier_freq_comman_info","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_comman_info", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_cell_reselection_priority, 
	{ "cell_reselection_priority","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_ncc_peritted, 
	{ "ncc_peritted","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.ncc_peritted",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ncc_peritted", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_q_rx_lev_min, 
	{ "q_rx_lev_min","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.q_rx_lev_min",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_rx_lev_min", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_p_max_geran, 
	{ "p_max_geran","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.p_max_geran",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_max_geran", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_high, 
	{ "thresh_x_high","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.thresh_x_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_high", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_low, 
	{ "thresh_x_low","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_offset_freq, 
	{ "offset_freq","rrm_oam_idle_mode_mobility_params_t.rrm_oam_carrier_freq_comman_info.offset_freq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"offset_freq", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t, 
	{ "rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_search_window_size, 
	{ "search_window_size","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.search_window_size",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"search_window_size", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_support_for_dual_rx_ues_r9, 
	{ "csfb_support_for_dual_rx_ues_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.csfb_support_for_dual_rx_ues_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"csfb_support_for_dual_rx_ues_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_registration_param_1xrtt_v920, 
	{ "csfb_registration_param_1xrtt_v920","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.csfb_registration_param_1xrtt_v920",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"csfb_registration_param_1xrtt_v920", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9, 
	{ "ac_barring_config_1_xrtt_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.ac_barring_config_1_xrtt_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_config_1_xrtt_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd, 
	{ "pre_reg_info_hrpd","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.pre_reg_info_hrpd",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pre_reg_info_hrpd", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params, 
	{ "mobility_sib_8_params","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.mobility_sib_8_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"mobility_sib_8_params", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param, 
	{ "cdma2000_cell_param","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.cdma2000_cell_param",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_cell_param", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920, 
	{ "inter_rat_parameters_cdma2000_v920","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.inter_rat_parameters_cdma2000_v920",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"inter_rat_parameters_cdma2000_v920", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd, 
	{ "cell_reselection_params_hrpd","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.cell_reselection_params_hrpd",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_params_hrpd", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt, 
	{ "cell_reselection_params_1xrtt","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.cell_reselection_params_1xrtt",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_params_1xrtt", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_system_time_info, 
	{ "system_time_info","rrm_oam_idle_mode_mobility_params_t.rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t.system_time_info",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"system_time_info", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t, 
	{ "rrm_oam_ac_barring_config_1_xrtt_r9_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ac_barring_config_1_xrtt_r9_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_0_to_9_r9, 
	{ "ac_barring_0_to_9_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_0_to_9_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_0_to_9_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_10_r9, 
	{ "ac_barring_10_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_10_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_10_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_11_r9, 
	{ "ac_barring_11_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_11_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_11_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_12_r9, 
	{ "ac_barring_12_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_12_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_12_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_13_r9, 
	{ "ac_barring_13_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_13_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_13_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_14_r9, 
	{ "ac_barring_14_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_14_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_14_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_15_r9, 
	{ "ac_barring_15_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_15_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_15_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_msg_r9, 
	{ "ac_barring_msg_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_msg_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_msg_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_reg_r9, 
	{ "ac_barring_reg_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_reg_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_reg_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_emg_r9, 
	{ "ac_barring_emg_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.ac_barring_emg_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_emg_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_thresh_x_low, 
	{ "thresh_x_low","rrm_oam_idle_mode_mobility_params_t.rrm_oam_ac_barring_config_1_xrtt_r9_t.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t, 
	{ "rrm_oam_pre_reg_info_hrpd_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_pre_reg_info_hrpd_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_pre_reg_info_hrpd_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_pre_reg_info_hrpd_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_allowed, 
	{ "pre_reg_allowed","rrm_oam_idle_mode_mobility_params_t.rrm_oam_pre_reg_info_hrpd_t.pre_reg_allowed",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pre_reg_allowed", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_zone_id, 
	{ "pre_reg_zone_id","rrm_oam_idle_mode_mobility_params_t.rrm_oam_pre_reg_info_hrpd_t.pre_reg_zone_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pre_reg_zone_id", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list, 
	{ "secondary_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_pre_reg_info_hrpd_t.secondary_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"secondary_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t, 
	{ "rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_count, 
	{ "count","rrm_oam_idle_mode_mobility_params_t.rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t.count",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"count", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_pre_reg_zone_id, 
	{ "pre_reg_zone_id","rrm_oam_idle_mode_mobility_params_t.rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t.pre_reg_zone_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pre_reg_zone_id", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t, 
	{ "rrm_oam_mobility_sib_8_params_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_mobility_sib_8_params_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_sid, 
	{ "sid","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.sid",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sid", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_nid, 
	{ "nid","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.nid",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"nid", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_sid, 
	{ "multiple_sid","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.multiple_sid",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"multiple_sid", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_nid, 
	{ "multiple_nid","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.multiple_nid",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"multiple_nid", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_zone, 
	{ "reg_zone","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.reg_zone",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"reg_zone", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_total_zone, 
	{ "total_zone","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.total_zone",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"total_zone", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_zone_timer, 
	{ "zone_timer","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.zone_timer",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"zone_timer", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_packet_zone_id, 
	{ "packet_zone_id","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.packet_zone_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"packet_zone_id", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_home_reg, 
	{ "home_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.home_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"home_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_sid_reg, 
	{ "foreign_sid_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.foreign_sid_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"foreign_sid_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_nid_reg, 
	{ "foreign_nid_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.foreign_nid_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"foreign_nid_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_parame_reg, 
	{ "parame_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.parame_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"parame_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_up_reg, 
	{ "power_up_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.power_up_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"power_up_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_prd, 
	{ "reg_prd","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.reg_prd",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"reg_prd", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_down_reg, 
	{ "power_down_reg","rrm_oam_idle_mode_mobility_params_t.rrm_oam_mobility_sib_8_params_t.power_down_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"power_down_reg", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t, 
	{ "rrm_oam_cdma2000_cell_param_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_cell_param_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cdma2000_cell_param_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_cell_param_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand, 
	{ "cdma2000_rand","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_cell_param_t.cdma2000_rand",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_rand", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt, 
	{ "cell_id_1xrtt","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_cell_param_t.cell_id_1xrtt",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_id_1xrtt", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd, 
	{ "cell_id_hrpd","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_cell_param_t.cell_id_hrpd",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_id_hrpd", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t, 
	{ "rrm_oam_cdma2000_rand_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_rand_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cdma2000_rand_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_seed, 
	{ "rand_seed","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_rand_t.rand_seed",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rand_seed", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_min, 
	{ "rand_min","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_rand_t.rand_min",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rand_min", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_max, 
	{ "rand_max","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_rand_t.rand_max",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rand_max", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_regenerate_timer, 
	{ "rand_regenerate_timer","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_rand_t.rand_regenerate_timer",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rand_regenerate_timer", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t, 
	{ "rrm_oam_cdma2000_1xrtt_cell_identifier_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_1xrtt_cell_identifier_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cdma2000_1xrtt_cell_identifier_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t_cdma2000_1xrtt_cell_id, 
	{ "cdma2000_1xrtt_cell_id","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_1xrtt_cell_identifier_t.cdma2000_1xrtt_cell_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_1xrtt_cell_id", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t, 
	{ "rrm_oam_cdma2000_hrpd_cell_identifier_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_hrpd_cell_identifier_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cdma2000_hrpd_cell_identifier_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id_length, 
	{ "cdma2000_hrpd_cell_id_length","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_hrpd_cell_identifier_t.cdma2000_hrpd_cell_id_length",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_hrpd_cell_id_length", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id, 
	{ "cdma2000_hrpd_cell_id","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cdma2000_hrpd_cell_identifier_t.cdma2000_hrpd_cell_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_hrpd_cell_id", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t, 
	{ "rrm_oam_irat_parameters_cdma2000_v920_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_parameters_cdma2000_v920_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_parameters_cdma2000_v920_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_parameters_cdma2000_v920_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_1xrtt_r9, 
	{ "eCSFB_1xrtt_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_parameters_cdma2000_v920_t.eCSFB_1xrtt_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"eCSFB_1xrtt_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_conc_ps_mobility_1xrtt_r9, 
	{ "eCSFB_conc_ps_mobility_1xrtt_r9","rrm_oam_idle_mode_mobility_params_t.rrm_oam_irat_parameters_cdma2000_v920_t.eCSFB_conc_ps_mobility_1xrtt_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"eCSFB_conc_ps_mobility_1xrtt_r9", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t, 
	{ "rrm_oam_cell_reselection_params_cdma2000_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cell_reselection_params_cdma2000_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_reselection_params_cdma2000_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cell_reselection_params_cdma2000_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list, 
	{ "band_class_list","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cell_reselection_params_cdma2000_t.band_class_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class_list", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000, 
	{ "t_reselection_cdma2000","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cell_reselection_params_cdma2000_t.t_reselection_cdma2000",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reselection_cdma2000", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf, 
	{ "t_reselection_cdma2000_sf","rrm_oam_idle_mode_mobility_params_t.rrm_oam_cell_reselection_params_cdma2000_t.t_reselection_cdma2000_sf",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reselection_cdma2000_sf", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t, 
	{ "rrm_oam_band_class_list_cdma2000_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_list_cdma2000_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_band_class_list_cdma2000_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_count, 
	{ "count","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_list_cdma2000_t.count",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"count", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000, 
	{ "band_class_info_cdma2000","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_list_cdma2000_t.band_class_info_cdma2000",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class_info_cdma2000", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t, 
	{ "rrm_oam_band_class_info_cdma2000_t","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_band_class_info_cdma2000_t", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_bitmask, 
	{ "bitmask","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_band_class, 
	{ "band_class","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t.band_class",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_cell_reselection_priority, 
	{ "cell_reselection_priority","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_high, 
	{ "thresh_x_high","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t.thresh_x_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_high", HFILL }},
{ &hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_low, 
	{ "thresh_x_low","rrm_oam_idle_mode_mobility_params_t.rrm_oam_band_class_info_cdma2000_t.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},    
    { &hf_rrm_oam_common_params_t, 
        { "rrm_oam_common_params_t","rrm_oam_common_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_common_params_t", HFILL }},
    { &hf_rrm_oam_common_params_t_bitmask, 
        { "bitmask","rrm_oam_common_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_common_params_t_q_hyst, 
        { "q_hyst","rrm_oam_common_params_t.q_hyst",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_hyst_values),0x0,"q_hyst", HFILL }},
    { &hf_rrm_oam_common_params_t_speed_state_params, 
        { "speed_state_params","rrm_oam_common_params_t.speed_state_params",FT_NONE,BASE_NONE ,NULL,0x0,"speed_state_params", HFILL }},
    { &hf_rrm_oam_speed_state_params_t, 
        { "rrm_oam_speed_state_params_t","rrm_oam_speed_state_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_speed_state_params_t", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_q_hyst_sf_medium, 
        { "q_hyst_sf_medium","rrm_oam_speed_state_params_t.q_hyst_sf_medium",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_hyst_sf_medium_values),0x0,"q_hyst_sf_medium", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_q_hyst_sf_high, 
        { "q_hyst_sf_high","rrm_oam_speed_state_params_t.q_hyst_sf_high",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_hyst_sf_high_values),0x0,"q_hyst_sf_high", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_t_evaluation, 
        { "t_evaluation","rrm_oam_speed_state_params_t.t_evaluation",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_evaluation_values),0x0,"t_evaluation", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_t_hyst_normal, 
        { "t_hyst_normal","rrm_oam_speed_state_params_t.t_hyst_normal",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_hyst_normal_values),0x0,"t_hyst_normal", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_n_cell_change_medium, 
        { "n_cell_change_medium","rrm_oam_speed_state_params_t.n_cell_change_medium",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n_cell_change_medium", HFILL }},
    { &hf_rrm_oam_speed_state_params_t_n_cell_change_high, 
        { "n_cell_change_high","rrm_oam_speed_state_params_t.n_cell_change_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"n_cell_change_high", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t, 
        { "rrm_oam_intra_freq_params_t","rrm_oam_intra_freq_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_intra_freq_params_t", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_bitmask, 
        { "bitmask","rrm_oam_intra_freq_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_1, 
        { "q_rx_lev_min_sib_1","rrm_oam_intra_freq_params_t.q_rx_lev_min_sib_1",FT_INT8,BASE_DEC ,NULL,0x0,"q_rx_lev_min_sib_1", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_offset, 
        { "q_rx_lev_min_offset","rrm_oam_intra_freq_params_t.q_rx_lev_min_offset",FT_INT8,BASE_DEC ,NULL,0x0,"q_rx_lev_min_offset", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_p_max_sib_1, 
        { "p_max_sib_1","rrm_oam_intra_freq_params_t.p_max_sib_1",FT_INT8,BASE_DEC ,NULL,0x0,"p_max_sib_1", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_p_max_sib_3, 
        { "p_max_sib_3","rrm_oam_intra_freq_params_t.p_max_sib_3",FT_INT8,BASE_DEC ,NULL,0x0,"p_max_sib_3", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_3, 
        { "q_rx_lev_min_sib_3","rrm_oam_intra_freq_params_t.q_rx_lev_min_sib_3",FT_INT8,BASE_DEC ,NULL,0x0,"q_rx_lev_min_sib_3", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_s_intra_search, 
        { "s_intra_search","rrm_oam_intra_freq_params_t.s_intra_search",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_intra_search", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_t_reselection_eutra, 
        { "t_reselection_eutra","rrm_oam_intra_freq_params_t.t_reselection_eutra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reselection_eutra", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_speed_scale_factors, 
        { "speed_scale_factors","rrm_oam_intra_freq_params_t.speed_scale_factors",FT_NONE,BASE_NONE ,NULL,0x0,"speed_scale_factors", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_s_non_intra_search, 
        { "s_non_intra_search","rrm_oam_intra_freq_params_t.s_non_intra_search",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_non_intra_search", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_cell_reselection_priority, 
        { "cell_reselection_priority","rrm_oam_intra_freq_params_t.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_thresh_serving_low, 
        { "thresh_serving_low","rrm_oam_intra_freq_params_t.thresh_serving_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_low", HFILL }},
    { &hf_rrm_oam_intra_freq_params_t_neigh_cell_config, 
        { "neigh_cell_config","rrm_oam_intra_freq_params_t.neigh_cell_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"neigh_cell_config", HFILL }},
    { &hf_rrm_oam_speed_scale_factors_t, 
        { "rrm_oam_speed_scale_factors_t","rrm_oam_speed_scale_factors_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_speed_scale_factors_t", HFILL }},
    { &hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_medium, 
        { "t_reselection_eutra_sf_medium","rrm_oam_speed_scale_factors_t.t_reselection_eutra_sf_medium",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_reselection_eutra_sf_medium_values),0x0,"t_reselection_eutra_sf_medium", HFILL }},
    { &hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_high, 
        { "t_reselection_eutra_sf_high","rrm_oam_speed_scale_factors_t.t_reselection_eutra_sf_high",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t_reselection_eutra_sf_high_values),0x0,"t_reselection_eutra_sf_high", HFILL }},
    { &hf_rrm_oam_inter_frequency_params_list_t, 
        { "rrm_oam_inter_frequency_params_list_t","rrm_oam_inter_frequency_params_list_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_inter_frequency_params_list_t", HFILL }},
    { &hf_rrm_oam_inter_frequency_params_list_t_num_valid_inter_freq_list, 
        { "num_valid_inter_freq_list","rrm_oam_inter_frequency_params_list_t.num_valid_inter_freq_list",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_inter_freq_list", HFILL }},
    { &hf_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params, 
        { "idle_mode_mobility_inter_freq_params","rrm_oam_inter_frequency_params_list_t.idle_mode_mobility_inter_freq_params",FT_NONE,BASE_NONE ,NULL,0x0,"idle_mode_mobility_inter_freq_params", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t, 
        { "rrm_oam_inter_freq_params_t","rrm_oam_inter_freq_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_inter_freq_params_t", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_bitmask, 
        { "bitmask","rrm_oam_inter_freq_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_eutra_carrier_arfcn, 
        { "eutra_carrier_arfcn","rrm_oam_inter_freq_params_t.eutra_carrier_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"eutra_carrier_arfcn", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_q_rx_lev_min_sib_5, 
        { "q_rx_lev_min_sib_5","rrm_oam_inter_freq_params_t.q_rx_lev_min_sib_5",FT_INT8,BASE_DEC ,NULL,0x0,"q_rx_lev_min_sib_5", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_q_offset_freq, 
        { "q_offset_freq","rrm_oam_inter_freq_params_t.q_offset_freq",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_offset_freq_values),0x0,"q_offset_freq", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_t_reselection_eutra, 
        { "t_reselection_eutra","rrm_oam_inter_freq_params_t.t_reselection_eutra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reselection_eutra", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_cell_reselection_priority, 
        { "cell_reselection_priority","rrm_oam_inter_freq_params_t.cell_reselection_priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_reselection_priority", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_thresh_x_high, 
        { "thresh_x_high","rrm_oam_inter_freq_params_t.thresh_x_high",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_high", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_thresh_x_low, 
        { "thresh_x_low","rrm_oam_inter_freq_params_t.thresh_x_low",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_x_low", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_p_max, 
        { "p_max","rrm_oam_inter_freq_params_t.p_max",FT_INT8,BASE_DEC ,NULL,0x0,"p_max", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_measurement_bandwidth, 
        { "measurement_bandwidth","rrm_oam_inter_freq_params_t.measurement_bandwidth",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&measurement_bandwidth_values),0x0,"measurement_bandwidth", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_presence_antenna_port1, 
        { "presence_antenna_port1","rrm_oam_inter_freq_params_t.presence_antenna_port1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"presence_antenna_port1", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_neigh_cell_config, 
        { "neigh_cell_config","rrm_oam_inter_freq_params_t.neigh_cell_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"neigh_cell_config", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_speed_scale_factors, 
        { "speed_scale_factors","rrm_oam_inter_freq_params_t.speed_scale_factors",FT_NONE,BASE_NONE ,NULL,0x0,"speed_scale_factors", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_q_qual_min_r9, 
        { "q_qual_min_r9","rrm_oam_inter_freq_params_t.q_qual_min_r9",FT_INT8,BASE_DEC ,NULL,0x0,"q_qual_min_r9", HFILL }},
    { &hf_rrm_oam_inter_freq_params_t_threshx_q_r9, 
        { "threshx_q_r9","rrm_oam_inter_freq_params_t.threshx_q_r9",FT_NONE,BASE_NONE ,NULL,0x0,"threshx_q_r9", HFILL }},
    { &hf_rrm_oam_thresholdx_q_r9_t, 
        { "rrm_oam_thresholdx_q_r9_t","rrm_oam_thresholdx_q_r9_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_thresholdx_q_r9_t", HFILL }},
    { &hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_highq_r9, 
        { "thresh_serving_highq_r9","rrm_oam_thresholdx_q_r9_t.thresh_serving_highq_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_highq_r9", HFILL }},
    { &hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_lowq_r9, 
        { "thresh_serving_lowq_r9","rrm_oam_thresholdx_q_r9_t.thresh_serving_lowq_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_lowq_r9", HFILL }},
    { &hf_rrm_oam_rrc_timers_and_constants_t, 
        { "rrm_oam_rrc_timers_and_constants_t","rrm_oam_rrc_timers_and_constants_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rrc_timers_and_constants_t", HFILL }},
    { &hf_rrm_oam_rrc_timers_and_constants_t_rrc_timers, 
        { "rrc_timers","rrm_oam_rrc_timers_and_constants_t.rrc_timers",FT_NONE,BASE_NONE ,NULL,0x0,"rrc_timers", HFILL }},
    { &hf_rrm_oam_rrc_timers_and_constants_t_rrc_constants, 
        { "rrc_constants","rrm_oam_rrc_timers_and_constants_t.rrc_constants",FT_NONE,BASE_NONE ,NULL,0x0,"rrc_constants", HFILL }},
    { &hf_rrm_oam_rrc_timers_t, 
        { "rrm_oam_rrc_timers_t","rrm_oam_rrc_timers_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rrc_timers_t", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t300, 
        { "t300","rrm_oam_rrc_timers_t.t300",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t300_values),0x0,"t300", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t301, 
        { "t301","rrm_oam_rrc_timers_t.t301",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t301_values),0x0,"t301", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t302, 
        { "t302","rrm_oam_rrc_timers_t.t302",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t302_values),0x0,"t302", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t304_eutra, 
        { "t304_eutra","rrm_oam_rrc_timers_t.t304_eutra",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t304_eutra_values),0x0,"t304_eutra", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t304_irat, 
        { "t304_irat","rrm_oam_rrc_timers_t.t304_irat",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t304_irat_values),0x0,"t304_irat", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t310, 
        { "t310","rrm_oam_rrc_timers_t.t310",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t310_values),0x0,"t310", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t311, 
        { "t311","rrm_oam_rrc_timers_t.t311",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t311_values),0x0,"t311", HFILL }},
    { &hf_rrm_oam_rrc_timers_t_t320, 
        { "t320","rrm_oam_rrc_timers_t.t320",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&t320_values),0x0,"t320", HFILL }},
    { &hf_rrm_oam_rrc_constants_t, 
        { "rrm_oam_rrc_constants_t","rrm_oam_rrc_constants_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rrc_constants_t", HFILL }},
    { &hf_rrm_oam_rrc_constants_t_n310, 
        { "n310","rrm_oam_rrc_constants_t.n310",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&n310_values),0x0,"n310", HFILL }},
    { &hf_rrm_oam_rrc_constants_t_n311, 
        { "n311","rrm_oam_rrc_constants_t.n311",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&n311_values),0x0,"n311", HFILL }},
    { &hf_rrm_oam_rf_params_t, 
        { "rrm_oam_rf_params_t","rrm_oam_rf_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rf_params_t", HFILL }},
    { &hf_rrm_oam_rf_params_t_rf_configurations, 
        { "rf_configurations","rrm_oam_rf_params_t.rf_configurations",FT_NONE,BASE_NONE ,NULL,0x0,"rf_configurations", HFILL }},
    { &hf_rrm_oam_rf_configurations_t, 
        { "rrm_oam_rf_configurations_t","rrm_oam_rf_configurations_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rf_configurations_t", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_bitmask, 
        { "bitmask","rrm_oam_rf_configurations_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_frequency_band_indicator, 
        { "frequency_band_indicator","rrm_oam_rf_configurations_t.frequency_band_indicator",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"frequency_band_indicator", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_dl_earfcn, 
        { "dl_earfcn","rrm_oam_rf_configurations_t.dl_earfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"dl_earfcn", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_dl_bandwidth, 
        { "bandwidth","rrm_oam_rf_configurations_t.dl_bandwidth",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&dl_bandwidth_values),0x0,"dl_bandwidth", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_ul_earfcn, 
        { "ul_earfcn","rrm_oam_rf_configurations_t.ul_earfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"ul_earfcn", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_ul_bandwidth, 
        { "ul_bandwidth","rrm_oam_rf_configurations_t.ul_bandwidth",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&ul_bandwidth_values),0x0,"ul_bandwidth", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_reference_signal_power, 
        { "reference_signal_power","rrm_oam_rf_configurations_t.reference_signal_power",FT_INT8,BASE_DEC ,NULL,0x0,"reference_signal_power", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_phy_cell_id, 
        { "phy_cell_id","rrm_oam_rf_configurations_t.phy_cell_id",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"phy_cell_id", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_psch_power_offset, 
        { "psch_power_offset","rrm_oam_rf_configurations_t.psch_power_offset",FT_INT16,BASE_DEC ,NULL,0x0,"psch_power_offset", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_ssch_power_offset, 
        { "ssch_power_offset","rrm_oam_rf_configurations_t.ssch_power_offset",FT_INT16,BASE_DEC ,NULL,0x0,"ssch_power_offset", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_pbch_power_offset, 
        { "pbch_power_offset","rrm_oam_rf_configurations_t.pbch_power_offset",FT_INT16,BASE_DEC ,NULL,0x0,"pbch_power_offset", HFILL }},
    { &hf_rrm_oam_rf_configurations_t_max_rs_epre, 
        { "max_rs_epre","rrm_oam_rf_configurations_t.max_rs_epre",FT_INT16,BASE_DEC ,NULL,0x0,"max_rs_epre", HFILL }},
    { &hf_rrm_oam_s1ap_params_t, 
        { "rrm_oam_s1ap_params_t","rrm_oam_s1ap_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_s1ap_params_t", HFILL }},
    { &hf_rrm_oam_s1ap_params_t_t_reloc_prep, 
        { "t_reloc_prep","rrm_oam_s1ap_params_t.t_reloc_prep",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reloc_prep", HFILL }},
    { &hf_rrm_oam_s1ap_params_t_t_reloc_overall, 
        { "t_reloc_overall","rrm_oam_s1ap_params_t.t_reloc_overall",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_reloc_overall", HFILL }},
    { &hf_rrm_oam_ncl_params_t, 
        { "rrm_oam_ncl_params_t","rrm_oam_ncl_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_ncl_params_t", HFILL }},
    { &hf_rrm_oam_ncl_params_t_bitmask, 
        { "bitmask","rrm_oam_ncl_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_ncl_params_t_lte_ncl, 
        { "lte_ncl","rrm_oam_ncl_params_t.lte_ncl",FT_NONE,BASE_NONE ,NULL,0x0,"lte_ncl", HFILL }},
    { &hf_rrm_oam_ncl_params_t_inter_rat_ncl, 
        { "inter_rat_ncl","rrm_oam_ncl_params_t.inter_rat_ncl",FT_NONE,BASE_NONE ,NULL,0x0,"inter_rat_ncl", HFILL }},
    { &hf_rrm_oam_inter_rat_ncl_t_unparsed_data, 
	{ "Unparsed protocol data","rrm_oam_inter_rat_ncl_t.unparsed_data",FT_BYTES,BASE_NONE, NULL, 0x0,"Unparsed frr protocol data", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t, 
	{ "rrm_oam_inter_rat_ncl_t","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_inter_rat_ncl_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_num_valid_utran_freq_cell, 
	{ "num_valid_utran_freq_cell","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.num_valid_utran_freq_cell",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_utran_freq_cell", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_utran_freq_cells, 
	{ "utran_freq_cells","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.utran_freq_cells",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"utran_freq_cells", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_num_valid_geran_freq_cell, 
	{ "num_valid_utran_freq_cell","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.num_valid_geran_freq_cell",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_utran_freq_cell", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_geran_freq_cells, 
	{ "geran_freq_cells","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.geran_freq_cells",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"geran_freq_cells", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_num_valid_cdma2000_freq_cells, 
	{ "num_valid_utran_freq_cell","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.num_valid_cdma2000_freq_cells",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_utran_freq_cell", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells, 
	{ "cdma2000_freq_cells","rrm_oam_inter_rat_ncl_t.rrm_oam_inter_rat_ncl_t.cdma2000_freq_cells",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_freq_cells", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t, 
	{ "rrm_oam_utran_freq_cells_t","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_utran_freq_cells_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai, 
	{ "rai","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.rai",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rai", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id, 
	{ "uc_id","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.uc_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"uc_id", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ura, 
	{ "ura","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.ura",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"ura", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcnul, 
	{ "uarfcnul","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.uarfcnul",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"uarfcnul", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcndl, 
	{ "uarfcndl","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.uarfcndl",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"uarfcndl", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_scrambling_code, 
	{ "pcpich_scrambling_code","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.pcpich_scrambling_code",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pcpich_scrambling_code", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_tx_power, 
	{ "pcpich_tx_power","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.pcpich_tx_power",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pcpich_tx_power", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_offset_freq, 
	{ "offset_freq","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.offset_freq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"offset_freq", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_cell_access_mode, 
	{ "cell_access_mode","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.cell_access_mode",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cell_access_mode", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_blacklisted, 
	{ "blacklisted","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.blacklisted",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"blacklisted", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_csg_identity, 
	{ "csg_identity","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.csg_identity",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"csg_identity", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ho_status, 
	{ "ho_status","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.ho_status",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ho_status", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ps_ho_supported, 
	{ "ps_ho_supported","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.ps_ho_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ps_ho_supported", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_voip_capable, 
	{ "voip_capable","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.voip_capable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"voip_capable", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_daho_indication, 
	{ "daho_indication","rrm_oam_inter_rat_ncl_t.rrm_oam_utran_freq_cells_t.daho_indication",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"daho_indication", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t, 
	{ "rrm_rai_t","rrm_oam_inter_rat_ncl_t.rrm_rai_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_rai_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai, 
	{ "lai","rrm_oam_inter_rat_ncl_t.rrm_rai_t.lai",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"lai", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_rac, 
	{ "rac","rrm_oam_inter_rat_ncl_t.rrm_rai_t.rac",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rac", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t, 
	{ "rrm_lai_t","rrm_oam_inter_rat_ncl_t.rrm_lai_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_lai_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id, 
	{ "plmn_id","rrm_oam_inter_rat_ncl_t.rrm_lai_t.plmn_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"plmn_id", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_lac, 
	{ "lac","rrm_oam_inter_rat_ncl_t.rrm_lai_t.lac",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"lac", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t, 
	{ "rrm_oam_geran_freq_cells_t","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_geran_freq_cells_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai, 
	{ "lai","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.lai",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"lai", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_cell_id, 
	{ "cell_id","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.cell_id",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"cell_id", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bandindicator, 
	{ "bandindicator","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.bandindicator",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bandindicator", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bccharfcn, 
	{ "bccharfcn","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.bccharfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"bccharfcn", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_pci, 
	{ "pci","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.pci",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pci", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_network_control_order, 
	{ "network_control_order","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.network_control_order",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"network_control_order", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_ho_status, 
	{ "ho_status","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.ho_status",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ho_status", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_supported, 
	{ "dtm_supported","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.dtm_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dtm_supported", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_ho_supported, 
	{ "dtm_ho_supported","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.dtm_ho_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dtm_ho_supported", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_voip_capable, 
	{ "voip_capable","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.voip_capable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"voip_capable", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_daho_indication, 
	{ "daho_indication","rrm_oam_inter_rat_ncl_t.rrm_oam_geran_freq_cells_t.daho_indication",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"daho_indication", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t, 
	{ "rrm_oam_cdma2000_freq_cells_t","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cdma2000_freq_cells_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai, 
	{ "band_class","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.lai",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_band_class, 
	{ "band_class","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.band_class",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_arfcn, 
	{ "arfcn","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"arfcn", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_pn_offset, 
	{ "pn_offset","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.pn_offset",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"pn_offset", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_type, 
	{ "type","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.type",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"type", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_num_valid_count_cid, 
	{ "num_valid_count_cid","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.num_valid_count_cid",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_count_cid", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_CID, 
	{ "CID","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.CID",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"CID", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params, 
	{ "cell_specific_params","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.cell_specific_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_specific_params", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_daho_indication, 
	{ "daho_indication","rrm_oam_inter_rat_ncl_t.rrm_oam_cdma2000_freq_cells_t.daho_indication",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"daho_indication", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t, 
	{ "rrm_oam_cell_specific_params_t","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_specific_params_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included, 
	{ "pz_hyst_parameters_included","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.pz_hyst_parameters_included",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_parameters_included", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_p_rev, 
	{ "p_rev","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.p_rev",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_rev", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_min_p_rev, 
	{ "min_p_rev","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.min_p_rev",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"min_p_rev", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_neg_slot_cycle_index_sup, 
	{ "neg_slot_cycle_index_sup","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.neg_slot_cycle_index_sup",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"neg_slot_cycle_index_sup", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_encrypt_mode, 
	{ "encrypt_mode","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.encrypt_mode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"encrypt_mode", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_enc_supported, 
	{ "enc_supported","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.enc_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"enc_supported", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_encrypt_sup, 
	{ "sig_encrypt_sup","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.sig_encrypt_sup",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sig_encrypt_sup", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_msg_integrity_sup, 
	{ "msg_integrity_sup","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.msg_integrity_sup",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"msg_integrity_sup", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup_incl, 
	{ "sig_integrity_sup_incl","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.sig_integrity_sup_incl",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sig_integrity_sup_incl", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup, 
	{ "sig_integrity_sup","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.sig_integrity_sup",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sig_integrity_sup", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_ms_init_pos_loc_sup_ind, 
	{ "ms_init_pos_loc_sup_ind","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.ms_init_pos_loc_sup_ind",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ms_init_pos_loc_sup_ind", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class_info_req, 
	{ "band_class_info_req","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.band_class_info_req",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class_info_req", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class, 
	{ "band_class","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.band_class",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"band_class", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_alt_band_class, 
	{ "alt_band_class","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.alt_band_class",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"alt_band_class", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_mode_supported, 
	{ "tkz_mode_supported","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.tkz_mode_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"tkz_mode_supported", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_id, 
	{ "tkz_id","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.tkz_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"tkz_id", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included, 
	{ "fpc_fch_included","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.fpc_fch_included",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"fpc_fch_included", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_t_add, 
	{ "t_add","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.t_add",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"t_add", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pilot_inc, 
	{ "pilot_inc","rrm_oam_inter_rat_ncl_t.rrm_oam_cell_specific_params_t.pilot_inc",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pilot_inc", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t, 
	{ "rrm_oam_pz_hyst_parameters_included_t","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_pz_hyst_parameters_included_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_enabled, 
	{ "pz_hyst_enabled","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_enabled",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_enabled", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_info_incl, 
	{ "pz_hyst_info_incl","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_info_incl",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_info_incl", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_list_len, 
	{ "pz_hyst_list_len","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_list_len",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_list_len", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_act_timer, 
	{ "pz_hyst_act_timer","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_act_timer",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_act_timer", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_mul, 
	{ "pz_hyst_timer_mul","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_timer_mul",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_timer_mul", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_exp, 
	{ "pz_hyst_timer_exp","rrm_oam_inter_rat_ncl_t.rrm_oam_pz_hyst_parameters_included_t.pz_hyst_timer_exp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pz_hyst_timer_exp", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t, 
	{ "rrm_oam_fpc_fch_included_t","rrm_oam_inter_rat_ncl_t.rrm_oam_fpc_fch_included_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_fpc_fch_included_t", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_bitmask, 
	{ "bitmask","rrm_oam_inter_rat_ncl_t.rrm_oam_fpc_fch_included_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc3, 
	{ "fpc_fch_init_setpt_rc3","rrm_oam_inter_rat_ncl_t.rrm_oam_fpc_fch_included_t.fpc_fch_init_setpt_rc3",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"fpc_fch_init_setpt_rc3", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc4, 
	{ "fpc_fch_init_setpt_rc4","rrm_oam_inter_rat_ncl_t.rrm_oam_fpc_fch_included_t.fpc_fch_init_setpt_rc4",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"fpc_fch_init_setpt_rc4", HFILL }},
{ &hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc5, 
	{ "fpc_fch_init_setpt_rc5","rrm_oam_inter_rat_ncl_t.rrm_oam_fpc_fch_included_t.fpc_fch_init_setpt_rc5",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"fpc_fch_init_setpt_rc5", HFILL }},
    { &hf_rrm_oam_connected_mode_mobility_params_t_unparsed_data, 
	{ "Unparsed protocol data","rrm_oam_connected_mode_mobility_params_t.unparsed_data",FT_BYTES,BASE_NONE, NULL, 0x0,"Unparsed frr protocol data", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t, 
	{ "rrm_oam_connected_mode_mobility_params_t","rrm_oam_connected_mode_mobility_params_t.rrm_oam_connected_mode_mobility_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_connected_mode_mobility_params_t", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_bitmask, 
	{ "bitmask","rrm_oam_connected_mode_mobility_params_t.rrm_oam_connected_mode_mobility_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra, 
	{ "common_params_for_eutra","rrm_oam_connected_mode_mobility_params_t.rrm_oam_connected_mode_mobility_params_t.common_params_for_eutra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"common_params_for_eutra", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat, 
	{ "irat","rrm_oam_connected_mode_mobility_params_t.rrm_oam_connected_mode_mobility_params_t.irat",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"irat", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t, 
	{ "rrm_oam_common_params_for_eutra_t","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_common_params_for_eutra_t", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_bitmask, 
	{ "bitmask","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrp, 
	{ "filter_coefficient_rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.filter_coefficient_rsrp",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"filter_coefficient_rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrq, 
	{ "filter_coefficient_rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.filter_coefficient_rsrq",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"filter_coefficient_rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrp, 
	{ "a1_threshold_rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a1_threshold_rsrp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a1_threshold_rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrq, 
	{ "a1_threshold_rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a1_threshold_rsrq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a1_threshold_rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrp, 
	{ "a2_threshold_rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a2_threshold_rsrp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a2_threshold_rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrq, 
	{ "a2_threshold_rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a2_threshold_rsrq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a2_threshold_rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a3_offset, 
	{ "a3_offset","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a3_offset",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a3_offset", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_on_leave, 
	{ "report_on_leave","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.report_on_leave",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"report_on_leave", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrp, 
	{ "a4_threshold_rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a4_threshold_rsrp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a4_threshold_rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrq, 
	{ "a4_threshold_rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a4_threshold_rsrq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a4_threshold_rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrp, 
	{ "a5_threshold_1rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a5_threshold_1rsrp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a5_threshold_1rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrq, 
	{ "a5_threshold_1rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a5_threshold_1rsrq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a5_threshold_1rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrp, 
	{ "a5_threshold_2rsrp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a5_threshold_2rsrp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a5_threshold_2rsrp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrq, 
	{ "a5_threshold_2rsrq","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.a5_threshold_2rsrq",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"a5_threshold_2rsrq", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_hysteresis, 
	{ "hysteresis","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.hysteresis",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"hysteresis", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_time_to_trigger, 
	{ "time_to_trigger","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.time_to_trigger",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"time_to_trigger", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_trigger_quantity, 
	{ "trigger_quantity","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.trigger_quantity",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"trigger_quantity", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_quantity, 
	{ "report_quantity","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.report_quantity",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_quantity", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_interval, 
	{ "report_interval","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.report_interval",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_interval", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_amount, 
	{ "report_amount","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.report_amount",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_amount", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_ps_ho_enabled, 
	{ "ps_ho_enabled","rrm_oam_connected_mode_mobility_params_t.rrm_oam_common_params_for_eutra_t.ps_ho_enabled",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ps_ho_enabled", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t, 
	{ "rrm_oam_irat_t","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_irat_t", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_bitmask, 
	{ "bitmask","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_qoffset_tutra, 
	{ "qoffset_tutra","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.qoffset_tutra",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"qoffset_tutra", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_utra, 
	{ "filter_coefficient_utra","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.filter_coefficient_utra",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"filter_coefficient_utra", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_fdd, 
	{ "meas_quantity_utra_fdd","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.meas_quantity_utra_fdd",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"meas_quantity_utra_fdd", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_tdd, 
	{ "meas_quantity_utra_tdd","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.meas_quantity_utra_tdd",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"meas_quantity_utra_tdd", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_rscp, 
	{ "b1_threshold_utra_rscp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b1_threshold_utra_rscp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b1_threshold_utra_rscp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_ecn0, 
	{ "b1_threshold_utra_ecn0","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b1_threshold_utra_ecn0",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b1_threshold_utra_ecn0", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_geran, 
	{ "q_offset_geran","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.q_offset_geran",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_offset_geran", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_geran, 
	{ "filter_coefficient_geran","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.filter_coefficient_geran",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"filter_coefficient_geran", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_geran, 
	{ "b1_threshold_geran","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b1_threshold_geran",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b1_threshold_geran", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_cdma2000, 
	{ "q_offset_cdma2000","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.q_offset_cdma2000",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_offset_cdma2000", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_cdma2000, 
	{ "meas_quantity_cdma2000","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.meas_quantity_cdma2000",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"meas_quantity_cdma2000", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_cdma2000, 
	{ "b1_threshold_cdma2000","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b1_threshold_cdma2000",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b1_threshold_cdma2000", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_rscp, 
	{ "b2_threshold_2utra_rscp","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b2_threshold_2utra_rscp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b2_threshold_2utra_rscp", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_ecn0, 
	{ "b2_threshold_2utra_ecn0","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b2_threshold_2utra_ecn0",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b2_threshold_2utra_ecn0", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2geran, 
	{ "b2_threshold_2geran","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b2_threshold_2geran",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b2_threshold_2geran", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2cdma, 
	{ "b2_threshold_2cdma","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.b2_threshold_2cdma",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"b2_threshold_2cdma", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_hysteresis, 
	{ "hysteresis","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.hysteresis",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"hysteresis", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_time_to_trigger, 
	{ "time_to_trigger","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.time_to_trigger",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"time_to_trigger", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_max_report_cells, 
	{ "max_report_cells","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.max_report_cells",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_report_cells", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_interval, 
	{ "report_interval","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.report_interval",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_interval", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_amount, 
	{ "report_amount","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.report_amount",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_amount", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ps_ho_enabled, 
	{ "ps_ho_enabled","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.ps_ho_enabled",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ps_ho_enabled", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params, 
	{ "ue_generic_cdma2000_params","rrm_oam_connected_mode_mobility_params_t.rrm_oam_irat_t.ue_generic_cdma2000_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ue_generic_cdma2000_params", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t, 
	{ "rrm_oam_ue_generic_cdma2000_params_t","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ue_generic_cdma2000_params_t", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bitmask, 
	{ "bitmask","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auth, 
	{ "auth","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.auth",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"auth", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_num_alt_so, 
	{ "max_num_alt_so","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.max_num_alt_so",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_num_alt_so", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_use_sync_id, 
	{ "use_sync_id","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.use_sync_id",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"use_sync_id", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mob_qos, 
	{ "mob_qos","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.mob_qos",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"mob_qos", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bypass_reg_ind, 
	{ "bypass_reg_ind","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.bypass_reg_ind",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"bypass_reg_ind", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_add_serv_instance, 
	{ "max_add_serv_instance","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.max_add_serv_instance",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_add_serv_instance", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_parameter_reg, 
	{ "parameter_reg","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.parameter_reg",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"parameter_reg", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reg_dist, 
	{ "reg_dist","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.reg_dist",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"reg_dist", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pref_msid_type, 
	{ "pref_msid_type","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.pref_msid_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pref_msid_type", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_ext_pref_msid_type, 
	{ "ext_pref_msid_type","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.ext_pref_msid_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ext_pref_msid_type", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_meid_reqd, 
	{ "meid_reqd","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.meid_reqd",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"meid_reqd", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mcc, 
	{ "mcc","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.mcc",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"mcc", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_11_12, 
	{ "imsi_11_12","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.imsi_11_12",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"imsi_11_12", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_t_supported, 
	{ "imsi_t_supported","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.imsi_t_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"imsi_t_supported", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reconnect_msg_ind, 
	{ "reconnect_msg_ind","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.reconnect_msg_ind",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"reconnect_msg_ind", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_rer_mode_supported, 
	{ "rer_mode_supported","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.rer_mode_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rer_mode_supported", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pilot_report, 
	{ "pilot_report","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.pilot_report",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pilot_report", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_supported, 
	{ "sdb_supported","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.sdb_supported",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sdb_supported", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auto_fcso_allowed, 
	{ "auto_fcso_allowed","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.auto_fcso_allowed",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"auto_fcso_allowed", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_in_rcnm_ind, 
	{ "sdb_in_rcnm_ind","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.sdb_in_rcnm_ind",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sdb_in_rcnm_ind", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_daylt, 
	{ "daylt","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.daylt",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"daylt", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_l2_ack_timer, 
	{ "gcsna_l2_ack_timer","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.gcsna_l2_ack_timer",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"gcsna_l2_ack_timer", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_sequence_context_timer, 
	{ "gcsna_sequence_context_timer","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.gcsna_sequence_context_timer",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"gcsna_sequence_context_timer", HFILL }},
{ &hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_lp_sec, 
	{ "lp_sec","rrm_oam_connected_mode_mobility_params_t.rrm_oam_ue_generic_cdma2000_params_t.lp_sec",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"lp_sec", HFILL }},
    { &hf_rrm_utran_cell_id_t, 
        { "rrm_utran_cell_id_t","rrm_utran_cell_id_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_utran_cell_id_t", HFILL }},
    { &hf_rrm_utran_cell_id_t_bitmask , 
        { "bitmask ","rrm_utran_cell_id_t",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"bitmask ", HFILL }},
    { &hf_rrm_utran_cell_id_t_cell_id , 
        { "cell_id ","rrm_utran_cell_id_t.cell_id",FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"cell_id", HFILL }},
    { &hf_rrm_utran_cell_id_t_rnc_id, 
        { "rnc_id","rrm_utran_cell_id_t.rnc_id",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"rnc_id", HFILL }},
    { &hf_rrm_utran_cell_id_t_extended_rnc_id, 
        { "extended_rnc_id","rrm_utran_cell_id_t.extended_rnc_id",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"extended_rnc_id", HFILL }},
    { &hf_rrm_oam_lte_ncl_t, 
        { "rrm_oam_lte_ncl_t","rrm_oam_lte_ncl_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_lte_ncl_t", HFILL }},
    { &hf_rrm_oam_lte_ncl_t_num_valid_intra_freq_cell, 
        { "num_valid_intra_freq_cell","rrm_oam_lte_ncl_t.num_valid_intra_freq_cell",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_intra_freq_cell", HFILL }},
    { &hf_rrm_oam_lte_ncl_t_intra_freq_cells, 
        { "intra_freq_cells","rrm_oam_lte_ncl_t.intra_freq_cells",FT_NONE,BASE_NONE ,NULL,0x0,"intra_freq_cells", HFILL }},
    { &hf_rrm_oam_lte_ncl_t_num_valid_inter_freq_cell, 
        { "num_valid_inter_freq_cell","rrm_oam_lte_ncl_t.num_valid_inter_freq_cell",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_inter_freq_cell", HFILL }},
    { &hf_rrm_oam_lte_ncl_t_inter_freq_cells, 
        { "inter_freq_cells","rrm_oam_lte_ncl_t.inter_freq_cells",FT_NONE,BASE_NONE ,NULL,0x0,"inter_freq_cells", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t, 
        { "rrm_oam_intra_freq_cells_t","rrm_oam_intra_freq_cells_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_intra_freq_cells_t", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_bitmask, 
        { "bitmask","rrm_oam_intra_freq_cells_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_cell_id, 
        { "cell_id","rrm_oam_intra_freq_cells_t.cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"cell_id", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_phy_cell_id, 
        { "phy_cell_id","rrm_oam_intra_freq_cells_t.phy_cell_id",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"phy_cell_id", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_q_offset, 
        { "q_offset","rrm_oam_intra_freq_cells_t.q_offset",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_offset_values),0x0,"q_offset", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_cell_individual_offset, 
        { "cell_individual_offset","rrm_oam_intra_freq_cells_t.cell_individual_offset",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&cio_values),0x0,"cell_individual_offset", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_r_stx_power, 
        { "r_stx_power","rrm_oam_intra_freq_cells_t.r_stx_power",FT_INT8,BASE_DEC ,NULL,0x0,"r_stx_power", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_blacklisted, 
        { "blacklisted","rrm_oam_intra_freq_cells_t.blacklisted",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&blacklisted_values),0x0,"blacklisted", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_cell_access_mode, 
        { "cell_access_mode","rrm_oam_intra_freq_cells_t.cell_access_mode",FT_INT32,BASE_HEX_DEC,NULL,0x0,"cell_access_mode", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_csg_identity, 
        { "csg_identity","rrm_oam_intra_freq_cells_t.csg_identity",FT_INT8,BASE_HEX_DEC,NULL,0x0,"csg_identity", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_ho_status, 
        { "ho_status","rrm_oam_intra_freq_cells_t.ho_status",FT_INT32,BASE_HEX_DEC,NULL,0x0,"ho_status", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_x2_status, 
        { "x2_status","rrm_oam_intra_freq_cells_t.x2_status",FT_INT32,BASE_HEX_DEC,NULL,0x0,"x2_status", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_broadcast_status, 
        { "broadcast_status","rrm_oam_intra_freq_cells_t.broadcast_status",FT_INT32,BASE_HEX_DEC,NULL,0x0,"broadcast_status", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_tac, 
        { "tac","rrm_oam_intra_freq_cells_t.tac",FT_INT8,BASE_HEX_DEC,NULL,0x0,"tac", HFILL }},
    { &hf_rrm_oam_intra_freq_cells_t_daho_indication, 
        { "daho_indication","rrm_oam_intra_freq_cells_t.daho_indication",FT_INT8,BASE_HEX_DEC,NULL,0x0,"daho_indication", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t, 
        { "rrm_oam_inter_freq_cells_t","rrm_oam_inter_freq_cells_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_inter_freq_cells_t", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_bitmask, 
        { "bitmask","rrm_oam_inter_freq_cells_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_cell_id, 
        { "cell_id","rrm_oam_inter_freq_cells_t.cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"cell_id", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_eutra_carrier_arfcn, 
        { "eutra_carrier_arfcn","rrm_oam_inter_freq_cells_t.eutra_carrier_arfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"eutra_carrier_arfcn", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_phy_cell_id, 
        { "phy_cell_id","rrm_oam_inter_freq_cells_t.phy_cell_id",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"phy_cell_id", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_q_offset, 
        { "q_offset","rrm_oam_inter_freq_cells_t.q_offset",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&q_offset_values),0x0,"q_offset", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_cell_individual_offset, 
        { "cell_individual_offset","rrm_oam_inter_freq_cells_t.cell_individual_offset",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&cio_values),0x0,"cell_individual_offset", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_r_stx_power, 
        { "r_stx_power","rrm_oam_inter_freq_cells_t.r_stx_power",FT_INT8,BASE_DEC ,NULL,0x0,"r_stx_power", HFILL }},
    { &hf_rrm_oam_inter_freq_cells_t_blacklisted, 
        { "blacklisted","rrm_oam_inter_freq_cells_t.blacklisted",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&blacklisted_values),0x0,"blacklisted", HFILL }},
    { &hf_rrm_oam_epc_t, 
        { "rrm_oam_epc_t","rrm_oam_epc_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_epc_t", HFILL }},
    { &hf_rrm_oam_epc_t_epc_params, 
        { "epc_params","rrm_oam_epc_t.epc_params",FT_NONE,BASE_NONE ,NULL,0x0,"epc_params", HFILL }},
    { &hf_rrm_oam_epc_params_t, 
        { "rrm_oam_epc_params_t","rrm_oam_epc_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_epc_params_t", HFILL }},
    { &hf_rrm_oam_epc_params_t_bitmask, 
        { "Bitmask","rrm_oam_epc_params_t.bitmask",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"Bitmask", HFILL }},
    { &hf_rrm_oam_epc_params_t_general_epc_params, 
        { "general_epc_params","rrm_oam_epc_params_t.general_epc_params",FT_NONE,BASE_NONE ,NULL,0x0,"general_epc_params", HFILL }},
    { &hf_rrm_oam_epc_params_t_num_valid_qos_profiles, 
        { "num_valid_qos_profiles","rrm_oam_epc_params_t.num_valid_qos_profiles",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_qos_profiles", HFILL }},
    { &hf_rrm_oam_epc_params_t_qos_config_params, 
        { "qos_config_params","rrm_oam_epc_params_t.qos_config_params",FT_NONE,BASE_NONE ,NULL,0x0,"qos_config_params", HFILL }},
    { &hf_rrm_oam_epc_params_t_emergency_erab_arp, 
        { "emergency_erab_arp","rrm_oam_epc_params_t.emergency_erab_arp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"emergency_erab_arp", HFILL }},
    { &hf_rrm_oam_general_epc_params_t, 
        { "rrm_oam_general_epc_params_t","rrm_oam_general_epc_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_general_epc_params_t", HFILL }},
    { &hf_rrm_oam_general_epc_params_t_bitmask, 
        { "bitmask","rrm_oam_general_epc_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_general_epc_params_t_num_valid_plmn, 
        { "num_valid_plmn","rrm_oam_general_epc_params_t.num_valid_plmn",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"num_valid_plmn", HFILL }},
    { &hf_rrm_oam_general_epc_params_t_plmn_list, 
        { "plmn_list","rrm_oam_general_epc_params_t.plmn_list",FT_NONE,BASE_NONE ,NULL,0x0,"plmn_list", HFILL }},
    { &hf_rrm_oam_general_epc_params_t_tac, 
        { "tac","rrm_oam_general_epc_params_t.tac",FT_STRING,BASE_NONE ,NULL,0x0,"tac", HFILL }},
    { &hf_rrm_oam_general_epc_params_t_eaid, 
        { "eaid","rrm_oam_general_epc_params_t.eaid",FT_STRING,BASE_NONE ,NULL,0x0,"eaid", HFILL }},
    { &hf_rrm_oam_plmn_access_info_t, 
        { "rrm_oam_plmn_access_info_t","rrm_oam_plmn_access_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_plmn_access_info_t", HFILL }},
    { &hf_rrm_oam_plmn_access_info_t_plmn_info, 
        { "plmn_info","rrm_oam_plmn_access_info_t.plmn_info",FT_NONE,BASE_NONE ,NULL,0x0,"plmn_info", HFILL }},
    { &hf_rrm_oam_plmn_access_info_t_reserve_operator_use, 
        { "reserve_operator_use","rrm_oam_plmn_access_info_t.reserve_operator_use",FT_INT32,BASE_DEC ,NULL,0x0,"reserve_operator_use", HFILL }},
    { &hf_rrm_oam_qos_config_params_t, 
        { "rrm_oam_qos_config_params_t","rrm_oam_qos_config_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_qos_config_params_t", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_bitmask, 
        { "bitmask","rrm_oam_qos_config_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_qci, 
        { "qci","rrm_oam_qos_config_params_t.qci",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"qci", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_type, 
        { "type","rrm_oam_qos_config_params_t.type",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&type_values),0x0,"type", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_priority, 
        { "priority","rrm_oam_qos_config_params_t.priority",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"priority", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_packet_delay_budget, 
        { "packet_delay_budget","rrm_oam_qos_config_params_t.packet_delay_budget",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&packet_delay_budget_values),0x0,"packet_delay_budget", HFILL }},
    { &hf_rrm_oam_qos_config_params_t_packet_error_loss_rate, 
        { "packet_error_loss_rate","rrm_oam_qos_config_params_t.packet_error_loss_rate",FT_INT32,BASE_HEX_DEC,NULL,0x0,"packet_error_loss_rate", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_dscp, 
	{ "dscp","lte.rrm_oam_qos_config_params_t.dscp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dscp", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_rlc_mode, 
	{ "rlc_mode","lte.rrm_oam_qos_config_params_t.rlc_mode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rlc_mode", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_lossless_ho_required, 
	{ "lossless_ho_required","lte.rrm_oam_qos_config_params_t.lossless_ho_required",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"lossless_ho_required", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_ue_inactivity_timer_config, 
	{ "ue_inactivity_timer_config","lte.rrm_oam_qos_config_params_t.ue_inactivity_timer_config",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ue_inactivity_timer_config", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_max_harq_tx, 
	{ "max_harq_tx","lte.rrm_oam_qos_config_params_t.max_harq_tx",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_harq_tx", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_max_harq_retrans, 
	{ "max_harq_retrans","lte.rrm_oam_qos_config_params_t.max_harq_retrans",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_harq_retrans", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_logical_channel_grouping_on_off, 
	{ "logical_channel_grouping_on_off","lte.rrm_oam_qos_config_params_t.logical_channel_grouping_on_off",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"logical_channel_grouping_on_off", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_max_rlc_transmissions, 
	{ "max_rlc_transmissions","lte.rrm_oam_qos_config_params_t.max_rlc_transmissions",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_rlc_transmissions", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_rohc_params, 
	{ "rohc_params","lte.rrm_oam_qos_config_params_t.rohc_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_params", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_sn_field_len, 
	{ "sn_field_len","lte.rrm_oam_qos_config_params_t.sn_field_len",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sn_field_len", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_sps_config_enabled, 
	{ "sps_config_enabled","lte.rrm_oam_qos_config_params_t.sps_config_enabled",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"sps_config_enabled", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_sps_data, 
	{ "sps_data","lte.rrm_oam_qos_config_params_t.sps_data",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sps_data", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_supported_rat, 
	{ "supported_rat","lte.rrm_oam_qos_config_params_t.supported_rat",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"supported_rat", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_dl_min_bitrate, 
	{ "dl_min_bitrate","lte.rrm_oam_qos_config_params_t.dl_min_bitrate",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"dl_min_bitrate", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_ul_min_bitrate, 
	{ "ul_min_bitrate","lte.rrm_oam_qos_config_params_t.ul_min_bitrate",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ul_min_bitrate", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_addl_rlc_param, 
	{ "addl_rlc_param","lte.rrm_oam_qos_config_params_t.addl_rlc_param",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"addl_rlc_param", HFILL }},
{ &hf_rrm_oam_qos_config_params_t_addl_mac_param, 
	{ "addl_mac_param","lte.rrm_oam_qos_config_params_t.addl_mac_param",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"addl_mac_param", HFILL }},
{ &hf_rrm_oam_pdcp_rohc_params_t, 
	{ "rrm_oam_pdcp_rohc_params_t","lte.rrm_oam_pdcp_rohc_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_pdcp_rohc_params_t", HFILL }},
{ &hf_rrm_oam_pdcp_rohc_params_t_bitmask, 
	{ "bitmask","lte.rrm_oam_pdcp_rohc_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_pdcp_rohc_params_t_enable_rohc, 
	{ "enable_rohc","lte.rrm_oam_pdcp_rohc_params_t.enable_rohc",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"enable_rohc", HFILL }},
{ &hf_rrm_oam_pdcp_rohc_params_t_rohc_pofiles, 
	{ "rohc_pofiles","lte.rrm_oam_pdcp_rohc_params_t.rohc_pofiles",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_pofiles", HFILL }},
{ &hf_rrm_oam_pdcp_rohc_params_t_max_cid, 
	{ "max_cid","lte.rrm_oam_pdcp_rohc_params_t.max_cid",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_cid", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t, 
	{ "rrm_oam_rohc_pofiles_t","lte.rrm_oam_rohc_pofiles_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_rohc_pofiles_t", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_bitmask, 
	{ "bitmask","lte.rrm_oam_rohc_pofiles_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0001, 
	{ "rohc_profile0x0001","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0001",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0001", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0002, 
	{ "rohc_profile0x0002","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0002",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0002", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0003, 
	{ "rohc_profile0x0003","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0003",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0003", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0004, 
	{ "rohc_profile0x0004","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0004",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0004", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0006, 
	{ "rohc_profile0x0006","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0006",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0006", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0101, 
	{ "rohc_profile0x0101","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0101",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0101", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0102, 
	{ "rohc_profile0x0102","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0102",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0102", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0103, 
	{ "rohc_profile0x0103","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0103",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0103", HFILL }},
{ &hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0104, 
	{ "rohc_profile0x0104","lte.rrm_oam_rohc_pofiles_t.rohc_profile0x0104",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profile0x0104", HFILL }},
{ &hf_rrm_oam_sn_field_len_t, 
	{ "rrm_oam_sn_field_len_t","lte.rrm_oam_sn_field_len_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sn_field_len_t", HFILL }},
{ &hf_rrm_oam_sn_field_len_t_bitmask, 
	{ "bitmask","lte.rrm_oam_sn_field_len_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_sn_field_len_t_dl_rlc, 
	{ "dl_rlc","lte.rrm_oam_sn_field_len_t.dl_rlc",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_rlc", HFILL }},
{ &hf_rrm_oam_sn_field_len_t_ul_rlc, 
	{ "ul_rlc","lte.rrm_oam_sn_field_len_t.ul_rlc",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_rlc", HFILL }},
{ &hf_rrm_oam_sn_field_len_t_dl_pdcp, 
	{ "dl_pdcp","lte.rrm_oam_sn_field_len_t.dl_pdcp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_pdcp", HFILL }},
{ &hf_rrm_oam_sn_field_len_t_ul_pdcp, 
	{ "ul_pdcp","lte.rrm_oam_sn_field_len_t.ul_pdcp",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_pdcp", HFILL }},
{ &hf_rrm_oam_sps_config_data_t, 
	{ "rrm_oam_sps_config_data_t","lte.rrm_oam_sps_config_data_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sps_config_data_t", HFILL }},
{ &hf_rrm_oam_sps_config_data_t_bitmask, 
	{ "bitmask","lte.rrm_oam_sps_config_data_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_sps_config_data_t_sps_config_dl, 
	{ "sps_config_dl","lte.rrm_oam_sps_config_data_t.sps_config_dl",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sps_config_dl", HFILL }},
{ &hf_rrm_oam_sps_config_data_t_sps_config_ul, 
	{ "sps_config_ul","lte.rrm_oam_sps_config_data_t.sps_config_ul",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sps_config_ul", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t, 
	{ "rrm_oam_sps_config_dl_t","lte.rrm_oam_sps_config_dl_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sps_config_dl_t", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t_bitmask, 
	{ "bitmask","lte.rrm_oam_sps_config_dl_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t_semi_persist_sched_interval_dl, 
	{ "semi_persist_sched_interval_dl","lte.rrm_oam_sps_config_dl_t.semi_persist_sched_interval_dl",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"semi_persist_sched_interval_dl", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t_number_of_conf_sps_processes, 
	{ "number_of_conf_sps_processes","lte.rrm_oam_sps_config_dl_t.number_of_conf_sps_processes",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"number_of_conf_sps_processes", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t_max_sps_harq_retx, 
	{ "max_sps_harq_retx","lte.rrm_oam_sps_config_dl_t.max_sps_harq_retx",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_sps_harq_retx", HFILL }},
{ &hf_rrm_oam_sps_config_dl_t_explicit_release_after, 
	{ "explicit_release_after","lte.rrm_oam_sps_config_dl_t.explicit_release_after",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"explicit_release_after", HFILL }},
{ &hf_rrm_oam_sps_config_ul_t, 
	{ "rrm_oam_sps_config_ul_t","lte.rrm_oam_sps_config_ul_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sps_config_ul_t", HFILL }},
{ &hf_rrm_oam_sps_config_ul_t_bitmask, 
	{ "bitmask","lte.rrm_oam_sps_config_ul_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_sps_config_ul_t_semi_persist_sched_interval_ul, 
	{ "semi_persist_sched_interval_ul","lte.rrm_oam_sps_config_ul_t.semi_persist_sched_interval_ul",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"semi_persist_sched_interval_ul", HFILL }},
{ &hf_rrm_oam_sps_config_ul_t_implicit_release_after, 
	{ "implicit_release_after","lte.rrm_oam_sps_config_ul_t.implicit_release_after",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"implicit_release_after", HFILL }},
{ &hf_rrm_oam_sps_config_ul_t_p_zero_nominal_pusch_persistent, 
	{ "p_zero_nominal_pusch_persistent","lte.rrm_oam_sps_config_ul_t.p_zero_nominal_pusch_persistent",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_zero_nominal_pusch_persistent", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t, 
	{ "rrm_oam_addl_rlc_params_t","lte.rrm_oam_addl_rlc_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_addl_rlc_params_t", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t_bitmask, 
	{ "bitmask","lte.rrm_oam_addl_rlc_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t_t_poll_pdu, 
	{ "t_poll_pdu","lte.rrm_oam_addl_rlc_params_t.t_poll_pdu",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_poll_pdu", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t_t_reordering, 
	{ "t_reordering","lte.rrm_oam_addl_rlc_params_t.t_reordering",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_reordering", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t_t_poll_retransmit, 
	{ "t_poll_retransmit","lte.rrm_oam_addl_rlc_params_t.t_poll_retransmit",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_poll_retransmit", HFILL }},
{ &hf_rrm_oam_addl_rlc_params_t_t_status_prohibit, 
	{ "t_status_prohibit","lte.rrm_oam_addl_rlc_params_t.t_status_prohibit",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_status_prohibit", HFILL }},
{ &hf_rrm_oam_addl_mac_params_t, 
	{ "rrm_oam_addl_mac_params_t","lte.rrm_oam_addl_mac_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_addl_mac_params_t", HFILL }},
{ &hf_rrm_oam_addl_mac_params_t_bitmask, 
	{ "bitmask","lte.rrm_oam_addl_mac_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_addl_mac_params_t_phr_config, 
	{ "phr_config","lte.rrm_oam_addl_mac_params_t.phr_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"phr_config", HFILL }},
{ &hf_rrm_oam_addl_mac_params_t_bsr_config, 
	{ "bsr_config","lte.rrm_oam_addl_mac_params_t.bsr_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"bsr_config", HFILL }},
{ &hf_rrm_oam_phr_config_t, 
	{ "rrm_oam_phr_config_t","lte.rrm_oam_phr_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_phr_config_t", HFILL }},
{ &hf_rrm_oam_phr_config_t_bitmask, 
	{ "bitmask","lte.rrm_oam_phr_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_phr_config_t_t_periodic_phr, 
	{ "t_periodic_phr","lte.rrm_oam_phr_config_t.t_periodic_phr",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_periodic_phr", HFILL }},
{ &hf_rrm_oam_phr_config_t_t_prohibit_phr, 
	{ "t_prohibit_phr","lte.rrm_oam_phr_config_t.t_prohibit_phr",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_prohibit_phr", HFILL }},
{ &hf_rrm_oam_phr_config_t_t_pathloss_chng, 
	{ "t_pathloss_chng","lte.rrm_oam_phr_config_t.t_pathloss_chng",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_pathloss_chng", HFILL }},
{ &hf_rrm_oam_bsr_config_t, 
	{ "rrm_oam_bsr_config_t","lte.rrm_oam_bsr_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_bsr_config_t", HFILL }},
{ &hf_rrm_oam_bsr_config_t_bitmask, 
	{ "bitmask","lte.rrm_oam_bsr_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_bsr_config_t_t_periodic_bsr, 
	{ "t_periodic_bsr","lte.rrm_oam_bsr_config_t.t_periodic_bsr",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_periodic_bsr", HFILL }},
{ &hf_rrm_oam_bsr_config_t_t_retx_bsr, 
	{ "t_retx_bsr","lte.rrm_oam_bsr_config_t.t_retx_bsr",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"t_retx_bsr", HFILL }},
    { &hf_rrm_oam_operator_info_t, 
        { "rrm_oam_operator_info_t","rrm_oam_operator_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_operator_info_t", HFILL }},
    { &hf_rrm_oam_operator_info_t_bitmask, 
        { "bitmask","rrm_oam_operator_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_operator_info_t_simultaneous_ack_nack_and_cqi, 
        { "simultaneous_ack_nack_and_cqi","rrm_oam_operator_info_t.simultaneous_ack_nack_and_cqi",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"simultaneous_ack_nack_and_cqi", HFILL }},
    { &hf_rrm_oam_operator_info_t_rrm_mac_config, 
        { "rrm_mac_config","rrm_oam_operator_info_t.rrm_mac_config",FT_NONE,BASE_NONE ,NULL,0x0,"rrm_mac_config", HFILL }},
    { &hf_rrm_oam_operator_info_t_phich_config, 
        { "phich_config","rrm_oam_operator_info_t.phich_config",FT_NONE,BASE_NONE ,NULL,0x0,"phich_config", HFILL }},
    { &hf_rrm_oam_operator_info_t_sib_1_info, 
        { "sib_1_info","rrm_oam_operator_info_t.sib_1_info",FT_NONE,BASE_NONE ,NULL,0x0,"sib_1_info", HFILL }},
    { &hf_rrm_oam_operator_info_t_sib_2_info, 
        { "sib_2_info","rrm_oam_operator_info_t.sib_2_info",FT_NONE,BASE_NONE ,NULL,0x0,"sib_2_info", HFILL }},
    { &hf_rrm_oam_operator_info_t_sib_3_info, 
        { "sib_3_info","rrm_oam_operator_info_t.sib_3_info",FT_NONE,BASE_NONE ,NULL,0x0,"sib_3_info", HFILL }},
    { &hf_rrm_oam_operator_info_t_sib_4_info, 
        { "sib_4_info","rrm_oam_operator_info_t.sib_4_info",FT_NONE,BASE_NONE ,NULL,0x0,"sib_4_info", HFILL }},
    { &hf_rrm_oam_operator_info_t_admission_control_info, 
        { "admission_control_info","rrm_oam_operator_info_t.admission_control_info",FT_NONE,BASE_NONE ,NULL,0x0,"admission_control_info", HFILL }},
{ &hf_rrm_oam_operator_info_t_additional_packet_scheduling_params, 
	{ "additional_packet_scheduling_params","rrm_oam_operator_info_t.additional_packet_scheduling_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"additional_packet_scheduling_params", HFILL }},
{ &hf_rrm_oam_operator_info_t_additional_cell_params, 
	{ "additional_cell_params","rrm_oam_operator_info_t.additional_cell_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"additional_cell_params", HFILL }},
{ &hf_rrm_oam_operator_info_t_load_params, 
	{ "load_params","rrm_oam_operator_info_t.load_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"load_params", HFILL }},
{ &hf_rrm_oam_operator_info_t_mimo_mode_params, 
	{ "mimo_mode_params","rrm_oam_operator_info_t.mimo_mode_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"mimo_mode_params", HFILL }},
{ &hf_rrm_oam_operator_info_t_ho_configuration, 
	{ "ho_configuration","rrm_oam_operator_info_t.ho_configuration",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ho_configuration", HFILL }},
{ &hf_rrm_oam_operator_info_t_measurement_configuration, 
	{ "measurement_configuration","rrm_oam_operator_info_t.measurement_configuration",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"measurement_configuration", HFILL }},
{ &hf_rrm_oam_operator_info_t_cell_capacity_class, 
	{ "cell_capacity_class","rrm_oam_operator_info_t.cell_capacity_class",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_capacity_class", HFILL }},
{ &hf_rrm_oam_operator_info_t_cell_type, 
	{ "cell_type","rrm_oam_operator_info_t.cell_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_type", HFILL }},
{ &hf_rrm_oam_operator_info_t_rrm_eutran_access_point_pos, 
	{ "rrm_eutran_access_point_pos","rrm_oam_operator_info_t.rrm_eutran_access_point_pos",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rrm_eutran_access_point_pos", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t, 
	{ "rrm_oam_adl_pkt_scheduling_params_t","rrm_oam_adl_pkt_scheduling_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_adl_pkt_scheduling_params_t", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t_bitmask, 
	{ "bitmask","rrm_oam_adl_pkt_scheduling_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t_dl_mcs, 
	{ "dl_mcs","rrm_oam_adl_pkt_scheduling_params_t.dl_mcs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_mcs", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t_ul_mcs, 
	{ "ul_mcs","rrm_oam_adl_pkt_scheduling_params_t.ul_mcs",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_mcs", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t_frequency_selective_scheduling, 
	{ "frequency_selective_scheduling","rrm_oam_adl_pkt_scheduling_params_t.frequency_selective_scheduling",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"frequency_selective_scheduling", HFILL }},
{ &hf_rrm_oam_adl_pkt_scheduling_params_t_cqi_reporting_mode, 
	{ "cqi_reporting_mode","rrm_oam_adl_pkt_scheduling_params_t.cqi_reporting_mode",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cqi_reporting_mode", HFILL }},
{ &hf_rrm_oam_adl_cell_params_t, 
	{ "rrm_oam_adl_cell_params_t","rrm_oam_adl_cell_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_adl_cell_params_t", HFILL }},
{ &hf_rrm_oam_adl_cell_params_t_bitmask, 
	{ "bitmask","rrm_oam_adl_cell_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_adl_cell_params_t_sub_carrier_spacing, 
	{ "sub_carrier_spacing","rrm_oam_adl_cell_params_t.sub_carrier_spacing",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sub_carrier_spacing", HFILL }},
{ &hf_rrm_oam_adl_cell_params_t_dl_cyclic_prefix, 
	{ "dl_cyclic_prefix","rrm_oam_adl_cell_params_t.dl_cyclic_prefix",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_cyclic_prefix", HFILL }},
{ &hf_rrm_oam_load_params_t, 
	{ "rrm_oam_load_params_t","rrm_oam_load_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_load_params_t", HFILL }},
{ &hf_rrm_oam_load_params_t_bitmask, 
	{ "bitmask","rrm_oam_load_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_load_params_t_wait_time, 
	{ "wait_time","rrm_oam_load_params_t.wait_time",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"wait_time", HFILL }},
{ &hf_rrm_oam_mimo_mode_params_t, 
	{ "rrm_oam_mimo_mode_params_t","rrm_oam_mimo_mode_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_mimo_mode_params_t", HFILL }},
{ &hf_rrm_oam_mimo_mode_params_t_bitmask, 
	{ "bitmask","rrm_oam_mimo_mode_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_mimo_mode_params_t_antenna_ports_count_number, 
	{ "antenna_ports_count_number","rrm_oam_mimo_mode_params_t.antenna_ports_count_number",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"antenna_ports_count_number", HFILL }},
{ &hf_rrm_oam_mimo_mode_params_t_supported_tx_mode, 
	{ "supported_tx_mode","rrm_oam_mimo_mode_params_t.supported_tx_mode",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"supported_tx_mode", HFILL }},
{ &hf_rrm_oam_ho_config_params_t, 
	{ "rrm_oam_ho_config_params_t","rrm_oam_ho_config_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ho_config_params_t", HFILL }},
{ &hf_rrm_oam_ho_config_params_t_bitmask, 
	{ "bitmask","rrm_oam_ho_config_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_ho_config_params_t_target_cell_selection_params, 
	{ "target_cell_selection_params","rrm_oam_ho_config_params_t.target_cell_selection_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"target_cell_selection_params", HFILL }},
{ &hf_rrm_oam_ho_config_params_t_ho_algo_params, 
	{ "ho_algo_params","rrm_oam_ho_config_params_t.ho_algo_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ho_algo_params", HFILL }},
{ &hf_rrm_oam_ho_config_params_t_ho_retry_params, 
	{ "ho_retry_params","rrm_oam_ho_config_params_t.ho_retry_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ho_retry_params", HFILL }},
{ &hf_rrm_oam_ho_config_params_t_blind_ho_timer, 
	{ "blind_ho_timer","rrm_oam_ho_config_params_t.blind_ho_timer",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"blind_ho_timer", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t, 
	{ "rrm_oam_target_cell_selection_params_t","rrm_oam_target_cell_selection_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_target_cell_selection_params_t", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_bitmask, 
	{ "bitmask","rrm_oam_target_cell_selection_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_neighboring_cell_load_based_ho_enable, 
	{ "neighboring_cell_load_based_ho_enable","rrm_oam_target_cell_selection_params_t.neighboring_cell_load_based_ho_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"neighboring_cell_load_based_ho_enable", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_ue_history_based_ho_enable, 
	{ "ue_history_based_ho_enable","rrm_oam_target_cell_selection_params_t.ue_history_based_ho_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ue_history_based_ho_enable", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_spid_based_ho_enable, 
	{ "spid_based_ho_enable","rrm_oam_target_cell_selection_params_t.spid_based_ho_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"spid_based_ho_enable", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_ue_measurement_based_ho_enable, 
	{ "ue_measurement_based_ho_enable","rrm_oam_target_cell_selection_params_t.ue_measurement_based_ho_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ue_measurement_based_ho_enable", HFILL }},
{ &hf_rrm_oam_target_cell_selection_params_t_daho_cell_based_ho_enable, 
	{ "daho_cell_based_ho_enable","rrm_oam_target_cell_selection_params_t.daho_cell_based_ho_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"daho_cell_based_ho_enable", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t, 
	{ "rrm_oam_ho_algo_params_t","rrm_oam_ho_algo_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ho_algo_params_t", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_bitmask, 
	{ "bitmask","rrm_oam_ho_algo_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_enb_measurements_for_ho, 
	{ "enb_measurements_for_ho","rrm_oam_ho_algo_params_t.enb_measurements_for_ho",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"enb_measurements_for_ho", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_ue_meas_trigger_quantity_for_ho, 
	{ "ue_meas_trigger_quantity_for_ho","rrm_oam_ho_algo_params_t.ue_meas_trigger_quantity_for_ho",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ue_meas_trigger_quantity_for_ho", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_coverage_based_ho, 
	{ "coverage_based_ho","rrm_oam_ho_algo_params_t.coverage_based_ho",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"coverage_based_ho", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_intra_freq_ho, 
	{ "intra_freq_ho","rrm_oam_ho_algo_params_t.intra_freq_ho",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"intra_freq_ho", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_inter_freq_ho, 
	{ "inter_freq_ho","rrm_oam_ho_algo_params_t.inter_freq_ho",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"inter_freq_ho", HFILL }},
{ &hf_rrm_oam_ho_algo_params_t_inter_rat_ho, 
	{ "inter_rat_ho","rrm_oam_ho_algo_params_t.inter_rat_ho",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"inter_rat_ho", HFILL }},
{ &hf_rrm_oam_ho_retry_params_t, 
	{ "rrm_oam_ho_retry_params_t","rrm_oam_ho_retry_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ho_retry_params_t", HFILL }},
{ &hf_rrm_oam_ho_retry_params_t_bitmask, 
	{ "bitmask","rrm_oam_ho_retry_params_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_ho_retry_params_t_ho_retry_enable, 
	{ "ho_retry_enable","rrm_oam_ho_retry_params_t.ho_retry_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ho_retry_enable", HFILL }},
{ &hf_rrm_oam_ho_retry_params_t_ho_retry_count, 
	{ "ho_retry_count","rrm_oam_ho_retry_params_t.ho_retry_count",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ho_retry_count", HFILL }},
{ &hf_rrm_oam_meas_config_t, 
	{ "rrm_oam_meas_config_t","rrm_oam_meas_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_meas_config_t", HFILL }},
{ &hf_rrm_oam_meas_config_t_bitmask, 
	{ "bitmask","rrm_oam_meas_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_meas_config_t_report_trigger_type, 
	{ "report_trigger_type","rrm_oam_meas_config_t.report_trigger_type",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"report_trigger_type", HFILL }},
{ &hf_rrm_oam_meas_config_t_meas_gap_config, 
	{ "meas_gap_config","rrm_oam_meas_config_t.meas_gap_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"meas_gap_config", HFILL }},
{ &hf_rrm_oam_meas_config_t_si_gap_enable, 
	{ "si_gap_enable","rrm_oam_meas_config_t.si_gap_enable",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"si_gap_enable", HFILL }},
{ &hf_rrm_oam_meas_config_t_csfb_tgt_selection, 
	{ "csfb_tgt_selection","rrm_oam_meas_config_t.csfb_tgt_selection",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"csfb_tgt_selection", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t, 
	{ "rrm_oam_meas_gap_config_t","rrm_oam_meas_gap_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_meas_gap_config_t", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t_bitmask, 
	{ "bitmask","rrm_oam_meas_gap_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t_eutran_gap_offset_type, 
	{ "eutran_gap_offset_type","rrm_oam_meas_gap_config_t.eutran_gap_offset_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"eutran_gap_offset_type", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t_utran_gap_offset_type, 
	{ "utran_gap_offset_type","rrm_oam_meas_gap_config_t.utran_gap_offset_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"utran_gap_offset_type", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t_geran_gap_offset_type, 
	{ "geran_gap_offset_type","rrm_oam_meas_gap_config_t.geran_gap_offset_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"geran_gap_offset_type", HFILL }},
{ &hf_rrm_oam_meas_gap_config_t_cdma2000_gap_offset_type, 
	{ "cdma2000_gap_offset_type","rrm_oam_meas_gap_config_t.cdma2000_gap_offset_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cdma2000_gap_offset_type", HFILL }},
{ &hf_rrm_csfb_tgt_selection_t, 
	{ "rrm_csfb_tgt_selection_t","rrm_csfb_tgt_selection_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_csfb_tgt_selection_t", HFILL }},
{ &hf_rrm_csfb_tgt_selection_t_bitmask, 
	{ "bitmask","rrm_csfb_tgt_selection_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_csfb_tgt_selection_t_utran_csfb_tgt_selection, 
	{ "utran_csfb_tgt_selection","rrm_csfb_tgt_selection_t.utran_csfb_tgt_selection",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"utran_csfb_tgt_selection", HFILL }},
{ &hf_rrm_csfb_tgt_selection_t_geran_csfb_tgt_selection, 
	{ "geran_csfb_tgt_selection","rrm_csfb_tgt_selection_t.geran_csfb_tgt_selection",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"geran_csfb_tgt_selection", HFILL }},
{ &hf_rrm_csfb_tgt_selection_t_cdma2000_csfb_tgt_selection, 
	{ "cdma2000_csfb_tgt_selection","rrm_csfb_tgt_selection_t.cdma2000_csfb_tgt_selection",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cdma2000_csfb_tgt_selection", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t, 
	{ "rrm_oam_eutran_access_point_pos_t","rrm_oam_eutran_access_point_pos_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_eutran_access_point_pos_t", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_bitmask, 
	{ "bitmask","rrm_oam_eutran_access_point_pos_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_latitude_sign, 
	{ "latitude_sign","rrm_oam_eutran_access_point_pos_t.latitude_sign",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"latitude_sign", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_deg_of_latitude, 
	{ "deg_of_latitude","rrm_oam_eutran_access_point_pos_t.deg_of_latitude",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"deg_of_latitude", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_deg_of_longitude, 
	{ "deg_of_longitude","rrm_oam_eutran_access_point_pos_t.deg_of_longitude",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"deg_of_longitude", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_dir_of_altitude, 
	{ "dir_of_altitude","rrm_oam_eutran_access_point_pos_t.dir_of_altitude",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"dir_of_altitude", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_altitude, 
	{ "altitude","rrm_oam_eutran_access_point_pos_t.altitude",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"altitude", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_major, 
	{ "uncertainty_semi_major","rrm_oam_eutran_access_point_pos_t.uncertainty_semi_major",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"uncertainty_semi_major", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_minor, 
	{ "uncertainty_semi_minor","rrm_oam_eutran_access_point_pos_t.uncertainty_semi_minor",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"uncertainty_semi_minor", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_orientation_of_major_axis, 
	{ "orientation_of_major_axis","rrm_oam_eutran_access_point_pos_t.orientation_of_major_axis",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"orientation_of_major_axis", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_uncertainty_altitude, 
	{ "uncertainty_altitude","rrm_oam_eutran_access_point_pos_t.uncertainty_altitude",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"uncertainty_altitude", HFILL }},
{ &hf_rrm_oam_eutran_access_point_pos_t_confidence, 
	{ "confidence","rrm_oam_eutran_access_point_pos_t.confidence",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"confidence", HFILL }},
{ &hf_rrm_oam_path_loss_to_target_sinr_map_info_t, 
	{ "rrm_oam_path_loss_to_target_sinr_map_info_t","rrm_oam_path_loss_to_target_sinr_map_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_path_loss_to_target_sinr_map_info_t", HFILL }},
{ &hf_rrm_oam_path_loss_to_target_sinr_map_info_t_start_PL, 
	{ "start_PL","rrm_oam_path_loss_to_target_sinr_map_info_t.start_PL",FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"start_PL", HFILL }},
{ &hf_rrm_oam_path_loss_to_target_sinr_map_info_t_end_PL, 
	{ "end_PL","rrm_oam_path_loss_to_target_sinr_map_info_t.end_PL",FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"end_PL", HFILL }},
{ &hf_rrm_oam_path_loss_to_target_sinr_map_info_t_target_SINR, 
	{ "target_SINR","rrm_oam_path_loss_to_target_sinr_map_info_t.target_SINR",FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"target_SINR", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t, 
	{ "rrm_oam_dynamic_icic_info_t","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_dynamic_icic_info_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_bitmask, 
	{ "bitmask","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_icic_scheme_type, 
	{ "icic_scheme_type","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.icic_scheme_type",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"icic_scheme_type", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info, 
	{ "dl_resource_partition_info","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.dl_resource_partition_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_resource_partition_info", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info, 
	{ "ul_resource_partition_info","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.ul_resource_partition_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_resource_partition_info", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask, 
	{ "ul_power_mask","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.ul_power_mask",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_power_mask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info, 
	{ "rntp_report_config_info","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.rntp_report_config_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rntp_report_config_info", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map, 
	{ "alpha_pathloss_target_sinr_map","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.alpha_pathloss_target_sinr_map",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"alpha_pathloss_target_sinr_map", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power, 
	{ "cqi_to_phich_power","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.cqi_to_phich_power",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cqi_to_phich_power", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_min_rb_for_pl_phr_calc, 
	{ "min_rb_for_pl_phr_calc","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.min_rb_for_pl_phr_calc",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"min_rb_for_pl_phr_calc", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset, 
	{ "pdcch_aggregation_power_offset","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.pdcch_aggregation_power_offset",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pdcch_aggregation_power_offset", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti, 
	{ "sps_dl_scheduling_Info_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.sps_dl_scheduling_Info_per_tti",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sps_dl_scheduling_Info_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti, 
	{ "sps_ul_scheduling_Info_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.sps_ul_scheduling_Info_per_tti",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"sps_ul_scheduling_Info_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps, 
	{ "alpha_pathloss_target_sinr_map_sps","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.alpha_pathloss_target_sinr_map_sps",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"alpha_pathloss_target_sinr_map_sps", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params, 
	{ "dynamic_cfi_extension_params","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.dynamic_cfi_extension_params",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dynamic_cfi_extension_params", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config, 
	{ "atb_config","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.atb_config",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"atb_config", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_mu_mimo_type, 
	{ "ul_mu_mimo_type","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.ul_mu_mimo_type",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ul_mu_mimo_type", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_msc_threshold_ul_mu_mimo, 
	{ "msc_threshold_ul_mu_mimo","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.msc_threshold_ul_mu_mimo",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"msc_threshold_ul_mu_mimo", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_x2ap_icic_report_periodicity, 
	{ "x2ap_icic_report_periodicity","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.x2ap_icic_report_periodicity",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"x2ap_icic_report_periodicity", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pa_for_ce_ue, 
	{ "pa_for_ce_ue","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_icic_info_t.pa_for_ce_ue",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"pa_for_ce_ue", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t, 
	{ "rrm_oam_resource_partition_info_t","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_resource_partition_info_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_bitmask, 
	{ "bitmask","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_edge_region, 
	{ "num_of_cell_edge_region","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t.num_of_cell_edge_region",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"num_of_cell_edge_region", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_center_region, 
	{ "num_of_cell_center_region","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t.num_of_cell_center_region",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"num_of_cell_center_region", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region, 
	{ "cell_center_region","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t.cell_center_region",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_center_region", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region, 
	{ "cell_edge_region","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_info_t.cell_edge_region",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cell_edge_region", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t, 
	{ "rrm_oam_resource_partition_t","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_resource_partition_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_start_rb, 
	{ "start_rb","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_t.start_rb",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"start_rb", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_num_of_rb, 
	{ "num_of_rb","rrm_oam_dynamic_icic_info_t.rrm_oam_resource_partition_t.num_of_rb",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"num_of_rb", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t, 
	{ "rrm_oam_ul_power_mask_t","rrm_oam_dynamic_icic_info_t.rrm_oam_ul_power_mask_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ul_power_mask_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_center_user_power_mask, 
	{ "cell_center_user_power_mask","rrm_oam_dynamic_icic_info_t.rrm_oam_ul_power_mask_t.cell_center_user_power_mask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cell_center_user_power_mask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_edge_user_power_mask, 
	{ "cell_edge_user_power_mask","rrm_oam_dynamic_icic_info_t.rrm_oam_ul_power_mask_t.cell_edge_user_power_mask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cell_edge_user_power_mask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_qci_delta_power_mask, 
	{ "qci_delta_power_mask","rrm_oam_dynamic_icic_info_t.rrm_oam_ul_power_mask_t.qci_delta_power_mask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"qci_delta_power_mask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t, 
	{ "rrm_oam_rntp_report_config_info_t","rrm_oam_dynamic_icic_info_t.rrm_oam_rntp_report_config_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_rntp_report_config_info_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_bitmask, 
	{ "bitmask","rrm_oam_dynamic_icic_info_t.rrm_oam_rntp_report_config_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_report_on_X2_required, 
	{ "rntp_report_on_X2_required","rrm_oam_dynamic_icic_info_t.rrm_oam_rntp_report_config_info_t.rntp_report_on_X2_required",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rntp_report_on_X2_required", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_threshold, 
	{ "rntp_threshold","rrm_oam_dynamic_icic_info_t.rrm_oam_rntp_report_config_info_t.rntp_threshold",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"rntp_threshold", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_max_nominal_epre, 
	{ "max_nominal_epre","rrm_oam_dynamic_icic_info_t.rrm_oam_rntp_report_config_info_t.max_nominal_epre",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_nominal_epre", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t, 
	{ "rrm_oam_alpha_based_pathloss_target_sinr_map_t","rrm_oam_dynamic_icic_info_t.rrm_oam_alpha_based_pathloss_target_sinr_map_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_alpha_based_pathloss_target_sinr_map_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_default_path_loss, 
	{ "default_path_loss","rrm_oam_dynamic_icic_info_t.rrm_oam_alpha_based_pathloss_target_sinr_map_t.default_path_loss",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"default_path_loss", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map, 
	{ "path_loss_target_sinr_map","rrm_oam_dynamic_icic_info_t.rrm_oam_alpha_based_pathloss_target_sinr_map_t.path_loss_target_sinr_map",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"path_loss_target_sinr_map", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t, 
	{ "rrm_oam_path_loss_to_target_sinr_map_t","rrm_oam_dynamic_icic_info_t.rrm_oam_path_loss_to_target_sinr_map_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_path_loss_to_target_sinr_map_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_count, 
	{ "count","rrm_oam_dynamic_icic_info_t.rrm_oam_path_loss_to_target_sinr_map_t.count",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"count", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info, 
	{ "path_loss_to_target_sinr_map_info","rrm_oam_dynamic_icic_info_t.rrm_oam_path_loss_to_target_sinr_map_t.path_loss_to_target_sinr_map_info",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"path_loss_to_target_sinr_map_info", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t, 
	{ "rrm_oam_pdcch_aggregation_power_offset_t","rrm_oam_dynamic_icic_info_t.rrm_oam_pdcch_aggregation_power_offset_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_pdcch_aggregation_power_offset_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_bitmask, 
	{ "bitmask","rrm_oam_dynamic_icic_info_t.rrm_oam_pdcch_aggregation_power_offset_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user, 
	{ "aggregation_power_offset_cc_user","rrm_oam_dynamic_icic_info_t.rrm_oam_pdcch_aggregation_power_offset_t.aggregation_power_offset_cc_user",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"aggregation_power_offset_cc_user", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user, 
	{ "aggregation_power_offset_ce_user","rrm_oam_dynamic_icic_info_t.rrm_oam_pdcch_aggregation_power_offset_t.aggregation_power_offset_ce_user",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"aggregation_power_offset_ce_user", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t, 
	{ "rrm_oam_aggregation_power_offset_on_cqi_basis_t","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_on_cqi_basis_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_aggregation_power_offset_on_cqi_basis_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user, 
	{ "aggregation_power_offset_user","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_on_cqi_basis_t.aggregation_power_offset_user",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"aggregation_power_offset_user", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t, 
	{ "rrm_oam_aggregation_power_offset_t","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_aggregation_power_offset_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_count, 
	{ "count","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_t.count",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"count", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples, 
	{ "aggr_pwr_offset_tuples","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_t.aggr_pwr_offset_tuples",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"aggr_pwr_offset_tuples", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t, 
	{ "rrm_oam_aggregation_power_offset_info_t","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_info_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_aggregation_power_offset_info_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_aggregation_level, 
	{ "aggregation_level","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_info_t.aggregation_level",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"aggregation_level", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_power_offset, 
	{ "power_offset","rrm_oam_dynamic_icic_info_t.rrm_oam_aggregation_power_offset_info_t.power_offset",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"power_offset", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t, 
	{ "rrm_oam_cqi_to_phich_power_t","rrm_oam_dynamic_icic_info_t.rrm_oam_cqi_to_phich_power_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cqi_to_phich_power_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t_cqi_to_phich_power_info, 
	{ "cqi_to_phich_power_info","rrm_oam_dynamic_icic_info_t.rrm_oam_cqi_to_phich_power_t.cqi_to_phich_power_info",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cqi_to_phich_power_info", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t, 
	{ "rrm_oam_sps_dl_scheduling_Info_per_tti_t","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_dl_scheduling_Info_per_tti_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sps_dl_scheduling_Info_per_tti_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_dci_per_tti, 
	{ "max_dl_sps_dci_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_dl_scheduling_Info_per_tti_t.max_dl_sps_dci_per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_dl_sps_dci_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_Occasion_Per_tti, 
	{ "max_dl_sps_Occasion_Per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_dl_scheduling_Info_per_tti_t.max_dl_sps_Occasion_Per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_dl_sps_Occasion_Per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti, 
	{ "max_dl_sps_rbs_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_dl_scheduling_Info_per_tti_t.max_dl_sps_rbs_per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_dl_sps_rbs_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti_per_interval, 
	{ "max_dl_sps_rbs_per_tti_per_interval","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_dl_scheduling_Info_per_tti_t.max_dl_sps_rbs_per_tti_per_interval",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_dl_sps_rbs_per_tti_per_interval", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t, 
	{ "rrm_oam_sps_ul_scheduling_Info_per_tti_t","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_ul_scheduling_Info_per_tti_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_sps_ul_scheduling_Info_per_tti_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_dci_per_tti, 
	{ "max_ul_sps_dci_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_ul_scheduling_Info_per_tti_t.max_ul_sps_dci_per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_ul_sps_dci_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_Occasion_Per_tti, 
	{ "max_ul_sps_Occasion_Per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_ul_scheduling_Info_per_tti_t.max_ul_sps_Occasion_Per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_ul_sps_Occasion_Per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti, 
	{ "max_ul_sps_rbs_per_tti","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_ul_scheduling_Info_per_tti_t.max_ul_sps_rbs_per_tti",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_ul_sps_rbs_per_tti", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti_per_interval, 
	{ "max_ul_sps_rbs_per_tti_per_interval","rrm_oam_dynamic_icic_info_t.rrm_oam_sps_ul_scheduling_Info_per_tti_t.max_ul_sps_rbs_per_tti_per_interval",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"max_ul_sps_rbs_per_tti_per_interval", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t, 
	{ "rrm_oam_dynamic_cfi_extension_params_t","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_cfi_extension_params_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_dynamic_cfi_extension_params_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_up_factor, 
	{ "cce_correction_step_up_factor","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_cfi_extension_params_t.cce_correction_step_up_factor",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cce_correction_step_up_factor", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_down_factor, 
	{ "cce_correction_step_down_factor","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_cfi_extension_params_t.cce_correction_step_down_factor",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cce_correction_step_down_factor", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_adjust_factor, 
	{ "cce_adjust_factor","rrm_oam_dynamic_icic_info_t.rrm_oam_dynamic_cfi_extension_params_t.cce_adjust_factor",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"cce_adjust_factor", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t, 
	{ "rrm_oam_atb_config_t","rrm_oam_dynamic_icic_info_t.rrm_oam_atb_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_atb_config_t", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_mcs_index_for_atb, 
	{ "min_mcs_index_for_atb","rrm_oam_dynamic_icic_info_t.rrm_oam_atb_config_t.min_mcs_index_for_atb",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"min_mcs_index_for_atb", HFILL }},
{ &hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_prb_val_for_atb, 
	{ "min_prb_val_for_atb","rrm_oam_dynamic_icic_info_t.rrm_oam_atb_config_t.min_prb_val_for_atb",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"min_prb_val_for_atb", HFILL }},
    { &hf_rrm_oam_rrmc_mac_config_t, 
        { "rrm_oam_rrmc_mac_config_t","rrm_oam_rrmc_mac_config_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_rrmc_mac_config_t", HFILL }},
    { &hf_rrm_oam_rrmc_mac_config_t_start_rarnti_range, 
        { "start_rarnti_range","rrm_oam_rrmc_mac_config_t.start_rarnti_range",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"start_rarnti_range", HFILL }},
    { &hf_rrm_oam_rrmc_mac_config_t_end_rarnti_range, 
        { "end_rarnti_range","rrm_oam_rrmc_mac_config_t.end_rarnti_range",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"end_rarnti_range", HFILL }},
    { &hf_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch, 
        { "enable_frequency_selective_scheduling","rrm_oam_rrmc_mac_config_t.enable_freq_selct_sch",FT_NONE,BASE_NONE ,NULL,0x0,"enable_frequency_selective_scheduling", HFILL }},
    { &hf_rrm_oam_rrmc_mac_config_t_ue_inactive_time_config, 
        { "ue_inactive_time_config","rrm_oam_rrmc_mac_config_t.ue_inactive_time_config",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"ue_inactive_time_config", HFILL }},
    { &hf_rrm_oam_mac_enable_frequency_selective_scheduling_t, 
        { "rrm_oam_mac_enable_frequency_selective_scheduling_t","rrm_oam_mac_enable_frequency_selective_scheduling_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_mac_enable_frequency_selective_scheduling_t", HFILL }},
    { &hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_ul_freq_selective_enable, 
        { "ul_freq_selective_enable","rrm_oam_mac_enable_frequency_selective_scheduling_t.ul_freq_selective_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_freq_selective_enable", HFILL }},
    { &hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_dl_freq_selective_enable, 
        { "dl_freq_selective_enable","rrm_oam_mac_enable_frequency_selective_scheduling_t.dl_freq_selective_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_freq_selective_enable", HFILL }},
    { &hf_rrm_oam_phy_phich_configuration_t, 
        { "rrm_oam_phy_phich_configuration_t","rrm_oam_phy_phich_configuration_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_phy_phich_configuration_t", HFILL }},
    { &hf_rrm_oam_phy_phich_configuration_t_phich_resource, 
        { "phich_resource","rrm_oam_phy_phich_configuration_t.phich_resource",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"phich_resource", HFILL }},
    { &hf_rrm_oam_phy_phich_configuration_t_phich_duration, 
        { "phich_duration","rrm_oam_phy_phich_configuration_t.phich_duration",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"phich_duration", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t, 
        { "rrm_oam_sib_type_1_info_t","rrm_oam_sib_type_1_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sib_type_1_info_t", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_bitmask, 
        { "bitmask","rrm_oam_sib_type_1_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_ims_emergency_support_r9, 
        { "ims_emergency_support_r9","rrm_oam_sib_type_1_info_t.ims_emergency_support_r9",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&ims_emergency_support_r9_values),0x0,"ims_emergency_support_r9", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_cell_selection_info, 
        { "cell_selection_info","rrm_oam_sib_type_1_info_t.cell_selection_info",FT_NONE,BASE_NONE ,NULL,0x0,"cell_selection_info", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_si_window_length, 
        { "si_window_length","rrm_oam_sib_type_1_info_t.si_window_length",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"si_window_length", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_si_count, 
        { "si_count","rrm_oam_sib_type_1_info_t.si_count",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_sib_type_1_info_t_scheduling_info, 
        { "scheduling_info","rrm_oam_sib_type_1_info_t.scheduling_info",FT_NONE,BASE_NONE ,NULL,0x0,"scheduling_info", HFILL }},
    { &hf_rrm_oam_scheduling_info_t, 
        { "rrm_oam_scheduling_info_t","rrm_oam_scheduling_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_scheduling_info_t", HFILL }},
    { &hf_rrm_oam_scheduling_info_t_si_periodicity, 
        { "si_periodicity","rrm_oam_scheduling_info_t.si_periodicity",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"si_periodicity", HFILL }},
    { &hf_rrm_oam_scheduling_info_t_sib_mapping_info, 
        { "sib_mapping_info","rrm_oam_scheduling_info_t.sib_mapping_info",FT_NONE,BASE_NONE, NULL, 0x0,"sib_mapping_info", HFILL }},
    { &hf_rrm_oam_sib_mapping_info_t, 
        { "rrm_oam_sib_mapping_info_t","rrm_oam_sib_mapping_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sib_mapping_info_t", HFILL }},
    { &hf_rrm_oam_sib_mapping_info_t_sib_type, 
        { "sib_type","rrm_oam_sib_mapping_info_t.sib_type",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"sib_type", HFILL }},
    { &hf_rrm_oam_cell_selection_info_v920_t, 
        { "rrm_oam_cell_selection_info_v920_t","rrm_oam_cell_selection_info_v920_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_cell_selection_info_v920_t", HFILL }},
    { &hf_rrm_oam_cell_selection_info_v920_t_bitmask, 
        { "bitmask","rrm_oam_cell_selection_info_v920_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_r9, 
        { "q_qual_min_r9","rrm_oam_cell_selection_info_v920_t.q_qual_min_r9",FT_INT8,BASE_DEC ,NULL,0x0,"q_qual_min_r9", HFILL }},
    { &hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_offset_r9_present, 
        { "q_qual_min_offset_r9_present","rrm_oam_cell_selection_info_v920_t.q_qual_min_offset_r9_present",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"q_qual_min_offset_r9_present", HFILL }},
    { &hf_rrm_oam_sib_type_2_info_t, 
        { "rrm_oam_sib_type_2_info_t","rrm_oam_sib_type_2_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sib_type_2_info_t", HFILL }},
    { &hf_rrm_oam_sib_type_2_info_t_bitmask, 
    	{ "bitmask","rrm_oam_sib_type_2_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib, 
        { "radio_res_config_common_sib","rrm_oam_sib_type_2_info_t.radio_res_config_common_sib",FT_NONE,BASE_NONE ,NULL,0x0,"radio_res_config_common_sib", HFILL }},
    //{ &hf_rrm_oam_sib_type_2_info_t_rrm_freq_info, 
    //	{ "rrm_freq_info","rrm_oam_sib_type_2_info_t.rrm_freq_info",FT_NONE,BASE_NONE ,NULL,0x0,"rrm_freq_info", HFILL }},
    { &hf_rrm_oam_sib_type_2_info_t_additional_spectrum_emission, 
        { "additional_spectrum_emission","rrm_oam_sib_type_2_info_t.additional_spectrum_emission",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"additional_spectrum_emission", HFILL }},

    { &hf_rrm_oam_sib_type_2_info_t_time_alignment_timer_common, 
        { "time_alignment_timer_common","rrm_oam_sib_type_2_info_t.time_alignment_timer_common",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"time_alignment_timer_common", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t, 
        { "rrm_oam_radio_resource_config_common_sib_t","rrm_oam_radio_resource_config_common_sib_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_radio_resource_config_common_sib_t", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_bitmask, 
        { "bitmask","rrm_oam_radio_resource_config_common_sib_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_modification_period_coeff, 
        { "modification_period_coeff","rrm_oam_radio_resource_config_common_sib_t.modification_period_coeff",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&modification_period_coeff_values),0x0,"modification_period_coeff", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_default_paging_cycle, 
        { "default_paging_cycle","rrm_oam_radio_resource_config_common_sib_t.default_paging_cycle",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&default_paging_cycle_values),0x0,"default_paging_cycle", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_nB, 
        { "nB","rrm_oam_radio_resource_config_common_sib_t.nB",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&nB_values),0x0,"nB", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config, 
        { "rrm_bcch_config","rrm_oam_radio_resource_config_common_sib_t.rrm_bcch_config",FT_NONE,BASE_NONE ,NULL,0x0,"rrm_bcch_config", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config, 
        { "rrm_pcch_config","rrm_oam_radio_resource_config_common_sib_t.rrm_pcch_config",FT_NONE,BASE_NONE ,NULL,0x0,"rrm_pcch_config", HFILL }},
    { &hf_rrm_oam_radio_resource_config_common_sib_t_ul_cyclic_prefix_length, 
        { "ul_cyclic_prefix_length","rrm_oam_radio_resource_config_common_sib_t.ul_cyclic_prefix_length",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&ul_cyclic_prefix_length_values),0x0,"ul_cyclic_prefix_length", HFILL }},
    { &hf_rrm_oam_bcch_config_t, 
        { "rrm_oam_bcch_config_t","rrm_oam_bcch_config_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_bcch_config_t", HFILL }},
    { &hf_rrm_oam_bcch_config_t_bitmask, 
        { "bitmask","rrm_oam_bcch_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_bcch_config_t_modification_period_coeff, 
        { "modification_period_coeff","rrm_oam_bcch_config_t.modification_period_coeff",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&modification_period_coeff_values),0x0,"modification_period_coeff", HFILL }},
    { &hf_rrm_oam_pcch_config_t, 
        { "rrm_oam_pcch_config_t","rrm_oam_pcch_config_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_pcch_config_t", HFILL }},
    { &hf_rrm_oam_pcch_config_t_bitmask, 
        { "bitmask","rrm_oam_pcch_config_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_pcch_config_t_default_paging_cycle, 
        { "default_paging_cycle","rrm_oam_pcch_config_t.default_paging_cycle",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&default_paging_cycle_values),0x0,"default_paging_cycle", HFILL }},
    { &hf_rrm_oam_pcch_config_t_nB, 
        { "nB","rrm_oam_pcch_config_t.nB",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&nB_values),0x0,"nB", HFILL }},
    { &hf_rrm_oam_freq_info_t, 
        { "rrm_oam_freq_info_t","rrm_oam_freq_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_freq_info_t", HFILL }},
    { &hf_rrm_oam_freq_info_t_additional_spectrum_emission, 
        { "additional_spectrum_emission","rrm_oam_freq_info_t.additional_spectrum_emission",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"additional_spectrum_emission", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t, 
        { "rrm_oam_sib_type_3_info_t","rrm_oam_sib_type_3_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sib_type_3_info_t", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_bitmask, 
        { "bitmask","rrm_oam_sib_type_3_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info, 
        { "intra_freq_reselection_info","rrm_oam_sib_type_3_info_t.intra_freq_reselection_info",FT_NONE,BASE_NONE ,NULL,0x0,"intra_freq_reselection_info", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_s_intra_search, 
        { "s_intra_search","rrm_oam_sib_type_3_info_t.s_intra_search",FT_NONE,BASE_NONE ,NULL,0x0,"s_intra_search", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_s_non_intra_search, 
        { "s_non_intra_search","rrm_oam_sib_type_3_info_t.s_non_intra_search",FT_NONE,BASE_NONE ,NULL,0x0,"s_non_intra_search", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_q_qual_min_r9, 
        { "q_qual_min_r9","rrm_oam_sib_type_3_info_t.q_qual_min_r9",FT_INT8,BASE_DEC ,NULL,0x0,"q_qual_min_r9", HFILL }},
    { &hf_rrm_oam_sib_type_3_info_t_thresh_serving_lowq_r9, 
        { "thresh_serving_lowq_r9","rrm_oam_sib_type_3_info_t.thresh_serving_lowq_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"thresh_serving_lowq_r9", HFILL }},
    { &hf_rrm_oam_intra_freq_cell_reselection_info_t, 
        { "rrm_oam_intra_freq_cell_reselection_info_t","rrm_oam_intra_freq_cell_reselection_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_intra_freq_cell_reselection_info_t", HFILL }},
    { &hf_rrm_oam_intra_freq_cell_reselection_info_t_bitmask, 
        { "bitmask","rrm_oam_intra_freq_cell_reselection_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_intra_freq_cell_reselection_info_t_measurement_bandwidth, 
        { "measurement_bandwidth","rrm_oam_intra_freq_cell_reselection_info_t.measurement_bandwidth",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&measurement_bandwidth_values),0x0,"measurement_bandwidth", HFILL }},
    { &hf_rrm_oam_intra_freq_cell_reselection_info_t_presence_antenna_port1, 
        { "presence_antenna_port1","rrm_oam_intra_freq_cell_reselection_info_t.presence_antenna_port1",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"presence_antenna_port1", HFILL }},
    { &hf_rrm_oam_s_intra_search_v920_t, 
        { "rrm_oam_s_intra_search_v920_t","rrm_oam_s_intra_search_v920_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_s_intra_search_v920_t", HFILL }},
    { &hf_rrm_oam_s_intra_search_v920_t_s_intra_search_p_r9, 
        { "s_intra_search_p_r9","rrm_oam_s_intra_search_v920_t.s_intra_search_p_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_intra_search_p_r9", HFILL }},
    { &hf_rrm_oam_s_intra_search_v920_t_s_intra_search_q_r9, 
        { "s_intra_search_q_r9","rrm_oam_s_intra_search_v920_t.s_intra_search_q_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_intra_search_q_r9", HFILL }},
    { &hf_rrm_oam_s_non_intra_search_v920_t, 
        { "rrm_oam_s_non_intra_search_v920_t","rrm_oam_s_non_intra_search_v920_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_s_non_intra_search_v920_t", HFILL }},
    { &hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_p_r9, 
        { "s_non_intra_search_p_r9","rrm_oam_s_non_intra_search_v920_t.s_non_intra_search_p_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_non_intra_search_p_r9", HFILL }},
    { &hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_q_r9, 
        { "s_non_intra_search_q_r9","rrm_oam_s_non_intra_search_v920_t.s_non_intra_search_q_r9",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"s_non_intra_search_q_r9", HFILL }},
    { &hf_rrm_oam_sib_type_4_info_t, 
        { "rrm_oam_sib_type_4_info_t","rrm_oam_sib_type_4_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sib_type_4_info_t", HFILL }},
    { &hf_rrm_oam_sib_type_4_info_t_csg_id_range, 
        { "csg_id_range","rrm_oam_sib_type_4_info_t.csg_id_range",FT_NONE,BASE_NONE ,NULL,0x0,"csg_id_range", HFILL }},
    { &hf_rrm_oam_csg_cell_id_range_t, 
        { "rrm_oam_csg_cell_id_range_t","rrm_oam_csg_cell_id_range_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_csg_cell_id_range_t", HFILL }},
    { &hf_rrm_oam_csg_cell_id_range_t_bitmask, 
        { "bitmask","rrm_oam_csg_cell_id_range_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_csg_cell_id_range_t_start, 
        { "start","rrm_oam_csg_cell_id_range_t.start",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"start", HFILL }},
    { &hf_rrm_oam_csg_cell_id_range_t_range, 
        { "range","rrm_oam_csg_cell_id_range_t.range",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&range_values),0x0,"range", HFILL }},
    { &hf_rrm_oam_admission_control_info_t, 
        { "rrm_oam_admission_control_info_t","rrm_oam_admission_control_info_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_admission_control_info_t", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_bitmask, 
        { "bitmask","rrm_oam_admission_control_info_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_max_num_ue_per_cell, 
        { "max_num_ue_per_cell","rrm_oam_admission_control_info_t.max_num_ue_per_cell",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_num_ue_per_cell", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_max_sps_ues, 
        { "max_sps_ues","rrm_oam_admission_control_info_t.max_sps_ues",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_sps_ues", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_max_num_drbs_per_ue, 
        { "max_num_drbs_per_ue","rrm_oam_admission_control_info_t.max_num_drbs_per_ue",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_num_drbs_per_ue", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_max_num_gbr_drbs_per_ue, 
        { "max_num_gbr_drbs_per_ue","rrm_oam_admission_control_info_t.max_num_gbr_drbs_per_ue",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_num_gbr_drbs_per_ue", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_max_num_non_gbr_drbs_per_ue, 
        { "max_num_non_gbr_drbs_per_ue","rrm_oam_admission_control_info_t.max_num_non_gbr_drbs_per_ue",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"max_num_non_gbr_drbs_per_ue", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_dl_prb_budget, 
        { "dl_prb_budget","rrm_oam_admission_control_info_t.dl_prb_budget",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_prb_budget", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_ul_prb_budget, 
        { "ul_prb_budget","rrm_oam_admission_control_info_t.ul_prb_budget",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_prb_budget", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_dl_prb_budget_gbr, 
        { "dl_prb_budget_gbr","rrm_oam_admission_control_info_t.dl_prb_budget_gbr",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_prb_budget_gbr", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_ul_prb_budget_gbr, 
        { "ul_prb_budget_gbr","rrm_oam_admission_control_info_t.ul_prb_budget_gbr",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_prb_budget_gbr", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_dl_prb_budget_ngbr, 
        { "dl_prb_budget_ngbr","rrm_oam_admission_control_info_t.dl_prb_budget_ngbr",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dl_prb_budget_ngbr", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_ul_prb_budget_ngbr, 
        { "ul_prb_budget_ngbr","rrm_oam_admission_control_info_t.ul_prb_budget_ngbr",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ul_prb_budget_ngbr", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_resource_reserved_for_existing_users, 
        { "resource_reserved_for_existing_users","rrm_oam_admission_control_info_t.resource_reserved_for_existing_users",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"resource_reserved_for_existing_users", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_total_backhaul_capacity, 
        { "total_backhaul_capacity","rrm_oam_admission_control_info_t.total_backhaul_capacity",FT_UINT64,BASE_HEX_DEC ,NULL,0x0,"total_backhaul_capacity", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_capacity_threshold, 
        { "capacity_threshold","rrm_oam_admission_control_info_t.capacity_threshold",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"capacity_threshold", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_spid_table, 
        { "spid_table","rrm_oam_admission_control_info_t.spid_table",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"spid_table", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_preemption_allowed, 
        { "preemption_allowed","rrm_oam_admission_control_info_t.preemption_allowed",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"preemption_allowed", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_preemption_status, 
        { "preemption_status","rrm_oam_admission_control_info_t.preemption_status",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"preemption_status", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_proximity_indication_status, 
        { "proximity_indication_status","rrm_oam_admission_control_info_t.proximity_indication_status",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"proximity_indication_status", HFILL }},
    { &hf_rrm_oam_admission_control_info_t_available_gbr_limit, 
        { "available_gbr_limit","rrm_oam_admission_control_info_t.available_gbr_limit",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"available_gbr_limit", HFILL }},
    { &hf_available_gbr_limit_t, 
        { "available_gbr_limit_t","available_gbr_limit_t",FT_NONE,BASE_NONE, NULL, 0x0,"available_gbr_limit_t", HFILL }},
    { &hf_available_gbr_limit_t_dl_gbr_limit, 
        { "dl_gbr_limit","available_gbr_limit_t.dl_gbr_limit",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"dl_gbr_limit", HFILL }},
    { &hf_available_gbr_limit_t_ul_gbr_limit, 
        { "ul_gbr_limit","available_gbr_limit_t.ul_gbr_limit",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"ul_gbr_limit", HFILL }},
    { &hf_rrm_oam_spid_table_t, 
        { "rrm_oam_spid_table_t","rrm_oam_spid_table_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_spid_table_t", HFILL }},
    { &hf_rrm_oam_spid_table_t_spid_count, 
        { "spid_count","rrm_oam_spid_table_t.spid_count",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"spid_count", HFILL }},
    { &hf_rrm_oam_spid_table_t_spid_config, 
        { "spid_config","rrm_oam_spid_table_t.spid_config",FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"spid_config", HFILL }},
    { &hf_rrm_oam_spid_configuration_t, 
        { "rrm_oam_spid_configuration_t","rrm_oam_spid_configuration_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_spid_configuration_t", HFILL }},
    { &hf_rrm_oam_spid_configuration_t_bitmask, 
        { "bitmask","rrm_oam_spid_configuration_t.bitmask",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_spid_configuration_t_sp_id, 
        { "sp_id","rrm_oam_spid_configuration_t.sp_id",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"sp_id", HFILL }},
    { &hf_rrm_oam_spid_configuration_t_eutran_freq_priority_info, 
        { "eutran_freq_priority_info","rrm_oam_spid_configuration_t.eutran_freq_priority_info",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"eutran_freq_priority_info", HFILL }},
    { &hf_rrm_oam_spid_configuration_t_utran_freq_priority_info, 
        { "utran_freq_priority_info","rrm_oam_spid_configuration_t.utran_freq_priority_info",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"utran_freq_priority_info", HFILL }},
    { &hf_rrm_oam_spid_configuration_t_geran_freq_priority_info, 
        { "geran_freq_priority_info","rrm_oam_spid_configuration_t.geran_freq_priority_info",FT_UINT32,BASE_HEX_DEC, NULL, 0x0,"geran_freq_priority_info", HFILL }},
{ &hf_rrm_power_control_params_rrm_power_control_params, 
	{ "rrm_power_control_params","rrm_power_control_params.rrm_power_control_params",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_power_control_params", HFILL }},
{ &hf_rrm_power_control_params_rrm_power_control_params_bitmask, 
	{ "bitmask","rrm_power_control_params.rrm_power_control_params.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable, 
	{ "rrm_power_control_enable","rrm_power_control_params.rrm_power_control_params.rrm_power_control_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rrm_power_control_enable", HFILL }},
{ &hf_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range, 
	{ "rrm_tpc_rnti_range","rrm_power_control_params.rrm_power_control_params.rrm_tpc_rnti_range",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rrm_tpc_rnti_range", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t, 
	{ "rrm_oam_power_control_enable_t","rrm_power_control_params.rrm_oam_power_control_enable_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_power_control_enable_t", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_bitmask, 
	{ "bitmask","rrm_power_control_params.rrm_oam_power_control_enable_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_harqBlerClpcPucchEnable, 
	{ "harqBlerClpcPucchEnable","rrm_power_control_params.rrm_oam_power_control_enable_t.harqBlerClpcPucchEnable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"harqBlerClpcPucchEnable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_cqiSinrClpcPucchEnable, 
	{ "cqiSinrClpcPucchEnable","rrm_power_control_params.rrm_oam_power_control_enable_t.cqiSinrClpcPucchEnable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"cqiSinrClpcPucchEnable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschEnable, 
	{ "clpcPuschEnable","rrm_power_control_params.rrm_oam_power_control_enable_t.clpcPuschEnable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"clpcPuschEnable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pucch_enable, 
	{ "dci_3_3a_based_power_control_for_pucch_enable","rrm_power_control_params.rrm_oam_power_control_enable_t.dci_3_3a_based_power_control_for_pucch_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dci_3_3a_based_power_control_for_pucch_enable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pusch_enable, 
	{ "dci_3_3a_based_power_control_for_pusch_enable","rrm_power_control_params.rrm_oam_power_control_enable_t.dci_3_3a_based_power_control_for_pusch_enable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"dci_3_3a_based_power_control_for_pusch_enable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschfreqSelectiveEnable, 
	{ "clpcPuschfreqSelectiveEnable","rrm_power_control_params.rrm_oam_power_control_enable_t.clpcPuschfreqSelectiveEnable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"clpcPuschfreqSelectiveEnable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_pdcchPowOrAggregationEnable, 
	{ "pdcchPowOrAggregationEnable","rrm_power_control_params.rrm_oam_power_control_enable_t.pdcchPowOrAggregationEnable",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pdcchPowOrAggregationEnable", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_mcs_enabled, 
	{ "delta_mcs_enabled","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_mcs_enabled",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"delta_mcs_enabled", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_accumulation_enabled, 
	{ "accumulation_enabled","rrm_power_control_params.rrm_oam_power_control_enable_t.accumulation_enabled",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"accumulation_enabled", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1, 
	{ "delta_f_pucch_format_1","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_f_pucch_format_1",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"delta_f_pucch_format_1", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1b, 
	{ "delta_f_pucch_format_1b","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_f_pucch_format_1b",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"delta_f_pucch_format_1b", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2, 
	{ "delta_f_pucch_format_2","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_f_pucch_format_2",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"delta_f_pucch_format_2", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2a, 
	{ "delta_f_pucch_format_2a","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_f_pucch_format_2a",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"delta_f_pucch_format_2a", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2b, 
	{ "delta_f_pucch_format_2b","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_f_pucch_format_2b",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"delta_f_pucch_format_2b", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_preamble_msg_3, 
	{ "delta_preamble_msg_3","rrm_power_control_params.rrm_oam_power_control_enable_t.delta_preamble_msg_3",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"delta_preamble_msg_3", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t, 
	{ "rrm_oam_tpc_rnti_range_t","rrm_power_control_params.rrm_oam_tpc_rnti_range_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_tpc_rnti_range_t", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPucch, 
	{ "startTpcRntiPucch","rrm_power_control_params.rrm_oam_tpc_rnti_range_t.startTpcRntiPucch",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"startTpcRntiPucch", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPucch, 
	{ "endTpcRntiPucch","rrm_power_control_params.rrm_oam_tpc_rnti_range_t.endTpcRntiPucch",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"endTpcRntiPucch", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPusch, 
	{ "startTpcRntiPusch","rrm_power_control_params.rrm_oam_tpc_rnti_range_t.startTpcRntiPusch",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"startTpcRntiPusch", HFILL }},
{ &hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPusch, 
	{ "endTpcRntiPusch","rrm_power_control_params.rrm_oam_tpc_rnti_range_t.endTpcRntiPusch",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"endTpcRntiPusch", HFILL }},
    { &hf_rrm_oam_sps_crnti_range_t, 
        { "rrm_oam_sps_crnti_range_t","rrm_oam_sps_crnti_range_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_sps_crnti_range_t", HFILL }},
    { &hf_rrm_oam_sps_crnti_range_t_start_sps_crnti_range, 
        { "start_sps_crnti_range","rrm_oam_sps_crnti_range_t.start_sps_crnti_range",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"start_sps_crnti_range", HFILL }},
    { &hf_rrm_oam_sps_crnti_range_t_end_sps_crnti_range, 
        { "end_sps_crnti_range","rrm_oam_sps_crnti_range_t.end_sps_crnti_range",FT_UINT16,BASE_HEX_DEC, NULL, 0x0,"end_sps_crnti_range", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t, 
        { "rrm_oam_access_mgmt_params_t","rrm_oam_access_mgmt_params_t",FT_NONE,BASE_NONE, NULL, 0x0,"rrm_oam_access_mgmt_params_t", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_access_mode, 
        { "access_mode","rrm_oam_access_mgmt_params_t.access_mode",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&access_mode_values),0x0,"access_mode", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_max_csg_members, 
        { "max_csg_members","rrm_oam_access_mgmt_params_t.max_csg_members",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_csg_members", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_max_non_csg_members, 
        { "max_non_csg_members","rrm_oam_access_mgmt_params_t.max_non_csg_members",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_non_csg_members", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_csg_id, 
        { "csg_id","rrm_oam_access_mgmt_params_t.csg_id",FT_STRING,BASE_NONE ,NULL,0x0,"csg_id", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_hnb_name_size, 
        { "hnb_name_size","rrm_oam_access_mgmt_params_t.hnb_name_size",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"hnb_name_size", HFILL }},
    { &hf_rrm_oam_access_mgmt_params_t_hnb_name, 
        { "hnb_name","rrm_oam_access_mgmt_params_t.hnb_name",FT_STRING,BASE_NONE ,NULL,0x0,"hnb_name", HFILL }},
    //RRM OAM INIT IND
    { &hf_rrm_oam_init_ind_t,
        { "rrm_oam_init_ind_t","RRM_OAM_INIT_IND.rrm_oam_init_ind_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_init_ind_t", HFILL }},
    //RRM OAM SHUTDOWN REQ
    { &hf_rrm_oam_shutdown_req_t, 
        { "rrm_oam_shutdown_req_t","RRM_OAM_SHUTDOWN_REQ.rrm_oam_shutdown_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_shutdown_req_t", HFILL }},
    { &hf_rrm_oam_shutdown_req_t_shutdown_mode, 
        { "shutdown_mode","rrm_oam_shutdown_req_t.shutdown_mode",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&shutdown_mode_values),0x0,"shutdown_mode", HFILL }},
    { &hf_rrm_oam_shutdown_req_t_time_to_shutdown, 
        { "time_to_shutdown","rrm_oam_shutdown_req_t.time_to_shutdown",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"time_to_shutdown", HFILL }},
    //RRM OAM SHUTDOWN RESP
    { &hf_rrm_oam_shutdown_resp_t, 
        { "rrm_oam_shutdown_resp_t","RRM_OAM_SHUTDOWN_RESP.rrm_oam_shutdown_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_shutdown_resp_t", HFILL }},
    { &hf_rrm_oam_shutdown_resp_t_response, 
        { "response","rrm_oam_shutdown_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_shutdown_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_shutdown_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //SET LOG LEVEL REQ
    { &hf_rrm_oam_set_log_level_req_t, 
        { "rrm_oam_set_log_level_req_t","RRM_OAM_SET_LOG_LEVEL_REQ.rrm_oam_set_log_level_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_set_log_level_req_t", HFILL }},
    { &hf_rrm_oam_set_log_level_req_t_module_id, 
        { "module_id","rrm_oam_set_log_level_req_t.module_id",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&module_id_values),0x0,"module_id", HFILL }},
    { &hf_rrm_oam_set_log_level_req_t_log_level, 
        { "log_level","rrm_oam_set_log_level_req_t.log_level",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&log_level_values),0x0,"log_level", HFILL }},
    //SET LOG LEVEL RESP
    { &hf_rrm_oam_set_log_level_resp_t, 
        { "rrm_oam_set_log_level_resp_t","RRM_OAM_SET_LOG_LEVEL_RESP.rrm_oam_set_log_level_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_set_log_level_resp_t", HFILL }},
    { &hf_rrm_oam_set_log_level_resp_t_response, 
        { "response","rrm_oam_set_log_level_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_set_log_level_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_set_log_level_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //resume service req
    { &hf_rrm_oam_resume_service_req_t, 
        { "rrm_oam_resume_service_req_t","RRM_OAM_RESUME_SERVICE_REQ.rrm_oam_resume_service_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_resume_service_req_t", HFILL }},
    //resume service resp
    { &hf_rrm_oam_resume_service_resp_t, 
        { "rrm_oam_resume_service_resp_t","RRM_OAM_RESUME_SERVICE_RESP.rrm_oam_resume_service_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_resume_service_resp_t", HFILL }},
    { &hf_rrm_oam_resume_service_resp_t_response, 
        { "response","rrm_oam_resume_service_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_resume_service_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_resume_service_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //ready for shutdown ind
    { &hf_rrm_oam_ready_for_shutdown_ind_t, 
        { "rrm_oam_ready_for_shutdown_ind_t","RRM_OAM_READY_FOR_SHUTDOWN_IND.rrm_oam_ready_for_shutdown_ind_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ready_for_shutdown_ind_t", HFILL }},
    //rac enable disable req
    { &hf_rrm_oam_rac_enable_disable_req_t, 
        { "rrm_oam_rac_enable_disable_req_t","RRM_OAM_RAC_ENABLE_DISABLE_REQ.rrm_oam_rac_enable_disable_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_rac_enable_disable_req_t", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_req_t_bitmask, 
        { "bitmask","rrm_oam_rac_enable_disable_req_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_req_t_request_type, 
        { "request_type","rrm_oam_rac_enable_disable_req_t.request_type",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&request_type_values),0x0,"request_type", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_req_t_global_cell_id, 
        { "global_cell_id","rrm_oam_rac_enable_disable_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    //rac enable disble resp
    { &hf_rrm_oam_rac_enable_disable_resp_t, 
        { "rrm_oam_rac_enable_disable_resp_t","RRM_OAM_RAC_ENABLE_DISABLE_RESP.rrm_oam_rac_enable_disable_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_rac_enable_disable_resp_t", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_resp_t_bitmask, 
        { "bitmask","rrm_oam_rac_enable_disable_resp_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_rac_enable_disable_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_resp_t_response, 
        { "response","rrm_oam_rac_enable_disable_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_rac_enable_disable_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_rac_enable_disable_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //log enable disable req
    { &hf_rrm_oam_log_enable_disable_req_t, 
        { "rrm_oam_log_enable_disable_req_t","RRM_OAM_LOG_ENABLE_DISABLE_REQ.rrm_oam_log_enable_disable_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_log_enable_disable_req_t", HFILL }},
    { &hf_rrm_oam_log_enable_disable_req_t_module_id, 
        { "module_id","rrm_oam_log_enable_disable_req_t.module_id",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&module_id_values),0x0,"module_id", HFILL }},
    { &hf_rrm_oam_log_enable_disable_req_t_log_config, 
        { "log_config","rrm_oam_log_enable_disable_req_t.log_config",FT_NONE,BASE_NONE ,NULL,0x0,"log_config", HFILL }},
    { &hf_rrm_oam_log_config_t, 
        { "rrm_oam_log_config_t","rrm_oam_log_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_log_config_t", HFILL }},
    { &hf_rrm_oam_log_config_t_log_on_off, 
        { "log_on_off","rrm_oam_log_config_t.log_on_off",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&log_on_off_values),0x0,"log_on_off", HFILL }},
    { &hf_rrm_oam_log_config_t_log_level, 
        { "log_level","rrm_oam_log_config_t.log_level",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&log_level_values),0x0,"log_level", HFILL }},
    //log enable disable resp
    { &hf_rrm_oam_log_enable_disable_resp_t, 
        { "rrm_oam_log_enable_disable_resp_t","RRM_OAM_LOG_ENABLE_DISABLE_RESP.rrm_oam_log_enable_disable_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_log_enable_disable_resp_t", HFILL }},
    { &hf_rrm_oam_log_enable_disable_resp_t_response, 
        { "response","rrm_oam_log_enable_disable_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_log_enable_disable_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_log_enable_disable_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //RRM OAM INIT CONFIG REQ
    { &hf_rrm_oam_init_config_req_t, 
        { "rrm_oam_init_config_req_t","RRM_OAM_INIT_CONFIG_REQ.rrm_oam_init_config_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_init_config_req_t", HFILL }},
    { &hf_rrm_oam_init_config_req_t_bitmask, 
        { "bitmask","rrm_oam_init_config_req_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_init_config_req_t_init_module_config, 
        { "init_module_config","rrm_oam_init_config_req_t.init_module_config",FT_NONE,BASE_NONE ,NULL,0x0,"init_module_config", HFILL }},
    { &hf_rrm_oam_module_init_config_t, 
        { "rrm_oam_module_init_config_t","rrm_oam_module_init_config_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_module_init_config_t", HFILL }},
    { &hf_rrm_oam_module_init_config_t_module_id, 
        { "module_id","rrm_oam_module_init_config_t.module_id",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&module_id_values),0x0,"module_id", HFILL }},
    { &hf_rrm_oam_module_init_config_t_log_config, 
        { "log_config","rrm_oam_module_init_config_t.log_config",FT_NONE,BASE_NONE ,NULL,0x0,"log_config", HFILL }},
    //RRM OAM INIT CONFIG RESP
    { &hf_rrm_oam_init_config_resp_t, 
        { "rrm_oam_init_config_resp_t","RRM_OAM_INIT_CONFIG_RESP.rrm_oam_init_config_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_init_config_resp_t", HFILL }},
    { &hf_rrm_oam_init_config_resp_t_response, 
        { "response","rrm_oam_init_config_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_init_config_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_init_config_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //RRM OAM CELL START REQ
    { &hf_rrm_oam_cell_start_req_t, 
        { "rrm_oam_cell_start_req_t","RRM_OAM_CELL_START_REQ.rrm_oam_cell_start_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_start_req_t", HFILL }},
    { &hf_rrm_oam_cell_start_req_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_start_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    //RRM OAM CELL START RESP
    { &hf_rrm_oam_cell_start_resp_t, 
        { "rrm_oam_cell_start_resp_t","RRM_OAM_CELL_START_RESP.rrm_oam_cell_start_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_start_resp_t", HFILL }},
    { &hf_rrm_oam_cell_start_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_start_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_start_resp_t_response, 
        { "response","rrm_oam_cell_start_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_start_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_cell_start_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    // CELL STOP REQ
    { &hf_rrm_oam_cell_stop_req_t, 
        { "rrm_oam_cell_stop_req_t","RRM_OAM_CELL_STOP_REQ.rrm_oam_cell_stop_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_stop_req_t", HFILL }},
    { &hf_rrm_oam_cell_stop_req_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_stop_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    // CELL STOP RESP
    { &hf_rrm_oam_cell_stop_resp_t, 
        { "rrm_oam_cell_stop_resp_t","RRM_OAM_CELL_STOP_RESP.rrm_oam_cell_stop_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_stop_resp_t", HFILL }},
    { &hf_rrm_oam_cell_stop_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_stop_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_stop_resp_t_response, 
        { "response","rrm_oam_cell_stop_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_stop_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_cell_stop_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    // CELL DELETE REQ API header field
    { &hf_rrm_oam_cell_delete_req_t, 
        { "rrm_oam_cell_delete_req_t","RRM_OAM_CELL_DELETE_REQ.rrm_oam_cell_delete_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_delete_req_t", HFILL }},
    { &hf_rrm_oam_cell_delete_req_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_delete_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    // CELL DELETE RESP API header field
    { &hf_rrm_oam_cell_delete_resp_t, 
        { "rrm_oam_cell_delete_resp_t","RRM_OAM_CELL_DELETE_RESP.rrm_oam_cell_delete_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_delete_resp_t", HFILL }},
    { &hf_rrm_oam_cell_delete_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_delete_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_delete_resp_t_response, 
        { "response","rrm_oam_cell_delete_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_delete_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_cell_delete_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    // CEll CONFIG RESP
    { &hf_rrm_oam_cell_config_resp_t, 
        { "rrm_oam_cell_config_resp_t","RRM_OAM_CELL_CONFIG_RESP.rrm_oam_cell_config_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_config_resp_t", HFILL }},
    { &hf_rrm_oam_cell_config_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_config_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_config_resp_t_response, 
        { "response","rrm_oam_cell_config_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_config_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_cell_config_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},

    //Cell reconfig req
    { &hf_rrm_oam_cell_reconfig_req_t, 
        { "rrm_oam_cell_reconfig_req_t","RRM_OAM_CELL_RECONFIG_REQ.rrm_oam_cell_reconfig_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_reconfig_req_t", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_bitmask, 
        { "bitmask","rrm_oam_cell_reconfig_req_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_global_cell_id, 
        { "eutran_global_cell_id","rrm_oam_cell_reconfig_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"eutran_global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params, 
        { "cell_access_restriction_params","rrm_oam_cell_reconfig_req_t.cell_access_restriction_params",FT_NONE,BASE_NONE ,NULL,0x0,"cell_access_restriction_params", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_ran_info, 
        { "ran_info","rrm_oam_cell_reconfig_req_t.ran_info",FT_NONE,BASE_NONE ,NULL,0x0,"ran_info", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_epc_info, 
        { "epc_info","rrm_oam_cell_reconfig_req_t.epc_info",FT_NONE,BASE_NONE ,NULL,0x0,"epc_info", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_operator_info, 
        { "operator_info","rrm_oam_cell_reconfig_req_t.operator_info",FT_NONE,BASE_NONE ,NULL,0x0,"operator_info", HFILL }},
    { &hf_rrm_oam_cell_reconfig_req_t_access_mgmt_params, 
        { "access_mgmt_params","rrm_oam_cell_reconfig_req_t.access_mgmt_params",FT_NONE,BASE_NONE ,NULL,0x0,"access_mgmt_params", HFILL }},
    //CELL RECONFIG RESP
    { &hf_rrm_oam_cell_reconfig_resp_t, 
        { "rrm_oam_cell_reconfig_resp_t","RRM_OAM_CELL_RECONFIG_RESP.rrm_oam_cell_reconfig_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_reconfig_resp_t", HFILL }},
    { &hf_rrm_oam_cell_reconfig_resp_t_global_cell_id, 
        { "global_cell_id","rrm_oam_cell_reconfig_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_reconfig_resp_t_response, 
        { "response","rrm_oam_cell_reconfig_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_reconfig_resp_t_fail_cause, 
        { "fail_cause","rrm_oam_cell_reconfig_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},

    //ADDED PT.
    { &hf_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req, 
        { "rrm_oam_cell_context_print_req","rrm_oam_cell_context_print_req.rrm_oam_cell_context_print_req",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_context_print_req", HFILL }},
    // CARRIER FREQ DL TX PARAMS REQ API header field
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t, 
        { "rrm_oam_carrier_freq_dl_tx_params_req_t","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_dl_tx_params_req_t", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_meas_bandwidth, 
        { "meas_bandwidth","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.meas_bandwidth",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"meas_bandwidth", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_no_of_arfcn, 
        { "no_of_arfcn","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.no_of_arfcn",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"no_of_arfcn", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_arfcn_list, 
        { "arfcn_list","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.arfcn_list",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"arfcn_list", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_upp, 
        { "p_tx_upp","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.p_tx_upp",FT_INT8,BASE_DEC ,NULL,0x0,"p_tx_upp", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_low, 
        { "p_tx_low","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.p_tx_low",FT_INT8,BASE_DEC ,NULL,0x0,"p_tx_low", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_offset_o, 
        { "p_offset_o","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.p_offset_o",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_offset_o", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_adjust, 
        { "p_adjust","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.p_adjust",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_adjust", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_penetration_loss, 
        { "p_penetration_loss","rrm_oam_carrier_freq_dl_tx_params_req_t.rrm_oam_carrier_freq_dl_tx_params_req_t.p_penetration_loss",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"p_penetration_loss", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t, 
        { "rrm_oam_carrier_freq_dl_tx_params_resp_t","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_carrier_freq_dl_tx_params_resp_t", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_bitmask, 
        { "bitmask","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_dl_earfcn, 
        { "dl_earfcn","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t.dl_earfcn",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"dl_earfcn", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_reference_signal_power, 
        { "reference_signal_power","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t.reference_signal_power",FT_INT8,BASE_DEC ,NULL,0x0,"reference_signal_power", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_result, 
        { "result","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t.result",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&result_values),0x0,"result", HFILL }},
    { &hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_error_code, 
    { "error_code","rrm_oam_carrier_freq_dl_tx_params_resp_t.rrm_oam_carrier_freq_dl_tx_params_resp_t.error_code",FT_INT32,BASE_DEC ,NULL,0x0,"error_code", HFILL }},
    { &hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t, 
    { "rrm_oam_ue_release_req_t","rrm_oam_ue_release_req_t.rrm_oam_ue_release_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ue_release_req_t", HFILL }},
    { &hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t_ue_index, 
    { "ue_index","rrm_oam_ue_release_req_t.rrm_oam_ue_release_req_t.ue_index",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"ue_index", HFILL }},   
    { &hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t, 
    { "rrm_oam_proc_supervision_resp_t","rrm_oam_proc_supervision_resp_t.rrm_oam_proc_supervision_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_proc_supervision_resp_t", HFILL }},
    { &hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_alive_status, 
    { "alive_status","rrm_oam_proc_supervision_resp_t.rrm_oam_proc_supervision_resp_t.alive_status",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&alive_status_values),0x0,"alive_status", HFILL }},
    { &hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_proc_supervision_resp_t.rrm_oam_proc_supervision_resp_t.fail_cause",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&fail_cause_values),0x0,"fail_cause", HFILL }},
    //RRM_OAM_BLOCK_CELL_REQ API header field
    { &hf_rrm_oam_block_cell_req_t, 
    { "rrm_oam_block_cell_req_t","RRM_OAM_CELL_BLOCK_REQ.rrm_oam_block_cell_req_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_block_cell_req_t", HFILL }},
    { &hf_rrm_oam_block_cell_req_t_bitmask, 
    { "bitmask","rrm_oam_block_cell_req_t.bitmask",FT_UINT32,BASE_HEX_DEC ,NULL,0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_block_cell_req_t_global_cell_id, 
    { "global_cell_id","rrm_oam_block_cell_req_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_block_cell_req_t_cell_block_priority, 
    { "cell_block_priority","rrm_oam_block_cell_req_t.cell_block_priority",FT_INT32,BASE_DEC ,NULL,0x0,"cell_block_priority", HFILL }},
    { &hf_rrm_oam_block_cell_req_t_cell_block_resource_cleanup_timer, 
    { "cell_block_resource_cleanup_timer","rrm_oam_block_cell_req_t.cell_block_resource_cleanup_timer",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"cell_block_resource_cleanup_timer", HFILL }},
    
    //RRM_OAM_BLOCK_CELL_RESP API header field 
    { &hf_rrm_oam_block_cell_resp_t, 
    { "rrm_oam_block_cell_resp_t","rrm_oam_block_cell_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_block_cell_resp_t", HFILL }},
    { &hf_rrm_oam_block_cell_resp_t_global_cell_id, 
    { "global_cell_id","rrm_oam_block_cell_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_block_cell_resp_t_response, 
    { "response","rrm_oam_block_cell_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_block_cell_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_block_cell_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    
    //RRM_OAM_READY_FOR_CELL_BLOCK_IND API header field
   { &hf_rrm_oam_ready_for_cell_block_ind_t, 
    { "rrm_oam_ready_for_cell_block_ind_t","RRM_OAM_READY_FOR_CELL_BLOCK_IND.rrm_oam_ready_for_cell_block_ind_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_ready_for_cell_block_ind_t", HFILL }},
    { &hf_rrm_oam_ready_for_cell_block_ind_t_global_cell_id, 
    { "global_cell_id","RRM_OAM_READY_FOR_CELL_BLOCK_IND.rrm_oam_ready_for_cell_block_ind_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    //RRM_OAM_UNBLOCK_CELL_CMD API header field
    { &hf_rrm_oam_unblock_cell_cmd_t, 
    { "rrm_oam_unblock_cell_cmd_t","rrm_oam_unblock_cell_cmd_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_unblock_cell_cmd_t", HFILL }},
    { &hf_rrm_oam_unblock_cell_cmd_t_global_cell_id, 
    { "global_cell_id","rrm_oam_unblock_cell_cmd_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_get_ver_id_req_t,
    { "rrm_oam_get_ver_id_req_t", "rrm_oam_get_ver_id_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_get_ver_id_req_t", HFILL }},
    { &hf_rrm_oam_get_ver_id_resp_t,
    { "rrm_oam_get_ver_id_resp_t", "rrm_oam_get_ver_id_resp_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_get_ver_id_resp_t", HFILL }},
    { &hf_rrm_oam_get_ver_id_resp_t_response,
    { "response","rrm_oam_get_ver_id_resp_t.response",FT_INT32,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&response_values),0x0,"response", HFILL }},
    //RRM_OAM_CELL_UPDATE_REQ API header field
    { &hf_rrm_oam_cell_update_req_t,
    { "rrm_oam_cell_update_req_t", "rrm_oam_cell_update_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_update_req_t", HFILL }},
    { &hf_rrm_oam_cell_update_req_t_bitmask,
    { "bitmask","rrm_oam_cell_update_req_t.bitmask",FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask",  HFILL }},
    { &hf_rrm_oam_cell_update_req_t_pci_value,
    { "pci_value","rrm_oam_cell_update_req_t.pci_value",FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "pci_value",  HFILL }},
    { &hf_rrm_oam_updated_plmn_info_t,
    { "rrm_oam_updated_plmn_info_t","rrm_oam_updated_plmn_info_t",FT_NONE, BASE_NONE, NULL, 0x0, "rrm_oam_updated_plmn_info_t",  HFILL }},
    { &hf_rrm_oam_updated_plmn_info_t_num_valid_plmn,
    { "num_of_valid_plmn","rrm_oam_cell_update_req_t.updated_plmn_info.num_of_valid_plmn",FT_UINT8,BASE_HEX_DEC, NULL, 0x0, "num_of_valid_plmn",  HFILL }},
    { &hf_rrm_oam_cell_update_req_t_conn_mode_cell_spec_off,
    { "conn_mode_cell_spec_off","rrm_oam_cell_update_req_t.conn_mode_cell_spec_off",FT_UINT8,BASE_HEX_DEC, NULL, 0x0, "conn_mode_cell_spec_off",  HFILL }},
    { &hf_rrm_oam_cell_update_req_t_idle_mode_cell_spec_off,
    { "idle_mode_cell_spec_off","rrm_oam_cell_update_req_t.idle_mode_cell_spec_off",FT_UINT8,BASE_HEX_DEC, NULL, 0x0, "idle_mode_cell_spec_off",  HFILL }},

    //RRM_OAM_CELL_UPDATE_RESP API header field 
    { &hf_rrm_oam_cell_update_resp_t, 
    { "rrm_oam_cell_update_resp_t","rrm_oam_cell_update_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_update_resp_t", HFILL }},
    { &hf_rrm_oam_cell_update_resp_t_global_cell_id, 
    { "global_cell_id","rrm_oam_cell_update_resp_t.global_cell_id",FT_NONE,BASE_NONE ,NULL,0x0,"global_cell_id", HFILL }},
    { &hf_rrm_oam_cell_update_resp_t_response, 
    { "response","rrm_oam_cell_update_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_update_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_cell_update_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    
    //RRM_OAM_EVENT_NOTIFICATION API header field
    { &hf_rrm_oam_event_notification_t,
    { "rrm_oam_event_notification_t", "rrm_oam_event_notification_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_event_notification_t", HFILL }},
    { &hf_rrm_oam_event_notification_t_bitmask,
    { "bitmask","rrm_oam_event_notification_t.bitmask",FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "bitmask",  HFILL }},
    { &hf_rrm_oam_event_header_t, 
    { "msg_header","rrm_oam_event_header_t",FT_NONE,BASE_NONE ,NULL,0x0,"msg_header", HFILL }},
    { &hf_rrm_oam_time_stamp_t, 
    { "time_stamp","rrm_oam_time_stamp_t",FT_NONE,BASE_NONE ,NULL,0x0,"time_stamp", HFILL }},
    { &hf_rrm_oam_time_stamp_t_year, 
    { "year","rrm_oam_time_stamp_t_year",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"year", HFILL }},
    { &hf_rrm_oam_time_stamp_t_month, 
    { "month","rrm_oam_time_stamp_t_month",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"month", HFILL }},
    { &hf_rrm_oam_time_stamp_t_day, 
    { "day","rrm_oam_time_stamp_t_day",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"day", HFILL }},
    { &hf_rrm_oam_time_stamp_t_hour, 
    { "hour","rrm_oam_time_stamp_t_hour",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"hour", HFILL }},
    { &hf_rrm_oam_time_stamp_t_min, 
    { "min","rrm_oam_time_stamp_t_min",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"min", HFILL }},
    { &hf_rrm_oam_time_stamp_t_sec, 
    { "sec","rrm_oam_time_stamp_t_sec",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"sec", HFILL }},
    { &hf_rrm_oam_event_header_t_event_type, 
    { "event_type","rrm_oam_event_header_t_event_type",FT_INT32,BASE_DEC ,NULL,0x0,"event_type", HFILL }},
    { &hf_rrm_oam_event_header_t_event_subtype, 
    { "event_subtype","rrm_oam_event_header_t_event_subtype",FT_INT32,BASE_DEC ,NULL,0x0,"event_subtype", HFILL }},
    { &hf_rrm_oam_event_header_t_event_id, 
    { "event_id","rrm_oam_event_header_t_event_id",FT_UINT16, BASE_HEX_DEC ,NULL,0x0,"event_id", HFILL }},
    { &hf_rrm_oam_event_notification_t_api_data, 
    { "api_data","rrm_oam_event_notification_t.api_data",FT_STRING,BASE_NONE ,NULL,0x0,"api_data", HFILL }},
    
    //RRM_OAM_LOAD_CONFIG_REQ API header field
    { &hf_rrm_oam_load_config_req_t,
    { "rrm_oam_load_config_req_t", "rrm_oam_load_config_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_load_config_req_t", HFILL }},
    { &hf_rrm_oam_load_config_req_t_bitmask,
    { "bitmask", "rrm_oam_load_config_req_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_load_config_req_t_ncl_load_ind_intrvl,
    { "ncl_load_ind_intrvl", "rrm_oam_load_config_req_t.ncl_load_ind_intrvl", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"ncl_load_ind_intrvl", HFILL }},
    { &hf_rrm_oam_load_config_req_t_load_rpt_intrvl,
    { "load_rpt_intrvl", "rrm_oam_load_config_req_t.load_rpt_intrvl", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,"load_rpt_intrvl", HFILL }},
    { &hf_rrm_oam_load_config_req_t_num_enb_cells,
    { "num_enb_cells", "rrm_oam_load_config_req_t.num_enb_cells", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,"num_enb_cells", HFILL }},
    { &hf_rrm_oam_serving_enb_cell_info_t,
    { "serv_enb_cell_info", "rrm_oam_serving_enb_cell_info_t", FT_NONE, BASE_NONE, NULL, 0x0,"serving_enb_cell_info", HFILL }},
    { &hf_rrm_oam_serving_enb_cell_info_t_bitmask,
    { "bitmask", "rrm_oam_serving_enb_cell_info_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_over_load_def_t,
    { "over_load_lvl_act", "rrm_oam_load_def_t", FT_NONE, BASE_NONE, NULL, 0x0,"over_load_lvl_act", HFILL }},
    { &hf_rrm_oam_high_load_def_t,
    { "high_load_lvl_act", "rrm_oam_load_def_t", FT_NONE, BASE_NONE, NULL, 0x0,"high_load_lvl_act", HFILL }},
    { &hf_rrm_oam_mid_load_def_t,
    { "mid_load_lvl_act", "rrm_oam_load_def_t", FT_NONE, BASE_NONE, NULL, 0x0,"mid_load_lvl_act", HFILL }},
    { &hf_rrm_oam_load_def_t_bitmask,
    { "bitmask", "rrm_oam_load_def_t_bit_mask",FT_UINT32, BASE_HEX_DEC , NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_load_def_t_load_perctg,
    { "load_perctg", "rrm_oam_load_def_t_load_perctg", FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"load_perctg", HFILL }},
    { &hf_rrm_oam_load_def_t_action,
    { "action", "rrm_oam_load_def_t_action",FT_INT32,BASE_DEC  , NULL, 0x0,"action", HFILL }},
    { &hf_rrm_oam_load_def_t_num_usr,
    { "num_usr", "rrm_oam_load_def_t_num_usr",FT_UINT8,BASE_HEX_DEC  , NULL, 0x0,"num_usr", HFILL }},
    { &hf_rrm_oam_watermark_t,
    { "q_watermark", "rrm_oam_watermark_t", FT_NONE, BASE_NONE, NULL, 0x0,"q_watermark", HFILL }},
    { &hf_rrm_oam_watermark_t_high_watermark,
    { "high_watermark", "rrm_oam_watermark_t_high_watermark",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"high_watermark", HFILL }},
    { &hf_rrm_oam_watermark_t_low_watermark,
    { "low_watermark", "rrm_oam_watermark_t_low_watermark",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"low_watermark", HFILL }},
    { &hf_rrm_oam_resource_load_info_t,
    { "resrc_spec", "rrm_oam_resource_load_info_t", FT_NONE, BASE_NONE, NULL, 0x0,"resrc_spec", HFILL }},
    { &hf_rrm_oam_resource_load_info_t_bitmask,
    { "bitmask", "rrm_oam_resource_load_info_t.bitmask",FT_UINT32, BASE_HEX_DEC , NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_resource_load_info_t_count,
    { "count", "rrm_oam_resource_load_info_t.count", FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"count", HFILL }},
    { &hf_rrm_oam_resrc_info_t,
    { "resrc_info", "rrm_oam_resrc_info_t", FT_NONE, BASE_NONE, NULL, 0x0,"resrc_info", HFILL }},
    { &hf_rrm_oam_resrc_info_t_bitmask,
    { "bitmask", "rrm_oam_resrc_info_t.bitmask",FT_UINT32, BASE_HEX_DEC , NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_resrc_info_t_resrc_type, 
    { "resrc_type","rrm_oam_resrc_info_t.resrc_type",FT_INT32,BASE_DEC ,NULL,0x0,"resrc_type", HFILL }},
    { &hf_rrm_oam_access_barring_info_t,
    { "ld_ac_bar", "rrm_oam_access_barring_info_t", FT_NONE, BASE_NONE, NULL, 0x0,"ld_ac_bar", HFILL }},
    { &hf_rrm_oam_access_barring_info_t_bitmask,
    { "bitmask", "rrm_oam_access_barring_info_t.bitmask",FT_UINT32, BASE_HEX_DEC , NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_access_class_barring_information_t,
    { "class_barring_info", "rrm_oam_access_class_barring_information_t", FT_NONE, BASE_NONE, NULL, 0x0,"class_barring_info", HFILL }},
    { &hf_rrm_oam_access_class_barring_information_t_ac_barring_factor, 
    { "ac_barring_factor","rrm_oam_access_class_barring_information_t.ac_barring_factor",FT_INT32,BASE_DEC ,NULL,0x0,"ac_barring_factor", HFILL }},
    { &hf_rrm_oam_access_class_barring_information_t_ac_barring_time, 
    { "ac_barring_time","rrm_oam_access_class_barring_information_t.ac_barring_time",FT_INT32,BASE_DEC ,NULL,0x0,"ac_barring_time", HFILL }},
    { &hf_rrm_oam_access_class_barring_information_t_ac_barring_for_special_ac, 
    { "ac_barring_for_special_ac","rrm_oam_access_class_barring_information_t.ac_barring_for_special_ac",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"ac_barring_for_special_ac", HFILL }},
    { &hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t,
    { "ssac_barring_r9", "rrm_oam_access_ssac_barring_for_mmtel_r9_t", FT_NONE, BASE_NONE, NULL, 0x0,"ssac_barring_r9", HFILL }},
    { &hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_bitmask,
    { "bitmask", "rrm_oam_access_ssac_barring_for_mmtel_r9_t.bitmask",FT_UINT32, BASE_HEX_DEC , NULL, 0x0,"bitmask", HFILL }},
    //RRM_OAM_LOAD_CONFIG_RESP API header field 
    { &hf_rrm_oam_load_config_resp_t, 
    { "rrm_oam_load_config_resp_t","rrm_oam_load_config_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_load_config_resp_t", HFILL }},
    { &hf_rrm_oam_load_config_resp_t_response, 
    { "response","rrm_oam_load_config_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_load_config_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_load_config_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    //RRM_OAM_LOAD_REPORT_IND API header field
    { &hf_rrm_oam_load_report_ind_t,
    { "rrm_oam_load_report_ind_t", "rrm_oam_load_report_ind_t", FT_NONE, BASE_NONE, NULL, 0x0, "rrm_oam_load_report_ind_t", HFILL }},
    { &hf_rrm_oam_load_cell_info_t,
    { "rrm_oam_load_cell_info_t", "rrm_oam_load_cell_info_t", FT_NONE, BASE_NONE, NULL, 0x0, "rrm_oam_load_cell_info_t", HFILL }},
    { &hf_rrm_oam_load_cell_info_bitmask,
    { "bitmask", "rrm_oam_load_report_ind_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_hw_load_ind_t,
    { "rrm_oam_hw_load_ind_t", "rrm_oam_cell_load_ind_t.hw_load", FT_NONE, BASE_NONE, NULL, 0x0,"hw_load", HFILL }},
    { &hf_rrm_oam_rs_load_lvl_ul,
    { "rrm_rs_load_lvl_et", "rrm_oam_hw_load_ind_t.ul", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,"rs_load_lvl_ul", HFILL }},
    { &hf_rrm_oam_rs_load_lvl_dl,
    { "rrm_rs_load_lvl_et", "rrm_oam_hw_load_ind_t.dl", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,"rs_load_lvl_dl", HFILL }},
    { &hf_rrm_oam_s1_tnl_load_ind_t,
    { "rrm_oam_s1_tnl_load_ind_t", "rrm_oam_cell_load_ind_t.s1_tnl_load", FT_NONE, BASE_NONE, NULL, 0x0,"s1_tnl_load", HFILL }},
    { &hf_rrm_oam_rrs_load_ind_t,
    { "rrm_oam_rrs_load_ind_t", "rrm_oam_cell_load_ind_t.rrs", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_rrs_load_ind_t", HFILL }},
    { &hf_rrm_oam_dl_gbr_prb_usage,
    { "rrm_oam_dl_gbr_prb_usage", "rrm_rrs_load_ind_t.dl_gbr_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"dl_gbr_prb_usage", HFILL }},
    { &hf_rrm_oam_ul_gbr_prb_usage,
    { "rrm_oam_ul_gbr_prb_usage", "rrm_rrs_load_ind_t.ul_gbr_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"ul_gbr_prb_usage", HFILL }},
    { &hf_rrm_oam_dl_non_gbr_prb_usage,
    { "rrm_oam_dl_non_gbr_prb_usage", "rrm_rrs_load_ind_t.dl_non_gbr_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"dl_non_gbr_prb_usage", HFILL }},
    { &hf_rrm_oam_ul_non_gbr_prb_usage,
    { "rrm_oam_ul_non_gbr_prb_usage", "rrm_rrs_load_ind_t.ul_non_gbr_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"ul_non_gbr_prb_usage", HFILL }},
    { &hf_rrm_oam_dl_total_prb_usage,
    { "rrm_oam_dl_total_prb_usage", "rrm_rrs_load_ind_t.dl_total_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"dl_total_prb_usage", HFILL }},
    { &hf_rrm_oam_ul_total_prb_usage,
    { "rrm_oam_ul_total_prb_usage", "rrm_rrs_load_ind_t.ul_total_prb_usage",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"ul_total_prb_usage", HFILL }},
    { &hf_rrm_oam_comp_avl_cap_grp_t,
    { "rrm_oam_comp_avl_cap_grp_t", "rrm_oam_cell_load_ind_t.comp_avl_cap_grp", FT_NONE, BASE_NONE, NULL, 0x0,"comp_avl_cap_grp", HFILL }},
    { &hf_rrm_oam_comp_avl_cap_dl_t,
    { "rrm_oam_comp_avl_cap_dl_t", "rrm_comp_avl_cap_grp_t.dl_comp_avl_cap", FT_NONE, BASE_NONE, NULL, 0x0,"dl_comp_avl_cap", HFILL }},
    { &hf_rrm_oam_comp_avl_cap_ul_t,
    { "rrm_oam_comp_avl_cap_ul_t", "rrm_comp_avl_cap_grp_t.ul_comp_avl_cap", FT_NONE, BASE_NONE, NULL, 0x0,"ul_comp_avl_cap", HFILL }},
    { &hf_rrm_oam_comp_avl_dl_cell_cap_class_val,
    { "rrm_oam_comp_avl_dl_cell_cap_class_val", "rrm_comp_avl_cap_t.cell_cap_class_val",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"cell_cap_class_val", HFILL }},
    { &hf_rrm_oam_comp_avl_dl_cap_val,
    { "rrm_oam_comp_avl_dl_cap_val", "rrm_comp_avl_cap_t.cap_val",FT_UINT8,BASE_HEX_DEC , NULL, 0x0,"cap_val", HFILL }},
    //RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ API header field
    { &hf_rrm_oam_cell_ecn_capacity_enhance_req_t,
    { "rrm_oam_cell_ecn_capacity_enhance_req_t", "rrm_oam_cell_ecn_capacity_enhance_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_ecn_capacity_enhance_req_t", HFILL }},
    { &hf_rrm_oam_cell_ecn_capacity_enhance_req_t_bitmask,
    { "bitmask", "rrm_oam_cell_ecn_capacity_enhance_req_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_cell_ecn_capacity_enhance_req_t_count,
    { "count", "rrm_oam_cell_ecn_capacity_enhance_req_t.count", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"count", HFILL }},
    { &hf_rrm_ecn_configure_cell_list_t,
    { "rrm_ecn_configure_cell_list_t", "rrm_ecn_configure_cell_list_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_ecn_configure_cell_list_t", HFILL }},
    { &hf_rrm_ecn_configure_cell_list_t_bitmask,
    { "bitmask", "rrm_ecn_configure_cell_list_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_ecn_configure_cell_list_t_num_of_ue,
    { "num_of_ue", "rrm_ecn_configure_cell_list_t.num_of_ue", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"num_of_ue", HFILL }},
    { &hf_rrm_qci_bitrate_info_t,
    { "rrm_qci_bitrate_info_t", "rrm_qci_bitrate_info_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_qci_bitrate_info_t", HFILL }},
    { &hf_rrm_qci_bitrate_info_t_bitmask,
    { "bitmask", "rrm_qci_bitrate_info_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_qci_bitrate_info_t_count,
    { "count", "rrm_qci_bitrate_info_t.count", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"count", HFILL }},
    { &hf_rrm_configure_qci_bitrate_t,
    { "rrm_configure_qci_bitrate_t", "rrm_configure_qci_bitrate_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_configure_qci_bitrate_t", HFILL }},
    { &hf_rrm_configure_qci_bitrate_t_bitmask,
    { "bitmask", "rrm_configure_qci_bitrate_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_configure_qci_bitrate_t_qci,
    { "qci", "rrm_configure_qci_bitrate_t.qci", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"qci", HFILL }},
    { &hf_rrm_bitrate_ul_dl_t,
    { "rrm_bitrate_ul_dl_t", "rrm_bitrate_ul_dl_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_bitrate_ul_dl_t", HFILL }},
    { &hf_rrm_bitrate_ul_dl_t_max_bitrate,
    { "max_bitrate", "rrm_bitrate_ul_dl_t.max_bitrate", FT_UINT64, BASE_HEX_DEC, NULL, 0x0,"max_bitrate", HFILL }},
    { &hf_rrm_bitrate_ul_dl_t_min_bitrate,
    { "min_bitrate", "rrm_bitrate_ul_dl_t.min_bitrate", FT_UINT64, BASE_HEX_DEC, NULL, 0x0,"min_bitrate", HFILL }},
    //RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP API header field 
    { &hf_rrm_oam_cell_ecn_capacity_enhance_resp_t, 
    { "rrm_oam_cell_ecn_capacity_enhance_resp_t","rrm_oam_cell_ecn_capacity_enhance_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_cell_ecn_capacity_enhance_resp_t", HFILL }},
    { &hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_response, 
    { "response","rrm_oam_cell_ecn_capacity_enhance_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_cell_ecn_capacity_enhance_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    //RRM_OAM_CONFIG_KPI_REQ API header field
    { &hf_rrm_oam_config_kpi_req_t,
    { "rrm_oam_config_kpi_req_t", "rrm_oam_config_kpi_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_config_kpi_req_t", HFILL }},
    { &hf_rrm_oam_config_kpi_req_t_bitmask,
    { "bitmask", "rrm_oam_config_kpi_req_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_config_kpi_req_t_duration,
    { "duration", "rrm_oam_config_kpi_req_t.duration", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,"duration", HFILL }},
    { &hf_rrm_oam_config_kpi_req_t_periodic_reporting,
    { "periodic_reporting", "rrm_oam_config_kpi_req_t.periodic_reporting", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"periodic_reporting", HFILL }},
    { &hf_rrm_oam_kpi_t,
    { "kpi_to_report", "rrm_oam_kpi_t", FT_NONE, BASE_NONE, NULL, 0x0,"kpi_to_report", HFILL }},
    { &hf_rrm_oam_kpi_t_bitmap, 
    { "bitmap","rrm_oam_kpi_t.bitmap",FT_STRING,BASE_NONE ,NULL,0x0,"bitmap", HFILL }},
    //RRM_OAM_CONFIG_KPI_RESP API header field 
    { &hf_rrm_oam_config_kpi_resp_t, 
    { "rrm_oam_config_kpi_resp_t","rrm_oam_config_kpi_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_config_kpi_resp_t", HFILL }},
    { &hf_rrm_oam_config_kpi_resp_t_bitmask,
    { "bitmask", "rrm_oam_config_kpi_resp_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_config_kpi_resp_t_response, 
    { "response","rrm_oam_config_kpi_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_config_kpi_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_config_kpi_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    //RRM_OAM_GET_KPI_REQ API header field
    { &hf_rrm_oam_get_kpi_req_t,
    { "rrm_oam_get_kpi_req_t", "rrm_oam_get_kpi_req_t", FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_get_kpi_req_t", HFILL }},
    { &hf_rrm_oam_get_kpi_req_t_bitmask,
    { "bitmask", "rrm_oam_get_kpi_req_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_get_kpi_req_t_reset,
    { "reset", "rrm_oam_get_kpi_req_t.reset", FT_UINT8,BASE_HEX_DEC, NULL, 0x0,"reset", HFILL }},
    //RRM_OAM_GET_KPI_RESP API header field 
    { &hf_rrm_oam_get_kpi_resp_t, 
    { "rrm_oam_config_kpi_resp_t","rrm_oam_config_kpi_resp_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_config_kpi_resp_t", HFILL }},
    { &hf_rrm_oam_get_kpi_resp_t_bitmask,
    { "bitmask", "rrm_oam_get_kpi_resp_t.bitmask", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,"bitmask", HFILL }},
    { &hf_rrm_oam_get_kpi_resp_t_response, 
    { "response","rrm_oam_config_kpi_resp_t.response",FT_INT32,BASE_DEC ,NULL,0x0,"response", HFILL }},
    { &hf_rrm_oam_get_kpi_resp_t_fail_cause, 
    { "fail_cause","rrm_oam_get_kpi_resp_t.fail_cause",FT_INT32,BASE_DEC ,NULL,0x0,"fail_cause", HFILL }},
    { &hf_rrm_oam_kpi_data_t, 
    { "rrm_oam_kpi_data_t","rrm_oam_kpi_data_t",FT_NONE, BASE_NONE, NULL, 0x0,"rrm_oam_kpi_data_t", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_admitted_csg_user, 
    { "num_of_admitted_csg_user","rrm_oam_kpi_data_t.num_of_admitted_csg_user",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_admitted_csg_user", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_admitted_non_csg_user, 
    { "num_of_admitted_non_csg_user","rrm_oam_kpi_data_t.num_of_admitted_non_csg_user",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_admitted_non_csg_user", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_ue_admission_success, 
    { "num_of_ue_admission_success","rrm_oam_kpi_data_t.num_of_ue_admission_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_ue_admission_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_ue_admission_fail, 
    { "num_of_ue_admission_fail","rrm_oam_kpi_data_t.num_of_ue_admission_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_ue_admission_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_setup_success, 
    { "num_of_erb_setup_success","rrm_oam_kpi_data_t.num_of_erb_setup_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_setup_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_setup_fail, 
    { "num_of_erb_setup_fail","rrm_oam_kpi_data_t.num_of_erb_setup_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_setup_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_modify_success, 
    { "num_of_erb_modify_success","rrm_oam_kpi_data_t.num_of_erb_modify_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_modify_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_modify_fail, 
    { "num_of_erb_modify_fail","rrm_oam_kpi_data_t.num_of_erb_modify_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_modify_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_release_success, 
    { "num_of_erb_release_success","rrm_oam_kpi_data_t.num_of_erb_release_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_release_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_erb_release_fail, 
    { "num_of_erb_release_fail","rrm_oam_kpi_data_t.num_of_erb_release_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_erb_release_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_total_dl_allocated_gbr_prb, 
    { "total_dl_allocated_gbr_prb","rrm_oam_kpi_data_t.total_dl_allocated_gbr_prb",FT_INT32,BASE_DEC ,NULL,0x0,"total_dl_allocated_gbr_prb", HFILL }},
    { &hf_rrm_oam_kpi_data_t_total_ul_allocated_gbr_prb, 
    { "total_ul_allocated_gbr_prb","rrm_oam_kpi_data_t.total_ul_allocated_gbr_prb",FT_INT32,BASE_DEC ,NULL,0x0,"total_ul_allocated_gbr_prb", HFILL }},
    { &hf_rrm_oam_kpi_data_t_dl_allocated_ngbr_prb, 
    { "dl_allocated_ngbr_prb","rrm_oam_kpi_data_t.dl_allocated_ngbr_prb",FT_INT32,BASE_DEC ,NULL,0x0,"dl_allocated_ngbr_prb", HFILL }},
    { &hf_rrm_oam_kpi_data_t_ul_allocated_ngbr_prb, 
    { "ul_allocated_ngbr_prb","rrm_oam_kpi_data_t.ul_allocated_ngbr_prb",FT_INT32,BASE_DEC ,NULL,0x0,"ul_allocated_ngbr_prb", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_geran_ho_success, 
    { "num_of_geran_ho_success","rrm_oam_kpi_data_t.num_of_geran_ho_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_geran_ho_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_geran_ho_fail, 
    { "num_of_geran_ho_fail","rrm_oam_kpi_data_t.num_of_geran_ho_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_geran_ho_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_utran_ho_success, 
    { "num_of_utran_ho_success","rrm_oam_kpi_data_t.num_of_utran_ho_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_utran_ho_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_utran_ho_fail, 
    { "num_of_utran_ho_fail","rrm_oam_kpi_data_t.num_of_utran_ho_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_utran_ho_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_eutran_ho_attempt, 
    { "num_of_eutran_ho_attempt","rrm_oam_kpi_data_t.num_of_eutran_ho_attempt",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_eutran_ho_attempt", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_eutran_ho_fail, 
    { "num_of_eutran_ho_fail","rrm_oam_kpi_data_t.num_of_eutran_ho_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_eutran_ho_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_geran_hi_success, 
    { "num_of_geran_hi_success","rrm_oam_kpi_data_t.num_of_geran_hi_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_geran_hi_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_geran_hi_fail, 
    { "num_of_geran_hi_fail","rrm_oam_kpi_data_t.num_of_geran_hi_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_geran_hi_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_utran_hi_success, 
    { "num_of_utran_hi_success","rrm_oam_kpi_data_t.num_of_utran_hi_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_utran_hi_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_utran_hi_fail, 
    { "num_of_utran_hi_fail","rrm_oam_kpi_data_t.num_of_utran_hi_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_utran_hi_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_eutran_hi_success, 
    { "num_of_eutran_hi_success","rrm_oam_kpi_data_t.num_of_eutran_hi_success",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_eutran_hi_success", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_eutran_hi_fail, 
    { "num_of_eutran_hi_fail","rrm_oam_kpi_data_t.num_of_eutran_hi_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_eutran_hi_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_csg_usr, 
    { "num_of_enb_init_ho_csg_usr","rrm_oam_kpi_data_t.num_of_enb_init_ho_csg_usr",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_enb_init_ho_csg_usr", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_non_csg_usr, 
    { "num_of_enb_init_ho_non_csg_usr","rrm_oam_kpi_data_t.num_of_enb_init_ho_non_csg_usr",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_enb_init_ho_non_csg_usr", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_enb_init_ue_release, 
    { "num_of_enb_init_ue_release","rrm_oam_kpi_data_t.num_of_enb_init_ue_release",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_enb_init_ue_release", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_pucch_res_alloc_attempts, 
    { "num_pucch_res_alloc_attempts","rrm_oam_kpi_data_t.num_pucch_res_alloc_attempts",FT_INT32,BASE_DEC ,NULL,0x0,"num_pucch_res_alloc_attempts", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_sr_res_alloc_fail, 
    { "num_of_sr_res_alloc_fail","rrm_oam_kpi_data_t.num_of_sr_res_alloc_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_sr_res_alloc_fail", HFILL }},
    { &hf_rrm_oam_kpi_data_t_num_of_sr_cqi_alloc_fail, 
    { "num_of_sr_cqi_alloc_fail","rrm_oam_kpi_data_t.num_of_sr_cqi_alloc_fail",FT_INT32,BASE_DEC ,NULL,0x0,"num_of_sr_cqi_alloc_fail", HFILL }},
    };

/****************************************************************************
 * Function Name  :proto_reg_handoff_iprRrmOamDissector
 * Inputs         :None
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function creates the dissector and registers a routine
 *                 to be called to do the actual dissecting.
 ****************************************************************************/

void proto_reg_handoff_iprRrmOamDissector(void)
{
    static gboolean initialized=FALSE;

    if (!initialized)
    {
        iprRrmOamDissector_handle = create_dissector_handle(dissect_rrmOamipr, proto_iprRrmOamDissector);
        dissector_add("udp.port", global_port0, iprRrmOamDissector_handle);
    }
}

/****************************************************************************
 * Function Name  :proto_register_iprRrmOamDissector
 * Inputs         :None
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function registers the given protocol.
 ****************************************************************************/

void proto_register_iprRrmOamDissector (void)
{
    if (proto_iprRrmOamDissector == -1) 
    {
        proto_iprRrmOamDissector = proto_register_protocol("rrm_oam_iprDissector", "RRMOAMDISSECTOR", "ipr_rrm_oam_dissector");

        proto_register_field_array (proto_iprRrmOamDissector, hf, array_length(hf));

        proto_register_subtree_array (ett, array_length (ett));

        register_dissector("ipr_rrm_oam_dissector", dissect_rrmOamipr, proto_iprRrmOamDissector);
    } 
}

/****************************************************************************
 * Function Name  :dissect_rrmOamipr 
 * Inputs         :tvbuff_t: *tvb, 
packet_info: *pinfo, 
proto_tree: *tree 
 * Outputs        : 
 * Returns        :None 
 * Variables      : 
 * Description    :This function performs the decoding of the fields  
 for LTE (dissects the packets presented  
 to it on Well Defined Port).C Data", "lte.macdata", FT_BYTE                   S, BASE_HEX,

 ***************************************************************************/

void dissect_rrmOamipr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{   
    guint32 offset=0;
    guint16 typeoftag=0;
    guint16 bufferLen=0;
    guint16 src = 0;
    guint16 dst = 0;
    proto_item *rrm_item=NULL;
    proto_tree *rrm_tree=NULL;

    src = tvb_get_ntohs(tvb, offset+2);
    dst = tvb_get_ntohs(tvb, offset+4);

    if(( RRM_MODULE_ID == src ) && ( RRM_OAM_MODULE_ID == dst ))
    {

        if(check_col(pinfo->cinfo,COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo,COL_PROTOCOL, "RRM -> OAM");
        }

        typeoftag = tvb_get_ntohs(tvb, offset+6);
        if(check_col(pinfo->cinfo,COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                    val_to_str(typeoftag, tagType_rrm_oam, "Unknown Packet"));
        }

        rrm_item=proto_tree_add_item(tree,hf_rrm_oam_header,tvb, 0, -1, FALSE);
        rrm_tree=proto_item_add_subtree(rrm_item, ett_rrm_oam);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_transactionId,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_sourceModId,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_destModId,tvb,offset,2,FALSE);
        offset+=2;
        typeoftag = tvb_get_ntohs(tvb,offset);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_TypeOfAPI,tvb,offset,2,FALSE);
        offset+=2;
        bufferLen = tvb_get_ntohs(tvb,offset);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_MsgBufferlen,tvb,offset,2,FALSE);
        offset+=2;
        bufferLen = tvb_get_ntohs(tvb,offset);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_MsgBufferlen,tvb,offset,2,FALSE);
        offset+=2;


        if (tree)
        {
            /* we are being asked for details */
            switch( typeoftag  )
            {
                case RRM_OAM_INIT_IND:
                    {
                        offset += (guint32)dissect_RRM_OAM_INIT_IND_rrm_oam_init_ind_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_INIT_CONFIG_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_INIT_CONFIG_RESP_rrm_oam_init_config_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_SET_LOG_LEVEL_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_SET_LOG_LEVEL_RESP_rrm_oam_set_log_level_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_LOG_ENABLE_DISABLE_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_LOG_ENABLE_DISABLE_RESP_rrm_oam_log_enable_disable_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_SHUTDOWN_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_SHUTDOWN_RESP_rrm_oam_shutdown_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
               /* case RRM_OAM_READY_FOR_SHUTDOWN_IND:
                    {
                        offset += (guint32)dissect_RRM_OAM_READY_FOR_SHUTDOWN_IND_rrm_oam_ready_for_shutdown_ind_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }*/
                case RRM_OAM_RESUME_SERVICE_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_RESUME_SERVICE_RESP_rrm_oam_resume_service_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_START_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_START_RESP_rrm_oam_cell_start_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_STOP_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_STOP_RESP_rrm_oam_cell_stop_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_CONFIG_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_CONFIG_RESP_rrm_oam_cell_config_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_RECONFIG_RESP:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_RECONFIG_RESP_rrm_oam_cell_reconfig_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_RAC_ENABLE_DISABLE_RESP:
                            /*This  case will call function dissect_rrm_oam_rac_enable_disable_resp_t to dissect API RRM_OAM_RAC_ENABLE_DISABLE_RESP */
                    {
                        offset += (guint32)dissect_rrm_oam_rac_enable_disable_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_DELETE_RESP:
                            /*This  case will call function dissect_rrm_oam_cell_delete_resp_t to dissect API RRM_OAM_CELL_DELETE_RESP */
                    {
                        offset += (guint32)dissect_rrm_oam_cell_delete_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP:
                     /*This  case will call function dissect_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t to dissect API RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP */
                    {
                        offset += (guint32)dissect_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_BLOCK_CELL_RESP:       
                            /*This  case will call function dissect_rrm_oam_block_cell_resp_t to dissect API RRM_OAM_BLOCK_CELL_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_block_cell_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                   
                case RRM_OAM_READY_FOR_CELL_BLOCK_IND:  
                            /*This case will call function dissect_rrm_oam_ready_for_cell_block_ind_t to dissect API RRM_OAM_READY_FOR_CELL_BLOCK_IND*/
                    {
                        offset += (guint32)dissect_rrm_oam_ready_for_cell_block_ind_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_GET_VER_ID_RESP:  
                            /*This case will call function dissect_rrm_oam_ready_for_cell_block_ind_t to dissect API RRM_OAM_READY_FOR_CELL_BLOCK_IND*/
                    {
                        offset += (guint32)dissect_rrm_oam_get_ver_id_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }

                case RRM_OAM_CELL_UPDATE_RESP:       
                            /*This  case will call function dissect_rrm_oam_cell_update_resp_t to dissect API RRM_OAM_CELL_UPDATE_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_cell_update_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                   
                case RRM_OAM_EVENT_NOTIFICATION:       
                            /*This  case will call function dissect_rrm_oam_event_notification_t to dissect API RRM_OAM_EVENT_NOTIFICATION*/
                    {
                        offset += (guint32)dissect_rrm_oam_event_notification_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                                                                                                            
                case RRM_OAM_LOAD_CONFIG_RESP:       
                            /*This  case will call function dissect_rrm_oam_load_config_resp_t to dissect API RRM_OAM_LOAD_CONFIG_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_load_config_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                case RRM_OAM_LOAD_REPORT_IND:
		    {
			offset += (guint32)dissect_rrm_oam_load_report_ind_t(tvb,pinfo,tree,offset,-1,&rrm_item);
                        break;
                    }
                   
                case RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP:       
                            /*This  case will call function dissect_rrm_oam_cell_ecn_capacity_enhance_resp_t to dissect API RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_cell_ecn_capacity_enhance_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                   
                case RRM_OAM_CONFIG_KPI_RESP:       
                            /*This  case will call function dissect_rrm_oam_config_kpi_resp_t to dissect API RRM_OAM_CONFIG_KPI_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_config_kpi_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                   
                case RRM_OAM_GET_KPI_RESP:       
                            /*This  case will call function dissect_rrm_oam_get_kpi_resp_t to dissect API RRM_OAM_GET_KPI_RESP*/
                    {
                        offset += (guint32)dissect_rrm_oam_get_kpi_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }             
                   
                
              /*  case RRM_OAM_PROC_SUPERVISION_RESP:
                    {
                        offset += (guint32)dissect_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    } */
                default: 
                    { 
                        break;
                    }
            }

        }
        return;
    }
    if(( RRM_OAM_MODULE_ID == src ) && ( RRM_MODULE_ID == dst ))
    {

        if(check_col(pinfo->cinfo,COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo,COL_PROTOCOL, "OAM -> RRM");
        }

        typeoftag = tvb_get_ntohs(tvb, offset+6);
        if(check_col(pinfo->cinfo,COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                    val_to_str(typeoftag, tagType_rrm_oam, "Unknown Packet"));
        }

        rrm_item=proto_tree_add_item(tree,hf_rrm_oam_header,tvb, 0, -1, FALSE);
        rrm_tree=proto_item_add_subtree(rrm_item, ett_rrm_oam);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_transactionId,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_sourceModId,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_destModId,tvb,offset,2,FALSE);
        offset+=2;
        typeoftag = tvb_get_ntohs(tvb,offset);
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_TypeOfAPI,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_MsgBufferlen,tvb,offset,2,FALSE);
        offset+=2;
        proto_tree_add_item(rrm_tree,hf_rrm_oam_header_MsgBufferlen,tvb,offset,2,FALSE);
        offset+=2;

        if (tree)
        {
            /* we are being asked for details */
            switch( typeoftag  )
            {
                case RRM_OAM_INIT_CONFIG_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_INIT_CONFIG_REQ_rrm_oam_init_config_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_SET_LOG_LEVEL_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_SET_LOG_LEVEL_REQ_rrm_oam_set_log_level_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_LOG_ENABLE_DISABLE_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_LOG_ENABLE_DISABLE_REQ_rrm_oam_log_enable_disable_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_SHUTDOWN_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_SHUTDOWN_REQ_rrm_oam_shutdown_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_RESUME_SERVICE_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_RESUME_SERVICE_REQ_rrm_oam_resume_service_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_START_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_START_REQ_rrm_oam_cell_start_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_STOP_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_STOP_REQ_rrm_oam_cell_stop_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_CONFIG_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_CONFIG_REQ_rrm_oam_cell_config_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_DELETE_REQ:
                               /*This case will call function dissect_rrm_oam_cell_delete_req_t to dissect API RRM_OAM_CELL_DELETE_REQ */  
                    {
                        offset += (guint32)dissect_rrm_oam_cell_delete_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_RAC_ENABLE_DISABLE_REQ:
                               /*This case will call function dissect_rrm_oam_rac_enable_disable_req_t to dissect API RRM_OAM_RAC_ENABLE_DISABLE_REQ */
                    {
                        offset += (guint32)dissect_rrm_oam_rac_enable_disable_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CELL_RECONFIG_REQ:
                    {
                        offset += (guint32)dissect_RRM_OAM_CELL_RECONFIG_REQ_rrm_oam_cell_reconfig_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_CELL_CONTEXT_PRINT_REQ:
                    {
                        offset += (guint32)dissect_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
                case RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ:
                                /*This case will call function dissect_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t to dissect API RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ */
                    {
                        offset += (guint32)dissect_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
		       case RRM_OAM_UE_RELEASE_REQ:
		            {
          		        offset += (guint32)dissect_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
			            break;
		            }
               case RRM_OAM_BLOCK_CELL_REQ: 
                                /*This case will call function dissect_rrm_oam_block_cell_req_t to dissect API RRM_OAM_BLOCK_CELL_REQ */
                    {
                        offset += (guint32)dissect_rrm_oam_block_cell_req_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
             
               case RRM_OAM_UNBLOCK_CELL_CMD:
                                /*This case will call function dissect_rrm_oam_unblock_cell_cmd_t to dissect API RRM_OAM_UNBLOCK_CELL_CMD */
                    {
                        offset += (guint32)dissect_rrm_oam_unblock_cell_cmd_t(tvb, pinfo, tree, offset,-1, &rrm_item);
                        break;
                    }
		/*+ Tirtha adding +*/
		case RRM_OAM_GET_VER_ID_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_get_version_id_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }
                /*- Tirtha adding -*/
                                                                                                           

		case RRM_OAM_CELL_UPDATE_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_cell_update_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }

		case RRM_OAM_LOAD_CONFIG_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_load_config_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }
               
		case RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_cell_ecn_capacity_enhance_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }
               
		case RRM_OAM_CONFIG_KPI_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_config_kpi_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }
               
		case RRM_OAM_GET_KPI_REQ:
		    {
			offset += (guint32)dissect_rrm_oam_get_kpi_req_t(tvb,pinfo,tree, offset, -1, &rrm_item);
		    	break;
                    }
               
               
               default: 
                    { 
                        break;
                    }
            }

        }
        return;
    }
}
