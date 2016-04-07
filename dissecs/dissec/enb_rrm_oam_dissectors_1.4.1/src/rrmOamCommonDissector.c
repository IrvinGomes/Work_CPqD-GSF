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

#include "rrm_ext_api_hdr.h"
#include "ueTags.h"
#include "rrmOamDissector.h"
#include "rrm_oam_intf.h"
#include "rrm_defines.h"
#include "rrm_oam_defines.h"
#include "rrm_api_defines.h"

int g_load_def = 0;

guint64 oam_get_64 (tvbuff_t *tvb, const gint offset)
{
    if (IS_LITTLE_ENDIAN_OAM)
        return tvb_get_letoh64 (tvb, offset);
    else
        return tvb_get_ntoh64 (tvb, offset);
}
guint32 oam_get_32 (tvbuff_t *tvb, const gint offset)
{
    if (IS_LITTLE_ENDIAN_OAM)
        return tvb_get_letohl (tvb, offset);
    else
        return tvb_get_ntohl (tvb, offset);
}
guint32 oam_get_24 (tvbuff_t *tvb, const gint offset)
{
    if (IS_LITTLE_ENDIAN_OAM)
        return tvb_get_letoh24 (tvb, offset);
    else
        return tvb_get_ntoh24 (tvb, offset);
}
guint16 oam_get_16 (tvbuff_t *tvb, const gint offset)
{
    if (IS_LITTLE_ENDIAN_OAM)
        return tvb_get_letohs (tvb, offset);
    else
        return tvb_get_ntohs (tvb, offset);
}

extern gint ett_rrm_oam;
extern gint ett_rrm_oam_payload;
extern int rrm_oam_header_count;
extern gint ett_rrm_oam_header;

//RRM_OAM_INIT_IND
extern gint ett_RRM_OAM_INIT_IND ;
extern gint ett_RRM_OAM_INIT_IND_payload ;
extern int rrm_oam_init_ind_t_count ;
extern gint ett_rrm_oam_init_ind_t ;


//Cell Config Req
extern gint ett_RRM_OAM_CELL_CONFIG_REQ ;
extern gint ett_RRM_OAM_CELL_CONFIG_REQ_payload ;
extern int rrm_oam_cell_config_req_t_count ;
extern gint ett_rrm_oam_cell_config_req_t ;
extern gint ett_rrm_oam_cell_config_req_t_global_cell_info ;
extern gint ett_rrm_oam_cell_config_req_t_ran_info ;
extern gint ett_rrm_oam_cell_config_req_t_epc_info ;
extern gint ett_rrm_oam_cell_config_req_t_operator_info ;
extern gint ett_rrm_oam_cell_config_req_t_access_mgmt_params ;
extern int rrm_oam_cell_info_t_count ;
extern gint ett_rrm_oam_cell_info_t ;
extern gint ett_rrm_oam_cell_info_t_eutran_global_cell_id ;
extern gint ett_rrm_oam_cell_info_t_cell_access_restriction_params ;
extern int rrm_oam_eutran_global_cell_id_t_count ;
extern gint ett_rrm_oam_eutran_global_cell_id_t ;
extern gint ett_rrm_oam_eutran_global_cell_id_t_primary_plmn_id ;
extern int rrm_oam_cell_plmn_info_t_count ;
extern gint ett_myrrm_oam_cell_plmn_info_t ;
extern int rrm_oam_cell_access_restriction_params_t_count ;
extern gint ett_rrm_oam_cell_access_restriction_params_t ;
extern int rrm_oam_ran_t_count ;
extern gint ett_rrm_oam_ran_t ;
extern gint ett_rrm_oam_ran_t_physical_layer_params ;
extern gint ett_rrm_oam_ran_t_mac_layer_params ;
extern gint ett_rrm_oam_ran_t_rlc_layer_params ;
extern gint ett_rrm_oam_ran_t_mobility_params ;
extern gint ett_rrm_oam_ran_t_rrc_timers_and_constants ;
extern gint ett_rrm_oam_ran_t_rf_params ;
extern gint ett_rrm_oam_ran_t_s1ap_params ;
extern gint ett_rrm_oam_ran_t_ncl_params ;
extern gint ett_rrm_oam_ran_t_connected_mode_mobility_params ;
extern int rrm_oam_physical_layer_params_t_count ;
extern gint ett_rrm_oam_physical_layer_params_t ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_srs ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_prach ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pucch ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_pusch ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_prs ;
extern gint ett_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure ;
extern gint ett_rrm_oam_physical_layer_params_t_addl_physical_layer_params ;
extern gint ett_rrm_oam_addl_phy_params_t ;
extern gint ett_rrm_oam_addl_phy_params_t_addl_pucch_parameters ;
extern gint ett_rrm_oam_addl_phy_params_t_additional_pusch_parameters ;
extern gint ett_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params ;
extern gint ett_rrm_oam_addl_pucch_config_t ;
extern gint ett_rrm_oam_addl_pusch_config_t ;
extern gint ett_rrm_oam_addl_ul_reference_signal_params_t ;
extern gint ett_rrm_oam_tdd_frame_structure_t;
extern int rrm_oam_pdsch_t_count ;
extern gint ett_rrm_oam_pdsch_t ;
extern int rrm_oam_srs_t_count ;
extern gint ett_rrm_oam_srs_t ;
extern int rrm_oam_prach_t_count ;
extern gint ett_rrm_oam_prach_t ;
extern int rrm_oam_pucch_t_count ;
extern gint ett_rrm_oam_pucch_t ;
extern int rrm_oam_pusch_t_count ;
extern gint ett_rrm_oam_pusch_t ;
extern int rrm_oam_ul_reference_signal_t_count ;
extern gint ett_rrm_oam_ul_reference_signal_t ;
extern int rrm_oam_uplink_power_control_t_count ;
extern gint ett_rrm_oam_uplink_power_control_t ;
extern int rrm_oam_prs_t_count ;
extern gint ett_rrm_oam_prs_t ;
extern int rrm_oam_mac_layer_params_t_count ;
extern gint ett_rrm_oam_mac_layer_params_t ;
extern gint ett_rrm_oam_mac_layer_params_t_mac_layer_param_rach ;
extern gint ett_rrm_oam_mac_layer_params_t_mac_layer_param_drx ;
extern int rrm_oam_rach_t_count ;
extern gint ett_rrm_oam_rach_t ;
extern gint ett_rrm_oam_rach_t_preamble_info ;
extern int rrm_oam_preamble_info_t_count ;
extern gint ett_rrm_oam_preamble_info_t ;
extern gint ett_rrm_oam_preamble_info_t_ra_preamble_groupA_info ;
extern int rrm_oam_preamble_groupA_info_t_count ;
extern gint ett_rrm_oam_preamble_groupA_info_t ;
extern int rrm_oam_drx_t_count ;
extern gint ett_rrm_oam_drx_t ;
extern gint ett_rrm_oam_drx_t_drx_config ;
extern int rrm_oam_drx_config_t_count ;
extern gint ett_rrm_oam_drx_config_t ;
extern gint ett_rrm_oam_drx_config_t_short_drx_cycle ;
extern int rrm_oam_short_drx_cycle_config_t_count ;
extern gint ett_rrm_oam_short_drx_cycle_config_t ;
extern int rrm_oam_rlc_layer_params_t_count ;
extern gint ett_rrm_oam_rlc_layer_params_t ;
extern gint ett_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb ;
extern int rrm_oam_srb_t_count ;
extern gint ett_rrm_oam_srb_t ;
extern gint ett_rrm_oam_srb_t_srb_params ;
extern int rrm_oam_srb_info_t_count ;
extern gint ett_rrm_oam_srb_info_t ;
extern int rrm_oam_mobility_params_t_count ;
extern gint ett_rrm_oam_mobility_params_t ;
extern gint ett_rrm_oam_mobility_params_t_idle_mode_mobility_params ;
extern int rrm_oam_idle_mode_mobility_params_t_count ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9 ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9 ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920 ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000 ;
extern gint ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t ;
extern int rrm_oam_common_params_t_count ;
extern gint ett_rrm_oam_common_params_t ;
extern gint ett_rrm_oam_common_params_t_speed_state_params ;
extern int rrm_oam_speed_state_params_t_count ;
extern gint ett_rrm_oam_speed_state_params_t ;
extern int rrm_oam_intra_freq_params_t_count ;
extern gint ett_rrm_oam_intra_freq_params_t ;
extern gint ett_rrm_oam_intra_freq_params_t_speed_scale_factors ;
extern int rrm_oam_speed_scale_factors_t_count ;
extern gint ett_rrm_oam_speed_scale_factors_t ;
extern int rrm_oam_inter_frequency_params_list_t_count ;
extern gint ett_rrm_oam_inter_frequency_params_list_t ;
extern gint ett_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params ;
extern int rrm_oam_inter_freq_params_t_count ;
extern gint ett_rrm_oam_inter_freq_params_t ;
extern gint ett_rrm_oam_inter_freq_params_t_speed_scale_factors ;
extern gint ett_rrm_oam_inter_freq_params_t_threshx_q_r9 ;
extern int rrm_oam_thresholdx_q_r9_t_count ;
extern gint ett_rrm_oam_thresholdx_q_r9_t ;
extern int rrm_oam_rrc_timers_and_constants_t_count ;
extern gint ett_rrm_oam_rrc_timers_and_constants_t ;
extern gint ett_rrm_oam_rrc_timers_and_constants_t_rrc_timers ;
extern gint ett_rrm_oam_rrc_timers_and_constants_t_rrc_constants ;
extern int rrm_oam_rrc_timers_t_count ;
extern gint ett_rrm_oam_rrc_timers_t ;
extern int rrm_oam_rrc_constants_t_count ;
extern gint ett_rrm_oam_rrc_constants_t ;
extern int rrm_oam_rf_params_t_count ;
extern gint ett_rrm_oam_rf_params_t ;
extern gint ett_rrm_oam_rf_params_t_rf_configurations ;
extern int rrm_oam_rf_configurations_t_count ;
extern gint ett_rrm_oam_rf_configurations_t ;
extern int rrm_oam_s1ap_params_t_count ;
extern gint ett_rrm_oam_s1ap_params_t ;
extern int rrm_oam_ncl_params_t_count ;
extern gint ett_rrm_oam_ncl_params_t ;
extern gint ett_rrm_oam_ncl_params_t_lte_ncl ;
extern gint ett_rrm_oam_ncl_params_t_inter_rat_ncl ;
extern gint ett_rrm_oam_inter_rat_ncl_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_payload ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_utran_freq_cells ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_geran_freq_cells ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t ;
extern gint ett_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_payload ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params ;
extern gint ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t ;
extern gint ett_rrm_utran_cell_id_t ;
extern int rrm_oam_lte_ncl_t_count ;
extern gint ett_rrm_oam_lte_ncl_t ;
extern gint ett_rrm_oam_lte_ncl_t_intra_freq_cells ;
extern gint ett_rrm_oam_lte_ncl_t_inter_freq_cells ;
extern int rrm_oam_intra_freq_cells_t_count ;
extern gint ett_rrm_oam_intra_freq_cells_t ;
extern gint ett_rrm_oam_intra_freq_cells_t_cell_id ;
extern int rrm_oam_inter_freq_cells_t_count ;
extern gint ett_rrm_oam_inter_freq_cells_t ;
extern gint ett_rrm_oam_inter_freq_cells_t_cell_id ;
extern int rrm_oam_epc_t_count ;
extern gint ett_rrm_oam_epc_t ;
extern gint ett_rrm_oam_epc_t_epc_params ;
extern int rrm_oam_epc_params_t_count ;
extern gint ett_rrm_oam_epc_params_t ;
extern gint ett_rrm_oam_epc_params_t_general_epc_params ;
extern gint ett_rrm_oam_epc_params_t_qos_config_params ;
extern int rrm_oam_general_epc_params_t_count ;
extern gint ett_rrm_oam_general_epc_params_t ;
extern gint ett_rrm_oam_general_epc_params_t_plmn_list ;
extern int rrm_oam_plmn_access_info_t_count ;
extern gint ett_rrm_oam_plmn_access_info_t ;
extern gint ett_rrm_oam_plmn_access_info_t_plmn_info ;
extern int rrm_oam_qos_config_params_t_count ;
extern gint ett_rrm_oam_qos_config_params_t ;
extern gint ett_rrm_oam_qos_config_params_t_rohc_params ;
extern gint ett_rrm_oam_qos_config_params_t_sn_field_len ;
extern gint ett_rrm_oam_qos_config_params_t_sps_data ;
extern gint ett_rrm_oam_qos_config_params_t_addl_rlc_param ;
extern gint ett_rrm_oam_qos_config_params_t_addl_mac_param ;
extern gint ett_rrm_oam_pdcp_rohc_params_t ;
extern gint ett_rrm_oam_pdcp_rohc_params_t_rohc_pofiles ;
extern gint ett_rrm_oam_rohc_pofiles_t ;
extern gint ett_rrm_oam_sn_field_len_t ;
extern gint ett_rrm_oam_sps_config_data_t ;
extern gint ett_rrm_oam_sps_config_data_t_sps_config_dl ;
extern gint ett_rrm_oam_sps_config_data_t_sps_config_ul ;
extern gint ett_rrm_oam_sps_config_dl_t ;
extern gint ett_rrm_oam_sps_config_ul_t ;
extern gint ett_rrm_oam_addl_rlc_params_t ;
extern gint ett_rrm_oam_addl_mac_params_t ;
extern gint ett_rrm_oam_addl_mac_params_t_phr_config ;
extern gint ett_rrm_oam_addl_mac_params_t_bsr_config ;
extern gint ett_rrm_oam_phr_config_t ;
extern gint ett_rrm_oam_bsr_config_t ;
extern int rrm_oam_operator_info_t_count ;
extern gint ett_rrm_oam_operator_info_t ;
extern gint ett_rrm_oam_operator_info_t_rrm_mac_config ;
extern gint ett_rrm_oam_operator_info_t_phich_config ;
extern gint ett_rrm_oam_operator_info_t_sib_1_info ;
extern gint ett_rrm_oam_operator_info_t_sib_2_info ;
extern gint ett_rrm_oam_operator_info_t_sib_3_info ;
extern gint ett_rrm_oam_operator_info_t_sib_4_info ;
extern gint ett_rrm_oam_operator_info_t_admission_control_info ;
extern gint ett_rrm_oam_operator_info_t ;
extern gint ett_rrm_oam_operator_info_t_additional_packet_scheduling_params ;
extern gint ett_rrm_oam_operator_info_t_additional_cell_params ;
extern gint ett_rrm_oam_operator_info_t_load_params ;
extern gint ett_rrm_oam_operator_info_t_mimo_mode_params ;
extern gint ett_rrm_oam_operator_info_t_ho_configuration ;
extern gint ett_rrm_oam_operator_info_t_measurement_configuration ;
extern gint ett_rrm_oam_operator_info_t_rrm_eutran_access_point_pos ;
extern gint ett_rrm_oam_adl_pkt_scheduling_params_t ;
extern gint ett_rrm_oam_adl_cell_params_t ;
extern gint ett_rrm_oam_load_params_t ;
extern gint ett_rrm_oam_mimo_mode_params_t ;
extern gint ett_rrm_oam_ho_config_params_t ;
extern gint ett_rrm_oam_ho_config_params_t_target_cell_selection_params ;
extern gint ett_rrm_oam_ho_config_params_t_ho_algo_params ;
extern gint ett_rrm_oam_ho_config_params_t_ho_retry_params ;
extern gint ett_rrm_oam_target_cell_selection_params_t ;
extern gint ett_rrm_oam_ho_algo_params_t ;
extern gint ett_rrm_oam_ho_retry_params_t ;
extern gint ett_rrm_oam_meas_config_t ;
extern gint ett_rrm_oam_meas_config_t_meas_gap_config ;
extern gint ett_rrm_oam_meas_config_t_csfb_tgt_selection ;
extern gint ett_rrm_oam_meas_gap_config_t ;
extern gint ett_rrm_csfb_tgt_selection_t ;
extern gint ett_rrm_oam_eutran_access_point_pos_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t ;
extern gint ett_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_ul_power_mask ;
extern gint ett_rrm_oam_dynamic_icic_info_t_rntp_report_config_info ;
extern gint ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map ;
extern gint ett_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern gint ett_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power ;
extern gint ett_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti ;
extern gint ett_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti ;
extern gint ett_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps ;
extern gint ett_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params ;
extern gint ett_rrm_oam_dynamic_icic_info_t_atb_config ;
extern gint ett_rrm_oam_pdcch_aggregation_power_offset_t ;
extern gint ett_rrm_oam_aggregation_power_offset_t ;
extern gint ett_rrm_oam_aggregation_power_offset_info_t;
extern int rrm_oam_resource_partition_info_t_count ;
extern gint ett_rrm_oam_resource_partition_info_t ;
extern gint ett_rrm_oam_resource_partition_info_t_cell_center_region ;
extern gint ett_rrm_oam_resource_partition_info_t_cell_edge_region ;
extern int rrm_oam_ul_power_mask_t_count ;
extern gint ett_rrm_oam_ul_power_mask_t ;
extern int rrm_oam_rntp_report_config_info_t_count ;
extern gint ett_rrm_oam_rntp_report_config_info_t ;
extern int rrm_oam_cqi_to_phich_power_t_count ;
extern gint ett_rrm_oam_cqi_to_phich_power_t ;
extern int rrm_oam_alpha_based_pathloss_target_sinr_map_t_count ;
extern gint ett_rrm_oam_alpha_based_pathloss_target_sinr_map_t;
extern int rrm_oam_path_loss_to_target_sinr_map_t_count ;
extern gint ett_rrm_oam_path_loss_to_target_sinr_map_t ;
extern ett_rrm_oam_path_loss_to_target_sinr_map_info_t_count ;
extern gint ett_rrm_oam_path_loss_to_target_sinr_map_info_t ;
extern gint ett_rrm_oam_resource_partition_t ;


extern int rrm_oam_rrmc_mac_config_t_count ;
extern gint ett_rrm_oam_rrmc_mac_config_t ;
extern gint ett_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch ;
extern int rrm_oam_mac_enable_frequency_selective_scheduling_t_count ;
extern gint ett_rrm_oam_mac_enable_frequency_selective_scheduling_t ;
extern int rrm_oam_phy_phich_configuration_t_count ;
extern gint ett_rrm_oam_phy_phich_configuration_t ;
extern int rrm_oam_sib_type_1_info_t_count ;
extern gint ett_rrm_oam_sib_type_1_info_t ;
extern gint ett_rrm_oam_sib_type_1_info_t_cell_selection_info ;
extern gint ett_rrm_oam_sib_type_1_info_t_scheduling_info ;
extern gint ett_rrm_oam_scheduling_info_t ;
extern gint ett_rrm_oam_scheduling_info_t_sib_mapping_info ;
extern gint ett_rrm_oam_sib_mapping_info_t ;
extern int rrm_oam_cell_selection_info_v920_t_count ;
extern gint ett_rrm_oam_cell_selection_info_v920_t ;

extern int rrm_oam_sib_type_2_info_t_count ;
extern gint ett_rrm_oam_sib_type_2_info_t ;
extern gint ett_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib ;
extern gint ett_rrm_oam_sib_type_2_info_t_rrm_freq_info ;

extern int rrm_oam_radio_resource_config_common_sib_t_count ;
extern gint ett_rrm_oam_radio_resource_config_common_sib_t ;

extern gint ett_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config ;
extern gint ett_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config ;

extern int rrm_oam_bcch_config_t_count ;
extern gint ett_rrm_oam_bcch_config_t ;
extern int rrm_oam_pcch_config_t_count ;
extern gint ett_rrm_oam_pcch_config_t ;

extern int rrm_oam_freq_info_t_count ;
extern gint ett_rrm_oam_freq_info_t ;
extern int rrm_oam_sib_type_3_info_t_count ;
extern gint ett_rrm_oam_sib_type_3_info_t ;
extern gint ett_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info ;
extern gint ett_rrm_oam_sib_type_3_info_t_s_intra_search ;
extern gint ett_rrm_oam_sib_type_3_info_t_s_non_intra_search ;
extern int rm_oam_intra_freq_cell_reselection_info_t_count ;
extern gint ett_rrm_oam_intra_freq_cell_reselection_info_t ;
extern int rrm_oam_s_intra_search_v920_t_count ;
extern gint ett_rrm_oam_s_intra_search_v920_t ;
extern int rrm_oam_s_non_intra_search_v920_t_count ;
extern gint ett_rrm_oam_s_non_intra_search_v920_t ;
extern int rrm_oam_sib_type_4_info_t_count ;
extern gint ett_rrm_oam_sib_type_4_info_t ;
extern gint ett_rrm_oam_sib_type_4_info_t_csg_id_range ;
extern int rrm_oam_csg_cell_id_range_t_count ;
extern gint ett_rrm_oam_csg_cell_id_range_t ;
extern int rrm_oam_admission_control_info_t_count ;
extern gint ett_rrm_oam_admission_control_info_t ;
extern gint ett_rrm_oam_admission_control_info_t_available_gbr_limit ;
extern gint ett_rrm_oam_admission_control_info_t_spid_table ;
extern gint ett_available_gbr_limit_t ;
extern gint ett_rrm_oam_spid_table_t ;
extern gint ett_rrm_oam_spid_table_t_spid_config ;
extern gint ett_rrm_oam_spid_configuration_t ;
extern gint ett_rrm_power_control_params ;
extern gint ett_rrm_power_control_params_payload ;
extern gint ett_rrm_power_control_params_rrm_power_control_params ;
extern gint ett_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable ;
extern gint ett_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range ;
extern gint ett_rrm_power_control_params_rrm_oam_power_control_enable_t ;
extern gint ett_rrm_power_control_params_rrm_oam_tpc_rnti_range_t ;
extern gint ett_rrm_oam_sps_crnti_range_t ;
extern int rrm_oam_access_mgmt_params_t_count ;
extern gint ett_rrm_oam_access_mgmt_params_t ;

//RRM OAM SHUTDOWN REQ
extern gint ett_RRM_OAM_SHUTDOWN_REQ ;
extern gint ett_RRM_OAM_SHUTDOWN_REQ_payload ;
extern int rrm_oam_shutdown_req_t_count ;
extern gint ett_rrm_oam_shutdown_req_t ;

//RRM SHUTDOWN RESP
extern gint ett_RRM_OAM_SHUTDOWN_RESP ;
extern gint ett_RRM_OAM_SHUTDOWN_RESP_payload ;
extern int rrm_oam_shutdown_resp_t_count ;
extern gint ett_rrm_oam_shutdown_resp_t ;

//SET LOG LEVEL REQ
extern gint ett_RRM_OAM_SET_LOG_LEVEL_REQ ;
extern gint ett_RRM_OAM_SET_LOG_LEVEL_REQ_payload ;
extern int rrm_oam_set_log_level_req_t_count ;
extern gint ett_rrm_oam_set_log_level_req_t ;

//SET LOG LEVEL RESP
extern gint ett_RRM_OAM_SET_LOG_LEVEL_RESP ;
extern gint ett_RRM_OAM_SET_LOG_LEVEL_RESP_payload ;
extern int rrm_oam_set_log_level_resp_t_count ;
extern gint ett_rrm_oam_set_log_level_resp_t ;

// resume service req
extern gint ett_RRM_OAM_RESUME_SERVICE_REQ ;
extern gint ett_RRM_OAM_RESUME_SERVICE_REQ_payload ;
extern int rrm_oam_resume_service_req_t_count ;
extern gint ett_rrm_oam_resume_service_req_t ;

// resume service resp
extern gint ett_RRM_OAM_RESUME_SERVICE_RESP ;
extern gint ett_RRM_OAM_RESUME_SERVICE_RESP_payload ;
extern int rrm_oam_resume_service_resp_t_count ;
extern gint ett_rrm_oam_resume_service_resp_t ;

//ready for shutdown ind
extern gint ett_RRM_OAM_READY_FOR_SHUTDOWN_IND ;
extern gint ett_RRM_OAM_READY_FOR_SHUTDOWN_IND_payload ;
extern int rrm_oam_ready_for_shutdown_ind_t_count ;
extern gint ett_rrm_oam_ready_for_shutdown_ind_t ;

//rrm oam rac enable disable req
extern gint ett_RRM_OAM_RAC_ENABLE_DISABLE_REQ ;
extern gint ett_RRM_OAM_RAC_ENABLE_DISABLE_REQ_payload ;
extern int rrm_oam_rac_enable_disable_req_t_count ;
extern gint ett_rrm_oam_rac_enable_disable_req_t ;
extern gint ett_rrm_oam_rac_enable_disable_req_t_global_cell_id ;

//rrm oam rac enable disable resp
extern gint ett_RRM_OAM_RAC_ENABLE_DISABLE_RESP ;
extern gint ett_RRM_OAM_RAC_ENABLE_DISABLE_RESP_payload ;
extern int rrm_oam_rac_enable_disable_resp_t_count ;
extern gint ett_rrm_oam_rac_enable_disable_resp_t ;
extern gint ett_rrm_oam_rac_enable_disable_resp_t_global_cell_id ;

//rrm oam log enable disable req
extern gint ett_RRM_OAM_LOG_ENABLE_DISABLE_REQ ;
extern gint ett_RRM_OAM_LOG_ENABLE_DISABLE_REQ_payload ;
extern int rrm_oam_log_enable_disable_req_t_count ;
extern gint ett_rrm_oam_log_enable_disable_req_t ;
extern gint ett_rrm_oam_log_enable_disable_req_t_log_config ;
extern int rrm_oam_log_config_t_count ;
extern gint ett_rrm_oam_log_config_t ;

//rrm oam log enable disable resp
extern gint ett_RRM_OAM_LOG_ENABLE_DISABLE_RESP ;
extern gint ett_RRM_OAM_LOG_ENABLE_DISABLE_RESP_payload ;
extern int rrm_oam_log_enable_disable_resp_t_count ;
extern gint ett_rrm_oam_log_enable_disable_resp_t ;


//RRM OAM INIT CONFIG REQ
extern gint ett_RRM_OAM_INIT_CONFIG_REQ ;
extern gint ett_RRM_OAM_INIT_CONFIG_REQ_payload ;
extern int rrm_oam_init_config_req_t_count ;
extern gint ett_rrm_oam_init_config_req_t ;
extern gint ett_rrm_oam_init_config_req_t_init_module_config ;
extern int rrm_oam_module_init_config_t_count ;
extern gint ett_rrm_oam_module_init_config_t ;
extern gint ett_rrm_oam_module_init_config_t_log_config ;

//RRM OAM INIT CONFIG RESP
extern gint ett_RRM_OAM_INIT_CONFIG_RESP ;
extern gint ett_RRM_OAM_INIT_CONFIG_RESP_payload ;
extern int rrm_oam_init_config_resp_t_count ;
extern gint ett_rrm_oam_init_config_resp_t ;

//Cell Start Req
extern gint ett_RRM_OAM_CELL_START_REQ ;
extern gint ett_RRM_OAM_CELL_START_REQ_payload ;
extern int rrm_oam_cell_start_req_t_count ;
extern gint ett_rrm_oam_cell_start_req_t ;
extern gint ett_rrm_oam_cell_start_req_t_global_cell_id ;

//Cell Start Resp
extern gint ett_RRM_OAM_CELL_START_RESP ;
extern gint ett_RRM_OAM_CELL_START_RESP_payload ;
extern int rrm_oam_cell_start_resp_t_count ;
extern gint ett_rrm_oam_cell_start_resp_t ;
extern gint ett_rrm_oam_cell_start_resp_t_global_cell_id ;

// CELL STOP REQ
extern gint ett_RRM_OAM_CELL_STOP_REQ ;
extern gint ett_RRM_OAM_CELL_STOP_REQ_payload ;
extern int rrm_oam_cell_stop_req_t_count ;
extern gint ett_rrm_oam_cell_stop_req_t ;
extern gint ett_rrm_oam_cell_stop_req_t_global_cell_id ;


// CELL STOP RESP
extern gint ett_RRM_OAM_CELL_STOP_RESP ;
extern gint ett_RRM_OAM_CELL_STOP_RESP_payload ;
extern int rrm_oam_cell_stop_resp_t_count ;
extern gint ett_rrm_oam_cell_stop_resp_t ;
extern gint ett_rrm_oam_cell_stop_resp_t_global_cell_id ;


//CELL DELETE REQ
extern gint ett_RRM_OAM_CELL_DELETE_REQ ;
extern gint ett_RRM_OAM_CELL_DELETE_REQ_payload ;
extern int rrm_oam_cell_delete_req_t_count ;
extern gint ett_rrm_oam_cell_delete_req_t ;
extern gint ett_rrm_oam_cell_delete_req_t_global_cell_id ;

// CELL DELETE RESP
extern gint ett_RRM_OAM_CELL_DELETE_RESP ;
extern gint ett_RRM_OAM_CELL_DELETE_RESP_payload ;
extern int rrm_oam_cell_delete_resp_t_count ;
extern gint ett_rrm_oam_cell_delete_resp_t ;
extern gint ett_rrm_oam_cell_delete_resp_t_global_cell_id ;

//CELL CONFIG RESP
extern gint ett_RRM_OAM_CELL_CONFIG_RESP;
extern gint ett_RRM_OAM_CELL_CONFIG_RESP_payload;
extern int rrm_oam_cell_config_resp_t_count;
extern gint ett_rrm_oam_cell_config_resp_t;
extern gint ett_rrm_oam_cell_config_resp_t_global_cell_id;

//CELL RECONFIG REQ
extern gint ett_RRM_OAM_CELL_RECONFIG_REQ;
extern gint ett_RRM_OAM_CELL_RECONFIG_REQ_payload;
extern int rrm_oam_cell_reconfig_req_t_count;
extern gint ett_rrm_oam_cell_reconfig_req_t;
extern gint ett_rrm_oam_cell_reconfig_req_t_global_cell_id;
extern gint ett_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params;
extern gint ett_rrm_oam_cell_reconfig_req_t_ran_info;
extern gint ett_rrm_oam_cell_reconfig_req_t_epc_info;
extern gint ett_rrm_oam_cell_reconfig_req_t_operator_info;
extern gint ett_rrm_oam_cell_reconfig_req_t_access_mgmt_params;

//Cell reconfig resp
extern gint ett_RRM_OAM_CELL_RECONFIG_RESP;
extern gint ett_RRM_OAM_CELL_RECONFIG_RESP_payload;
extern int rrm_oam_cell_reconfig_resp_t_count;
extern gint ett_rrm_oam_cell_reconfig_resp_t;
extern gint ett_rrm_oam_cell_reconfig_resp_t_global_cell_id;

//CELL CONTEXT PRINT REQ
extern gint ett_rrm_oam_cell_context_print_req;
extern gint ett_rrm_oam_cell_context_print_req_payload;
extern int rrm_oam_cell_context_print_req_count;
extern gint ett_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req;

// CARRRIER FREQ DL TX PARAMS REQ
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t;
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t_payload;
extern int rrm_oam_carrier_freq_dl_tx_params_req_t_count;
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t;

//CARRRIER FREQ DL TX PARAMS RESP
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t;
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_payload;
extern int rrm_oam_carrier_freq_dl_tx_params_resp_t_count;
extern gint ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t;

//RRM OAM UE RELEASE REQ
extern gint ett_rrm_oam_ue_release_req_t;
extern gint ett_rrm_oam_ue_release_req_t_payload;
extern int rrm_oam_ue_release_req_t_count;
extern gint ett_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t;

//RRM_OAM_BLOCK_CELL_REQ
extern gint ett_RRM_OAM_BLOCK_CELL_REQ;
extern gint ett_RRM_OAM_BLOCK_CELL_REQ_payload;
extern int rrm_oam_block_cell_req_t_count;
extern gint ett_rrm_oam_block_cell_req_t;
extern gint ett_rrm_oam_block_cell_req_t_global_cell_id;
extern gint ett_rrm_oam_eutran_global_cell_id_t;
extern gint ett_rrm_oam_cell_plmn_info_t;

//RRM_OAM_BLOCK_CELL_RESP
extern gint ett_RRM_OAM_BLOCK_CELL_RESP;
extern gint ett_RRM_OAM_BLOCK_CELL_RESP_payload;
extern int rrm_oam_block_cell_resp_t_count;
extern gint ett_rrm_oam_block_cell_resp_t;
extern gint ett_rrm_oam_block_cell_resp_t_global_cell_id;


//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ
extern gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ;
extern gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_REQ_payload;

//RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP
extern gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP;
extern gint ett_RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER_RESP_payload;

//RRM_OAM_READY_FOR_CELL_BLOCK_IND
extern gint ett_RRM_OAM_READY_FOR_CELL_BLOCK_IND;
extern gint ett_RRM_OAM_READY_FOR_CELL_BLOCK_IND_payload;
extern int rrm_oam_ready_for_cell_block_ind_t_count;
extern gint ett_rrm_oam_ready_for_cell_block_ind_t;
extern gint ett_rrm_oam_ready_for_cell_block_ind_t_global_cell_id;

//RRM_OAM_UNBLOCK_CELL_CMD
extern gint ett_RRM_OAM_UNBLOCK_CELL_CMD;
extern gint ett_RRM_OAM_UNBLOCK_CELL_CMD_payload;
extern int rrm_oam_unblock_cell_cmd_t_count;
extern gint ett_rrm_oam_unblock_cell_cmd_t;
extern gint ett_rrm_oam_unblock_cell_cmd_t_global_cell_id;

// PROC SUPERVISION RESP
extern gint ett_rrm_oam_proc_supervision_resp_t;
extern gint ett_rrm_oam_proc_supervision_resp_t_payload;
extern int rrm_oam_proc_supervision_resp_t_count;
extern gint ett_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t;

//RRM_OAM_GET_VER_ID_RESP

extern gint ett_RRM_OAM_GET_VER_ID_RESP ;
extern gint ett_ett_RRM_OAM_GET_VER_ID_RESP_payload ;
extern int rrm_oam_get_ver_id_resp_t_count ;
extern gint ett_rrm_oam_get_ver_id_resp_t ;

//RRM_OAM_CELL_UPDATE_REQ
extern gint ett_RRM_OAM_CELL_UPDATE_REQ ;
extern gint ett_RRM_OAM_CELL_UPDATE_REQ_payload ;
extern int rrm_oam_cell_update_req_t_count;
extern gint ett_rrm_oam_cell_update_req_t;
extern gint ett_rrm_oam_cell_update_req_t_global_cell_id;
extern gint ett_rrm_oam_eutran_global_cell_id_t;
extern gint ett_rrm_oam_cell_plmn_info_t;

//RRM_OAM_UPDATED_PLMN_INFO
extern gint ett_RRM_OAM_UPDATED_PLMN_INFO ;
extern gint ett_RRM_OAM_UPDATED_PLMN_INFO_payload;
extern int rrm_oam_updated_plmn_info_t_count;
extern gint ett_rrm_oam_updated_plmn_info_t;

//RRM_OAM_CELL_UPDATE_RESP
extern gint ett_RRM_OAM_CELL_UPDATE_RESP;
extern gint ett_RRM_OAM_CELL_UPDATE_RESP_payload;
extern int rrm_oam_cell_update_resp_t_count;
extern gint ett_rrm_oam_cell_update_resp_t;
extern gint ett_rrm_oam_cell_update_resp_t_global_cell_id;

//RRM_OAM_EVENT_NOTIFICATION
extern gint ett_RRM_OAM_EVENT_NOTIFICATION ;
extern gint ett_RRM_OAM_EVENT_NOTIFICATION_payload ;
extern int rrm_oam_event_notification_t_count ;
extern gint ett_rrm_oam_event_notification_t ;
extern gint ett_rrm_oam_event_notification_t_msg_header ;

//RRM_OAM_LOAD_CONFIG_RESP
extern gint ett_RRM_OAM_LOAD_CONFIG_RESP ;
extern gint ett_RRM_OAM_LOAD_CONFIG_RESP_payload ;
extern int rrm_oam_load_config_resp_t_count ;
extern gint ett_rrm_oam_load_config_resp_t ;

//RRM_OAM_EVENT_HEADER
extern gint ett_RRM_OAM_EVENT_HEADER ;
extern gint ett_RRM_OAM_EVENT_HEADER_payload ;
extern int rrm_oam_event_header_t_count ;
extern gint ett_rrm_oam_event_header_t ;
extern gint ett_rrm_oam_event_header_t_time_stamp ;

//RRM_OAM_TIME_STAMP
extern gint ett_RRM_OAM_TIME_STAMP ;
extern gint ett_RRM_OAM_TIME_STAMP_payload ;
extern int rrm_oam_time_stamp_t_count ;
extern gint ett_rrm_oam_time_stamp_t ;

//RRM_OAM_LOAD_CONFIG_REQ
extern gint ett_RRM_OAM_LOAD_CONFIG_REQ ;
extern gint ett_RRM_OAM_LOAD_CONFIG_REQ_payload ;
extern int rrm_oam_load_config_req_t_count ;
extern gint ett_rrm_oam_load_config_req_t ;
extern gint ett_rrm_oam_load_config_req_t_serv_enb_cell_info ;
extern int rrm_oam_serving_enb_cell_info_count;

//RRM_OAM_LOAD_REPORT_IND
extern gint ett_RRM_OAM_LOAD_REPORT_IND;
extern gint ett_RRM_OAM_LOAD_REPORT_IND_payload;
extern int rrm_oam_load_report_ind_t_count;
extern gint ett_rrm_oam_load_report_ind_t;
extern gint ett_rrm_oam_load_cell_info_t;
extern gint ett_rrm_oam_hw_load_ind_t;
extern gint ett_rrm_oam_s1_tnl_load_t;
extern gint ett_rrm_oam_rrs_load_ind_t;
extern gint ett_rrm_oam_comp_avl_grp_t;
extern gint ett_rrm_oam_comp_avl_dl_t;


//RRM_OAM_SERVING_ENB_CELL_INFO
extern gint ett_RRM_OAM_SERVING_ENB_CELL_INFO ;
extern gint ett_RRM_OAM_SERVING_ENB_CELL_INFO_payload ;
extern int rrm_oam_serving_enb_cell_info_t_count ;
extern gint ett_rrm_oam_serving_enb_cell_info_t ;
extern gint ett_rrm_oam_serving_enb_cell_info_t_global_cell_id ;
extern gint ett_rrm_oam_serving_enb_cell_info_t_over_load_lvl_act ;
extern gint ett_rrm_oam_serving_enb_cell_info_t_high_load_lvl_act ;
extern gint ett_rrm_oam_serving_enb_cell_info_t_mid_load_lvl_act ;
extern gint ett_rrm_oam_serving_enb_cell_info_t_resrc_spec ;

//RRM_OAM_LOAD_DEF
extern gint ett_RRM_OAM_LOAD_DEF ;
extern gint ett_RRM_OAM_LOAD_DEF_payload ;
extern int rrm_oam_load_def_t_count ;
extern gint ett_rrm_oam_over_load_def_t ;
extern gint ett_rrm_oam_high_load_def_t ;
extern gint ett_rrm_oam_mid_load_def_t ;
extern gint ett_rrm_oam_load_def_t_q_watermark;
extern gint ett_rrm_oam_load_def_t_ld_ac_bar ;

//RRM_OAM_WATERMARK
extern gint ett_RRM_OAM_WATERMARK ;
extern gint ett_RRM_OAM_WATERMARK_payload ;
extern int rrm_oam_watermark_t_count ;
extern gint ett_rrm_oam_watermark_t ;

//RRM_OAM_RESOURCE_LOAD_INFO
extern gint ett_RRM_OAM_RESOURCE_LOAD_INFO ;
extern gint ett_RRM_OAM_RESOURCE_LOAD_INFO_payload ;
extern int rrm_oam_resource_load_info_t_count ;
extern gint ett_rrm_oam_resource_load_info_t ;
extern gint ett_rrm_oam_resource_load_info_t_resrc_info;

//RRM_OAM_RESRC_INFO
extern gint ett_RRM_OAM_RESRC_INFO ;
extern gint ett_RRM_OAM_RESRC_INFO_payload ;
extern int rrm_oam_resrc_info_t_count ;
extern guint ett_rrm_oam_resrc_info_t ;
extern guint ett_rrm_oam_resrc_info_t_overload ;
extern guint ett_rrm_oam_resrc_info_t_highload ;
extern guint ett_rrm_oam_resrc_info_t_midload ;

//RRM_OAM_ACCESS_BARRING_INFO
extern gint ett_RRM_OAM_ACCESS_BARRING_INFO ;
extern gint ett_RRM_OAM_ACCESS_BARRING_INFO_payload ;
extern int rrm_oam_access_barring_info_t_count ;
extern guint ett_rrm_oam_access_barring_info_t ;
extern guint ett_rrm_oam_access_barring_info_t_class_barring_info ;
extern guint ett_rrm_oam_access_barring_info_t_ssac_barring_r9 ;

//RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION
extern gint ett_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION ;
extern gint ett_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION_payload ;
extern int rrm_oam_access_class_barring_information_t_count ;
extern gint ett_rrm_oam_access_class_barring_information_t ;

//RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9
extern gint ett_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9;
extern gint ett_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9_payload ;
extern int rrm_oam_access_ssac_barring_for_mmtel_r9_t_count ;
extern guint ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t ;
extern guint ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t_class_barring_info ;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ
extern gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ ;
extern gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ_payload ;
extern int rrm_oam_cell_ecn_capacity_enhance_req_t_count ;
extern guint ett_rrm_oam_cell_ecn_capacity_enhance_req_t ;
extern guint ett_rrm_oam_cell_ecn_capacity_enhance_req_t_ecn_cells ;

//RRM_ECN_CONFIGURE_CELL_LIST
extern gint ett_RRM_ECN_CONFIGURE_CELL_LIST ;
extern gint ett_RRM_ECN_CONFIGURE_CELL_LIST_payload ;
extern int rrm_ecn_configure_cell_list_t_count ;
extern guint ett_rrm_ecn_configure_cell_list_t ;
extern guint ett_rrm_ecn_configure_cell_list_t_global_cell_id ;
extern guint ett_rrm_ecn_configure_cell_list_t_bitrate ;

//RRM_QCI_BITRATE_INFO
extern gint ett_RRM_QCI_BITRATE_INFO ;
extern gint ett_RRM_QCI_BITRATE_INFO_payload ;
extern int rrm_qci_bitrate_info_t_count ;
extern guint ett_rrm_qci_bitrate_info_t ;
extern guint ett_rrm_qci_bitrate_info_t_bitrate_for_qci ;

//RRM_CONFIGURE_QCI_BITRATE
extern gint ett_RRM_CONFIGURE_QCI_BITRATE ;
extern gint ett_RRM_CONFIGURE_QCI_BITRATE_payload ;
extern int rrm_configure_qci_bitrate_t_count ;
extern guint ett_rrm_configure_qci_bitrate_t ;
extern guint ett_rrm_configure_qci_bitrate_t_ul_bitrate ;
extern guint ett_rrm_configure_qci_bitrate_t_dl_bitrate ;

//RRM_BITRATE_UL_DL
extern gint ett_RRM_BITRATE_UL_DL ;
extern gint ett_RRM_BITRATE_UL_DL_payload ;
extern int rrm_bitrate_ul_dl_t_count ;
extern guint ett_rrm_bitrate_ul_dl_t ;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP
extern gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP ;
extern gint ett_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP_payload ;
extern int rrm_oam_cell_ecn_capacity_enhance_resp_t_count ;
extern gint ett_rrm_oam_cell_ecn_capacity_enhance_resp_t ;

//RRM_OAM_CONFIG_KPI_REQ
extern gint ett_RRM_OAM_CONFIG_KPI_REQ ;
extern gint ett_RRM_OAM_CONFIG_KPI_REQ_payload ;
extern int rrm_oam_config_kpi_req_t_count ;
extern guint ett_rrm_oam_config_kpi_req_t ;
extern guint ett_rrm_oam_config_kpi_req_t_kpi_to_report ;
    
//RRM_OAM_KPI
extern gint ett_RRM_OAM_KPI ;
extern gint ett_RRM_OAM_KPI_payload ;
extern int rrm_oam_kpi_t_count ;
extern guint ett_rrm_oam_kpi_t ;

//RRM_OAM_CONFIG_KPI_RESP
extern gint ett_RRM_OAM_CONFIG_KPI_RESP ;              
extern gint ett_RRM_OAM_CONFIG_KPI_RESP_payload ;
extern int rrm_oam_config_kpi_resp_t_count ;
extern gint ett_rrm_oam_config_kpi_resp_t ;
extern gint ett_rrm_oam_config_kpi_resp_t_global_cell_id ;

//RRM_OAM_GET_KPI_REQ
extern gint ett_RRM_OAM_GET_KPI_REQ ;
extern gint ett_RRM_OAM_GET_KPI_REQ_payload ;
extern int rrm_oam_get_kpi_req_t_count ;
extern guint ett_rrm_oam_get_kpi_req_t ;
extern guint ett_rrm_oam_get_kpi_req_t_kpi_to_report ;

//RRM_OAM_GET_KPI_RESP
extern gint ett_RRM_OAM_GET_KPI_RESP ;
extern gint ett_RRM_OAM_GET_KPI_RESP_payload ;
extern int rrm_oam_get_kpi_resp_t_count ;
extern gint ett_rrm_oam_get_kpi_resp_t ;
extern gint ett_rrm_oam_get_kpi_resp_t_global_cell_id ;
extern gint ett_rrm_oam_get_kpi_resp_t_resp_t_kpi_data ;

//RRM_OAM_KPI_DATA
extern gint ett_RRM_OAM_KPI_DATA ;
extern gint ett_RRM_OAM_KPI_DATA_payload ;                  
extern int rrm_oam_kpi_data_t_count ;
extern guint ett_rrm_oam_kpi_data_t ;
extern guint ett_rrm_oam_kpi_data_t_kpi_to_report ;

    


//hfinfo

//CELL RECONFIG RESP
extern int hf_RRM_OAM_CELL_RECONFIG_RESP_unparsed_data;
extern int hf_rrm_oam_cell_reconfig_resp_t;
extern int hf_rrm_oam_cell_reconfig_resp_t_global_cell_id;
extern int hf_rrm_oam_cell_reconfig_resp_t_response;
extern int hf_rrm_oam_cell_reconfig_resp_t_fail_cause;

//CELL RECONFIG REQ
extern int hf_RRM_OAM_CELL_RECONFIG_REQ_unparsed_data;
extern int hf_rrm_oam_cell_reconfig_req_t;
extern int hf_rrm_oam_cell_reconfig_req_t_bitmask;
extern int hf_rrm_oam_cell_reconfig_req_t_global_cell_id;
extern int hf_rrm_oam_cell_reconfig_req_t_cell_access_restriction_params;
extern int hf_rrm_oam_cell_reconfig_req_t_ran_info;
extern int hf_rrm_oam_cell_reconfig_req_t_epc_info;
extern int hf_rrm_oam_cell_reconfig_req_t_operator_info;
extern int hf_rrm_oam_cell_reconfig_req_t_access_mgmt_params;


//CEll CONFIG RESP
extern int hf_RRM_OAM_CELL_CONFIG_RESP_unparsed_data;
extern int hf_rrm_oam_cell_config_resp_t;
extern int hf_rrm_oam_cell_config_resp_t_global_cell_id;
extern int hf_rrm_oam_cell_config_resp_t_response;
extern int hf_rrm_oam_cell_config_resp_t_fail_cause;

// CELL DELETE RESP
extern int hf_RRM_OAM_CELL_DELETE_RESP_unparsed_data ;
extern int hf_rrm_oam_cell_delete_resp_t ;
extern int hf_rrm_oam_cell_delete_resp_t_global_cell_id ;
extern int hf_rrm_oam_cell_delete_resp_t_response ;
extern int hf_rrm_oam_cell_delete_resp_t_fail_cause ;

//CELL DELETE REQ
extern int hf_RRM_OAM_CELL_DELETE_REQ_unparsed_data ;
extern int hf_rrm_oam_cell_delete_req_t ;
extern int hf_rrm_oam_cell_delete_req_t_global_cell_id ;

// CELL STOP RESP
extern int hf_RRM_OAM_CELL_STOP_RESP_unparsed_data ;
extern int hf_rrm_oam_cell_stop_resp_t ;
extern int hf_rrm_oam_cell_stop_resp_t_global_cell_id ;
extern int hf_rrm_oam_cell_stop_resp_t_response ;
extern int hf_rrm_oam_cell_stop_resp_t_fail_cause ;


//CELL STOP REQ
extern int hf_RRM_OAM_CELL_STOP_REQ_unparsed_data ;
extern int hf_rrm_oam_cell_stop_req_t ;
extern int hf_rrm_oam_cell_stop_req_t_global_cell_id ;


//Cell Start Resp
extern int hf_RRM_OAM_CELL_START_RESP_unparsed_data ;
extern int hf_rrm_oam_cell_start_resp_t ;
extern int hf_rrm_oam_cell_start_resp_t_global_cell_id ;
extern int hf_rrm_oam_cell_start_resp_t_response ;
extern int hf_rrm_oam_cell_start_resp_t_fail_cause ;


//Cell Start Req
extern int hf_RRM_OAM_CELL_START_REQ_unparsed_data ;
extern int hf_rrm_oam_cell_start_req_t ;
extern int hf_rrm_oam_cell_start_req_t_global_cell_id ;

//RRM OAM INIT CONFIG RESP
extern int hf_RRM_OAM_INIT_CONFIG_RESP_unparsed_data ;
extern int hf_rrm_oam_init_config_resp_t ;
extern int hf_rrm_oam_init_config_resp_t_response ;
extern int hf_rrm_oam_init_config_resp_t_fail_cause ;

//RRM OAM INIT CONFIG REQ
extern int hf_RRM_OAM_INIT_CONFIG_REQ_unparsed_data ;
extern int hf_rrm_oam_init_config_req_t ;
extern int hf_rrm_oam_init_config_req_t_bitmask ;
extern int hf_rrm_oam_init_config_req_t_init_module_config ;
extern int hf_rrm_oam_module_init_config_t ;
extern int hf_rrm_oam_module_init_config_t_module_id ;
extern int hf_rrm_oam_module_init_config_t_log_config ;

//rrm oam log enable disable resp
extern int hf_RRM_OAM_LOG_ENABLE_DISABLE_RESP_unparsed_data ;
extern int hf_rrm_oam_log_enable_disable_resp_t ;
extern int hf_rrm_oam_log_enable_disable_resp_t_response ;
extern int hf_rrm_oam_log_enable_disable_resp_t_fail_cause ;

//rrm oam log enable disable req
extern int hf_RRM_OAM_LOG_ENABLE_DISABLE_REQ_unparsed_data ;
extern int hf_rrm_oam_log_enable_disable_req_t ;
extern int hf_rrm_oam_log_enable_disable_req_t_module_id ;
extern int hf_rrm_oam_log_enable_disable_req_t_log_config ;
extern int hf_rrm_oam_log_config_t ;
extern int hf_rrm_oam_log_config_t_log_on_off ;
extern int hf_rrm_oam_log_config_t_log_level ;


//rrm oam rac enable disable resp
extern int hf_RRM_OAM_RAC_ENABLE_DISABLE_RESP_unparsed_data ;
extern int hf_rrm_oam_rac_enable_disable_resp_t ;
extern int hf_rrm_oam_rac_enable_disable_resp_t_bitmask ;
extern int hf_rrm_oam_rac_enable_disable_resp_t_global_cell_id ;
extern int hf_rrm_oam_rac_enable_disable_resp_t_response ;
extern int hf_rrm_oam_rac_enable_disable_resp_t_fail_cause ;

//rrm oam rac enable disable req
extern int hf_RRM_OAM_RAC_ENABLE_DISABLE_REQ_unparsed_data ;
extern int hf_rrm_oam_rac_enable_disable_req_t ;
extern int hf_rrm_oam_rac_enable_disable_req_t_bitmask ;
extern int hf_rrm_oam_rac_enable_disable_req_t_request_type ;
extern int hf_rrm_oam_rac_enable_disable_req_t_global_cell_id ;

//SHUTDOWN REQ
extern int hf_RRM_OAM_SHUTDOWN_REQ_unparsed_data ;
extern int hf_rrm_oam_shutdown_req_t ;
extern int hf_rrm_oam_shutdown_req_t_shutdown_mode ;
extern int hf_rrm_oam_shutdown_req_t_time_to_shutdown ;

//SHUTDOWN RESP
extern int hf_RRM_OAM_SHUTDOWN_RESP_unparsed_data ;
extern int hf_rrm_oam_shutdown_resp_t ;
extern int hf_rrm_oam_shutdown_resp_t_response ;
extern int hf_rrm_oam_shutdown_resp_t_fail_cause ;

// RRM OAM INIT IND
extern int hf_RRM_OAM_INIT_IND_unparsed_data ;
extern int hf_rrm_oam_init_ind_t ;

//SET LOG LEVEL REQ
extern int hf_RRM_OAM_SET_LOG_LEVEL_REQ_unparsed_data ;
extern int hf_rrm_oam_set_log_level_req_t ;
extern int hf_rrm_oam_set_log_level_req_t_module_id ;
extern int hf_rrm_oam_set_log_level_req_t_log_level ;

//SET LOG LEVEL RESP
extern int hf_RRM_OAM_SET_LOG_LEVEL_RESP_unparsed_data ;
extern int hf_rrm_oam_set_log_level_resp_t ;
extern int hf_rrm_oam_set_log_level_resp_t_response ;
extern int hf_rrm_oam_set_log_level_resp_t_fail_cause ;

//resume service req
extern int hf_RRM_OAM_RESUME_SERVICE_REQ_unparsed_data ;
extern int hf_rrm_oam_resume_service_req_t ;

//resume service resp
extern int hf_RRM_OAM_RESUME_SERVICE_RESP_unparsed_data ;
extern int hf_rrm_oam_resume_service_resp_t ;
extern int hf_rrm_oam_resume_service_resp_t_response ;
extern int hf_rrm_oam_resume_service_resp_t_fail_cause ;

//ready for shutdown ind
extern int hf_RRM_OAM_READY_FOR_SHUTDOWN_IND_unparsed_data ;
extern int hf_rrm_oam_ready_for_shutdown_ind_t ;

//Cell Config req
extern int hf_unparsed_data ;
extern int hf_rrm_oam_cell_config_req_t ;
extern int hf_rrm_oam_cell_config_req_t_bitmask ;
extern int hf_rrm_oam_cell_config_req_t_global_cell_info ;
extern int hf_rrm_oam_cell_config_req_t_ran_info ;
extern int hf_rrm_oam_cell_config_req_t_epc_info ;
extern int hf_rrm_oam_cell_config_req_t_operator_info ;
extern int hf_rrm_oam_cell_config_req_t_access_mgmt_params ;
extern int hf_rrm_oam_cell_config_req_t_immediate_start_needed ;

extern int hf_rrm_oam_cell_info_t ;
extern int hf_rrm_oam_cell_info_t_eutran_global_cell_id ;
extern int hf_rrm_oam_cell_info_t_cell_access_restriction_params ;
extern int hf_rrm_oam_eutran_global_cell_id_t ;
extern int hf_rrm_oam_eutran_global_cell_id_t_primary_plmn_id ;
extern int hf_rrm_oam_eutran_global_cell_id_t_cell_identity ;
extern int hf_rrm_oam_cell_plmn_info_t ;
extern int hf_rrm_oam_cell_plmn_info_t_mcc ;
extern int hf_rrm_oam_cell_plmn_info_t_num_mnc_digit ;
extern int hf_rrm_oam_cell_plmn_info_t_mnc ;
extern int hf_rrm_oam_cell_access_restriction_params_t ;
extern int hf_rrm_oam_cell_access_restriction_params_t_cell_barred ;

extern int hf_rrm_oam_cell_access_restriction_params_t_intra_freq_reselection ;

extern int hf_rrm_oam_cell_access_restriction_params_t_barring_for_emergency ;

extern int hf_rrm_oam_ran_t ;
extern int hf_rrm_oam_ran_t_bitmask ;
extern int hf_rrm_oam_ran_t_physical_layer_params ;
extern int hf_rrm_oam_ran_t_mac_layer_params ;
extern int hf_rrm_oam_ran_t_rlc_layer_params ;
extern int hf_rrm_oam_ran_t_mobility_params ;
extern int hf_rrm_oam_ran_t_rrc_timers_and_constants ;
extern int hf_rrm_oam_ran_t_rf_params ;
extern int hf_rrm_oam_ran_t_s1ap_params ;
extern int hf_rrm_oam_ran_t_ncl_params ;
extern int hf_rrm_oam_ran_t_connected_mode_mobility_params ;
extern int hf_rrm_oam_physical_layer_params_t ;
extern int hf_rrm_oam_physical_layer_params_t_bitmask ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pdsch ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_srs ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_prach ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pucch ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_pusch ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_reference_signal ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_ul_power_control ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_prs ;
extern int hf_rrm_oam_physical_layer_params_t_addl_physical_layer_params ;
extern int hf_rrm_oam_physical_layer_params_t_physical_layer_param_tdd_frame_structure ;
extern int hf_rrm_oam_addl_phy_params_t ;
extern int hf_rrm_oam_addl_phy_params_t_bitmask ;
extern int hf_rrm_oam_addl_phy_params_t_addl_pucch_parameters ;
extern int hf_rrm_oam_addl_phy_params_t_additional_pusch_parameters ;
extern int hf_rrm_oam_addl_phy_params_t_addtl_ul_reference_signal_params ;
extern int hf_rrm_oam_addl_pucch_config_t ;
extern int hf_rrm_oam_addl_pucch_config_t_bitmask ;
extern int hf_rrm_oam_addl_pucch_config_t_n1_cs ;
extern int hf_rrm_oam_addl_pusch_config_t ;
extern int hf_rrm_oam_addl_pusch_config_t_bitmask ;
extern int hf_rrm_oam_addl_pusch_config_t_pusch_enable_64_qam ;
extern int hf_rrm_oam_addl_ul_reference_signal_params_t ;
extern int hf_rrm_oam_addl_ul_reference_signal_params_t_bitmask ;
extern int hf_rrm_oam_addl_ul_reference_signal_params_t_group_assignment_pusch ;
extern int hf_rrm_oam_addl_ul_reference_signal_params_t_ul_reference_signal_pusch_cyclicshift ;
extern int hf_rrm_oam_tdd_frame_structure_t;
extern int hf_rrm_oam_tdd_frame_structure_t_sub_frame_assignment;
extern int hf_rrm_oam_tdd_frame_structure_t_special_sub_frame_patterns;
extern int hf_rrm_oam_pdsch_t ;
extern int hf_rrm_oam_pdsch_t_p_b ;

extern int hf_rrm_oam_pdsch_t_p_a ;

extern int hf_rrm_oam_srs_t ;
extern int hf_rrm_oam_srs_t_bitmask ;
extern int hf_rrm_oam_srs_t_srsEnabled ;

extern int hf_rrm_oam_srs_t_srs_bandwidth_config ;

extern int hf_rrm_oam_srs_t_srs_subframe_config ;

extern int hf_rrm_oam_srs_t_srs_max_up_pts ;

extern int hf_rrm_oam_srs_t_ack_nack_srs_simultaneous_transmission ;


extern int hf_rrm_oam_prach_t ;
extern int hf_rrm_oam_prach_t_root_sequence_index ;
extern int hf_rrm_oam_prach_t_configuration_index ;
extern int hf_rrm_oam_prach_t_high_speed_flag ;
extern int hf_rrm_oam_prach_t_zero_correlation_zone_config ;
extern int hf_rrm_oam_prach_t_frequency_offset ;
extern int hf_rrm_oam_pucch_t ;
extern int hf_rrm_oam_pucch_t_delta_pucch_shift ;
extern int hf_rrm_oam_pucch_t_n_rb_cqi ;
extern int hf_rrm_oam_pucch_t_n1_pucch_an ;
extern int hf_rrm_oam_pucch_t_cqi_pucch_resource_index ;
extern int hf_rrm_oam_pucch_t_tdd_ack_nack_feedback_mode ;
extern int hf_rrm_oam_pucch_t_pucch_cqi_sinr_value ;
extern int hf_rrm_oam_pusch_t ;
extern int hf_rrm_oam_pusch_t_n_sb ;
extern int hf_rrm_oam_pusch_t_pusch_hopping_mode ;

extern int hf_rrm_oam_pusch_t_hopping_offset ;
extern int hf_rrm_oam_ul_reference_signal_t ;
extern int hf_rrm_oam_ul_reference_signal_t_group_hopping_enabled ;

extern int hf_rrm_oam_ul_reference_signal_t_sequence_hopping_enabled ;
extern int hf_rrm_oam_uplink_power_control_t ;
extern int hf_rrm_oam_uplink_power_control_t_p_0_nominal_pusch ;
extern int hf_rrm_oam_uplink_power_control_t_alpha ;


extern int hf_rrm_oam_uplink_power_control_t_p_0_nominal_pucch ;
extern int hf_rrm_oam_prs_t ;
extern int hf_rrm_oam_prs_t_num_prs_resource_blocks ;
extern int hf_rrm_oam_prs_t_prs_configuration_index ;
extern int hf_rrm_oam_prs_t_num_consecutive_prs_subfames ;

extern int hf_rrm_oam_mac_layer_params_t ;
extern int hf_rrm_oam_mac_layer_params_t_mac_layer_param_rach ;
extern int hf_rrm_oam_mac_layer_params_t_mac_layer_param_drx ;
extern int hf_rrm_oam_rach_t ;
extern int hf_rrm_oam_rach_t_preamble_info ;
extern int hf_rrm_oam_rach_t_power_ramping_step ;

extern int hf_rrm_oam_rach_t_preamble_initial_received_target_power ;

extern int hf_rrm_oam_rach_t_preamble_trans_max ;

extern int hf_rrm_oam_rach_t_response_window_size ;


extern int hf_rrm_oam_rach_t_contention_resolution_timer ;

extern int hf_rrm_oam_rach_t_max_harq_msg_3tx ;
extern int hf_rrm_oam_preamble_info_t ;
extern int hf_rrm_oam_preamble_info_t_bitmask ;
extern int hf_rrm_oam_preamble_info_t_number_of_ra_preambles ;

extern int hf_rrm_oam_preamble_info_t_ra_preamble_groupA_info ;
extern int hf_rrm_oam_preamble_groupA_info_t ;
extern int hf_rrm_oam_preamble_groupA_info_t_size_of_ra_group_a ;

extern int hf_rrm_oam_preamble_groupA_info_t_message_size_group_a ;

extern int hf_rrm_oam_preamble_groupA_info_t_message_power_offset_group_b ;

extern int hf_rrm_oam_drx_t ;
extern int hf_rrm_oam_drx_t_drx_enabled ;

extern int hf_rrm_oam_drx_t_num_valid_drx_profiles ;
extern int hf_rrm_oam_drx_t_drx_config ;
extern int hf_rrm_oam_drx_config_t ;
extern int hf_rrm_oam_drx_config_t_bitmask ;
extern int hf_rrm_oam_drx_config_t_num_applicable_qci ;
extern int hf_rrm_oam_drx_config_t_applicable_qci_list ;
extern int hf_rrm_oam_drx_config_t_on_duration_timer ;

extern int hf_rrm_oam_drx_config_t_drx_inactivity_timer ;

extern int hf_rrm_oam_drx_config_t_drx_retransmission_timer ;

extern int hf_rrm_oam_drx_config_t_long_drx_cycle ;


extern int hf_rrm_oam_drx_config_t_drx_start_offset ;
extern int hf_rrm_oam_drx_config_t_short_drx_cycle ;

extern int hf_rrm_oam_short_drx_cycle_config_t ;
extern int hf_rrm_oam_short_drx_cycle_config_t_short_drx_cycle ;
extern int hf_rrm_oam_short_drx_cycle_config_t_drx_short_cycle_timer ;
extern int hf_rrm_oam_mac_layer_params_t_ul_sync_loss_timer;
extern int hf_rrm_oam_mac_layer_params_t_ul_ngap;

extern int hf_rrm_oam_rlc_layer_params_t ;
extern int hf_rrm_oam_rlc_layer_params_t_num_valid_srb_info ;
extern int hf_rrm_oam_rlc_layer_params_t_rlc_layer_param_srb ;
extern int hf_rrm_oam_srb_t ;
extern int hf_rrm_oam_srb_t_bitmask ;
extern int hf_rrm_oam_srb_t_default_configuration ;
extern int hf_rrm_oam_srb_t_srb_params ;
extern int hf_rrm_oam_srb_info_t ;
extern int hf_rrm_oam_srb_info_t_t_poll_retransmit ;

extern int hf_rrm_oam_srb_info_t_poll_pdu ;


extern int hf_rrm_oam_srb_info_t_poll_byte ;


extern int hf_rrm_oam_srb_info_t_max_retx_threshold ;


extern int hf_rrm_oam_srb_info_t_t_reordering ;

extern int hf_rrm_oam_srb_info_t_t_status_prohibit ;

extern int hf_rrm_oam_mobility_params_t ;
extern int hf_rrm_oam_mobility_params_t_bitmask;
extern int hf_rrm_oam_mobility_params_t_idle_mode_mobility_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_common_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_intra_freq_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_inter_freq_params_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_utra_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_geran_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_idle_mode_mobility_inter_rat_cdma2000_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutra_to_utra_reselection_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_fdd_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_irat_eutran_to_utran_tdd_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_t_reselection_utra ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_speed_scale_factors ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_num_irat_eutran_to_utran_fdd_carriers ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_irat_eutran_to_utran_fdd_carriers ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_utra_carrier_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_rx_lev_min ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_qual_min ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_cell_reselection_priority ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_high ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_low ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_p_max_utra ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_offset_freq ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_threshx_q_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_highq_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_lowq_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_preemption_vulnerability ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_num_irat_eutran_to_utran_tdd_carriers ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_irat_eutran_to_utran_tdd_carriers ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_utra_carrier_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_q_rx_lev_min ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_cell_reselection_priority ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_high ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_low ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_p_max_utra ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_irat_eutra_to_geran_reselection_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_carrier_freq_info_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_t_reselection_geran ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_speed_scale_factors ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_count_geran_carrier ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_carrier_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_carrier_freq ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t_common_info ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_starting_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_band_indicator ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_following_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_explicit_list_of_arfcns ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_equally_spaced_arfcns ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_var_bitmap_of_arfcns ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_count_explicit_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_data_explicit_arfcn ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_arfcn_spacing ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_num_of_following_arfcns ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_count_var_bit_map ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_data_var_bitmap ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_cell_reselection_priority ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_ncc_peritted ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_q_rx_lev_min ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_p_max_geran ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_high ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_low ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_offset_freq ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_search_window_size ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_support_for_dual_rx_ues_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_registration_param_1xrtt_v920 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_ac_barring_config_1_xrtt_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_pre_reg_info_hrpd ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_mobility_sib_8_params ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cdma2000_cell_param ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_inter_rat_parameters_cdma2000_v920 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_hrpd ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_cell_reselection_params_1xrtt ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_system_time_info ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_0_to_9_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_10_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_11_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_12_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_13_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_14_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_15_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_msg_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_reg_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_emg_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_thresh_x_low ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_allowed ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_zone_id ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_secondary_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_count ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_pre_reg_zone_id ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_sid ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_nid ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_sid ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_nid ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_zone ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_total_zone ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_zone_timer ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_packet_zone_id ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_home_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_sid_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_nid_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_parame_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_up_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_prd ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_down_reg ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cdma2000_rand ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_1xrtt ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_cell_id_hrpd ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_seed ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_min ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_max ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_regenerate_timer ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t_cdma2000_1xrtt_cell_id ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id_length ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_1xrtt_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_conc_ps_mobility_1xrtt_r9 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_band_class_list ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000_sf ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_count ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_band_class_info_cdma2000 ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_bitmask ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_band_class ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_cell_reselection_priority ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_high ;
extern int hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_low ;
extern int hf_rrm_oam_common_params_t ;
extern int hf_rrm_oam_common_params_t_bitmask ;
extern int hf_rrm_oam_common_params_t_q_hyst ;


extern int hf_rrm_oam_common_params_t_speed_state_params ;
extern int hf_rrm_oam_speed_state_params_t ;
extern int hf_rrm_oam_speed_state_params_t_q_hyst_sf_medium ;

extern int hf_rrm_oam_speed_state_params_t_q_hyst_sf_high ;
extern int hf_rrm_oam_speed_state_params_t_t_evaluation ;
extern int hf_rrm_oam_speed_state_params_t_t_hyst_normal ;
extern int hf_rrm_oam_speed_state_params_t_n_cell_change_medium ;
extern int hf_rrm_oam_speed_state_params_t_n_cell_change_high ;
extern int hf_rrm_oam_intra_freq_params_t ;
extern int hf_rrm_oam_intra_freq_params_t_bitmask ;
extern int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_1 ;
extern int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_offset ;
extern int hf_rrm_oam_intra_freq_params_t_p_max_sib_1 ;
extern int hf_rrm_oam_intra_freq_params_t_p_max_sib_3 ;
extern int hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_3 ;
extern int hf_rrm_oam_intra_freq_params_t_s_intra_search ;
extern int hf_rrm_oam_intra_freq_params_t_t_reselection_eutra ;
extern int hf_rrm_oam_intra_freq_params_t_speed_scale_factors ;
extern int hf_rrm_oam_intra_freq_params_t_s_non_intra_search ;
extern int hf_rrm_oam_intra_freq_params_t_cell_reselection_priority ;
extern int hf_rrm_oam_intra_freq_params_t_thresh_serving_low ;
extern int hf_rrm_oam_intra_freq_params_t_neigh_cell_config ;
extern int hf_rrm_oam_speed_scale_factors_t ;
extern int hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_medium ;
extern int hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_high ;

extern int hf_rrm_oam_inter_frequency_params_list_t ;
extern int hf_rrm_oam_inter_frequency_params_list_t_num_valid_inter_freq_list ;
extern int hf_rrm_oam_inter_frequency_params_list_t_idle_mode_mobility_inter_freq_params ;
extern int hf_rrm_oam_inter_freq_params_t ;
extern int hf_rrm_oam_inter_freq_params_t_bitmask ;
extern int hf_rrm_oam_inter_freq_params_t_eutra_carrier_arfcn ;
extern int hf_rrm_oam_inter_freq_params_t_q_rx_lev_min_sib_5 ;
extern int hf_rrm_oam_inter_freq_params_t_q_offset_freq ;

extern int hf_rrm_oam_inter_freq_params_t_t_reselection_eutra ;
extern int hf_rrm_oam_inter_freq_params_t_cell_reselection_priority ;
extern int hf_rrm_oam_inter_freq_params_t_thresh_x_high ;
extern int hf_rrm_oam_inter_freq_params_t_thresh_x_low ;
extern int hf_rrm_oam_inter_freq_params_t_p_max ;
extern int hf_rrm_oam_inter_freq_params_t_measurement_bandwidth ;

extern int hf_rrm_oam_inter_freq_params_t_presence_antenna_port1 ;
extern int hf_rrm_oam_inter_freq_params_t_neigh_cell_config ;
extern int hf_rrm_oam_inter_freq_params_t_speed_scale_factors ;
extern int hf_rrm_oam_inter_freq_params_t_q_qual_min_r9 ;
extern int hf_rrm_oam_inter_freq_params_t_threshx_q_r9 ;

extern int hf_rrm_oam_thresholdx_q_r9_t ;
extern int hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_highq_r9 ;
extern int hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_lowq_r9 ;

extern int hf_rrm_oam_rrc_timers_and_constants_t ;
extern int hf_rrm_oam_rrc_timers_and_constants_t_rrc_timers ;
extern int hf_rrm_oam_rrc_timers_and_constants_t_rrc_constants ;
extern int hf_rrm_oam_rrc_timers_t ;
extern int hf_rrm_oam_rrc_timers_t_t300 ;

extern int hf_rrm_oam_rrc_timers_t_t301 ;

extern int hf_rrm_oam_rrc_timers_t_t302 ;

extern int hf_rrm_oam_rrc_timers_t_t304_eutra ;

extern int hf_rrm_oam_rrc_timers_t_t304_irat ;

extern int hf_rrm_oam_rrc_timers_t_t310 ;

extern int hf_rrm_oam_rrc_timers_t_t311 ;

extern int hf_rrm_oam_rrc_timers_t_t320 ;
extern int hf_rrm_oam_rrc_constants_t ;
extern int hf_rrm_oam_rrc_constants_t_n310 ;


extern int hf_rrm_oam_rrc_constants_t_n311 ;


extern int hf_rrm_oam_rf_params_t ;
extern int hf_rrm_oam_rf_params_t_rf_configurations ;
extern int hf_rrm_oam_rf_configurations_t ;
extern int hf_rrm_oam_rf_configurations_t_bitmask ;
extern int hf_rrm_oam_rf_configurations_t_frequency_band_indicator ;
extern int hf_rrm_oam_rf_configurations_t_dl_earfcn ;
extern int hf_rrm_oam_rf_configurations_t_dl_bandwidth ;

extern int hf_rrm_oam_rf_configurations_t_ul_earfcn ;
extern int hf_rrm_oam_rf_configurations_t_ul_bandwidth ;

extern int hf_rrm_oam_rf_configurations_t_reference_signal_power ;
extern int hf_rrm_oam_rf_configurations_t_phy_cell_id ;
extern int hf_rrm_oam_rf_configurations_t_psch_power_offset ;
extern int hf_rrm_oam_rf_configurations_t_ssch_power_offset ;
extern int hf_rrm_oam_rf_configurations_t_pbch_power_offset ;
extern int hf_rrm_oam_s1ap_params_t ;
extern int hf_rrm_oam_s1ap_params_t_t_reloc_prep ;
extern int hf_rrm_oam_s1ap_params_t_t_reloc_overall ;
extern int hf_rrm_oam_ncl_params_t ;
extern int hf_rrm_oam_ncl_params_t_bitmask ;
extern int hf_rrm_oam_ncl_params_t_lte_ncl ;
extern int hf_rrm_oam_ncl_params_t_inter_rat_ncl ;
extern int hf_rrm_oam_inter_rat_ncl_t_unparsed_data ;
extern int hf_rrm_oam_inter_rat_ncl_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_num_valid_utran_freq_cell ;
extern int hf_rrm_oam_inter_rat_ncl_t_utran_freq_cells ;
extern int hf_rrm_oam_inter_rat_ncl_t_num_valid_geran_freq_cell ;
extern int hf_rrm_oam_inter_rat_ncl_t_geran_freq_cells ;
extern int hf_rrm_oam_inter_rat_ncl_t_num_valid_cdma2000_freq_cells ;
extern int hf_rrm_oam_inter_rat_ncl_t_cdma2000_freq_cells ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_rai ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uc_id ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ura ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcnul ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcndl ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_scrambling_code ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_tx_power ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_offset_freq ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_cell_access_mode ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_blacklisted ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_csg_identity ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ho_status ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ps_ho_supported ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_voip_capable ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_daho_indication ;
extern int hf_rrm_utran_cell_id_t ;
extern int hf_rrm_utran_cell_id_t_bitmask ;
extern int hf_rrm_utran_cell_id_t_cell_id ;
extern int hf_rrm_utran_cell_id_t_rnc_id ;
extern int hf_rrm_utran_cell_id_t_extended_rnc_id ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_lai ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_rac ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_plmn_id ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_lac ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_lai ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_cell_id ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bandindicator ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bccharfcn ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_pci ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_network_control_order ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_ho_status ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_supported ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_ho_supported ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_voip_capable ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_daho_indication ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_lai ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_band_class ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_arfcn ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_pn_offset ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_type ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_num_valid_count_cid ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_CID ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_cell_specific_params ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_daho_indication ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pz_hyst_parameters_included ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_p_rev ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_min_p_rev ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_neg_slot_cycle_index_sup ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_encrypt_mode ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_enc_supported ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_encrypt_sup ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_msg_integrity_sup ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup_incl ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_ms_init_pos_loc_sup_ind ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class_info_req ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_alt_band_class ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_mode_supported ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_id ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_fpc_fch_included ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_t_add ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pilot_inc ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_enabled ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_info_incl ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_list_len ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_act_timer ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_mul ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_exp ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_bitmask ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc3 ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc4 ;
extern int hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc5 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_unparsed_data ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_bitmask ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_common_params_for_eutra ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_irat ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_bitmask ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a3_offset ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_on_leave ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrq ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_hysteresis ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_time_to_trigger ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_trigger_quantity ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_quantity ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_interval ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_amount ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_ps_ho_enabled ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_bitmask ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_qoffset_tutra ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_utra ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_fdd ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_tdd ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_rscp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_ecn0 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_geran ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_geran ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_geran ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_cdma2000 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_cdma2000 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_cdma2000 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_rscp ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_ecn0 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2geran ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2cdma ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_hysteresis ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_time_to_trigger ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_max_report_cells ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_interval ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_amount ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ps_ho_enabled ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_ue_generic_cdma2000_params ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bitmask ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auth ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_num_alt_so ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_use_sync_id ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mob_qos ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bypass_reg_ind ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_add_serv_instance ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_parameter_reg ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reg_dist ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pref_msid_type ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_ext_pref_msid_type ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_meid_reqd ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mcc ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_11_12 ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_t_supported ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reconnect_msg_ind ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_rer_mode_supported ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pilot_report ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_supported ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auto_fcso_allowed ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_in_rcnm_ind ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_daylt ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_l2_ack_timer ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_sequence_context_timer ;
extern int hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_lp_sec ;
extern int hf_rrm_oam_lte_ncl_t ;
extern int hf_rrm_oam_lte_ncl_t_num_valid_intra_freq_cell ;
extern int hf_rrm_oam_lte_ncl_t_intra_freq_cells ;
extern int hf_rrm_oam_lte_ncl_t_num_valid_inter_freq_cell ;
extern int hf_rrm_oam_lte_ncl_t_inter_freq_cells ;
extern int hf_rrm_oam_intra_freq_cells_t ;
extern int hf_rrm_oam_intra_freq_cells_t_bitmask ;
extern int hf_rrm_oam_intra_freq_cells_t_cell_id ;

extern int hf_rrm_oam_intra_freq_cells_t_phy_cell_id ;
extern int hf_rrm_oam_intra_freq_cells_t_q_offset ;
extern int hf_rrm_oam_intra_freq_cells_t_cell_individual_offset ;

extern int hf_rrm_oam_intra_freq_cells_t_r_stx_power ;
extern int hf_rrm_oam_intra_freq_cells_t_blacklisted ;
extern int hf_rrm_oam_intra_freq_cells_t_cell_access_mode ;
extern int hf_rrm_oam_intra_freq_cells_t_csg_identity ;
extern int hf_rrm_oam_intra_freq_cells_t_ho_status ;
extern int hf_rrm_oam_intra_freq_cells_t_x2_status ;
extern int hf_rrm_oam_intra_freq_cells_t_broadcast_status ;
extern int hf_rrm_oam_intra_freq_cells_t_tac ;
extern int hf_rrm_oam_intra_freq_cells_t_daho_indication ;

extern int hf_rrm_oam_inter_freq_cells_t ;
extern int hf_rrm_oam_inter_freq_cells_t_bitmask ;
extern int hf_rrm_oam_inter_freq_cells_t_cell_id ;
extern int hf_rrm_oam_inter_freq_cells_t_eutra_carrier_arfcn ;
extern int hf_rrm_oam_inter_freq_cells_t_phy_cell_id ;
extern int hf_rrm_oam_inter_freq_cells_t_q_offset ;


extern int hf_rrm_oam_inter_freq_cells_t_cell_individual_offset ;
extern int hf_rrm_oam_inter_freq_cells_t_r_stx_power ;
extern int hf_rrm_oam_inter_freq_cells_t_blacklisted ;
extern int hf_rrm_oam_epc_t ;
extern int hf_rrm_oam_epc_t_epc_params ;
extern int hf_rrm_oam_epc_params_t ;
extern int hf_rrm_oam_epc_params_t_bitmask ;
extern int hf_rrm_oam_epc_params_t_general_epc_params ;
extern int hf_rrm_oam_epc_params_t_num_valid_qos_profiles ;
extern int hf_rrm_oam_epc_params_t_emergency_erab_arp ;
extern int hf_rrm_oam_epc_params_t_qos_config_params ;
extern int hf_rrm_oam_general_epc_params_t ;
extern int hf_rrm_oam_general_epc_params_t_bitmask ;
extern int hf_rrm_oam_general_epc_params_t_num_valid_plmn ;
extern int hf_rrm_oam_general_epc_params_t_plmn_list ;
extern int hf_rrm_oam_general_epc_params_t_tac ;
extern int hf_rrm_oam_general_epc_params_t_eaid ;
extern int hf_rrm_oam_plmn_access_info_t ;
extern int hf_rrm_oam_plmn_access_info_t_plmn_info ;
extern int hf_rrm_oam_plmn_access_info_t_reserve_operator_use ;
extern int hf_rrm_oam_qos_config_params_t ;
extern int hf_rrm_oam_qos_config_params_t_bitmask ;
extern int hf_rrm_oam_qos_config_params_t_qci ;
extern int hf_rrm_oam_qos_config_params_t_type ;


extern int hf_rrm_oam_qos_config_params_t_priority ;
extern int hf_rrm_oam_qos_config_params_t_packet_delay_budget ;
extern int hf_rrm_oam_qos_config_params_t_packet_error_loss_rate ;
extern int hf_rrm_oam_qos_config_params_t_dscp ;
extern int hf_rrm_oam_qos_config_params_t_rlc_mode ;
extern int hf_rrm_oam_qos_config_params_t_lossless_ho_required ;
extern int hf_rrm_oam_qos_config_params_t_ue_inactivity_timer_config ;
extern int hf_rrm_oam_qos_config_params_t_max_harq_tx ;
extern int hf_rrm_oam_qos_config_params_t_max_harq_retrans ;
extern int hf_rrm_oam_qos_config_params_t_logical_channel_grouping_on_off ;
extern int hf_rrm_oam_qos_config_params_t_max_rlc_transmissions ;
extern int hf_rrm_oam_qos_config_params_t_rohc_params ;
extern int hf_rrm_oam_qos_config_params_t_sn_field_len ;
extern int hf_rrm_oam_qos_config_params_t_sps_config_enabled ;
extern int hf_rrm_oam_qos_config_params_t_sps_data ;
extern int hf_rrm_oam_qos_config_params_t_supported_rat ;
extern int hf_rrm_oam_qos_config_params_t_dl_min_bitrate ;
extern int hf_rrm_oam_qos_config_params_t_ul_min_bitrate ;
extern int hf_rrm_oam_qos_config_params_t_addl_rlc_param ;
extern int hf_rrm_oam_qos_config_params_t_addl_mac_param ;
extern int hf_rrm_oam_pdcp_rohc_params_t ;
extern int hf_rrm_oam_pdcp_rohc_params_t_bitmask ;
extern int hf_rrm_oam_pdcp_rohc_params_t_enable_rohc ;
extern int hf_rrm_oam_pdcp_rohc_params_t_rohc_pofiles ;
extern int hf_rrm_oam_pdcp_rohc_params_t_max_cid ;
extern int hf_rrm_oam_rohc_pofiles_t ;
extern int hf_rrm_oam_rohc_pofiles_t_bitmask ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0001 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0002 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0003 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0004 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0006 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0101 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0102 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0103 ;
extern int hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0104 ;
extern int hf_rrm_oam_sn_field_len_t ;
extern int hf_rrm_oam_sn_field_len_t_bitmask ;
extern int hf_rrm_oam_sn_field_len_t_dl_rlc ;
extern int hf_rrm_oam_sn_field_len_t_ul_rlc ;
extern int hf_rrm_oam_sn_field_len_t_dl_pdcp ;
extern int hf_rrm_oam_sn_field_len_t_ul_pdcp ;
extern int hf_rrm_oam_sps_config_data_t ;
extern int hf_rrm_oam_sps_config_data_t_bitmask ;
extern int hf_rrm_oam_sps_config_data_t_sps_config_dl ;
extern int hf_rrm_oam_sps_config_data_t_sps_config_ul ;
extern int hf_rrm_oam_sps_config_dl_t ;
extern int hf_rrm_oam_sps_config_dl_t_bitmask ;
extern int hf_rrm_oam_sps_config_dl_t_semi_persist_sched_interval_dl ;
extern int hf_rrm_oam_sps_config_dl_t_number_of_conf_sps_processes ;
extern int hf_rrm_oam_sps_config_dl_t_max_sps_harq_retx ;
extern int hf_rrm_oam_sps_config_dl_t_explicit_release_after ;
extern int hf_rrm_oam_sps_config_ul_t ;
extern int hf_rrm_oam_sps_config_ul_t_bitmask ;
extern int hf_rrm_oam_sps_config_ul_t_semi_persist_sched_interval_ul ;
extern int hf_rrm_oam_sps_config_ul_t_implicit_release_after ;
extern int hf_rrm_oam_sps_config_ul_t_p_zero_nominal_pusch_persistent ;
extern int hf_rrm_oam_addl_rlc_params_t ;
extern int hf_rrm_oam_addl_rlc_params_t_bitmask ;
extern int hf_rrm_oam_addl_rlc_params_t_t_poll_pdu ;
extern int hf_rrm_oam_addl_rlc_params_t_t_reordering ;
extern int hf_rrm_oam_addl_rlc_params_t_t_poll_retransmit ;
extern int hf_rrm_oam_addl_rlc_params_t_t_status_prohibit ;
extern int hf_rrm_oam_addl_mac_params_t ;
extern int hf_rrm_oam_addl_mac_params_t_bitmask ;
extern int hf_rrm_oam_addl_mac_params_t_phr_config ;
extern int hf_rrm_oam_addl_mac_params_t_bsr_config ;
extern int hf_rrm_oam_phr_config_t ;
extern int hf_rrm_oam_phr_config_t_bitmask ;
extern int hf_rrm_oam_phr_config_t_t_periodic_phr ;
extern int hf_rrm_oam_phr_config_t_t_prohibit_phr ;
extern int hf_rrm_oam_phr_config_t_t_pathloss_chng ;
extern int hf_rrm_oam_bsr_config_t ;
extern int hf_rrm_oam_bsr_config_t_bitmask ;
extern int hf_rrm_oam_bsr_config_t_t_periodic_bsr ;
extern int hf_rrm_oam_bsr_config_t_t_retx_bsr ;
extern int hf_rrm_oam_operator_info_t ;
extern int hf_rrm_oam_operator_info_t_bitmask ;
extern int hf_rrm_oam_operator_info_t_simultaneous_ack_nack_and_cqi ;
extern int hf_rrm_oam_operator_info_t_rrm_mac_config ;
extern int hf_rrm_oam_operator_info_t_phich_config ;
extern int hf_rrm_oam_operator_info_t_sib_1_info ;
extern int hf_rrm_oam_operator_info_t_sib_2_info ;
extern int hf_rrm_oam_operator_info_t_sib_3_info ;
extern int hf_rrm_oam_operator_info_t_sib_4_info ;
extern int hf_rrm_oam_operator_info_t_admission_control_info ;
extern int hf_rrm_oam_operator_info_t_additional_packet_scheduling_params ;
extern int hf_rrm_oam_operator_info_t_additional_cell_params ;
extern int hf_rrm_oam_operator_info_t_load_params ;
extern int hf_rrm_oam_operator_info_t_mimo_mode_params ;
extern int hf_rrm_oam_operator_info_t_ho_configuration ;
extern int hf_rrm_oam_operator_info_t_measurement_configuration ;
extern int hf_rrm_oam_operator_info_t_cell_capacity_class ;
extern int hf_rrm_oam_operator_info_t_cell_type ;
extern int hf_rrm_oam_operator_info_t_rrm_eutran_access_point_pos ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t_bitmask ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t_dl_mcs ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t_ul_mcs ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t_frequency_selective_scheduling ;
extern int hf_rrm_oam_adl_pkt_scheduling_params_t_cqi_reporting_mode ;
extern int hf_rrm_oam_adl_cell_params_t ;
extern int hf_rrm_oam_adl_cell_params_t_bitmask ;
extern int hf_rrm_oam_adl_cell_params_t_sub_carrier_spacing ;
extern int hf_rrm_oam_adl_cell_params_t_dl_cyclic_prefix ;
extern int hf_rrm_oam_load_params_t ;
extern int hf_rrm_oam_load_params_t_bitmask ;
extern int hf_rrm_oam_load_params_t_wait_time ;
extern int hf_rrm_oam_mimo_mode_params_t ;
extern int hf_rrm_oam_mimo_mode_params_t_bitmask ;
extern int hf_rrm_oam_mimo_mode_params_t_antenna_ports_count_number ;
extern int hf_rrm_oam_mimo_mode_params_t_supported_tx_mode ;
extern int hf_rrm_oam_ho_config_params_t ;
extern int hf_rrm_oam_ho_config_params_t_bitmask ;
extern int hf_rrm_oam_ho_config_params_t_target_cell_selection_params ;
extern int hf_rrm_oam_ho_config_params_t_ho_algo_params ;
extern int hf_rrm_oam_ho_config_params_t_ho_retry_params ;
extern int hf_rrm_oam_ho_config_params_t_blind_ho_timer ;
extern int hf_rrm_oam_target_cell_selection_params_t ;
extern int hf_rrm_oam_target_cell_selection_params_t_bitmask ;
extern int hf_rrm_oam_target_cell_selection_params_t_neighboring_cell_load_based_ho_enable ;
extern int hf_rrm_oam_target_cell_selection_params_t_ue_history_based_ho_enable ;
extern int hf_rrm_oam_target_cell_selection_params_t_spid_based_ho_enable ;
extern int hf_rrm_oam_target_cell_selection_params_t_ue_measurement_based_ho_enable ;
extern int hf_rrm_oam_target_cell_selection_params_t_daho_cell_based_ho_enable ;
extern int hf_rrm_oam_ho_algo_params_t ;
extern int hf_rrm_oam_ho_algo_params_t_bitmask ;
extern int hf_rrm_oam_ho_algo_params_t_enb_measurements_for_ho ;
extern int hf_rrm_oam_ho_algo_params_t_ue_meas_trigger_quantity_for_ho ;
extern int hf_rrm_oam_ho_algo_params_t_coverage_based_ho ;
extern int hf_rrm_oam_ho_algo_params_t_intra_freq_ho ;
extern int hf_rrm_oam_ho_algo_params_t_inter_freq_ho ;
extern int hf_rrm_oam_ho_algo_params_t_inter_rat_ho ;
extern int hf_rrm_oam_ho_retry_params_t ;
extern int hf_rrm_oam_ho_retry_params_t_bitmask ;
extern int hf_rrm_oam_ho_retry_params_t_ho_retry_enable ;
extern int hf_rrm_oam_ho_retry_params_t_ho_retry_count ;
extern int hf_rrm_oam_meas_config_t ;
extern int hf_rrm_oam_meas_config_t_bitmask ;
extern int hf_rrm_oam_meas_config_t_report_trigger_type ;
extern int hf_rrm_oam_meas_config_t_meas_gap_config ;
extern int hf_rrm_oam_meas_config_t_si_gap_enable ;
extern int hf_rrm_oam_meas_config_t_csfb_tgt_selection ;
extern int hf_rrm_oam_meas_gap_config_t ;
extern int hf_rrm_oam_meas_gap_config_t_bitmask ;
extern int hf_rrm_oam_meas_gap_config_t_eutran_gap_offset_type ;
extern int hf_rrm_oam_meas_gap_config_t_utran_gap_offset_type ;
extern int hf_rrm_oam_meas_gap_config_t_geran_gap_offset_type ;
extern int hf_rrm_oam_meas_gap_config_t_cdma2000_gap_offset_type ;
extern int hf_rrm_csfb_tgt_selection_t ;
extern int hf_rrm_csfb_tgt_selection_t_bitmask ;
extern int hf_rrm_csfb_tgt_selection_t_utran_csfb_tgt_selection ;
extern int hf_rrm_csfb_tgt_selection_t_geran_csfb_tgt_selection ;
extern int hf_rrm_csfb_tgt_selection_t_cdma2000_csfb_tgt_selection ;
extern int hf_rrm_oam_eutran_access_point_pos_t ;
extern int hf_rrm_oam_eutran_access_point_pos_t_bitmask ;
extern int hf_rrm_oam_eutran_access_point_pos_t_latitude_sign ;
extern int hf_rrm_oam_eutran_access_point_pos_t_deg_of_latitude ;
extern int hf_rrm_oam_eutran_access_point_pos_t_deg_of_longitude ;
extern int hf_rrm_oam_eutran_access_point_pos_t_dir_of_altitude ;
extern int hf_rrm_oam_eutran_access_point_pos_t_altitude ;
extern int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_major ;
extern int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_minor ;
extern int hf_rrm_oam_eutran_access_point_pos_t_orientation_of_major_axis ;
extern int hf_rrm_oam_eutran_access_point_pos_t_uncertainty_altitude ;
extern int hf_rrm_oam_eutran_access_point_pos_t_confidence ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_bitmask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_icic_scheme_type ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_power_mask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_rntp_report_config_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_min_rb_for_pl_phr_calc ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_atb_config ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_mu_mimo_type ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_msc_threshold_ul_mu_mimo ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_x2ap_icic_report_periodicity ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pa_for_ce_ue ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_bitmask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_edge_region ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_center_region ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_center_region ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_cell_edge_region ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_start_rb ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_num_of_rb ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_center_user_power_mask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_edge_user_power_mask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_qci_delta_power_mask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_bitmask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_report_on_X2_required ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_threshold ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_max_nominal_epre ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_default_path_loss ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_count ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_path_loss_to_target_sinr_map_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_bitmask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_ce_user ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_count ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_aggregation_level ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_power_offset ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t_cqi_to_phich_power_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_dci_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_Occasion_Per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti_per_interval ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_dci_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_Occasion_Per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti_per_interval ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_up_factor ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_down_factor ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_adjust_factor ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_mcs_index_for_atb ;
extern int hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_prb_val_for_atb ;
extern int hf_rrm_oam_dynamic_icic_info_t ;
extern int hf_rrm_oam_dynamic_icic_info_t_bitmask ;
extern int hf_rrm_oam_dynamic_icic_info_t_dl_resource_partition_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_ul_resource_partition_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_ul_power_mask ;
extern int hf_rrm_oam_dynamic_icic_info_t_rntp_report_config_info ;
extern int hf_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map ;
extern int hf_rrm_oam_dynamic_icic_info_t_pdcch_aggregation_power_offset ;
extern int hf_rrm_oam_dynamic_icic_info_t_cqi_to_phich_power ;
extern int hf_rrm_oam_dynamic_icic_info_t_min_rb_for_pl_phr_calc ;
extern int hf_rrm_oam_dynamic_icic_info_t_sps_dl_scheduling_Info_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_sps_ul_scheduling_Info_per_tti ;
extern int hf_rrm_oam_dynamic_icic_info_t_alpha_pathloss_target_sinr_map_sps ;
extern int hf_rrm_oam_dynamic_icic_info_t_dynamic_cfi_extension_params ;
extern int hf_rrm_oam_dynamic_icic_info_t_atb_config ;
extern int hf_rrm_oam_dynamic_icic_info_t_ul_mu_mimo_type ;
extern int hf_rrm_oam_dynamic_icic_info_t_msc_threshold_ul_mu_mimo ;
extern int hf_rrm_oam_dynamic_icic_info_t_x2ap_icic_report_periodicity ;
extern int hf_rrm_oam_dynamic_icic_info_t_pa_for_ce_ue ;
extern int hf_rrm_oam_resource_partition_info_t ;
extern int hf_rrm_oam_resource_partition_info_t_bitmask ;
extern int hf_rrm_oam_resource_partition_info_t_num_of_cell_edge_region ;
extern int hf_rrm_oam_resource_partition_info_t_num_of_cell_center_region ;
extern int hf_rrm_oam_resource_partition_info_t_cell_center_region ;
extern int hf_rrm_oam_resource_partition_t ;
extern int hf_rrm_oam_resource_partition_t_start_rb ;
extern int hf_rrm_oam_resource_partition_t_num_of_rb ;
extern int hf_rrm_oam_ul_power_mask_t ;
extern int hf_rrm_oam_ul_power_mask_t_cell_center_user_power_mask ;
extern int hf_rrm_oam_ul_power_mask_t_cell_edge_user_power_mask ;
extern int hf_rrm_oam_ul_power_mask_t_qci_delta_power_mask ;
extern int hf_rrm_oam_rntp_report_config_info_t ;
extern int hf_rrm_oam_rntp_report_config_info_t_bitmask ;
extern int hf_rrm_oam_rntp_report_config_info_t_rntp_report_on_X2_required ;
extern int hf_rrm_oam_rntp_report_config_info_t_rntp_threshold ;
extern int hf_rrm_oam_rntp_report_config_info_t_max_nominal_epre ;
extern int hf_rrm_oam_alpha_based_pathloss_target_sinr_map_t ;
extern int hf_rrm_oam_alpha_based_pathloss_target_sinr_map_t_default_path_loss ;
extern int hf_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_target_sinr_map ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_t ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_t_count ;
extern int hf_rrm_oam_alpha_based_pathloss_target_sinr_map_t_path_loss_to_target_sinr_map_info ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_info_t ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_count ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_start_PL ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_end_PL ;
extern int hf_rrm_oam_path_loss_to_target_sinr_map_info_t_target_SINR ;
extern int hf_rrm_oam_pdcch_aggregation_power_offset_t ;
extern int hf_rrm_oam_pdcch_aggregation_power_offset_t_count ;
extern int hf_rrm_oam_pdcch_aggregation_power_offset_t_bitmask ;
extern int hf_rrm_oam_pdcch_aggregation_power_offset_t_aggregation_power_offset_cc_user ;
extern int hf_rrm_oam_aggregation_power_offset_on_cqi_basis_t_aggregation_power_offset_user ;
extern int hf_rrm_oam_aggregation_power_offset_t ;
extern int hf_rrm_oam_aggregation_power_offset_t_count ;
extern int hf_rrm_oam_aggregation_power_offset_t_aggr_pwr_offset_tuples ;
extern int hf_rrm_oam_aggregation_power_offset_info_t ;
extern int hf_rrm_oam_aggregation_power_offset_info_t_count ;
extern int hf_rrm_oam_aggregation_power_offset_info_t_aggregation_level ;
extern int hf_rrm_oam_aggregation_power_offset_info_t_power_offset ;
extern int hf_rrm_oam_cqi_to_phich_power_t ;
extern int hf_rrm_oam_cqi_to_phich_power_t_cqi_to_phich_power_info ;
extern int hf_rrm_oam_sps_dl_scheduling_Info_per_tti_t ;
extern int hf_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_dci_per_tti ;
extern int hf_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_Occasion_Per_tti ;
extern int hf_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti ;
extern int hf_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti_per_interval ;
extern int hf_rrm_oam_dynamic_cfi_extension_params_t ;
extern int hf_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_up_factor ;
extern int hf_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_down_factor ;
extern int hf_rrm_oam_dynamic_cfi_extension_params_t_cce_adjust_factor ;
extern int hf_rrm_oam_atb_config_t ;
extern int hf_rrm_oam_atb_config_t_min_mcs_index_for_atb ;
extern int hf_rrm_oam_atb_config_t_min_prb_val_for_atb ;
extern int hf_rrm_oam_dynamic_icic_info_t_icic_scheme_type;
extern int hf_rrm_oam_rrmc_mac_config_t ;
extern int hf_rrm_oam_rrmc_mac_config_t_start_rarnti_range ;
extern int hf_rrm_oam_rrmc_mac_config_t_end_rarnti_range ;
extern int hf_rrm_oam_rrmc_mac_config_t_enable_freq_selct_sch ;
extern int hf_rrm_oam_rrmc_mac_config_t_ue_inactive_time_config ;
extern int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t ;
extern int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_ul_freq_selective_enable ;
extern int hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_dl_freq_selective_enable ;
extern int hf_rrm_oam_phy_phich_configuration_t ;
extern int hf_rrm_oam_phy_phich_configuration_t_phich_resource ;
extern int hf_rrm_oam_phy_phich_configuration_t_phich_duration ;
extern int hf_rrm_oam_sib_type_1_info_t ;
extern int hf_rrm_oam_sib_type_1_info_t_bitmask ;
extern int hf_rrm_oam_sib_type_1_info_t_ims_emergency_support_r9 ;
extern int hf_rrm_oam_sib_type_1_info_t_si_window_length ;
extern int hf_rrm_oam_sib_type_1_info_t_si_count ;
extern int hf_rrm_oam_sib_type_1_info_t_scheduling_info ;
extern int hf_rrm_oam_scheduling_info_t ;
extern int hf_rrm_oam_scheduling_info_t_si_periodicity ;
extern int hf_rrm_oam_scheduling_info_t_sib_mapping_info ;
extern int hf_rrm_oam_sib_mapping_info_t ;
extern int hf_rrm_oam_sib_mapping_info_t_sib_type ;

extern int hf_rrm_oam_sib_type_1_info_t_cell_selection_info ;
extern int hf_rrm_oam_cell_selection_info_v920_t ;
extern int hf_rrm_oam_cell_selection_info_v920_t_bitmask ;
extern int hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_r9 ;
extern int hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_offset_r9_present ;

extern int hf_rrm_oam_sib_type_2_info_t ;
extern int hf_rrm_oam_sib_type_2_info_t_bitmask ;
extern int hf_rrm_oam_sib_type_2_info_t_radio_res_config_common_sib ;
extern int hf_rrm_oam_sib_type_2_info_t_rrm_freq_info ;
extern int hf_rrm_oam_sib_type_2_info_t_additional_spectrum_emission ;
extern int hf_rrm_oam_sib_type_2_info_t_time_alignment_timer_common ;

extern int hf_rrm_oam_radio_resource_config_common_sib_t ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_bitmask ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_modification_period_coeff ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_default_paging_cycle ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_nB ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_ul_cyclic_prefix_length ;

extern int hf_rrm_oam_radio_resource_config_common_sib_t_rrm_bcch_config ;
extern int hf_rrm_oam_radio_resource_config_common_sib_t_rrm_pcch_config ;

extern int hf_rrm_oam_bcch_config_t ;
extern int hf_rrm_oam_bcch_config_t_bitmask ;
extern int hf_rrm_oam_bcch_config_t_modification_period_coeff ;


extern int hf_rrm_oam_pcch_config_t ;
extern int hf_rrm_oam_pcch_config_t_bitmask ;
extern int hf_rrm_oam_pcch_config_t_default_paging_cycle ;


extern int hf_rrm_oam_pcch_config_t_nB ;


extern int hf_rrm_oam_freq_info_t ;
extern int hf_rrm_oam_freq_info_t_additional_spectrum_emission ;
extern int hf_rrm_oam_sib_type_3_info_t ;
extern int hf_rrm_oam_sib_type_3_info_t_bitmask ;
extern int hf_rrm_oam_sib_type_3_info_t_intra_freq_reselection_info ;
extern int hf_rrm_oam_sib_type_3_info_t_s_intra_search ;
extern int hf_rrm_oam_sib_type_3_info_t_s_non_intra_search ;
extern int hf_rrm_oam_sib_type_3_info_t_q_qual_min_r9 ;
extern int hf_rrm_oam_sib_type_3_info_t_thresh_serving_lowq_r9 ;
extern int hf_rrm_oam_intra_freq_cell_reselection_info_t ;
extern int hf_rrm_oam_intra_freq_cell_reselection_info_t_bitmask ;
extern int hf_rrm_oam_intra_freq_cell_reselection_info_t_measurement_bandwidth ;
extern int hf_rrm_oam_intra_freq_cell_reselection_info_t_presence_antenna_port1 ;
extern int hf_rrm_oam_s_intra_search_v920_t ;
extern int hf_rrm_oam_s_intra_search_v920_t_s_intra_search_p_r9 ;
extern int hf_rrm_oam_s_intra_search_v920_t_s_intra_search_q_r9 ;
extern int hf_rrm_oam_s_non_intra_search_v920_t ;
extern int hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_p_r9 ;
extern int hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_q_r9 ;
extern int hf_rrm_oam_sib_type_4_info_t ;
extern int hf_rrm_oam_sib_type_4_info_t_csg_id_range ;
extern int hf_rrm_oam_csg_cell_id_range_t ;
extern int hf_rrm_oam_csg_cell_id_range_t_bitmask ;
extern int hf_rrm_oam_csg_cell_id_range_t_start ;
extern int hf_rrm_oam_csg_cell_id_range_t_range ;

extern int hf_rrm_oam_admission_control_info_t ;
extern int hf_rrm_oam_admission_control_info_t_bitmask ;
extern int hf_rrm_oam_admission_control_info_t_max_num_ue_per_cell ;
extern int hf_rrm_oam_admission_control_info_t_max_sps_ues ;
extern int hf_rrm_oam_admission_control_info_t_max_num_drbs_per_ue ;
extern int hf_rrm_oam_admission_control_info_t_max_num_gbr_drbs_per_ue ;
extern int hf_rrm_oam_admission_control_info_t_max_num_non_gbr_drbs_per_ue ;
extern int hf_rrm_oam_admission_control_info_t_dl_prb_budget ;
extern int hf_rrm_oam_admission_control_info_t_ul_prb_budget ;
extern int hf_rrm_oam_admission_control_info_t_dl_prb_budget_gbr ;
extern int hf_rrm_oam_admission_control_info_t_ul_prb_budget_gbr ;
extern int hf_rrm_oam_admission_control_info_t_dl_prb_budget_ngbr ;
extern int hf_rrm_oam_admission_control_info_t_ul_prb_budget_ngbr ;
extern int hf_rrm_oam_admission_control_info_t_available_gbr_limit ;
extern int hf_rrm_oam_admission_control_info_t_resource_reserved_for_existing_users ;
extern int hf_rrm_oam_admission_control_info_t_total_backhaul_capacity ;
extern int hf_rrm_oam_admission_control_info_t_capacity_threshold ;
extern int hf_rrm_oam_admission_control_info_t_spid_table ;
extern int hf_rrm_oam_admission_control_info_t_preemption_allowed ;
extern int hf_rrm_oam_admission_control_info_t_preemption_status ;
extern int hf_rrm_oam_admission_control_info_t_proximity_indication_status ;
extern int hf_available_gbr_limit_t ;
extern int hf_available_gbr_limit_t_dl_gbr_limit ;
extern int hf_available_gbr_limit_t_ul_gbr_limit ;
extern int hf_rrm_oam_spid_table_t ;
extern int hf_rrm_oam_spid_table_t_spid_count ;
extern int hf_rrm_oam_spid_table_t_spid_config ;
extern int hf_rrm_oam_spid_configuration_t ;
extern int hf_rrm_oam_spid_configuration_t_bitmask ;
extern int hf_rrm_oam_spid_configuration_t_sp_id ;
extern int hf_rrm_oam_spid_configuration_t_eutran_freq_priority_info ;
extern int hf_rrm_oam_spid_configuration_t_utran_freq_priority_info ;
extern int hf_rrm_oam_spid_configuration_t_geran_freq_priority_info ;

extern int hf_rrm_power_control_params_rrm_power_control_params ;
extern int hf_rrm_power_control_params_rrm_power_control_params_bitmask ;
extern int hf_rrm_power_control_params_rrm_power_control_params_rrm_power_control_enable ;
extern int hf_rrm_power_control_params_rrm_power_control_params_rrm_tpc_rnti_range ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_bitmask ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_harqBlerClpcPucchEnable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_cqiSinrClpcPucchEnable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschEnable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pucch_enable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pusch_enable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschfreqSelectiveEnable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_pdcchPowOrAggregationEnable ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_mcs_enabled ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_accumulation_enabled ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1 ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1b ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2 ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2a ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2b ;
extern int hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_preamble_msg_3 ;
extern int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t ;
extern int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPucch ;
extern int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPucch ;
extern int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPusch ;
extern int hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPusch ;
extern int hf_rrm_oam_sps_crnti_range_t ;
extern int hf_rrm_oam_sps_crnti_range_t_start_sps_crnti_range;
extern int hf_rrm_oam_sps_crnti_range_t_end_sps_crnti_range;
extern int hf_rrm_oam_access_mgmt_params_t;
extern int hf_rrm_oam_access_mgmt_params_t_access_mode ;
extern int hf_rrm_oam_access_mgmt_params_t_max_csg_members ;
extern int hf_rrm_oam_access_mgmt_params_t_max_non_csg_members ;
extern int hf_rrm_oam_access_mgmt_params_t_csg_id ;
extern int hf_rrm_oam_access_mgmt_params_t_hnb_name_size ;
extern int hf_rrm_oam_access_mgmt_params_t_hnb_name ;

//BLOCK_CELL_REQ
extern int hf_RRM_OAM_BLOCK_CELL_REQ_unparsed_data;
extern int hf_rrm_oam_block_cell_req_t;
extern int hf_rrm_oam_block_cell_req_t_bitmask;
extern int hf_rrm_oam_block_cell_req_t_global_cell_id;
extern int hf_rrm_oam_block_cell_req_t_cell_block_priority;
extern int hf_rrm_oam_block_cell_req_t_cell_block_resource_cleanup_timer;

//BLOCK_CELL_RESP
extern int hf_RRM_OAM_BLOCK_CELL_RESP_unparsed_data;
extern int hf_rrm_oam_block_cell_resp_t;
extern int hf_rrm_oam_block_cell_resp_t_global_cell_id;
extern int hf_rrm_oam_block_cell_resp_t_response;
extern int hf_rrm_oam_block_cell_resp_t_fail_cause;
      
//RRM_OAM_READY_FOR_CELL_BLOCK_IND
extern int hf_RRM_OAM_READY_FOR_CELL_BLOCK_IND_unparsed_data;
extern int hf_rrm_oam_ready_for_cell_block_ind_t;
extern int hf_rrm_oam_ready_for_cell_block_ind_t_global_cell_id;

//RRM_OAM_UNBLOCK_CELL_CMD
extern int hf_RRM_OAM_UNBLOCK_CELL_CMD_unparsed_data;
extern int hf_rrm_oam_unblock_cell_cmd_t;
extern int hf_rrm_oam_unblock_cell_cmd_t_global_cell_id;


//RRM_OAM_GET_VER_ID_REQ
extern int hf_RRM_OAM_GET_VER_ID_REQ_unspared_data ;
extern int hf_rrm_oam_get_ver_id_req_t ;

//RRM_OAM_GET_VER_ID_RESP
extern int hf_RRM_OAM_GET_VER_ID_RESP_unspared_data ;
extern int hf_rrm_oam_get_ver_id_resp_t;
extern int hf_rrm_oam_get_ver_id_resp_t_response;

//RRM_OAM_CELL_UPDATE_REQ
extern int hf_RRM_OAM_CELL_UPDATE_REQ_unparsed_data ;
extern int hf_rrm_oam_cell_update_req_t ;
extern int hf_rrm_oam_cell_update_req_t_bitmask ;
extern int hf_rrm_oam_cell_update_req_t_global_cell_id ;
extern int hf_rrm_oam_cell_update_req_t_pci_value ;
extern int hf_rrm_oam_cell_update_req_t_updated_plmn_info ;
extern int hf_rrm_oam_cell_update_req_t_conn_mode_cell_spec_off ;
extern int hf_rrm_oam_cell_update_req_t_idle_mode_cell_spec_off ;

//RRM_OAM_UPDATED_PLMN_INFO
extern int hf_RRM_OAM_UPDATED_PLMN_INFO_unparsed_data ;
extern int hf_rrm_oam_updated_plmn_info_t ;
extern int hf_rrm_oam_updated_plmn_info_t_num_valid_plmn ;
extern int hf_rrm_oam_updated_plmn_info_t_cell_plmn_info ;

//CELL_UPDATE_RESP
extern int hf_RRM_OAM_CELL_UPDATE_RESP_unparsed_data;
extern int hf_rrm_oam_cell_update_resp_t;
extern int hf_rrm_oam_cell_update_resp_t_global_cell_id;
extern int hf_rrm_oam_cell_update_resp_t_response;
extern int hf_rrm_oam_cell_update_resp_t_fail_cause;
      
//RRM_OAM_EVENT_NOTIFICATION
extern int hf_RRM_OAM_EVENT_NOTIFICATION_unparsed_data ;
extern int hf_rrm_oam_event_notification_t ;
extern int hf_rrm_oam_event_notification_t_bitmask ;
extern int hf_rrm_oam_event_notification_t_msg_header ;
extern int hf_rrm_oam_event_notification_t_api_data ;

//RRM_OAM_EVENT_HEADER
extern int hf_RRM_OAM_EVENT_HEADER_unparsed_data;
extern int hf_rrm_oam_event_header_t ;
extern int hf_rrm_oam_event_header_t_time_stamp ;
extern int hf_rrm_oam_event_header_t_event_type ;
extern int hf_rrm_oam_event_header_t_event_subtype ;
extern int hf_rrm_oam_event_header_t_event_id ;

//RRM_OAM_TIME_STAMP
extern int hf_RRM_OAM_TIME_STAMP_unparsed_data ;
extern int hf_rrm_oam_time_stamp_t ;
extern int hf_rrm_oam_time_stamp_t_year ;
extern int hf_rrm_oam_time_stamp_t_month ;
extern int hf_rrm_oam_time_stamp_t_day ;
extern int hf_rrm_oam_time_stamp_t_hour ;
extern int hf_rrm_oam_time_stamp_t_min ;
extern int hf_rrm_oam_time_stamp_t_sec ;

//RRM_OAM_LOAD_CONFIG_REQ
extern int hf_RRM_OAM_LOAD_CONFIG_REQ_unparsed_data ;
extern int hf_rrm_oam_load_config_req_t ;
extern int hf_rrm_oam_load_config_req_t_bitmask ;
extern int hf_rrm_oam_load_config_req_t_ncl_load_ind_intrvl ;
extern int hf_rrm_oam_load_config_req_t_load_rpt_intrvl ;
extern int hf_rrm_oam_load_config_req_t_num_enb_cells ;
extern int hf_rrm_oam_load_config_req_t_serv_enb_cell_info ;

//RRM_OAM_SERVING_ENB_CELL_INFO
extern int hf_RRM_OAM_SERVING_ENB_CELL_INFO_unparsed_data ;
extern int hf_rrm_oam_serving_enb_cell_info_t ;
extern int hf_rrm_oam_serving_enb_cell_info_t_bitmask ;
extern int hf_rrm_oam_serving_enb_cell_info_t_global_cell_id ;
extern int hf_rrm_oam_serving_enb_cell_info_t_over_load_lvl_act ;
extern int hf_rrm_oam_serving_enb_cell_info_t_high_load_lvl_act ;
extern int hf_rrm_oam_serving_enb_cell_info_t_mid_load_lvl_act ;
extern int hf_rrm_oam_serving_enb_cell_info_t_resrc_spec ;

//RRM_OAM_LOAD_DEF
extern int hf_RRM_OAM_LOAD_DEF_unparsed_data ;
extern int hf_rrm_oam_over_load_def_t ;
extern int hf_rrm_oam_high_load_def_t ;
extern int hf_rrm_oam_mid_load_def_t ;
extern int hf_rrm_oam_load_def_t_bitmask ;
extern int hf_rrm_oam_load_def_t_load_perctg ;
extern int hf_rrm_oam_load_def_t_action ;
extern int hf_rrm_oam_load_def_t_num_usr ;

//RRM_OAM_LOAD_WATERMARK
extern int hf_RRM_OAM_WATERMARK_unparsed_data ;
extern int hf_rrm_oam_watermark_t;
extern int hf_rrm_oam_watermark_t_high_watermark;
extern int hf_rrm_oam_watermark_t_low_watermark ;

//RRM_OAM_RESOURCE_LOAD_INFO
extern int hf_RRM_OAM_RESOURCE_LOAD_INFO_unparsed_data ;
extern int hf_rrm_oam_resource_load_info_t ;
extern int hf_rrm_oam_resource_load_info_t_bitmask;
extern int hf_rrm_oam_resource_load_info_t_count;
extern int hf_rrm_oam_resource_load_info_t_resrc_info ;

//RRM_OAM_RESRC_INFO
extern int hf_RRM_OAM_RESRC_INFO_unparsed_data ;
extern int hf_rrm_oam_resrc_info_t ;
extern int hf_rrm_oam_resrc_info_t_bitmask ;
extern int hf_rrm_oam_resrc_info_t_resrc_type ;
extern int hf_rrm_oam_resrc_info_t_overload ;
extern int hf_rrm_oam_resrc_info_t_highload ;
extern int hf_rrm_oam_resrc_info_t_midload ;

//RRM_OAM_ACCESS_BARRING_INFO
extern int hf_RRM_OAM_ACCESS_BARRING_INFO_unparsed_data ;
extern int hf_rrm_oam_access_barring_info_t ;
extern int hf_rrm_oam_access_barring_info_t_bitmask;
extern int hf_rrm_oam_access_barring_info_t_class_barring_info ;
extern int hf_rrm_oam_access_barring_info_t_ssac_barring_r9 ;

//RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION
extern int hf_RRM_OAM_ACCESS_CLASS_BARRING_INFORMATION_unparsed_data ;
extern int hf_rrm_oam_access_class_barring_information_t ;
extern int hf_rrm_oam_access_class_barring_information_t_ac_barring_factor ;
extern int hf_rrm_oam_access_class_barring_information_t_ac_barring_time ;
extern int hf_rrm_oam_access_class_barring_information_t_ac_barring_for_special_ac ;

//RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9
extern int hf_RRM_OAM_ACCESS_SSAC_BARRING_FOR_MMTEL_R9_unparsed_data ;
extern int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t ;
extern int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_bitmask ;
extern int hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_class_barring_info ;

//RRM_OAM_LOAD_CONFIG_RESP
extern int hf_RRM_OAM_LOAD_CONFIG_RESP_unparsed_data ;
extern int hf_rrm_oam_load_config_resp_t ;
extern int hf_rrm_oam_load_config_resp_t_response ;
extern int hf_rrm_oam_load_config_resp_t_fail_cause ;

//RRM_OAM_LOAD_REPORT_IND
extern int hf_RRM_OAM_LOAD_REPORT_IND_unparsed_data;
extern int hf_rrm_oam_load_report_ind_t;
extern int hf_rrm_oam_load_cell_info_t;
extern int hf_rrm_oam_load_cell_info_bitmask;
extern int hf_rrm_oam_hw_load_ind_t;
extern int hf_rrm_oam_rs_load_lvl_ul;
extern int hf_rrm_oam_rs_load_lvl_dl;
extern int hf_rrm_oam_s1_tnl_load_ind_t;
extern int hf_rrm_oam_rrs_load_ind_t;
extern int hf_rrm_oam_dl_gbr_prb_usage;
extern int hf_rrm_oam_ul_gbr_prb_usage;
extern int hf_rrm_oam_dl_non_gbr_prb_usage;
extern int hf_rrm_oam_ul_non_gbr_prb_usage;
extern int hf_rrm_oam_dl_total_prb_usage;
extern int hf_rrm_oam_ul_total_prb_usage;
extern int hf_rrm_oam_comp_avl_cap_grp_t;
extern int hf_rrm_oam_comp_avl_cap_dl_t;
extern int hf_rrm_oam_comp_avl_dl_bimask;
extern int hf_rrm_oam_comp_avl_dl_cell_cap_class_val;
extern int hf_rrm_oam_comp_avl_dl_cap_val;
extern int hf_rrm_oam_comp_avl_cap_ul_t;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ
extern int hf_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ_unparsed_data ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_req_t ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_bitmask ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_count ; 
extern int hf_rrm_oam_cell_ecn_capacity_enhance_req_t_ecn_cells ;
    
//RRM_ECN_CONFIGURE_CELL_LIST
extern int hf_RRM_ECN_CONFIGURE_CELL_LIST_unparsed_data ;
extern int hf_rrm_ecn_configure_cell_list_t ;
extern int hf_rrm_ecn_configure_cell_list_t_bitmask;
extern int hf_rrm_ecn_configure_cell_list_t_global_cell_id ;
extern int hf_rrm_ecn_configure_cell_list_t_num_of_ue ;
extern int hf_rrm_ecn_configure_cell_list_t_bitrate ;

//RRM_QCI_BITRATE_INFO
extern int hf_RRM_QCI_BITRATE_INFO_unparsed_data;
extern int hf_rrm_qci_bitrate_info_t ;
extern int hf_rrm_qci_bitrate_info_t_bitmask ;
extern int hf_rrm_qci_bitrate_info_t_count ;
extern int hf_rrm_qci_bitrate_info_t_bitrate_for_qci;

//RRM_CONFIGURE_QCI_BITRATE
extern int hf_RRM_CONFIGURE_QCI_BITRATE_unparsed_data ;
extern int hf_rrm_configure_qci_bitrate_t ;
extern int hf_rrm_configure_qci_bitrate_t_bitmask ;
extern int hf_rrm_configure_qci_bitrate_t_qci ;
extern int hf_rrm_configure_qci_bitrate_t_ul_bitrate ;
extern int hf_rrm_configure_qci_bitrate_t_dl_bitrate ;

//RRM_BITRATE_UL_DL
extern int hf_RRM_BITRATE_UL_DL_unparsed_data ;
extern int hf_rrm_bitrate_ul_dl_t ;
extern int hf_rrm_bitrate_ul_dl_t_max_bitrate ;
extern int hf_rrm_bitrate_ul_dl_t_min_bitrate ;

//RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP
extern int hf_RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP_unparsed_data ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_response ;
extern int hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_fail_cause;

//RRM_OAM_CONFIG_KPI_REQ
extern int hf_RRM_OAM_CONFIG_KPI_REQ_unparsed_data ;
extern int hf_rrm_oam_config_kpi_req_t ;
extern int hf_rrm_oam_config_kpi_req_t_bitmask ;
extern int hf_rrm_oam_config_kpi_req_t_cell_id ;               
extern int hf_rrm_oam_config_kpi_req_t_duration ;
extern int hf_rrm_oam_config_kpi_req_t_periodic_reporting ;
extern int hf_rrm_oam_config_kpi_req_t_kpi_to_report ;

//RRM_OAM_KPI
extern int hf_RRM_OAM_KPI_unparsed_data ;
extern int hf_rrm_oam_kpi_t ;
extern int hf_rrm_oam_kpi_t_bitmap ;
   
//RRM_OAM_CONFIG_KPI_RESP
extern int hf_RRM_OAM_CONFIG_KPI_RESP_unparsed_data ;
extern int hf_rrm_oam_config_kpi_resp_t ;
extern int hf_rrm_oam_config_kpi_resp_t_bitmask ;
extern int hf_rrm_oam_config_kpi_resp_t_global_cell_id ;
extern int hf_rrm_oam_config_kpi_resp_t_response ;
extern int hf_rrm_oam_config_kpi_resp_t_fail_cause ;

//RRM_OAM_GET_KPI_REQ
extern int hf_RRM_OAM_GET_KPI_REQ_unparsed_data ;
extern int hf_rrm_oam_get_kpi_req_t ;
extern int hf_rrm_oam_get_kpi_req_t_bitmask ;
extern int hf_rrm_oam_get_kpi_req_t_cell_id ;
extern int hf_rrm_oam_get_kpi_req_t_reset ;
extern int hf_rrm_oam_get_kpi_req_t_kpi_to_report ;
    
//RRM_OAM_GET_KPI_RESP
extern int hf_RRM_OAM_GET_KPI_RESP_unparsed_data ;
extern int hf_rrm_oam_get_kpi_resp_t ;
extern int hf_rrm_oam_get_kpi_resp_t_bitmask ;
extern int hf_rrm_oam_get_kpi_resp_t_global_cell_id ;
extern int hf_rrm_oam_get_kpi_resp_t_response ;
extern int hf_rrm_oam_get_kpi_resp_t_fail_cause ;
extern int hf_rrm_oam_get_kpi_resp_t_kpi_data ; 

//RRM_OAM_KPI_DATA
extern int hf_RRM_OAM_KPI_DATA_unparsed_data ;
extern int hf_rrm_oam_kpi_data_t ;
extern int hf_rrm_oam_kpi_data_t_num_of_admitted_csg_user ;
extern int hf_rrm_oam_kpi_data_t_num_of_admitted_non_csg_user ;
extern int hf_rrm_oam_kpi_data_t_num_of_ue_admission_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_ue_admission_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_setup_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_setup_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_modify_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_modify_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_release_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_erb_release_fail ;
extern int hf_rrm_oam_kpi_data_t_total_dl_allocated_gbr_prb ;
extern int hf_rrm_oam_kpi_data_t_total_ul_allocated_gbr_prb ;
extern int hf_rrm_oam_kpi_data_t_dl_allocated_ngbr_prb ;
extern int hf_rrm_oam_kpi_data_t_ul_allocated_ngbr_prb ;
extern int hf_rrm_oam_kpi_data_t_num_of_geran_ho_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_geran_ho_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_utran_ho_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_utran_ho_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_eutran_ho_attempt ;
extern int hf_rrm_oam_kpi_data_t_num_of_eutran_ho_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_geran_hi_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_geran_hi_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_utran_hi_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_utran_hi_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_eutran_hi_success ;
extern int hf_rrm_oam_kpi_data_t_num_of_eutran_hi_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_csg_usr ;
extern int hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_non_csg_usr ;
extern int hf_rrm_oam_kpi_data_t_num_of_enb_init_ue_release ;
extern int hf_rrm_oam_kpi_data_t_num_pucch_res_alloc_attempts ;
extern int hf_rrm_oam_kpi_data_t_num_of_sr_res_alloc_fail ;
extern int hf_rrm_oam_kpi_data_t_num_of_sr_cqi_alloc_fail ;
       




//ADDED PT.
extern int hf_rrm_oam_cell_context_print_req_unparsed_data;
extern int hf_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req;

extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_unparsed_data;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_meas_bandwidth;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_no_of_arfcn;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_arfcn_list;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_upp;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_low;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_offset_o;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_adjust;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_penetration_loss;

extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_unparsed_data;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_bitmask;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_dl_earfcn;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_reference_signal_power;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_result;
extern int hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_error_code;

extern int hf_rrm_oam_ue_release_req_t_unparsed_data ;
extern int hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t ;
extern int hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t_ue_index ;

extern int hf_rrm_oam_proc_supervision_resp_t_unparsed_data;
extern int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t;
extern int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_alive_status;
extern int hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_fail_cause;

//DISSECTOR FUNCTIONS.
int dissect_RRM_OAM_CELL_CONFIG_REQ_rrm_oam_cell_config_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 immediate_start_needed = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_config_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_config_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_cell_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_ran_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_epc_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_operator_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if((bitmask & 0x0001) == 0x0001)
    {
        offset_counter += dissect_rrm_oam_access_mgmt_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }

    immediate_start_needed = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_config_req_t_immediate_start_needed, tvb, offset + offset_counter, 4, immediate_start_needed, "immediate_start_needed: %d (0x%x)",immediate_start_needed,immediate_start_needed);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_cell_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_cell_access_restriction_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_eutran_global_cell_id_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 *cell_identity = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_eutran_global_cell_id_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_eutran_global_cell_id_t);
    offset_counter += dissect_rrm_oam_cell_plmn_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, MAX_CELL_IDENTITY_OCTETS);
    cell_identity = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter, MAX_CELL_IDENTITY_OCTETS,
            "cell_identity: %s", cell_identity);
    offset_counter += MAX_CELL_IDENTITY_OCTETS;


    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_cell_plmn_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 *mcc = 0;
    guint8 num_mnc_digit = 0;
    guint8 *mnc = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_plmn_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_myrrm_oam_cell_plmn_info_t);

    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, MAX_MCC_DIGITS);
    mcc = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,MAX_MCC_DIGITS,
            "mcc: %s", mcc);
    offset_counter += MAX_MCC_DIGITS;

    num_mnc_digit = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_plmn_info_t_num_mnc_digit, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;

    if( num_mnc_digit > MAX_MNC_DIGITS)
        num_mnc_digit = MAX_MNC_DIGITS;
    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, num_mnc_digit);
    mnc = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,num_mnc_digit,
            "mnc: %s", mnc);
    offset_counter += num_mnc_digit;


    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_cell_access_restriction_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 cell_barred = 0;
    gint32 intra_freq_reselection = 0;
    gint32 barring_for_emergency = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_access_restriction_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_access_restriction_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    cell_barred = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_access_restriction_params_t_cell_barred, tvb, offset + offset_counter, 4, cell_barred, "cell_barred: %d (0x%x)",cell_barred,cell_barred);
    offset_counter += 4;
    intra_freq_reselection = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_access_restriction_params_t_intra_freq_reselection, tvb, offset + offset_counter, 4, intra_freq_reselection, "intra_freq_reselection: %d (0x%x)",intra_freq_reselection,intra_freq_reselection);
    offset_counter += 4;
    barring_for_emergency = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_access_restriction_params_t_barring_for_emergency, tvb, offset + offset_counter, 4, barring_for_emergency, "barring_for_emergency: %d (0x%x)",barring_for_emergency,barring_for_emergency);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_ran_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_ran_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_ran_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ran_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_physical_layer_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_mac_layer_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_rlc_layer_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_mobility_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_rrc_timers_and_constants_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_rf_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_s1ap_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    if((bitmask & RRM_OAM_NCL_PARAMS_PRESENT) == RRM_OAM_NCL_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_ncl_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_CONNECTED_MODE_MOBILITY_PRESENT) == RRM_OAM_CONNECTED_MODE_MOBILITY_PRESENT)
    {
        offset_counter += dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_physical_layer_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_physical_layer_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_physical_layer_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_physical_layer_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_pdsch_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_srs_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_prach_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_pucch_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_pusch_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_ul_reference_signal_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_uplink_power_control_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    if((bitmask & RRM_OAM_PHYSICAL_LAYER_PARAM_PRS_CONFIG_PRESENT) == RRM_OAM_PHYSICAL_LAYER_PARAM_PRS_CONFIG_PRESENT)
    {
        offset_counter += dissect_rrm_oam_prs_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_ADDITIONAL_PHYSICAL_LAYER_PARAM_PRESENT) == RRM_OAM_ADDITIONAL_PHYSICAL_LAYER_PARAM_PRESENT)
    {
        offset_counter += dissect_rrm_oam_addl_phy_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if ((bitmask & RRM_OAM_PHYSICAL_LAYER_PARAM_TDD_FRAME_PRESENT) == RRM_OAM_PHYSICAL_LAYER_PARAM_TDD_FRAME_PRESENT )
    {
    offset_counter += dissect_rrm_oam_tdd_frame_structure_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_pdsch_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 p_b = 0;
    gint32 p_a = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_pdsch_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_pdsch_t);
    p_b = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_pdsch_t_p_b, tvb, offset + offset_counter, 4, p_b, "p_b: %d (0x%x)",p_b,p_b);
    offset_counter += 4;
    p_a = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_pdsch_t_p_a, tvb, offset + offset_counter, 4, p_a, "p_a: %d (0x%x)",p_a,p_a);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_srs_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 srsEnabled = 0;
    gint32 srs_bandwidth_config = 0;
    gint32 srs_subframe_config = 0;
    gint32 srs_max_up_pts = 0;
    gint32 ack_nack_srs_simultaneous_transmission = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_srs_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_srs_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_srs_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    srsEnabled = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srs_t_srsEnabled, tvb, offset + offset_counter, 4, srsEnabled, "srsEnabled: %d (0x%x)",srsEnabled,srsEnabled);
    offset_counter += 4;
    srs_bandwidth_config = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srs_t_srs_bandwidth_config, tvb, offset + offset_counter, 4, srs_bandwidth_config, "srs_bandwidth_config: %d (0x%x)",srs_bandwidth_config,srs_bandwidth_config);
    offset_counter += 4;
    srs_subframe_config = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srs_t_srs_subframe_config, tvb, offset + offset_counter, 4, srs_subframe_config, "srs_subframe_config: %d (0x%x)",srs_subframe_config,srs_subframe_config);
    offset_counter += 4;

   // if((bitmask & RRM_OAM_SRS_MAX_UP_PTS_PRESENT) == RRM_OAM_SRS_MAX_UP_PTS_PRESENT)
    if(bitmask & 0x01)
    {
        srs_max_up_pts = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srs_t_srs_max_up_pts, tvb, offset + offset_counter, 4, srs_max_up_pts, "srs_max_up_pts: %d (0x%x)",srs_max_up_pts,srs_max_up_pts);
        offset_counter += 4;
    }
    ack_nack_srs_simultaneous_transmission = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srs_t_ack_nack_srs_simultaneous_transmission, tvb, offset + offset_counter, 4, ack_nack_srs_simultaneous_transmission, "ack_nack_srs_simultaneous_transmission: %d (0x%x)",ack_nack_srs_simultaneous_transmission,ack_nack_srs_simultaneous_transmission);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_prach_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint16 root_sequence_index = 0;
    guint8 configuration_index = 0;
    guint8 high_speed_flag = 0;
    guint8 zero_correlation_zone_config = 0;
    guint8 frequency_offset = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_prach_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_prach_t);
    root_sequence_index = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prach_t_root_sequence_index, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    configuration_index = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prach_t_configuration_index, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    high_speed_flag = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prach_t_high_speed_flag, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    zero_correlation_zone_config = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prach_t_zero_correlation_zone_config, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    frequency_offset = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prach_t_frequency_offset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_pucch_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 delta_pucch_shift = 0;
    guint8 n_rb_cqi = 0;
    guint16 n1_pucch_an = 0;
    guint16 cqi_pucch_resource_index = 0;
    guint8 tdd_ack_nack_feedback_mode = 0;
    guint8 pucch_cqi_sinr_value = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_pucch_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_pucch_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    delta_pucch_shift = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_delta_pucch_shift, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    n_rb_cqi = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_n_rb_cqi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    n1_pucch_an = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_n1_pucch_an, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    cqi_pucch_resource_index = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_cqi_pucch_resource_index, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    if( bitmask & 0x0001 )
    {
    	tdd_ack_nack_feedback_mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_tdd_ack_nack_feedback_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    	offset_counter += 1;
    }		
    if( bitmask & 0x0002 )
    {
    	pucch_cqi_sinr_value = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pucch_t_pucch_cqi_sinr_value, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    	offset_counter += 1;
    }		
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_pusch_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 n_sb = 0;
    gint32 pusch_hopping_mode = 0;
    guint8 hopping_offset = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_pusch_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_pusch_t);
    n_sb = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pusch_t_n_sb, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    pusch_hopping_mode = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_pusch_t_pusch_hopping_mode, tvb, offset + offset_counter, 4, pusch_hopping_mode, "pusch_hopping_mode: %d (0x%x)",pusch_hopping_mode,pusch_hopping_mode);
    offset_counter += 4;
    hopping_offset = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pusch_t_hopping_offset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_ul_reference_signal_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 group_hopping_enabled = 0;
    gint32 sequence_hopping_enabled = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_ul_reference_signal_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_ul_reference_signal_t);
    group_hopping_enabled = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_ul_reference_signal_t_group_hopping_enabled, tvb, offset + offset_counter, 4, group_hopping_enabled, "group_hopping_enabled: %d (0x%x)",group_hopping_enabled,group_hopping_enabled);
    offset_counter += 4;
    sequence_hopping_enabled = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_ul_reference_signal_t_sequence_hopping_enabled, tvb, offset + offset_counter, 4, sequence_hopping_enabled, "sequence_hopping_enabled: %d (0x%x)",sequence_hopping_enabled,sequence_hopping_enabled);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_uplink_power_control_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint8 p_0_nominal_pusch = 0;
    gint32 alpha = 0;
    gint8 p_0_nominal_pucch = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_uplink_power_control_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_uplink_power_control_t);
    p_0_nominal_pusch = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_uplink_power_control_t_p_0_nominal_pusch, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    alpha = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_uplink_power_control_t_alpha, tvb, offset + offset_counter, 4, alpha, "alpha: %d (0x%x)",alpha,alpha);
    offset_counter += 4;
    p_0_nominal_pucch = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_uplink_power_control_t_p_0_nominal_pucch, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_tdd_frame_structure_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
{
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
    guint32 sub_frame_assignment = 0;
    guint32 special_sub_frame_patterns = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_tdd_frame_structure_t,tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_tdd_frame_structure_t);
    sub_frame_assignment = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_tdd_frame_structure_t_sub_frame_assignment, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;

    special_sub_frame_patterns = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_tdd_frame_structure_t_special_sub_frame_patterns, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;


}

int dissect_rrm_oam_addl_phy_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_addl_phy_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_phy_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_phy_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_ADDITIONAL_PUCCH_PARAMS_PRESENT) == RRM_OAM_ADDITIONAL_PUCCH_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_addl_pucch_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_ADDITIONAL_PUSCH_PARAMS_PRESENT) == RRM_OAM_ADDITIONAL_PUSCH_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_addl_pusch_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_ADDITIONAL_UL_REF_SIGNAL_PARAMS_PRESENT) == RRM_OAM_ADDITIONAL_UL_REF_SIGNAL_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_addl_ul_reference_signal_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_addl_pucch_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 bitmask = 0;
    gint8 n1_cs = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_addl_pucch_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_pucch_config_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_pucch_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_N1_CS_PRESENT) == RRM_OAM_N1_CS_PRESENT)
    {	
    n1_cs = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_pucch_config_t_n1_cs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }	
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_addl_pusch_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 pusch_enable_64_qam = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_addl_pusch_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_pusch_config_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_pusch_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_PUSCH_ENABLE_64_QAM_PRESENT) == RRM_OAM_PUSCH_ENABLE_64_QAM_PRESENT)
    {	
    pusch_enable_64_qam = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_pusch_config_t_pusch_enable_64_qam, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }	
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_addl_ul_reference_signal_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 group_assignment_pusch = 0;
    guint8 ul_reference_signal_pusch_cyclicshift = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_addl_ul_reference_signal_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_ul_reference_signal_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_ul_reference_signal_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_GROUP_ASSIGMENT_PUSCH_PRESENT) == RRM_OAM_GROUP_ASSIGMENT_PUSCH_PRESENT)
    {	
    group_assignment_pusch = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_ul_reference_signal_params_t_group_assignment_pusch, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }	
    if((bitmask & RRM_OAM_UL_REFER_SIGNAL_PUSCH_CYCLIC_SHIFT_PRESENT) == RRM_OAM_UL_REFER_SIGNAL_PUSCH_CYCLIC_SHIFT_PRESENT)
    {	
    ul_reference_signal_pusch_cyclicshift = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_ul_reference_signal_params_t_ul_reference_signal_pusch_cyclicshift, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }	proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_rrm_oam_prs_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_prs_resource_blocks = 0;
    guint16 prs_configuration_index = 0;
    gint32 num_consecutive_prs_subfames = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_prs_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_prs_t);
    num_prs_resource_blocks = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prs_t_num_prs_resource_blocks, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    prs_configuration_index = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_prs_t_prs_configuration_index, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    num_consecutive_prs_subfames = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_prs_t_num_consecutive_prs_subfames, tvb, offset + offset_counter, 4, num_consecutive_prs_subfames, "num_consecutive_prs_subfames: %d (0x%x)",num_consecutive_prs_subfames,num_consecutive_prs_subfames);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_mac_layer_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint ul_sync_loss_timer = 0;
    gint n_gap = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_mac_layer_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_mac_layer_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_rach_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_drx_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    ul_sync_loss_timer = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree,hf_rrm_oam_mac_layer_params_t_ul_sync_loss_timer, tvb, offset + offset_counter, 4, ul_sync_loss_timer, "ul_sync_loss_timer: %d (0x%x)",ul_sync_loss_timer,ul_sync_loss_timer);
    offset_counter += 4;
    n_gap = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree,hf_rrm_oam_mac_layer_params_t_ul_ngap, tvb, offset + offset_counter, 4, n_gap, "n_gap: %d (0x%x)",n_gap,n_gap);
    offset_counter += 4;
     
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rach_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 power_ramping_step = 0;
    gint32 preamble_initial_received_target_power = 0;
    gint32 preamble_trans_max = 0;
    gint32 response_window_size = 0;
    gint32 contention_resolution_timer = 0;
    guint8 max_harq_msg_3tx = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rach_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rach_t);
    offset_counter += dissect_rrm_oam_preamble_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    power_ramping_step = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rach_t_power_ramping_step, tvb, offset + offset_counter, 4, power_ramping_step, "power_ramping_step: %d (0x%x)",power_ramping_step,power_ramping_step);
    offset_counter += 4;
    preamble_initial_received_target_power = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rach_t_preamble_initial_received_target_power, tvb, offset + offset_counter, 4, preamble_initial_received_target_power, "preamble_initial_received_target_power: %d (0x%x)",preamble_initial_received_target_power,preamble_initial_received_target_power);
    offset_counter += 4;
    preamble_trans_max = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rach_t_preamble_trans_max, tvb, offset + offset_counter, 4, preamble_trans_max, "preamble_trans_max: %d (0x%x)",preamble_trans_max,preamble_trans_max);
    offset_counter += 4;
    response_window_size = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rach_t_response_window_size, tvb, offset + offset_counter, 4, response_window_size, "response_window_size: %d (0x%x)",response_window_size,response_window_size);
    offset_counter += 4;
    contention_resolution_timer = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rach_t_contention_resolution_timer, tvb, offset + offset_counter, 4, contention_resolution_timer, "contention_resolution_timer: %d (0x%x)",contention_resolution_timer,contention_resolution_timer);
    offset_counter += 4;
    max_harq_msg_3tx = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rach_t_max_harq_msg_3tx, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_preamble_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 number_of_ra_preambles = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_preamble_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_preamble_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_preamble_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    number_of_ra_preambles = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_preamble_info_t_number_of_ra_preambles, tvb, offset + offset_counter, 4, number_of_ra_preambles, "number_of_ra_preambles: %d (0x%x)",number_of_ra_preambles,number_of_ra_preambles);
    offset_counter += 4;
    if((bitmask & RRM_OAM_RA_PREABLE_GROUPA_INFO_PRESENT) == RRM_OAM_RA_PREABLE_GROUPA_INFO_PRESENT )
    {

        offset_counter += dissect_rrm_oam_preamble_groupA_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_preamble_groupA_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 size_of_ra_group_a = 0;
    gint32 message_size_group_a = 0;
    gint32 message_power_offset_group_b = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_preamble_groupA_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_preamble_groupA_info_t);
    size_of_ra_group_a = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_preamble_groupA_info_t_size_of_ra_group_a, tvb, offset + offset_counter, 4, size_of_ra_group_a, "size_of_ra_group_a: %d (0x%x)",size_of_ra_group_a,size_of_ra_group_a);
    offset_counter += 4;
    message_size_group_a = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_preamble_groupA_info_t_message_size_group_a, tvb, offset + offset_counter, 4, message_size_group_a, "message_size_group_a: %d (0x%x)",message_size_group_a,message_size_group_a);
    offset_counter += 4;
    message_power_offset_group_b = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_preamble_groupA_info_t_message_power_offset_group_b, tvb, offset + offset_counter, 4, message_power_offset_group_b, "message_power_offset_group_b: %d (0x%x)",message_power_offset_group_b,message_power_offset_group_b);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_drx_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 drx_enabled = 0;
    guint8 num_valid_drx_profiles = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_drx_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_drx_t);
    drx_enabled = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_drx_t_drx_enabled, tvb, offset + offset_counter, 4, drx_enabled, "drx_enabled: %d (0x%x)",drx_enabled,drx_enabled);
    offset_counter += 4;
    num_valid_drx_profiles = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_drx_t_num_valid_drx_profiles, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_drx_profiles >  MAX_NO_DRX_PROFILE)
        num_valid_drx_profiles = MAX_NO_DRX_PROFILE;
    for(loop_counter = 0; loop_counter < num_valid_drx_profiles; loop_counter++ ){
        rrm_oam_drx_config_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_drx_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_drx_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 num_applicable_qci = 0;
    guint8 applicable_qci_list = 0;
    gint32 on_duration_timer = 0;
    gint32 drx_inactivity_timer = 0;
    gint32 drx_retransmission_timer = 0;
    gint32 long_drx_cycle = 0;
    guint16 drx_start_offset = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_drx_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_drx_config_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_drx_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    num_applicable_qci = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_drx_config_t_num_applicable_qci, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    //if (0 != num_applicable_qci && num_applicable_qci > RRM_OAM_MAX_NUM_QCI_CLASSES)
    //{
     //   num_applicable_qci = RRM_OAM_MAX_NUM_QCI_CLASSES;
     for(loop_counter = 0;loop_counter < num_applicable_qci;loop_counter++)
     {	
        applicable_qci_list = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_drx_config_t_applicable_qci_list, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
     }
    on_duration_timer = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_drx_config_t_on_duration_timer, tvb, offset + offset_counter, 4, on_duration_timer, "on_duration_timer: %d (0x%x)",on_duration_timer,on_duration_timer);
    offset_counter += 4;
    drx_inactivity_timer = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_drx_config_t_drx_inactivity_timer, tvb, offset + offset_counter, 4, drx_inactivity_timer, "drx_inactivity_timer: %d (0x%x)",drx_inactivity_timer,drx_inactivity_timer);
    offset_counter += 4;
    drx_retransmission_timer = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_drx_config_t_drx_retransmission_timer, tvb, offset + offset_counter, 4, drx_retransmission_timer, "drx_retransmission_timer: %d (0x%x)",drx_retransmission_timer,drx_retransmission_timer);
    offset_counter += 4;
    long_drx_cycle = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_drx_config_t_long_drx_cycle, tvb, offset + offset_counter, 4, long_drx_cycle, "long_drx_cycle: %d (0x%x)",long_drx_cycle,long_drx_cycle);
    offset_counter += 4;
    drx_start_offset = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_drx_config_t_drx_start_offset, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    if((bitmask & RRM_OAM_SHORT_DRX_CYCLE_PRESENT) == RRM_OAM_SHORT_DRX_CYCLE_PRESENT)
    {
        offset_counter += dissect_rrm_oam_short_drx_cycle_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_short_drx_cycle_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 short_drx_cycle = 0;
    guint8 drx_short_cycle_timer = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_short_drx_cycle_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_short_drx_cycle_config_t);
    short_drx_cycle = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_short_drx_cycle_config_t_short_drx_cycle, tvb, offset + offset_counter, 4, short_drx_cycle, "short_drx_cycle: %d (0x%x)",short_drx_cycle,short_drx_cycle);
    offset_counter += 4;
    drx_short_cycle_timer = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_short_drx_cycle_config_t_drx_short_cycle_timer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rlc_layer_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_srb_info = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rlc_layer_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rlc_layer_params_t);
    num_valid_srb_info = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rlc_layer_params_t_num_valid_srb_info, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_srb_info > MAX_NO_SRB )
        num_valid_srb_info = MAX_NO_SRB ;
    for(loop_counter = 0; loop_counter < num_valid_srb_info; loop_counter++ ){
        rrm_oam_srb_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_srb_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_srb_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 default_configuration = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_srb_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_srb_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_srb_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    default_configuration = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_t_default_configuration, tvb, offset + offset_counter, 4, default_configuration, "default_configuration: %d (0x%x)",default_configuration,default_configuration);
    offset_counter += 4;
    if((bitmask & RRM_OAM_SRB_INFO_PRESENT) == RRM_OAM_SRB_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_srb_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_srb_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 t_poll_retransmit = 0;
    gint32 poll_pdu = 0;
    gint32 poll_byte = 0;
    gint32 max_retx_threshold = 0;
    gint32 t_reordering = 0;
    gint32 t_status_prohibit = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_srb_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_srb_info_t);
    t_poll_retransmit = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_t_poll_retransmit, tvb, offset + offset_counter, 4, t_poll_retransmit, "t_poll_retransmit: %d (0x%x)",t_poll_retransmit,t_poll_retransmit);
    offset_counter += 4;
    poll_pdu = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_poll_pdu, tvb, offset + offset_counter, 4, poll_pdu, "poll_pdu: %d (0x%x)",poll_pdu,poll_pdu);
    offset_counter += 4;
    poll_byte = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_poll_byte, tvb, offset + offset_counter, 4, poll_byte, "poll_byte: %d (0x%x)",poll_byte,poll_byte);
    offset_counter += 4;
    max_retx_threshold = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_max_retx_threshold, tvb, offset + offset_counter, 4, max_retx_threshold, "max_retx_threshold: %d (0x%x)",max_retx_threshold,max_retx_threshold);
    offset_counter += 4;
    t_reordering = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_t_reordering, tvb, offset + offset_counter, 4, t_reordering, "t_reordering: %d (0x%x)",t_reordering,t_reordering);
    offset_counter += 4;
    t_status_prohibit = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_srb_info_t_t_status_prohibit, tvb, offset + offset_counter, 4, t_status_prohibit, "t_status_prohibit: %d (0x%x)",t_status_prohibit,t_status_prohibit);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_mobility_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_mobility_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_mobility_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mobility_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if(bitmask & 0x01)
    offset_counter += dissect_rrm_oam_idle_mode_mobility_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_idle_mode_mobility_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_common_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_intra_freq_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_inter_frequency_params_list_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_common_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 q_hyst = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_common_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_common_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_common_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    q_hyst = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_common_params_t_q_hyst, tvb, offset + offset_counter, 4, q_hyst, "q_hyst: %d (0x%x)",q_hyst,q_hyst);
    offset_counter += 4;
    if((bitmask & RRM_OAM_SPEED_STATE_PARAMS_PRESENT) == RRM_OAM_SPEED_STATE_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_speed_state_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_speed_state_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 q_hyst_sf_medium = 0;
    gint32 q_hyst_sf_high = 0;
    gint32 t_evaluation = 0;
    gint32 t_hyst_normal = 0;
    guint8 n_cell_change_medium = 0;
    guint8 n_cell_change_high = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_speed_state_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_speed_state_params_t);
    q_hyst_sf_medium = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_state_params_t_q_hyst_sf_medium, tvb, offset + offset_counter, 4, q_hyst_sf_medium, "q_hyst_sf_medium: %d (0x%x)",q_hyst_sf_medium,q_hyst_sf_medium);
    offset_counter += 4;
    q_hyst_sf_high = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_state_params_t_q_hyst_sf_high, tvb, offset + offset_counter, 4, q_hyst_sf_high, "q_hyst_sf_high: %d (0x%x)",q_hyst_sf_high,q_hyst_sf_high);
    offset_counter += 4;
    t_evaluation = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_state_params_t_t_evaluation, tvb, offset + offset_counter, 4, t_evaluation, "t_evaluation: %d (0x%x)",t_evaluation,t_evaluation);
    offset_counter += 4;
    t_hyst_normal = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_state_params_t_t_hyst_normal, tvb, offset + offset_counter, 4, t_hyst_normal, "t_hyst_normal: %d (0x%x)",t_hyst_normal,t_hyst_normal);
    offset_counter += 4;
    n_cell_change_medium = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_speed_state_params_t_n_cell_change_medium, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    n_cell_change_high = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_speed_state_params_t_n_cell_change_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_intra_freq_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint8 q_rx_lev_min_sib_1 = 0;
    gint8 q_rx_lev_min_offset = 0;
    gint8 p_max_sib_1 = 0;
    gint8 p_max_sib_3 = 0;
    gint8 q_rx_lev_min_sib_3 = 0;
    guint8 s_intra_search = 0;
    guint8 t_reselection_eutra = 0;
    guint8 s_non_intra_search = 0;
    guint8 cell_reselection_priority = 0;
    guint8 thresh_serving_low = 0;
    guint8 neigh_cell_config = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_intra_freq_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_intra_freq_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    q_rx_lev_min_sib_1 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_Q_RX_LEV_MIN_OFFSET_PRESENT) == RRM_OAM_Q_RX_LEV_MIN_OFFSET_PRESENT)
    {
        q_rx_lev_min_offset = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_offset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_P_MAX_SIB1_PRESENT) == RRM_OAM_P_MAX_SIB1_PRESENT)
    {
        p_max_sib_1 = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_p_max_sib_1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_P_MAX_SIB3_PRESENT) == RRM_OAM_P_MAX_SIB3_PRESENT)
    {
        p_max_sib_3 = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_p_max_sib_3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }


    q_rx_lev_min_sib_3 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_q_rx_lev_min_sib_3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;

    if((bitmask & RRM_OAM_S_INTRA_SEARCH_PRESENT) == RRM_OAM_S_INTRA_SEARCH_PRESENT)
    {
        s_intra_search = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_s_intra_search, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }

    t_reselection_eutra = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_t_reselection_eutra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_T_RESELECTION_EUTR_SPEED_SCALE_FACTOR_PRESENT) == RRM_OAM_T_RESELECTION_EUTR_SPEED_SCALE_FACTOR_PRESENT)
    {
        offset_counter += dissect_rrm_oam_speed_scale_factors_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }

    if((bitmask & RRM_OAM_S_NON_INTRA_SEARCH_PRESENT) == RRM_OAM_S_NON_INTRA_SEARCH_PRESENT)
    {
        s_non_intra_search = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_s_non_intra_search, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    thresh_serving_low = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_thresh_serving_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    neigh_cell_config = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_params_t_neigh_cell_config, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_speed_scale_factors_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 t_reselection_eutra_sf_medium = 0;
    gint32 t_reselection_eutra_sf_high = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_speed_scale_factors_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_speed_scale_factors_t);
    t_reselection_eutra_sf_medium = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_medium, tvb, offset + offset_counter, 4, t_reselection_eutra_sf_medium, "t_reselection_eutra_sf_medium: %d (0x%x)",t_reselection_eutra_sf_medium,t_reselection_eutra_sf_medium);
    offset_counter += 4;
    t_reselection_eutra_sf_high = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_speed_scale_factors_t_t_reselection_eutra_sf_high, tvb, offset + offset_counter, 4, t_reselection_eutra_sf_high, "t_reselection_eutra_sf_high: %d (0x%x)",t_reselection_eutra_sf_high,t_reselection_eutra_sf_high);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_inter_frequency_params_list_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_inter_freq_list = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_inter_frequency_params_list_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_frequency_params_list_t);
    num_valid_inter_freq_list = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_frequency_params_list_t_num_valid_inter_freq_list, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_inter_freq_list > RRM_OAM_MAX_NUM_INTER_FREQ_CELLS)
        num_valid_inter_freq_list = RRM_OAM_MAX_NUM_INTER_FREQ_CELLS ;
    for(loop_counter = 0; loop_counter < num_valid_inter_freq_list; loop_counter++ ){
        rrm_oam_inter_freq_params_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_inter_freq_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_inter_freq_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 eutra_carrier_arfcn = 0;
    gint8 q_rx_lev_min_sib_5 = 0;
    gint32 q_offset_freq = 0;
    guint8 t_reselection_eutra = 0;
    guint8 cell_reselection_priority = 0;
    guint8 thresh_x_high = 0;
    guint8 thresh_x_low = 0;
    gint8 p_max = 0;
    gint32 measurement_bandwidth = 0;
    guint8 presence_antenna_port1 = 0;
    guint8 neigh_cell_config = 0;
    gint8 q_qual_min_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_inter_freq_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_freq_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    eutra_carrier_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_eutra_carrier_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    q_rx_lev_min_sib_5 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_q_rx_lev_min_sib_5, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    q_offset_freq = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_inter_freq_params_t_q_offset_freq, tvb, offset + offset_counter, 4, q_offset_freq, "q_offset_freq: %d (0x%x)",q_offset_freq,q_offset_freq);
    offset_counter += 4;
    t_reselection_eutra = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_t_reselection_eutra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_INTER_FREQ_CELL_RESELECTION_PRIORITY_PRESENT) == RRM_OAM_INTER_FREQ_CELL_RESELECTION_PRIORITY_PRESENT)
    {
        cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    thresh_x_high = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_thresh_x_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    thresh_x_low = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_thresh_x_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_P_MAX_PRESENT) == RRM_OAM_P_MAX_PRESENT)
    {
        p_max = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_p_max, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }

    measurement_bandwidth = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_inter_freq_params_t_measurement_bandwidth, tvb, offset + offset_counter, 4, measurement_bandwidth, "measurement_bandwidth: %d (0x%x)",measurement_bandwidth,measurement_bandwidth);
    offset_counter += 4;

    presence_antenna_port1 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_presence_antenna_port1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    neigh_cell_config = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_neigh_cell_config, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_T_EUTR_SPEED_SCALE_FACTOR_PRESENT) == RRM_OAM_T_EUTR_SPEED_SCALE_FACTOR_PRESENT)
    {
        offset_counter += dissect_rrm_oam_speed_scale_factors_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_Q_QUAL_MIN_R9_PRESENT) == RRM_OAM_Q_QUAL_MIN_R9_PRESENT)
    {
        q_qual_min_r9 = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_params_t_q_qual_min_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_THRESHX_Q_R9_PRESENT) == RRM_OAM_THRESHX_Q_R9_PRESENT)
    {
        offset_counter += dissect_rrm_oam_thresholdx_q_r9_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_thresholdx_q_r9_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 thresh_serving_highq_r9 = 0;
    guint8 thresh_serving_lowq_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_thresholdx_q_r9_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_thresholdx_q_r9_t);
    thresh_serving_highq_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_highq_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    thresh_serving_lowq_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_thresholdx_q_r9_t_thresh_serving_lowq_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rrc_timers_and_constants_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rrc_timers_and_constants_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rrc_timers_and_constants_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_rrc_timers_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_rrc_constants_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rrc_timers_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 t300 = 0;
    gint32 t301 = 0;
    gint32 t302 = 0;
    gint32 t304_eutra = 0;
    gint32 t304_irat = 0;
    gint32 t310 = 0;
    gint32 t311 = 0;
    gint32 t320 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rrc_timers_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rrc_timers_t);
    t300 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t300, tvb, offset + offset_counter, 4, t300, "t300: %d (0x%x)",t300,t300);
    offset_counter += 4;
    t301 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t301, tvb, offset + offset_counter, 4, t301, "t301: %d (0x%x)",t301,t301);
    offset_counter += 4;
    t302 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t302, tvb, offset + offset_counter, 4, t302, "t302: %d (0x%x)",t302,t302);
    offset_counter += 4;
    t304_eutra = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t304_eutra, tvb, offset + offset_counter, 4, t304_eutra, "t304_eutra: %d (0x%x)",t304_eutra,t304_eutra);
    offset_counter += 4;
    t304_irat = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t304_irat, tvb, offset + offset_counter, 4, t304_irat, "t304_irat: %d (0x%x)",t304_irat,t304_irat);
    offset_counter += 4;
    t310 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t310, tvb, offset + offset_counter, 4, t310, "t310: %d (0x%x)",t310,t310);
    offset_counter += 4;
    t311 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t311, tvb, offset + offset_counter, 4, t311, "t311: %d (0x%x)",t311,t311);
    offset_counter += 4;
    t320 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_timers_t_t320, tvb, offset + offset_counter, 4, t320, "t320: %d (0x%x)",t320,t320);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rrc_constants_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 n310 = 0;
    gint32 n311 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rrc_constants_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rrc_constants_t);
    n310 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_constants_t_n310, tvb, offset + offset_counter, 4, n310, "n310: %d (0x%x)",n310,n310);
    offset_counter += 4;
    n311 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rrc_constants_t_n311, tvb, offset + offset_counter, 4, n311, "n311: %d (0x%x)",n311,n311);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rf_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_rf_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rf_params_t);
    offset_counter += dissect_rrm_oam_rf_configurations_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rf_configurations_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 frequency_band_indicator = 0;
    guint16 dl_earfcn = 0;
    gint32 dl_bandwidth = 0;
    guint16 ul_earfcn = 0;
    gint32 ul_bandwidth = 0;
    gint8 reference_signal_power = 0;
    guint16 phy_cell_id = 0;
    gint16 psch_power_offset = 0;
    gint16 ssch_power_offset = 0;
    gint16 pbch_power_offset = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rf_configurations_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rf_configurations_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    frequency_band_indicator = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_frequency_band_indicator, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    dl_earfcn = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_dl_earfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    dl_bandwidth = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rf_configurations_t_dl_bandwidth, tvb, offset + offset_counter, 4, dl_bandwidth, "dl_bandwidth: %d (0x%x)",dl_bandwidth,dl_bandwidth);
    offset_counter += 4;
    if((bitmask & RRM_OAM_RF_CONFIGURATION_UL_EARFCN_PRESENT) == RRM_OAM_RF_CONFIGURATION_UL_EARFCN_PRESENT)
    {
        ul_earfcn = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_ul_earfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
    }
    if((bitmask & RRM_OAM_RF_CONFIGURATION_UL_BW_PRESENT) == RRM_OAM_RF_CONFIGURATION_UL_BW_PRESENT)
    {
        ul_bandwidth = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rf_configurations_t_ul_bandwidth, tvb, offset + offset_counter, 4, ul_bandwidth, "ul_bandwidth: %d (0x%x)",ul_bandwidth,ul_bandwidth);
        offset_counter += 4;
    }
    reference_signal_power = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_reference_signal_power, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    phy_cell_id = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rf_configurations_t_phy_cell_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    psch_power_offset = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rf_configurations_t_psch_power_offset, tvb, offset + offset_counter, 2, psch_power_offset, "psch_power_offset: %hd (0x%hx)",psch_power_offset,psch_power_offset);
    offset_counter += 2;
    ssch_power_offset = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rf_configurations_t_ssch_power_offset, tvb, offset + offset_counter, 2, ssch_power_offset, "ssch_power_offset: %hd (0x%hx)",ssch_power_offset,ssch_power_offset);
    offset_counter += 2;
    pbch_power_offset = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rf_configurations_t_pbch_power_offset, tvb, offset + offset_counter, 2, pbch_power_offset, "pbch_power_offset: %hd (0x%hx)",pbch_power_offset,pbch_power_offset);
    offset_counter += 2;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_s1ap_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 t_reloc_prep = 0;
    guint8 t_reloc_overall = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_s1ap_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_s1ap_params_t);
    t_reloc_prep = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s1ap_params_t_t_reloc_prep, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    t_reloc_overall = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s1ap_params_t_t_reloc_overall, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_ncl_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_ncl_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_ncl_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ncl_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_LTE_NCL_PRESENT) == RRM_OAM_LTE_NCL_PRESENT)
    {
        offset_counter += dissect_rrm_oam_lte_ncl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if(bitmask & 0x02)
    {
        offset_counter += dissect_rrm_oam_inter_rat_ncl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_inter_rat_ncl_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_intra_freq_cell = 0;
    guint8 num_valid_inter_freq_cell = 0;
    guint32 bitmask = 0;
    guint8 num_valid_utran_freq_cell = 0;
    guint8 num_valid_geran_freq_cell = 0;
    guint8 num_valid_cdma2000_freq_cells = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    num_valid_utran_freq_cell = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_num_valid_utran_freq_cell, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    for(loop_counter = 0;loop_counter < num_valid_utran_freq_cell;loop_counter++)
        offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    num_valid_geran_freq_cell = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_num_valid_geran_freq_cell, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    for(loop_counter = 0;loop_counter < num_valid_geran_freq_cell;loop_counter++)
        offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    num_valid_cdma2000_freq_cells = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_num_valid_cdma2000_freq_cells, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    for(loop_counter = 0;loop_counter < num_valid_cdma2000_freq_cells;loop_counter++)
        offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint16 ura = 0;
	guint16 uarfcnul = 0;
	guint16 uarfcndl = 0;
	guint16 pcpich_scrambling_code = 0;
	guint16 pcpich_tx_power = 0;
	guint8 offset_freq = 0;
	guint32 cell_access_mode = 0;
	guint32 blacklisted = 0;
	guint8 csg_identity = 0;
	guint32 ho_status = 0;
	guint8 ps_ho_supported = 0;
	guint8 voip_capable = 0;
	guint8 daho_indication = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_rai_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_utran_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	ura = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ura, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if(bitmask & 0x01)
	{
	uarfcnul = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcnul, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	uarfcndl = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_uarfcndl, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pcpich_scrambling_code = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_scrambling_code, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pcpich_tx_power = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_pcpich_tx_power, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	offset_freq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_offset_freq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x02)
	{
	cell_access_mode = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_cell_access_mode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	blacklisted = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_blacklisted, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x04)
	{
	for(loop_counter = 0;loop_counter < 4;loop_counter++)
	{
	csg_identity = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_csg_identity, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	}
	if(bitmask & 0x08)
	{
	ho_status = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ho_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x10)
	{
	ps_ho_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_ps_ho_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20)
	{
	voip_capable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_voip_capable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40)
	{
	daho_indication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_utran_freq_cells_t_daho_indication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_utran_cell_id_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 cell_id = 0;
	guint16 rnc_id = 0;
	guint16 extended_rnc_id = 0;
	item = proto_tree_add_item(tree, hf_rrm_utran_cell_id_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_utran_cell_id_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_utran_cell_id_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0;loop_counter < 4;loop_counter++)
	{
	cell_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_utran_cell_id_t_cell_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	rnc_id = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_utran_cell_id_t_rnc_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if(bitmask & 0x01)
	{
	extended_rnc_id = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_utran_cell_id_t_extended_rnc_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}


int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_rai_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 rac = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_rai_t);
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_lai_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	rac = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_rai_t_rac, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_lai_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 lac = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_lai_t);
	offset_counter += dissect_rrm_oam_cell_plmn_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	for(loop_counter = 0;loop_counter < 2;loop_counter++)
	{
	lac = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_lai_t_lac, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint16 cell_id = 0;
	guint32 bandindicator = 0;
	guint16 bccharfcn = 0;
	guint16 pci = 0;
	guint32 network_control_order = 0;
	guint32 ho_status = 0;
	guint8 dtm_supported = 0;
	guint8 dtm_ho_supported = 0;
	guint8 voip_capable = 0;
	guint8 daho_indication = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_lai_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	cell_id = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_cell_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	bandindicator = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bandindicator, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	bccharfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_bccharfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pci = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_pci, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	if(bitmask & 0x01)
	{
	network_control_order = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_network_control_order, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	ho_status = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_ho_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x04)
	{
	dtm_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	dtm_ho_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_dtm_ho_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	voip_capable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_voip_capable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20)
	{
	daho_indication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_geran_freq_cells_t_daho_indication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 band_class = 0;
	guint16 arfcn = 0;
	guint16 pn_offset = 0;
	guint32 type = 0;
	guint8 num_valid_count_cid = 0;
	guint8 CID = 0;
	guint8 daho_indication = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	band_class = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_band_class, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	pn_offset = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_pn_offset, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	type = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_type, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	num_valid_count_cid = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_num_valid_count_cid, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	for(loop_counter = 0;loop_counter < 16;loop_counter++)
	{
	CID = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_CID, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	{
	daho_indication = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cdma2000_freq_cells_t_daho_indication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 p_rev = 0;
	guint8 min_p_rev = 0;
	guint8 neg_slot_cycle_index_sup = 0;
	guint8 encrypt_mode = 0;
	guint8 enc_supported = 0;
	guint8 sig_encrypt_sup = 0;
	guint8 msg_integrity_sup = 0;
	guint8 sig_integrity_sup_incl = 0;
	guint8 sig_integrity_sup = 0;
	guint8 ms_init_pos_loc_sup_ind = 0;
	guint8 band_class_info_req = 0;
	guint8 band_class = 0;
	guint8 alt_band_class = 0;
	guint8 tkz_mode_supported = 0;
	guint8 tkz_id = 0;
	guint8 t_add = 0;
	guint8 pilot_inc = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	{
	p_rev = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_p_rev, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	min_p_rev = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_min_p_rev, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	neg_slot_cycle_index_sup = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_neg_slot_cycle_index_sup, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	encrypt_mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_encrypt_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20)
	{
	enc_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_enc_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40)
	{
	sig_encrypt_sup = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_encrypt_sup, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x80)
	{
	msg_integrity_sup = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_msg_integrity_sup, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x100)
	{
	sig_integrity_sup_incl = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup_incl, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x200)
	{
	sig_integrity_sup = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_sig_integrity_sup, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x400)
	{
	ms_init_pos_loc_sup_ind = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_ms_init_pos_loc_sup_ind, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x800)
	{
	band_class_info_req = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class_info_req, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x1000)
	{
	band_class = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_band_class, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x2000)
	{
	alt_band_class = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_alt_band_class, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x4000)
	{
	tkz_mode_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_mode_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x8000)
	{
	tkz_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_tkz_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10000)
	offset_counter += dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x20000)
	{
	t_add = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_t_add, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40000)
	{
	pilot_inc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_cell_specific_params_t_pilot_inc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 pz_hyst_enabled = 0;
	guint8 pz_hyst_info_incl = 0;
	guint8 pz_hyst_list_len = 0;
	guint8 pz_hyst_act_timer = 0;
	guint8 pz_hyst_timer_mul = 0;
	guint8 pz_hyst_timer_exp = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	pz_hyst_enabled = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_enabled, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pz_hyst_info_incl = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_info_incl, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pz_hyst_list_len = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_list_len, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pz_hyst_act_timer = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_act_timer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pz_hyst_timer_mul = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_mul, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	pz_hyst_timer_exp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_pz_hyst_parameters_included_t_pz_hyst_timer_exp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 fpc_fch_init_setpt_rc3 = 0;
	guint8 fpc_fch_init_setpt_rc4 = 0;
	guint8 fpc_fch_init_setpt_rc5 = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	fpc_fch_init_setpt_rc3 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	fpc_fch_init_setpt_rc4 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc4, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	fpc_fch_init_setpt_rc5 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_rat_ncl_t_rrm_oam_fpc_fch_included_t_fpc_fch_init_setpt_rc5, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}


int dissect_rrm_oam_lte_ncl_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_intra_freq_cell = 0;
    guint8 num_valid_inter_freq_cell = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_lte_ncl_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_lte_ncl_t);
    num_valid_intra_freq_cell = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_lte_ncl_t_num_valid_intra_freq_cell, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_intra_freq_cell > RRM_OAM_MAX_NUM_INTRA_FREQ_CELLS )
        num_valid_intra_freq_cell = RRM_OAM_MAX_NUM_INTRA_FREQ_CELLS ;
    for(loop_counter = 0; loop_counter < num_valid_intra_freq_cell; loop_counter++ ){
        rrm_oam_intra_freq_cells_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_intra_freq_cells_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    num_valid_inter_freq_cell = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_lte_ncl_t_num_valid_inter_freq_cell, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_inter_freq_cell > RRM_OAM_MAX_NUM_INTER_FREQ_CELLS)
        num_valid_inter_freq_cell = RRM_OAM_MAX_NUM_INTER_FREQ_CELLS ;
    for(loop_counter = 0; loop_counter < num_valid_inter_freq_cell; loop_counter++ ){
        rrm_oam_inter_freq_cells_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_inter_freq_cells_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_intra_freq_cells_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 phy_cell_id = 0;
    gint32 q_offset = 0;
    gint32 cell_individual_offset = 0;
    gint8 r_stx_power = 0;
    gint32 blacklisted = 0;
    gint32 cell_access_mode = 0;
    gint32 ho_status = 0;
    gint32 x2_status = 0;
    gint32 broadcast_status = 0;
    gint8 csg_identity = 0;
    gint8 tac = 0;
    gint8 daho_indication = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_intra_freq_cells_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_intra_freq_cells_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_INTRA_FREQ_GLOBAL_CELL_ID_PRESENT) == RRM_OAM_INTRA_FREQ_GLOBAL_CELL_ID_PRESENT)
    {
        offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    phy_cell_id = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_phy_cell_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    q_offset = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_intra_freq_cells_t_q_offset, tvb, offset + offset_counter, 4, q_offset, "q_offset: %d (0x%x)",q_offset,q_offset);
    offset_counter += 4;
    if((bitmask & RRM_OAM_INTRA_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT) == RRM_OAM_INTRA_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT)
    {
        cell_individual_offset = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_intra_freq_cells_t_cell_individual_offset, tvb, offset + offset_counter, 4, cell_individual_offset, "cell_individual_offset: %d (0x%x)",cell_individual_offset,cell_individual_offset);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_INTRA_FREQ_R_STX_POWER_PRESENT) == RRM_OAM_INTRA_FREQ_R_STX_POWER_PRESENT)
    {
        r_stx_power = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_r_stx_power, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    blacklisted = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_intra_freq_cells_t_blacklisted, tvb, offset + offset_counter, 4, blacklisted, "blacklisted: %d (0x%x)",blacklisted,blacklisted);
    offset_counter += 4;
    if(bitmask & 0x08)
    {
        cell_access_mode = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_cell_access_mode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x10)
    {
	for(loop_counter =0;loop_counter < 4;loop_counter++)
	{
        csg_identity = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_csg_identity, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
	}
    }
    if(bitmask & 0x20)
    {
        ho_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_ho_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x40)
    {
        x2_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_x2_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x80)
    {
        broadcast_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_broadcast_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    for(loop_counter =0;loop_counter < 2;loop_counter++)
	{
        tac = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_tac, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
	}
    if(bitmask & 0x100)
    {
        daho_indication = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_daho_indication, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_inter_freq_cells_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 eutra_carrier_arfcn = 0;
    guint16 phy_cell_id = 0;
    gint32 q_offset = 0;
    gint32 cell_individual_offset = 0;
    gint8 r_stx_power = 0;
    gint32 blacklisted = 0;
    gint32 cell_access_mode = 0;
    gint32 ho_status = 0;
    gint32 x2_status = 0;
    gint32 broadcast_status = 0;
    gint8 csg_identity = 0;
    gint8 tac = 0;
item = proto_tree_add_item(tree, hf_rrm_oam_inter_freq_cells_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_inter_freq_cells_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_cells_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_INTER_FREQ_GLOBAL_CELL_ID_PRESENT) == RRM_OAM_INTER_FREQ_GLOBAL_CELL_ID_PRESENT)
    {
        offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    eutra_carrier_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_cells_t_eutra_carrier_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    phy_cell_id = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_cells_t_phy_cell_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    q_offset = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_inter_freq_cells_t_q_offset, tvb, offset + offset_counter, 4, q_offset, "q_offset: %d (0x%x)",q_offset,q_offset);
    offset_counter += 4;
    if((bitmask & RRM_OAM_INTER_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT) == RRM_OAM_INTER_FREQ_CELL_INDIVIDUAL_OFFSET_PRESENT)
    {
        cell_individual_offset = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_inter_freq_cells_t_cell_individual_offset, tvb, offset + offset_counter, 4, cell_individual_offset, "cell_individual_offset: %d (0x%x)",cell_individual_offset,cell_individual_offset);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_INTER_FREQ_RSTX_POWER_PRESENT) == RRM_OAM_INTER_FREQ_RSTX_POWER_PRESENT)
    {
        r_stx_power = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_inter_freq_cells_t_r_stx_power, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    blacklisted = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_inter_freq_cells_t_blacklisted, tvb, offset + offset_counter, 4, blacklisted, "blacklisted: %d (0x%x)",blacklisted,blacklisted);
    offset_counter += 4;
    if(bitmask & 0x08)
    {
        cell_access_mode = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_cell_access_mode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x10)
    {
	for(loop_counter =0;loop_counter < 4;loop_counter++)
	{
        csg_identity = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_csg_identity, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
	}
    }
    if(bitmask & 0x20)
    {
        ho_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_ho_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x40)
    {
        x2_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_x2_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    if(bitmask & 0x80)
    {
        broadcast_status = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_broadcast_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
    }
    for(loop_counter =0;loop_counter < 2;loop_counter++)
	{
        tac = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cells_t_tac, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
	}
proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_connected_mode_mobility_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 filter_coefficient_rsrp = 0;
	guint32 filter_coefficient_rsrq = 0;
	guint8 a1_threshold_rsrp = 0;
	guint8 a1_threshold_rsrq = 0;
	guint8 a2_threshold_rsrp = 0;
	guint8 a2_threshold_rsrq = 0;
	guint8 a3_offset = 0;
	guint8 report_on_leave = 0;
	guint8 a4_threshold_rsrp = 0;
	guint8 a4_threshold_rsrq = 0;
	guint8 a5_threshold_1rsrp = 0;
	guint8 a5_threshold_1rsrq = 0;
	guint8 a5_threshold_2rsrp = 0;
	guint8 a5_threshold_2rsrq = 0;
	guint8 hysteresis = 0;
	guint32 time_to_trigger = 0;
	guint32 trigger_quantity = 0;
	guint32 report_quantity = 0;
	guint32 report_interval = 0;
	guint32 report_amount = 0;
	guint8 ps_ho_enabled = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t);
	filter_coefficient_rsrp = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrp, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	filter_coefficient_rsrq = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_filter_coefficient_rsrq, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	a1_threshold_rsrp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a1_threshold_rsrq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a1_threshold_rsrq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a2_threshold_rsrp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a2_threshold_rsrq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a2_threshold_rsrq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a3_offset = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a3_offset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	report_on_leave = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_on_leave, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a4_threshold_rsrp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a4_threshold_rsrq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a4_threshold_rsrq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a5_threshold_1rsrp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a5_threshold_1rsrq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_1rsrq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a5_threshold_2rsrp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	a5_threshold_2rsrq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_a5_threshold_2rsrq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	hysteresis = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_hysteresis, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	time_to_trigger = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_time_to_trigger, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	trigger_quantity = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_trigger_quantity, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	report_quantity = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_quantity, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	report_interval = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_interval, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	report_amount = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_report_amount, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	ps_ho_enabled = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_common_params_for_eutra_t_ps_ho_enabled, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 qoffset_tutra = 0;
	guint32 filter_coefficient_utra = 0;
	guint32 meas_quantity_utra_fdd = 0;
	guint32 meas_quantity_utra_tdd = 0;
	guint8 b1_threshold_utra_rscp = 0;
	guint8 b1_threshold_utra_ecn0 = 0;
	guint8 q_offset_geran = 0;
	guint32 filter_coefficient_geran = 0;
	guint8 b1_threshold_geran = 0;
	guint8 q_offset_cdma2000 = 0;
	guint8 meas_quantity_cdma2000 = 0;
	guint8 b1_threshold_cdma2000 = 0;
	guint8 b2_threshold_2utra_rscp = 0;
	guint8 b2_threshold_2utra_ecn0 = 0;
	guint8 b2_threshold_2geran = 0;
	guint8 b2_threshold_2cdma = 0;
	guint8 hysteresis = 0;
	guint32 time_to_trigger = 0;
	guint8 max_report_cells = 0;
	guint32 report_interval = 0;
	guint32 report_amount = 0;
	guint8 ps_ho_enabled = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	qoffset_tutra = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_qoffset_tutra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	filter_coefficient_utra = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_utra, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x1000)
	{
	meas_quantity_utra_fdd = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_fdd, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x2000)
	{
	meas_quantity_utra_tdd = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_utra_tdd, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x01)
	{
	b1_threshold_utra_rscp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_rscp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x02)
	{
	b1_threshold_utra_ecn0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_utra_ecn0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	q_offset_geran = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_geran, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	filter_coefficient_geran = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_filter_coefficient_geran, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x04)
	{
	b1_threshold_geran = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_geran, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x08)
	{
	q_offset_cdma2000 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_q_offset_cdma2000, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x10)
	{
	meas_quantity_cdma2000 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_meas_quantity_cdma2000, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x20)
	{
	b1_threshold_cdma2000 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b1_threshold_cdma2000, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x100)
	{
	b2_threshold_2utra_rscp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_rscp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x200)
	{
	b2_threshold_2utra_ecn0 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2utra_ecn0, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x400)
	{
	b2_threshold_2geran = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2geran, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x800)
	{
	b2_threshold_2cdma = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_b2_threshold_2cdma, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	hysteresis = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_hysteresis, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	time_to_trigger = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_time_to_trigger, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	max_report_cells = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_max_report_cells, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	report_interval = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_interval, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	report_amount = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_irat_t_report_amount, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x4000)
	offset_counter += dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 auth = 0;
	guint8 max_num_alt_so = 0;
	guint8 use_sync_id = 0;
	guint8 mob_qos = 0;
	guint8 bypass_reg_ind = 0;
	guint8 max_add_serv_instance = 0;
	guint8 parameter_reg = 0;
	guint16 reg_dist = 0;
	guint8 pref_msid_type = 0;
	guint8 ext_pref_msid_type = 0;
	guint8 meid_reqd = 0;
	guint16 mcc = 0;
	guint8 imsi_11_12 = 0;
	guint8 imsi_t_supported = 0;
	guint8 reconnect_msg_ind = 0;
	guint8 rer_mode_supported = 0;
	guint8 pilot_report = 0;
	guint8 sdb_supported = 0;
	guint8 auto_fcso_allowed = 0;
	guint8 sdb_in_rcnm_ind = 0;
	guint8 daylt = 0;
	guint8 gcsna_l2_ack_timer = 0;
	guint8 gcsna_sequence_context_timer = 0;
	guint8 lp_sec = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	auth = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	max_num_alt_so = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_num_alt_so, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	use_sync_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_use_sync_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;	
	}
	if(bitmask & 0x08)
	{
	mob_qos = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mob_qos, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	bypass_reg_ind = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_bypass_reg_ind, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;	
	}
	if(bitmask & 0x20)
	{
	max_add_serv_instance = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_max_add_serv_instance, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;	
	}
	if(bitmask & 0x40)
	{
	parameter_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_parameter_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x80)
	{
	reg_dist = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reg_dist, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	if(bitmask & 0x100)
	{
	pref_msid_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pref_msid_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x200)
	{
	ext_pref_msid_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_ext_pref_msid_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x400)
	{
	meid_reqd = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_meid_reqd, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x800)
	{
	mcc = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_mcc, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	if(bitmask & 0x1000)
	{
	imsi_11_12 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_11_12, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x2000)
	{
	imsi_t_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_imsi_t_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x4000)
	{
	reconnect_msg_ind = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_reconnect_msg_ind, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x8000)
	{
	rer_mode_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_rer_mode_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10000)
	{
	pilot_report = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_pilot_report, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20000)
	{
	sdb_supported = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_supported, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40000)
	{
	auto_fcso_allowed = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_auto_fcso_allowed, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x80000)
	{
	sdb_in_rcnm_ind = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_sdb_in_rcnm_ind, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x100000)
	{
	daylt = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_daylt, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x200000)
	{
	gcsna_l2_ack_timer = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_l2_ack_timer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x400000)
	{
	gcsna_sequence_context_timer = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_gcsna_sequence_context_timer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x800000)
	{
	lp_sec = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_connected_mode_mobility_params_t_rrm_oam_ue_generic_cdma2000_params_t_lp_sec, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}


int dissect_rrm_oam_epc_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_epc_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_epc_t);
    offset_counter += dissect_rrm_oam_epc_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_epc_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_qos_profiles = 0;
    guint32 bitmask = 0;
    guint8 emergency_erab_arp = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_epc_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_epc_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_epc_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_general_epc_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    num_valid_qos_profiles = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_epc_params_t_num_valid_qos_profiles, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_qos_profiles > RRM_OAM_MAX_NUM_QCI_CLASSES)
        num_valid_qos_profiles = RRM_OAM_MAX_NUM_QCI_CLASSES;
    for(loop_counter = 0; loop_counter < num_valid_qos_profiles; loop_counter++ ){
        rrm_oam_qos_config_params_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_qos_config_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    emergency_erab_arp = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_epc_params_t_emergency_erab_arp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_general_epc_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 num_valid_plmn = 0;
    guint8 *tac = 0;
    guint8 *eaid = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_general_epc_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_general_epc_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_general_epc_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    num_valid_plmn = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_general_epc_params_t_num_valid_plmn, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_plmn > RRM_OAM_MAX_NUM_PLMNS )
        num_valid_plmn = RRM_OAM_MAX_NUM_PLMNS ;
    for(loop_counter = 0; loop_counter < num_valid_plmn; loop_counter++ ){
        rrm_oam_plmn_access_info_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_plmn_access_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, RRM_OAM_MAX_NUM_TAC_OCTETS);
    tac = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,RRM_OAM_MAX_NUM_TAC_OCTETS,
            "tac: %s", tac);
    offset_counter += RRM_OAM_MAX_NUM_TAC_OCTETS;

    if((bitmask & RRM_OAM_EMERGENCY_AREA_ID_PRESENT) == RRM_OAM_EMERGENCY_AREA_ID_PRESENT)
    {
        temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, RRM_OAM_MAX_NUM_EAID_OCTETS);
        eaid = temporary_string_holder;
        local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,RRM_OAM_MAX_NUM_EAID_OCTETS,
                "eaid: %s", eaid);
        offset_counter += RRM_OAM_MAX_NUM_EAID_OCTETS;	
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_plmn_access_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 reserve_operator_use = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_plmn_access_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_plmn_access_info_t);
    offset_counter += dissect_rrm_oam_cell_plmn_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    reserve_operator_use = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_plmn_access_info_t_reserve_operator_use, tvb, offset + offset_counter, 4, reserve_operator_use, "reserve_operator_use: %d (0x%x)",reserve_operator_use,reserve_operator_use);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_qos_config_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 qci = 0;
    gint32 type = 0;
    guint8 priority = 0;
    gint32 packet_delay_budget = 0;
    gint32 packet_error_loss_rate = 0;
    guint8 dscp = 0;
    guint8 rlc_mode = 0;
    guint32 lossless_ho_required = 0;
    guint32 ue_inactivity_timer_config = 0;
    guint8 max_harq_tx = 0;
    guint8 max_harq_retrans = 0;
    guint8 logical_channel_grouping_on_off = 0;
    guint8 max_rlc_transmissions = 0;
    guint32 sps_config_enabled = 0;
    guint8 supported_rat = 0;
    guint32 dl_min_bitrate = 0;
    guint32 ul_min_bitrate = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_qos_config_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_qos_config_params_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    qci = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_qci, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    type = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_qos_config_params_t_type, tvb, offset + offset_counter, 4, type, "type: %d (0x%x)",type,type);
    offset_counter += 4;
    priority = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    packet_delay_budget = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_qos_config_params_t_packet_delay_budget, tvb, offset + offset_counter, 4, packet_delay_budget, "packet_delay_budget: %d (0x%x)",packet_delay_budget,packet_delay_budget);
    offset_counter += 4;
    if(bitmask & 0x01)
    {
    packet_error_loss_rate = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_qos_config_params_t_packet_error_loss_rate, tvb, offset + offset_counter, 4, packet_error_loss_rate, "packet_error_loss_rate: %d (0x%x)",packet_error_loss_rate,packet_error_loss_rate);
    offset_counter += 4;
    }	
	if(bitmask & 0x02)
	{
	dscp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_dscp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	rlc_mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_rlc_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	lossless_ho_required = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_lossless_ho_required, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x10)
	{
	ue_inactivity_timer_config = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_ue_inactivity_timer_config, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x20)
	{
	max_harq_tx = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_max_harq_tx, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40)
	{
	max_harq_retrans = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_max_harq_retrans, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x80)
	{
	logical_channel_grouping_on_off = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_logical_channel_grouping_on_off, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x100)
	{
	max_rlc_transmissions = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_max_rlc_transmissions, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x200)
	offset_counter += dissect_enb_rrm_oam_pdcp_rohc_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x400)
	offset_counter += dissect_enb_rrm_oam_sn_field_len_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x800)
	{
	sps_config_enabled = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_sps_config_enabled, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x1000)
	offset_counter += dissect_enb_rrm_oam_sps_config_data_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x2000)
	{
	supported_rat = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_supported_rat, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x4000)
	{
	dl_min_bitrate = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_dl_min_bitrate, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x8000)
	{
	ul_min_bitrate = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_qos_config_params_t_ul_min_bitrate, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x8000)
	offset_counter += dissect_enb_rrm_oam_addl_rlc_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x10000)
	offset_counter += dissect_enb_rrm_oam_addl_mac_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_enb_rrm_oam_pdcp_rohc_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 enable_rohc = 0;
	guint16 max_cid = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_pdcp_rohc_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_pdcp_rohc_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pdcp_rohc_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	enable_rohc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pdcp_rohc_params_t_enable_rohc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_rohc_pofiles_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x04)
	{
	max_cid = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pdcp_rohc_params_t_max_cid, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_rohc_pofiles_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 rohc_profile0x0001 = 0;
	guint8 rohc_profile0x0002 = 0;
	guint8 rohc_profile0x0003 = 0;
	guint8 rohc_profile0x0004 = 0;
	guint8 rohc_profile0x0006 = 0;
	guint8 rohc_profile0x0101 = 0;
	guint8 rohc_profile0x0102 = 0;
	guint8 rohc_profile0x0103 = 0;
	guint8 rohc_profile0x0104 = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_rohc_pofiles_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_rohc_pofiles_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	rohc_profile0x0001 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0001, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	rohc_profile0x0002 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0002, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	rohc_profile0x0003 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0003, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	rohc_profile0x0004 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0004, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	rohc_profile0x0006 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0006, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20)
	{
	rohc_profile0x0101 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0101, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x40)
	{
	rohc_profile0x0102 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0102, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x80)
	{
	rohc_profile0x0103 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0103, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x100)
	{
	rohc_profile0x0104 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rohc_pofiles_t_rohc_profile0x0104, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_sn_field_len_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 dl_rlc = 0;
	guint8 ul_rlc = 0;
	guint8 dl_pdcp = 0;
	guint8 ul_pdcp = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_sn_field_len_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_sn_field_len_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sn_field_len_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	dl_rlc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sn_field_len_t_dl_rlc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	ul_rlc = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sn_field_len_t_ul_rlc, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	dl_pdcp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sn_field_len_t_dl_pdcp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	ul_pdcp = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sn_field_len_t_ul_pdcp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_sps_config_data_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_sps_config_data_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_sps_config_data_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_data_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_sps_config_dl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_sps_config_ul_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_sps_config_dl_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 semi_persist_sched_interval_dl = 0;
	guint8 number_of_conf_sps_processes = 0;
	guint8 max_sps_harq_retx = 0;
	guint8 explicit_release_after = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_sps_config_dl_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_sps_config_dl_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_dl_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	semi_persist_sched_interval_dl = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_dl_t_semi_persist_sched_interval_dl, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	number_of_conf_sps_processes = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_dl_t_number_of_conf_sps_processes, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	max_sps_harq_retx = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_dl_t_max_sps_harq_retx, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	explicit_release_after = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_dl_t_explicit_release_after, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_sps_config_ul_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 semi_persist_sched_interval_ul = 0;
	guint8 implicit_release_after = 0;
	guint8 p_zero_nominal_pusch_persistent = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_sps_config_ul_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_sps_config_ul_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_ul_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	semi_persist_sched_interval_ul = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_ul_t_semi_persist_sched_interval_ul, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	implicit_release_after = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_ul_t_implicit_release_after, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	{
	p_zero_nominal_pusch_persistent = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_config_ul_t_p_zero_nominal_pusch_persistent, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_addl_rlc_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 t_poll_pdu = 0;
	guint32 t_reordering = 0;
	guint32 t_poll_retransmit = 0;
	guint32 t_status_prohibit = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_addl_rlc_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_rlc_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_rlc_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	t_poll_pdu = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_rlc_params_t_t_poll_pdu, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	t_reordering = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_rlc_params_t_t_reordering, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x04)
	{
	t_poll_retransmit = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_rlc_params_t_t_poll_retransmit, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x08)
	{
	t_status_prohibit = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_rlc_params_t_t_status_prohibit, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_addl_mac_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_addl_mac_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_addl_mac_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_addl_mac_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_phr_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_bsr_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_phr_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 t_periodic_phr = 0;
	guint32 t_prohibit_phr = 0;
	guint32 t_pathloss_chng = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_phr_config_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_phr_config_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phr_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	t_periodic_phr = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phr_config_t_t_periodic_phr, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	t_prohibit_phr = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phr_config_t_t_prohibit_phr, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x04)
	{
	t_pathloss_chng = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phr_config_t_t_pathloss_chng, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_bsr_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 t_periodic_bsr = 0;
	guint32 t_retx_bsr = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_bsr_config_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_bsr_config_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_bsr_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	t_periodic_bsr = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_bsr_config_t_t_periodic_bsr, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	t_retx_bsr = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_bsr_config_t_t_retx_bsr, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}


int dissect_rrm_oam_operator_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 simultaneous_ack_nack_and_cqi = 0;
    guint8 cell_capacity_class = 0;
    guint8 cell_type = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_operator_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_operator_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_operator_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_rrmc_mac_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_phy_phich_configuration_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if((bitmask & RRM_OAM_ADDL_SIB1_INFO_PRESENT) == RRM_OAM_ADDL_SIB1_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_sib_type_1_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    offset_counter += dissect_rrm_oam_sib_type_2_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_sib_type_3_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if((bitmask & RRM_OAM_ADDL_SIB4_INFO_PRESENT) == RRM_OAM_ADDL_SIB4_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_sib_type_4_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    offset_counter += dissect_rrm_oam_admission_control_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_power_control_params_rrm_power_control_params(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_sps_crnti_range_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    simultaneous_ack_nack_and_cqi= tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_operator_info_t_simultaneous_ack_nack_and_cqi, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    offset_counter += dissect_enb_rrm_oam_adl_pkt_scheduling_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    //offset_counter += dissect_enb_rrm_oam_adl_cell_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_load_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_mimo_mode_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_ho_config_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_enb_rrm_oam_meas_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    cell_capacity_class = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_operator_info_t_cell_capacity_class, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
/*    cell_type = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_operator_info_t_cell_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;*/
    offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//    offset_counter += dissect_enb_rrm_oam_eutran_access_point_pos_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_enb_rrm_oam_adl_pkt_scheduling_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 dl_mcs = 0;
	guint8 ul_mcs = 0;
	guint32 frequency_selective_scheduling = 0;
	guint32 cqi_reporting_mode = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_adl_pkt_scheduling_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_adl_pkt_scheduling_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_pkt_scheduling_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	dl_mcs = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_pkt_scheduling_params_t_dl_mcs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	ul_mcs = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_pkt_scheduling_params_t_ul_mcs, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	frequency_selective_scheduling = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_pkt_scheduling_params_t_frequency_selective_scheduling, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	cqi_reporting_mode = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_pkt_scheduling_params_t_cqi_reporting_mode, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_adl_cell_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 sub_carrier_spacing = 0;
	guint8 dl_cyclic_prefix = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_adl_cell_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_adl_cell_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_cell_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	sub_carrier_spacing = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_cell_params_t_sub_carrier_spacing, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	dl_cyclic_prefix = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_adl_cell_params_t_dl_cyclic_prefix, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_load_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 wait_time = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_load_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_load_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	wait_time = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_params_t_wait_time, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_mimo_mode_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 antenna_ports_count_number = 0;
	guint8 supported_tx_mode = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_mimo_mode_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_mimo_mode_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mimo_mode_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	antenna_ports_count_number = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mimo_mode_params_t_antenna_ports_count_number, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	supported_tx_mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mimo_mode_params_t_supported_tx_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_ho_config_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint16 blind_ho_timer = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_ho_config_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_ho_config_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_config_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_target_cell_selection_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_ho_algo_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x04)
	offset_counter += dissect_enb_rrm_oam_ho_retry_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x08)
	{
	blind_ho_timer = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_config_params_t_blind_ho_timer, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_target_cell_selection_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 neighboring_cell_load_based_ho_enable = 0;
	guint8 ue_history_based_ho_enable = 0;
	guint8 spid_based_ho_enable = 0;
	guint8 ue_measurement_based_ho_enable = 0;
	guint8 daho_cell_based_ho_enable = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_target_cell_selection_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_target_cell_selection_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	neighboring_cell_load_based_ho_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_neighboring_cell_load_based_ho_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	ue_history_based_ho_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_ue_history_based_ho_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	spid_based_ho_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_spid_based_ho_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	ue_measurement_based_ho_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_ue_measurement_based_ho_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	daho_cell_based_ho_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_target_cell_selection_params_t_daho_cell_based_ho_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_ho_algo_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 enb_measurements_for_ho = 0;
	guint32 ue_meas_trigger_quantity_for_ho = 0;
	guint32 coverage_based_ho = 0;
	guint8 intra_freq_ho = 0;
	guint8 inter_freq_ho = 0;
	guint32 inter_rat_ho = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_ho_algo_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_ho_algo_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	enb_measurements_for_ho = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_enb_measurements_for_ho, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	ue_meas_trigger_quantity_for_ho = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_ue_meas_trigger_quantity_for_ho, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x04)
	{
	coverage_based_ho = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_coverage_based_ho, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x08)
	{
	intra_freq_ho = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_intra_freq_ho, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x10)
	{
	inter_freq_ho = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_inter_freq_ho, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x20)
	{
	inter_rat_ho = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_algo_params_t_inter_rat_ho, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_ho_retry_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 ho_retry_enable = 0;
	guint8 ho_retry_count = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_ho_retry_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_ho_retry_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_retry_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	ho_retry_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_retry_params_t_ho_retry_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	ho_retry_count = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ho_retry_params_t_ho_retry_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_meas_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 report_trigger_type = 0;
	guint32 si_gap_enable = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_meas_config_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_meas_config_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	report_trigger_type = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_config_t_report_trigger_type, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_meas_gap_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x04)
	{
	si_gap_enable = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_config_t_si_gap_enable, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x08)
	offset_counter += dissect_enb_rrm_csfb_tgt_selection_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_meas_gap_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 eutran_gap_offset_type = 0;
	guint8 utran_gap_offset_type = 0;
	guint8 geran_gap_offset_type = 0;
	guint8 cdma2000_gap_offset_type = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_meas_gap_config_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_meas_gap_config_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_gap_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	eutran_gap_offset_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_gap_config_t_eutran_gap_offset_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	{
	utran_gap_offset_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_gap_config_t_utran_gap_offset_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x04)
	{
	geran_gap_offset_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_gap_config_t_geran_gap_offset_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x08)
	{
	cdma2000_gap_offset_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_meas_gap_config_t_cdma2000_gap_offset_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;	
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_csfb_tgt_selection_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 utran_csfb_tgt_selection = 0;
	guint32 geran_csfb_tgt_selection = 0;
	guint32 cdma2000_csfb_tgt_selection = 0;
	item = proto_tree_add_item(tree, hf_rrm_csfb_tgt_selection_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_csfb_tgt_selection_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_csfb_tgt_selection_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	utran_csfb_tgt_selection = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_csfb_tgt_selection_t_utran_csfb_tgt_selection, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	geran_csfb_tgt_selection = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_csfb_tgt_selection_t_geran_csfb_tgt_selection, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x04)
	{
	cdma2000_csfb_tgt_selection = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_csfb_tgt_selection_t_cdma2000_csfb_tgt_selection, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_eutran_access_point_pos_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 latitude_sign = 0;
	guint8 deg_of_latitude = 0;
	guint16 deg_of_longitude = 0;
	guint32 dir_of_altitude = 0;
	guint16 altitude = 0;
	guint32 uncertainty_semi_major = 0;
	guint32 uncertainty_semi_minor = 0;
	guint8 orientation_of_major_axis = 0;
	guint16 uncertainty_altitude = 0;
	guint8 confidence = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_eutran_access_point_pos_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_eutran_access_point_pos_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	latitude_sign = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_latitude_sign, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	deg_of_latitude = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_deg_of_latitude, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	deg_of_longitude = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_deg_of_longitude, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	dir_of_altitude = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_dir_of_altitude, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	altitude = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_altitude, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	uncertainty_semi_major = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_major, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	uncertainty_semi_minor = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_uncertainty_semi_minor, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	orientation_of_major_axis = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_orientation_of_major_axis, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	uncertainty_altitude = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_uncertainty_altitude, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	confidence = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_eutran_access_point_pos_t_confidence, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_sps_crnti_range_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint16 start_sps_crnti_range = 0;
	guint16 end_sps_crnti_range = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_sps_crnti_range_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_sps_crnti_range_t);
	start_sps_crnti_range = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_crnti_range_t_start_sps_crnti_range, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	end_sps_crnti_range = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sps_crnti_range_t_end_sps_crnti_range, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_power_control_params_rrm_power_control_params (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_power_control_params_rrm_power_control_params, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_power_control_params_rrm_power_control_params);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_power_control_params_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_power_control_params_rrm_oam_power_control_enable_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_power_control_params_rrm_oam_tpc_rnti_range_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_power_control_params_rrm_oam_power_control_enable_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 harqBlerClpcPucchEnable = 0;
	guint8 cqiSinrClpcPucchEnable = 0;
	guint8 clpcPuschEnable = 0;
	guint8 dci_3_3a_based_power_control_for_pucch_enable = 0;
	guint8 dci_3_3a_based_power_control_for_pusch_enable = 0;
	guint8 clpcPuschfreqSelectiveEnable = 0;
	guint8 pdcchPowOrAggregationEnable = 0;
	guint8 delta_mcs_enabled = 0;
	guint8 accumulation_enabled = 0;
	guint32 delta_f_pucch_format_1 = 0;
	guint32 delta_f_pucch_format_1b = 0;
	guint32 delta_f_pucch_format_2 = 0;
	guint32 delta_f_pucch_format_2a = 0;
	guint32 delta_f_pucch_format_2b = 0;
	guint8 delta_preamble_msg_3 = 0;
	item = proto_tree_add_item(tree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_power_control_params_rrm_oam_power_control_enable_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	{
	harqBlerClpcPucchEnable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_harqBlerClpcPucchEnable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x02)
	{
	cqiSinrClpcPucchEnable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_cqiSinrClpcPucchEnable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x04)
	{
	clpcPuschEnable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschEnable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x08)
	{
	dci_3_3a_based_power_control_for_pucch_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pucch_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x10)
	{
	dci_3_3a_based_power_control_for_pusch_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_dci_3_3a_based_power_control_for_pusch_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x20)
	{
	clpcPuschfreqSelectiveEnable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_clpcPuschfreqSelectiveEnable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	pdcchPowOrAggregationEnable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_pdcchPowOrAggregationEnable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x40)
	{
	delta_mcs_enabled = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_mcs_enabled, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x80)
	{
	accumulation_enabled = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_accumulation_enabled, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x100)
	{
	delta_f_pucch_format_1 = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x200)
	{
	delta_f_pucch_format_1b = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_1b, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x400)
	{
	delta_f_pucch_format_2 = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x800)
	{
	delta_f_pucch_format_2a = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2a, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x1000)
	{
	delta_f_pucch_format_2b = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_f_pucch_format_2b, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x2000)
	{
	delta_preamble_msg_3 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_power_control_enable_t_delta_preamble_msg_3, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_power_control_params_rrm_oam_tpc_rnti_range_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint16 startTpcRntiPucch = 0;
	guint16 endTpcRntiPucch = 0;
	guint16 startTpcRntiPusch = 0;
	guint16 endTpcRntiPusch = 0;
	item = proto_tree_add_item(tree, hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_power_control_params_rrm_oam_tpc_rnti_range_t);
	startTpcRntiPucch = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPucch, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	endTpcRntiPucch = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPucch, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	startTpcRntiPusch = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_startTpcRntiPusch, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	endTpcRntiPusch = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_power_control_params_rrm_oam_tpc_rnti_range_t_endTpcRntiPusch, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
int dissect_rrm_oam_rrmc_mac_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 start_rarnti_range = 0;
    guint8 end_rarnti_range = 0;
    guint32 ue_inactive_time_config = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rrmc_mac_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rrmc_mac_config_t);
    start_rarnti_range = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rrmc_mac_config_t_start_rarnti_range, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    end_rarnti_range = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rrmc_mac_config_t_end_rarnti_range, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
//    offset_counter += dissect_rrm_oam_mac_enable_frequency_selective_scheduling_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    ue_inactive_time_config = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rrmc_mac_config_t_ue_inactive_time_config, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_mac_enable_frequency_selective_scheduling_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 ul_freq_selective_enable = 0;
    guint8 dl_freq_selective_enable = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_mac_enable_frequency_selective_scheduling_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_mac_enable_frequency_selective_scheduling_t);
    ul_freq_selective_enable = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_ul_freq_selective_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    dl_freq_selective_enable = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_mac_enable_frequency_selective_scheduling_t_dl_freq_selective_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_phy_phich_configuration_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 phich_resource = 0;
    guint8 phich_duration = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_phy_phich_configuration_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_phy_phich_configuration_t);
    phich_resource = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phy_phich_configuration_t_phich_resource, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    phich_duration = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_phy_phich_configuration_t_phich_duration, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_sib_type_1_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint32 si_window_length = 0;
    guint32 si_count = 0;
    gint32 ims_emergency_support_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_sib_type_1_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_sib_type_1_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_1_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    ims_emergency_support_r9 = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_sib_type_1_info_t_ims_emergency_support_r9, tvb, offset + offset_counter, 4, ims_emergency_support_r9, "ims_emergency_support_r9: %d (0x%x)",ims_emergency_support_r9,ims_emergency_support_r9);
    offset_counter += 4;
    if((bitmask & RRM_OAM_CELL_SELECTION_INFO_R9_PRESENT) == RRM_OAM_CELL_SELECTION_INFO_R9_PRESENT)
    {
        offset_counter += dissect_rrm_oam_cell_selection_info_v920_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    si_window_length = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_1_info_t_si_window_length, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    si_count = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_1_info_t_si_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    for(loop_counter = 0;loop_counter < si_count;loop_counter++)
    {
        offset_counter += dissect_rrm_oam_scheduling_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_rrm_oam_scheduling_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 si_periodicity = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_scheduling_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_scheduling_info_t);
    si_periodicity = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_scheduling_info_t_si_periodicity, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    for(loop_counter = 0;loop_counter < 32;loop_counter++)
    {
        offset_counter += dissect_rrm_oam_sib_mapping_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_rrm_oam_sib_mapping_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 sib_type= 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_sib_mapping_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_sib_mapping_info_t);
    sib_type = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_mapping_info_t_sib_type, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}



int dissect_rrm_oam_cell_selection_info_v920_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint8 q_qual_min_r9 = 0;
    guint8 q_qual_min_offset_r9_present = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_selection_info_v920_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_selection_info_v920_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_selection_info_v920_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    q_qual_min_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if((bitmask & RRM_OAM_Q_QUAL_MIN_OFFSET_R9_PRESENT) == RRM_OAM_Q_QUAL_MIN_OFFSET_R9_PRESENT)
    {
        q_qual_min_offset_r9_present = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_selection_info_v920_t_q_qual_min_offset_r9_present, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_sib_type_2_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint8 time_alignment_timer_common = 0;
    guint8 additional_spectrum_emission = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_sib_type_2_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_sib_type_2_info_t);
    	
        bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_2_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
        offset_counter += 4;
     

    offset_counter += dissect_rrm_oam_radio_resource_config_common_sib_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    //	offset_counter += dissect_rrm_oam_freq_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    additional_spectrum_emission = tvb_get_guint8(tvb, offset + offset_counter); 
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_2_info_t_additional_spectrum_emission, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;

    time_alignment_timer_common = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_2_info_t_time_alignment_timer_common, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(bitmask & 0x01)
    offset_counter += dissect_rrm_oam_access_class_barring_information_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_rrm_oam_radio_resource_config_common_sib_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 modification_period_coeff = 0;
    gint32 default_paging_cycle = 0;
    gint32 nB = 0;
    gint32 ul_cyclic_prefix_length = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_radio_resource_config_common_sib_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_radio_resource_config_common_sib_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_radio_resource_config_common_sib_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT) == RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT)
    {
        modification_period_coeff = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_radio_resource_config_common_sib_t_modification_period_coeff, tvb, offset + offset_counter, 4, modification_period_coeff, "modification_period_coeff: %d (0x%x)",modification_period_coeff,modification_period_coeff);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT) == RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT)
    {
        default_paging_cycle = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_radio_resource_config_common_sib_t_default_paging_cycle, tvb, offset + offset_counter, 4, default_paging_cycle, "default_paging_cycle: %d (0x%x)",default_paging_cycle,default_paging_cycle);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_NB_PRESENT) == RRM_OAM_NB_PRESENT)
    {
        nB = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_radio_resource_config_common_sib_t_nB, tvb, offset + offset_counter, 4, nB, "nB: %d (0x%x)",nB,nB);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_UL_CYCLIC_PREFIX_LEN_PRESENT) == RRM_OAM_UL_CYCLIC_PREFIX_LEN_PRESENT)
    {
        ul_cyclic_prefix_length = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_radio_resource_config_common_sib_t_ul_cyclic_prefix_length, tvb, offset + offset_counter, 4, ul_cyclic_prefix_length, "ul_cyclic_prefix_length: %d (0x%x)",ul_cyclic_prefix_length,ul_cyclic_prefix_length);
        offset_counter += 4;
    }
    if(bitmask & 0x10)
    offset_counter += dissect_rrm_oam_access_barring_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_rrm_oam_bcch_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 modification_period_coeff = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_bcch_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_bcch_config_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_bcch_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT) == RRM_OAM_MODIFICATION_PERIOD_COEFF_PRESENT)
    {
        modification_period_coeff = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_bcch_config_t_modification_period_coeff, tvb, offset + offset_counter, 4, modification_period_coeff, "modification_period_coeff: %d (0x%x)",modification_period_coeff,modification_period_coeff);
        offset_counter += 4;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_pcch_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 default_paging_cycle = 0;
    gint32 nB = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_pcch_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_pcch_config_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_pcch_config_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT) == RRM_OAM_DEFAULT_PAGING_CYCLE_PRESENT)
    {
        default_paging_cycle = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_pcch_config_t_default_paging_cycle, tvb, offset + offset_counter, 4, default_paging_cycle, "default_paging_cycle: %d (0x%x)",default_paging_cycle,default_paging_cycle);
        offset_counter += 4;
    }
    if((bitmask & RRM_OAM_NB_PRESENT) == RRM_OAM_NB_PRESENT)
    {
        nB = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_pcch_config_t_nB, tvb, offset + offset_counter, 4, nB, "nB: %d (0x%x)",nB,nB);
        offset_counter += 4;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_freq_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 additional_spectrum_emission = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_freq_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_freq_info_t);
    additional_spectrum_emission = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_freq_info_t_additional_spectrum_emission, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_sib_type_3_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint8 q_qual_min_r9 = 0;
    guint8 thresh_serving_lowq_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_sib_type_3_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_sib_type_3_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_3_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_intra_freq_cell_reselection_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if((bitmask & RRM_OAM_S_INTRA_SEARCH_V920_PRESENT) ==  RRM_OAM_S_INTRA_SEARCH_V920_PRESENT)
    {
        offset_counter += dissect_rrm_oam_s_intra_search_v920_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_S_NON_INTRA_SEARCH_V920_PRESENT) == RRM_OAM_S_NON_INTRA_SEARCH_V920_PRESENT)
    {
        offset_counter += dissect_rrm_oam_s_non_intra_search_v920_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_Q_QUAL_MIN_R9_PRESENT1) == RRM_OAM_Q_QUAL_MIN_R9_PRESENT1)
    {
        q_qual_min_r9 = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_3_info_t_q_qual_min_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_THRESHOLD_SERVING_LOW_PRESENT) == RRM_OAM_THRESHOLD_SERVING_LOW_PRESENT)
    {
        thresh_serving_lowq_r9 = tvb_get_guint8(tvb, offset + offset_counter);

        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_sib_type_3_info_t_thresh_serving_lowq_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_intra_freq_cell_reselection_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    gint32 measurement_bandwidth = 0;
    guint8 presence_antenna_port1 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_intra_freq_cell_reselection_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_intra_freq_cell_reselection_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cell_reselection_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_MEAS_BW_PRESENT) == RRM_OAM_MEAS_BW_PRESENT)
    {
        measurement_bandwidth = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_intra_freq_cell_reselection_info_t_measurement_bandwidth, tvb, offset + offset_counter, 4, measurement_bandwidth, "measurement_bandwidth: %d (0x%x)",measurement_bandwidth,measurement_bandwidth);

        offset_counter += 4;
    }
    presence_antenna_port1 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_intra_freq_cell_reselection_info_t_presence_antenna_port1, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_s_intra_search_v920_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 s_intra_search_p_r9 = 0;
    guint8 s_intra_search_q_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_s_intra_search_v920_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_s_intra_search_v920_t);
    s_intra_search_p_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s_intra_search_v920_t_s_intra_search_p_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    s_intra_search_q_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s_intra_search_v920_t_s_intra_search_q_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_s_non_intra_search_v920_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 s_non_intra_search_p_r9 = 0;
    guint8 s_non_intra_search_q_r9 = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_s_non_intra_search_v920_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_s_non_intra_search_v920_t);
    s_non_intra_search_p_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_p_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    s_non_intra_search_q_r9 = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_s_non_intra_search_v920_t_s_non_intra_search_q_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_sib_type_4_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_sib_type_4_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_sib_type_4_info_t);
    offset_counter += dissect_rrm_oam_csg_cell_id_range_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_csg_cell_id_range_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 start = 0;
    gint32 range = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_csg_cell_id_range_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_csg_cell_id_range_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_csg_cell_id_range_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    start = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_csg_cell_id_range_t_start, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    if((bitmask & RRM_OAM_CELL_ID_RANGE_PRESENT) == RRM_OAM_CELL_ID_RANGE_PRESENT)
    {
        range = tvb_get_ntohl(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_csg_cell_id_range_t_range, tvb, offset + offset_counter, 4, range, "range: %d (0x%x)",range,range);
        offset_counter += 4;
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_admission_control_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 max_num_ue_per_cell = 0;
    guint8 max_num_drbs_per_ue = 0;
    guint8 max_num_gbr_drbs_per_ue = 0;
    guint8 max_num_non_gbr_drbs_per_ue = 0;
    guint8 dl_prb_budget = 0;
    guint8 ul_prb_budget = 0;
    guint8 dl_prb_budget_gbr = 0;
    guint8 ul_prb_budget_gbr = 0;
    guint8 dl_prb_budget_ngbr = 0;
    guint8 ul_prb_budget_ngbr = 0;
    guint16 max_sps_ues = 0;
    guint16 resource_reserved_for_existing_users = 0;
    guint32 total_backhaul_capacity = 0;
    guint8 capacity_threshold = 0;
    guint8 preemption_allowed = 0;
    guint32 preemption_status = 0;
    guint32 proximity_indication_status = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_admission_control_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_admission_control_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_MAX_NUM_UE_PER_CELL_PRESENT) == RRM_OAM_MAX_NUM_UE_PER_CELL_PRESENT)
    {
        max_num_ue_per_cell = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_max_num_ue_per_cell, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
    }
        max_sps_ues = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_max_sps_ues, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
    /*
       if((bitmask & RRM_OAM_MAX_NUM_DRBS_PER_UE_PRESENT) == RRM_OAM_MAX_NUM_DRBS_PER_UE_PRESENT)
       {
       max_num_drbs_per_ue = tvb_get_guint8(tvb, offset + offset_counter);
       local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_max_num_drbs_per_ue, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
       offset_counter += 1;
       }
     */
    if((bitmask & RRM_OAM_MAX_NUM_GBR_DRBS_PER_UE_PRESENT) == RRM_OAM_MAX_NUM_GBR_DRBS_PER_UE_PRESENT)
    {
        max_num_gbr_drbs_per_ue = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_max_num_gbr_drbs_per_ue, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_NUM_NGBR_DRBS_PER_UE_PRESENT) == RRM_OAM_MAX_NUM_NGBR_DRBS_PER_UE_PRESENT)
    {
        max_num_non_gbr_drbs_per_ue = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_max_num_non_gbr_drbs_per_ue, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_DL_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_DL_PRB_BUDGET)
    {
        dl_prb_budget = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_dl_prb_budget, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_UL_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_UL_PRB_BUDGET)
    {
        ul_prb_budget = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_ul_prb_budget, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_DL_GBR_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_DL_GBR_PRB_BUDGET)
    {
        dl_prb_budget_gbr = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_dl_prb_budget_gbr, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_UL_GBR_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_UL_GBR_PRB_BUDGET)
    {
        ul_prb_budget_gbr = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_ul_prb_budget_gbr, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_DL_NGBR_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_DL_NGBR_PRB_BUDGET)
    {
        dl_prb_budget_ngbr = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_dl_prb_budget_ngbr, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if((bitmask & RRM_OAM_MAX_TOTAL_UL_NGBR_PRB_BUDGET) == RRM_OAM_MAX_TOTAL_UL_NGBR_PRB_BUDGET)
    {
        ul_prb_budget_ngbr = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_ul_prb_budget_ngbr, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
    }
    if(bitmask & 0x400)
    offset_counter += dissect_available_gbr_limit_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x800)
    {    
        resource_reserved_for_existing_users = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_resource_reserved_for_existing_users, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
    }
    total_backhaul_capacity = tvb_get_ntoh64(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_total_backhaul_capacity, tvb, offset + offset_counter, 8, IS_LITTLE_ENDIAN);
    offset_counter += 8;
    capacity_threshold = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_capacity_threshold, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(bitmask & 0x1000)
    offset_counter += dissect_rrm_oam_spid_table_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x2000)
    {
    preemption_allowed = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_preemption_allowed, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }
    if(bitmask & 0x4000)
    {
    preemption_status = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_preemption_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    }
    if(bitmask & 0x8000)
    {
    proximity_indication_status = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_admission_control_info_t_proximity_indication_status, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    }
        proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_rrm_oam_spid_table_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint16 spid_count = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_spid_table_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_spid_table_t);
    spid_count = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_table_t_spid_count, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    for(loop_counter = 0;loop_counter < spid_count;loop_counter++)
    offset_counter += dissect_rrm_oam_spid_configuration_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_spid_configuration_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    guint16 sp_id = 0;
    guint16 eutran_freq_priority_info = 0;
    guint16 utran_freq_priority_info = 0;
    guint16 geran_freq_priority_info = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_spid_configuration_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_spid_configuration_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_configuration_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    sp_id = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_configuration_t_sp_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    eutran_freq_priority_info = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_configuration_t_eutran_freq_priority_info, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    utran_freq_priority_info = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_configuration_t_utran_freq_priority_info, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    geran_freq_priority_info = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_spid_configuration_t_geran_freq_priority_info, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_available_gbr_limit_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint16 dl_gbr_limit = 0;
    guint16 ul_gbr_limit = 0;
    item = proto_tree_add_item(tree, hf_available_gbr_limit_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_available_gbr_limit_t);
    dl_gbr_limit = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_available_gbr_limit_t_dl_gbr_limit, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    ul_gbr_limit = tvb_get_ntohs(tvb, offset + offset_counter); 
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_available_gbr_limit_t_ul_gbr_limit, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_access_mgmt_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 access_mode = 0;
    guint8 max_csg_members = 0;
    guint8 max_non_csg_members = 0;
    guint8 *csg_id = 0;
    guint8 hnb_name_size = 0;
    guint8 *hnb_name = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_access_mgmt_params_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_access_mgmt_params_t);
    access_mode = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_access_mgmt_params_t_access_mode, tvb, offset + offset_counter, 4, access_mode, "access_mode: %d (0x%x)",access_mode,access_mode);
    offset_counter += 4;
    max_csg_members = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_mgmt_params_t_max_csg_members, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    max_non_csg_members = tvb_get_ntohs(tvb, offset + offset_counter); 
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_mgmt_params_t_max_non_csg_members, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;

    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, RRM_OAM_MAX_NUM_CSG_OCTETS);
    csg_id = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,RRM_OAM_MAX_NUM_CSG_OCTETS,
            "csg_id: %s", csg_id);
    offset_counter += RRM_OAM_MAX_NUM_CSG_OCTETS;		

    hnb_name_size = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_mgmt_params_t_hnb_name_size, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;

    if(hnb_name_size > RRM_OAM_MAX_NUM_HNB_NAME_OCTETS)
        hnb_name_size = RRM_OAM_MAX_NUM_HNB_NAME_OCTETS;
    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, hnb_name_size);
    hnb_name = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,hnb_name_size,
            "hnb_name: %s", hnb_name);
    offset_counter += hnb_name_size;

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_INIT_IND_rrm_oam_init_ind_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_init_ind_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_init_ind_t);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_SHUTDOWN_REQ_rrm_oam_shutdown_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 shutdown_mode = 0;
    guint16 time_to_shutdown = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_shutdown_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_shutdown_req_t);
    shutdown_mode = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_shutdown_req_t_shutdown_mode, tvb, offset + offset_counter, 4, shutdown_mode, "shutdown_mode: %d (0x%x)",shutdown_mode,shutdown_mode);
    offset_counter += 4;
    time_to_shutdown = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_shutdown_req_t_time_to_shutdown, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_SHUTDOWN_RESP_rrm_oam_shutdown_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_shutdown_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_shutdown_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_shutdown_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_shutdown_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_SET_LOG_LEVEL_REQ_rrm_oam_set_log_level_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 module_id = 0;
    gint32 log_level = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_set_log_level_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_set_log_level_req_t);
    module_id = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_set_log_level_req_t_module_id, tvb, offset + offset_counter, 4, module_id, "module_id: %d (0x%x)",module_id,module_id);
    offset_counter += 4;
    log_level = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_set_log_level_req_t_log_level, tvb, offset + offset_counter, 4, log_level, "log_level: %d (0x%x)",log_level,log_level);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_SET_LOG_LEVEL_RESP_rrm_oam_set_log_level_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_set_log_level_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_set_log_level_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_set_log_level_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_set_log_level_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_RESUME_SERVICE_REQ_rrm_oam_resume_service_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_resume_service_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_resume_service_req_t);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_RESUME_SERVICE_RESP_rrm_oam_resume_service_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_resume_service_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_resume_service_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_resume_service_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_resume_service_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_READY_FOR_SHUTDOWN_IND_rrm_oam_ready_for_shutdown_ind_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_ready_for_shutdown_ind_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_ready_for_shutdown_ind_t);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_rac_enable_disable_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                           /*This function will dissect the API RRM_OAM_RAC_ENABLE_DISABLE_REQ which will direct towards RRM */
  {
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
    guint32 bitmask = 0;
    gint32 request_type = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rac_enable_disable_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rac_enable_disable_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rac_enable_disable_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    request_type = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rac_enable_disable_req_t_request_type, tvb, offset + offset_counter, 4, request_type, "request_type: %d (0x%x)",request_type,request_type);
    offset_counter += 4;
    if((bitmask & RRM_OAM_CELL_ID_PRESENT) == RRM_OAM_CELL_ID_PRESENT)
    {
        offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_rrm_oam_rac_enable_disable_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_RAC_ENABLE_DISABLE_RESP which will direct towards OAM */
   {
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
    guint32 bitmask = 0;
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_rac_enable_disable_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_rac_enable_disable_resp_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rac_enable_disable_resp_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if((bitmask & RRM_OAM_CELL_ID_PRESENT) == RRM_OAM_CELL_ID_PRESENT)
    {
        offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rac_enable_disable_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_rac_enable_disable_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_LOG_ENABLE_DISABLE_REQ_rrm_oam_log_enable_disable_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 module_id = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_log_enable_disable_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_log_enable_disable_req_t);
    module_id = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_log_enable_disable_req_t_module_id, tvb, offset + offset_counter, 4, module_id, "module_id: %d (0x%x)",module_id,module_id);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_log_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_log_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 log_on_off = 0;
    gint32 log_level = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_log_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_log_config_t);
    log_on_off = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_log_config_t_log_on_off, tvb, offset + offset_counter, 4, log_on_off, "log_on_off: %d (0x%x)",log_on_off,log_on_off);
    offset_counter += 4;
    log_level = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_log_config_t_log_level, tvb, offset + offset_counter, 4, log_level, "log_level: %d (0x%x)",log_level,log_level);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_LOG_ENABLE_DISABLE_RESP_rrm_oam_log_enable_disable_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_log_enable_disable_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_log_enable_disable_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_log_enable_disable_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_log_enable_disable_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_INIT_CONFIG_REQ_rrm_oam_init_config_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_init_config_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_init_config_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_init_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    //if((bitmask & RRM_OAM_MODULE_INIT_CONFIG_PRESENT) == RRM_OAM_MODULE_INIT_CONFIG_PRESENT)
    //{
        for(loop_counter = 0; loop_counter < RRM_MAX_NUM_INT_MODULES; loop_counter++)
        {
            offset_counter += dissect_rrm_oam_module_init_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        }
    //}
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_module_init_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 module_id = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_module_init_config_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_module_init_config_t);
    module_id = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_module_init_config_t_module_id, tvb, offset + offset_counter, 4, module_id, "module_id: %d (0x%x)",module_id,module_id);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_log_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }

    return offset_counter;
}

int dissect_RRM_OAM_INIT_CONFIG_RESP_rrm_oam_init_config_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_init_config_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_init_config_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_init_config_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_init_config_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_CELL_START_REQ_rrm_oam_cell_start_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_start_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_start_req_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_CELL_START_RESP_rrm_oam_cell_start_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_start_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_start_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_start_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_start_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_CELL_STOP_REQ_rrm_oam_cell_stop_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_stop_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_stop_req_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_RRM_OAM_CELL_STOP_RESP_rrm_oam_cell_stop_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_stop_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_stop_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_stop_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_stop_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_rrm_oam_cell_delete_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                                /*This function will dissect the API RRM_OAM_CELL_DELETE_REQ which will direct towards RRM */
  {
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
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_delete_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_delete_req_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_cell_delete_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                                /*This function will dissect the API RRM_OAM_CELL_DELETE_RESP which will direct towards OAM */
   {
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_delete_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_delete_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_delete_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_delete_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}



int dissect_RRM_OAM_CELL_CONFIG_RESP_rrm_oam_cell_config_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_config_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_config_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_config_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_config_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_CELL_RECONFIG_REQ_rrm_oam_cell_reconfig_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_reconfig_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_reconfig_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_reconfig_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if((bitmask & RRM_OAM_CELL_ACCESS_PARAMS_PRESENT) == RRM_OAM_CELL_ACCESS_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_cell_access_restriction_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_RAN_INFO_PRESENT) == RRM_OAM_RAN_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_ran_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_EPC_INFO_PRESENT) == RRM_OAM_EPC_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_epc_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_OPERATOR_INFO_PRESENT) == RRM_OAM_OPERATOR_INFO_PRESENT)
    {
        offset_counter += dissect_rrm_oam_operator_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    if((bitmask & RRM_OAM_RRM_ACCESS_MGMT_PARAMS_PRESENT) == RRM_OAM_RRM_ACCESS_MGMT_PARAMS_PRESENT)
    {
        offset_counter += dissect_rrm_oam_access_mgmt_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}


int dissect_RRM_OAM_CELL_RECONFIG_RESP_rrm_oam_cell_reconfig_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_reconfig_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_reconfig_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_reconfig_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_reconfig_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_context_print_req_rrm_oam_cell_context_print_req);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER _REQ which will direct towards RRM */
  {
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
    guint8 meas_bandwidth = 0;
    guint8 no_of_arfcn = 0;
    guint16 arfcn_list = 0;
    gint8 p_tx_upp = 0;
    gint8 p_tx_low = 0;
    guint8 p_offset_o = 0;
    guint8 p_adjust = 0;
    guint8 p_penetration_loss = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t);
    meas_bandwidth = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_meas_bandwidth, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    no_of_arfcn = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_no_of_arfcn, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    arfcn_list = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_arfcn_list, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    p_tx_upp = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_upp, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    p_tx_low = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_tx_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    p_offset_o = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_offset_o, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    p_adjust = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_adjust, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    p_penetration_loss = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_req_t_rrm_oam_carrier_freq_dl_tx_params_req_t_p_penetration_loss, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_CARRIER_FREQ_AND_DL_TX_POWER _RESP which will direct towards OAM */
  {
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
    guint32 bitmask = 0;
    guint16 dl_earfcn = 0;
    gint8 reference_signal_power = 0;
    gint32 result = 0;
    gint32 error_code = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
#if 0
    if((bitmask & RRM_OAM_DL_EARFCN_PRESENT) == RRM_OAM_DL_EARFCN_PRESENT)
    {
    dl_earfcn = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_dl_earfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    }
    if((bitmask & RRM_OAM_REFERENCE_SIGNAL_POWER_PRESENT)==RRM_OAM_REFERENCE_SIGNAL_POWER_PRESENT)
    {
    reference_signal_power = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_reference_signal_power, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }
#endif
    result = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_result, tvb, offset + offset_counter, 4, result, "result: %d (0x%x)",result,result);
    offset_counter += 4;
    error_code = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_carrier_freq_dl_tx_params_resp_t_rrm_oam_carrier_freq_dl_tx_params_resp_t_error_code, tvb, offset + offset_counter, 4, error_code, "error_code: %d (0x%x)",error_code,error_code);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

 int dissect_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint16 ue_index = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t);
	ue_index = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ue_release_req_t_rrm_oam_ue_release_req_t_ue_index, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}


int dissect_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    gint32 alive_status = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t);
    alive_status = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_alive_status, tvb, offset + offset_counter, 4, alive_status, "alive_status: %d (0x%x)",alive_status,alive_status);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_proc_supervision_resp_t_rrm_oam_proc_supervision_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
//BLOCK_CELL_REQ
int dissect_rrm_oam_block_cell_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_BLOCK_CELL_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    gint32 cell_block_priority = 0;
    guint16 cell_block_resource_cleanup_timer = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_block_cell_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_block_cell_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_block_cell_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
     cell_block_priority = tvb_get_ntohl(tvb, offset + offset_counter);
     local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_block_cell_req_t_cell_block_priority, tvb, offset + offset_counter, 4, cell_block_priority, "cell_block_priority: %d (0x%x)",cell_block_priority,cell_block_priority);
    offset_counter += 4;

    if (RRM_OAM_CELL_BLOCK_WAIT_TIMER_PRESENT == (bitmask & RRM_OAM_CELL_BLOCK_WAIT_TIMER_PRESENT))
    {    
    cell_block_resource_cleanup_timer = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_block_cell_req_t_cell_block_resource_cleanup_timer, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    }
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item) {                                                                                                                                                                 *ptr_to_currently_added_item = item;
  }                                                                                                                                    
  return offset_counter;
}

   
  

  //BLOCK_CELL_RESP
  int dissect_rrm_oam_block_cell_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_BLOCK_CELL_RESP which will direct towards OAM */
  {
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_block_cell_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_block_cell_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_block_cell_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_block_cell_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

           
           int dissect_rrm_oam_ready_for_cell_block_ind_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)                              /*This function will dissect the API RRM_OAM_READY_FOR_CELL_BLOCK_IND which will direct towards OAM */  
           {
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
                item = proto_tree_add_item(tree, hf_rrm_oam_ready_for_cell_block_ind_t, tvb,offset + offset_counter, 2, FALSE);
                subtree = proto_item_add_subtree(item,ett_rrm_oam_ready_for_cell_block_ind_t);
                offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
                proto_item_set_len(item, offset_counter);
                if(NULL != ptr_to_currently_added_item)
                {
                    *ptr_to_currently_added_item = item;
                }
               return offset_counter;
            }
            int dissect_rrm_oam_get_ver_id_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)                              
           {
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
                guint32 response = 0;
                item = proto_tree_add_item(tree, hf_rrm_oam_get_ver_id_resp_t, tvb,offset + offset_counter, 2, FALSE);
                subtree = proto_item_add_subtree(item,ett_rrm_oam_get_ver_id_resp_t);
                response = tvb_get_ntohl(tvb, offset + offset_counter);
                    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_get_ver_id_resp_t_response , tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);


                offset_counter +=4;
                proto_item_set_len(item, offset_counter);
                if(NULL != ptr_to_currently_added_item)
                {
                    *ptr_to_currently_added_item = item;
                }
               return offset_counter;
            }

      

            int dissect_rrm_oam_unblock_cell_cmd_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                                /*This function will dissect the API RRM_OAM_UNBLOCK_CELL_CMD which will direct towards RRM */
              {
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
                item = proto_tree_add_item(tree, hf_rrm_oam_unblock_cell_cmd_t, tvb,offset + offset_counter, 2, FALSE);
                subtree = proto_item_add_subtree(item,ett_rrm_oam_unblock_cell_cmd_t);
                offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
                proto_item_set_len(item, offset_counter);
                if(NULL != ptr_to_currently_added_item)
                    {
                        *ptr_to_currently_added_item = item;
                     }
             return offset_counter;
            }
/*+ Tirtha adding +*/
             int dissect_rrm_oam_get_version_id_req_t (
		tvbuff_t *tvb, 
		packet_info *pinfo,
		proto_tree *tree, 
		int offset, 
		int len, proto_item **ptr_to_currently_added_item
		)
                {
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
                item = proto_tree_add_item(tree,hf_rrm_oam_get_ver_id_req_t, tvb,offset + offset_counter, 2, FALSE);
                //subtree = proto_item_add_subtree(item,ett_rrm_oam_unblock_cell_cmd_t);
                //offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
                proto_item_set_len(item, offset_counter);
                if(NULL != ptr_to_currently_added_item)
                    {
                        *ptr_to_currently_added_item = item;
                     }
             return offset_counter;
            }
/*- Tirtha adding -*/

              
/*+ Puneet adding +*/
 
int dissect_rrm_oam_cell_update_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_CELL_UPDATE_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    guint16 pci_value = 0;
    gint8   conn_mode_cell_spec_off = 0;
    gint8   idle_mode_cell_spec_off = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_update_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_update_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_update_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    pci_value = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_update_req_t_pci_value, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    offset_counter += dissect_rrm_oam_updated_plmn_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    conn_mode_cell_spec_off = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_update_req_t_conn_mode_cell_spec_off, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    idle_mode_cell_spec_off = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_update_req_t_idle_mode_cell_spec_off, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;

    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_oam_updated_plmn_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
    guint8 num_valid_plmn = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_updated_plmn_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_updated_plmn_info_t);
    num_valid_plmn = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_updated_plmn_info_t_num_valid_plmn, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(num_valid_plmn > RRM_OAM_MAX_NUM_PLMNS )
        num_valid_plmn = RRM_OAM_MAX_NUM_PLMNS ;
    for(loop_counter = 0; loop_counter < num_valid_plmn; loop_counter++ ){
        rrm_oam_cell_plmn_info_t_count= loop_counter;
        offset_counter += dissect_rrm_oam_cell_plmn_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    }

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

  //CELL_UPDATE_RESP
  int dissect_rrm_oam_cell_update_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_CELL_UPDATE_RESP which will direct towards OAM */
  {
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_update_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_update_resp_t);
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_update_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_update_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

  //EVENT_NOTIFICATION
  int dissect_rrm_oam_event_notification_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_EVENT_NOTIFICATION which will direct towards OAM */
  {
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
    guint8 api_data = NULL;
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_event_notification_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_event_notification_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_event_notification_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_event_header_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x01)
    {
    if(0 != 200)
    {
    api_data = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_event_notification_t_api_data, tvb, offset + offset_counter, 200, IS_LITTLE_ENDIAN);
    offset_counter += 200;
    }
    }
#if 0
    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, RRM_OAM_MAX_EVENT_LEN);
    api_data = temporary_string_holder;
    if ((bitmask & 0x01) == 0x01 )
    {
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,RRM_OAM_MAX_EVENT_LEN,
            "api_data: %s", api_data);

    offset_counter += RRM_OAM_MAX_EVENT_LEN;
    }
#endif

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }


  int dissect_rrm_oam_event_header_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
  {
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
    gint32 event_type = 0;
    gint32 event_subtype = 0;
    guint16 event_id = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_event_header_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_event_header_t);
    offset_counter += dissect_rrm_oam_time_stamp_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    event_type = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_event_header_t_event_type, tvb, offset + offset_counter, 4, event_type, "event_type: %d (0x%x)",event_type,event_type);
    offset_counter += 4;
    event_subtype = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_event_header_t_event_subtype, tvb, offset + offset_counter, 4, event_subtype, "event_subtype: %d (0x%x)",event_subtype,event_subtype);
    offset_counter += 4;
    event_id = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_event_header_t_event_id, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

  int dissect_rrm_oam_time_stamp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
  {
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
    guint16 year = 0;
    guint16 month = 0;
    guint16 day = 0;
    guint16 hour = 0;
    guint16 min = 0;
    guint16 sec = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_time_stamp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_time_stamp_t);
    year = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_year, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    month = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_month, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    day = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_day, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    hour = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_hour, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    min = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_min, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    sec = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_time_stamp_t_sec, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

    int dissect_rrm_oam_load_report_ind_t ( tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_LOAD_REPORT_IND which will direct towards RRM */ 
    {
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
    item = proto_tree_add_item(tree, hf_rrm_oam_load_report_ind_t, tvb, offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_load_report_ind_t);
    offset_counter += 2;
    offset_counter += dissect_rrm_oam_cell_load_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
        *ptr_to_currently_added_item = item;
    }

    return offset_counter;
    }
    int dissect_rrm_oam_cell_load_info_t(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint16 hw_load_ind = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_load_cell_info_t , tvb, offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_load_cell_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_cell_info_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_hw_load_ind(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_s1_tnl_load_ind(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_rrs_load_ind_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;

    }
    int dissect_rrm_oam_hw_load_ind (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
        guint16 rs_load_lvl_ul = 0;
        guint16 rs_load_lvl_dl = 0;
        item = proto_tree_add_item(tree, hf_rrm_oam_hw_load_ind_t , tvb, offset + offset_counter, 2, FALSE);
        subtree = proto_item_add_subtree(item,ett_rrm_oam_hw_load_ind_t);
        rs_load_lvl_ul = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rs_load_lvl_ul, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
        rs_load_lvl_dl = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rs_load_lvl_dl, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
        proto_item_set_len(item, offset_counter);
    	if(NULL != ptr_to_currently_added_item)
    	{         
       		*ptr_to_currently_added_item = item;
    	}                                                                                                                                    
    	return offset_counter;

    }
    int dissect_rrm_oam_s1_tnl_load_ind (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
        guint16 rs_load_lvl_ul = 0;
        guint16 rs_load_lvl_dl = 0;
        item = proto_tree_add_item(tree, hf_rrm_oam_s1_tnl_load_ind_t , tvb, offset + offset_counter, 2, FALSE);
        subtree = proto_item_add_subtree(item,ett_rrm_oam_s1_tnl_load_t);
        rs_load_lvl_ul = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rs_load_lvl_ul, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
        rs_load_lvl_dl = tvb_get_ntohs(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_rs_load_lvl_dl, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
        proto_item_set_len(item, offset_counter);
    	if(NULL != ptr_to_currently_added_item)
    	{         
       		*ptr_to_currently_added_item = item;
    	}                                                                                                                                    
    	return offset_counter;

    }
    int dissect_rrm_oam_rrs_load_ind_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
        guint8 dl_gbr_prb_usage = 0; 
 	guint8 ul_gbr_prb_usage = 0;
 	guint8 dl_non_gbr_prb_usage = 0;
 	guint8 ul_non_gbr_prb_usage = 0;
 	guint8 dl_total_prb_usage = 0; 
 	guint8 ul_total_prb_usage = 0; 
        item = proto_tree_add_item(tree, hf_rrm_oam_rrs_load_ind_t , tvb, offset + offset_counter, 2, FALSE);
        subtree = proto_item_add_subtree(item,ett_rrm_oam_rrs_load_ind_t);
         
        dl_gbr_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dl_gbr_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        ul_gbr_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ul_gbr_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        dl_non_gbr_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dl_non_gbr_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        //ul_non_gbr_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        //local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ul_non_gbr_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        //offset_counter += 1;
        dl_total_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dl_total_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        //ul_total_prb_usage = tvb_get_guint8(tvb, offset + offset_counter);
        //local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_ul_total_prb_usage , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        //offset_counter += 1;
        proto_item_set_len(item, offset_counter);
    	if(NULL != ptr_to_currently_added_item)
    	{         
       		*ptr_to_currently_added_item = item;
    	}                                                                                                                                    
    	return offset_counter;
   
    } 
    int dissect_rrm_oam_comp_avl_cap_grp_t(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
        guint8 dl_gbr_prb_usage = 0;
        guint8 ul_gbr_prb_usage = 0;
        guint8 dl_non_gbr_prb_usage = 0;
        guint8 ul_non_gbr_prb_usage = 0;
        guint8 dl_total_prb_usage = 0;
        guint8 ul_total_prb_usage = 0;
        item = proto_tree_add_item(tree, hf_rrm_oam_comp_avl_cap_grp_t , tvb, offset + offset_counter, 2, FALSE);
        subtree = proto_item_add_subtree(item,ett_rrm_oam_comp_avl_grp_t);
        offset_counter+=2;
        offset_counter += dissect_rrm_oam_comp_avl_cap_dl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        //offset_counter += dissect_rrm_oam_comp_avl_cap_ul_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        proto_item_set_len(item, offset_counter);
    	if(NULL != ptr_to_currently_added_item)
    	{         
       		*ptr_to_currently_added_item = item;
    	}                                                                                                                                    
    	return offset_counter;
                
    }
    int dissect_rrm_oam_comp_avl_cap_dl_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
        guint32 bitmask = 0;
        guint8 cell_cap_class_val = 0;
        guint8 cap_val = 0;
        item = proto_tree_add_item(tree, hf_rrm_oam_comp_avl_cap_dl_t , tvb, offset + offset_counter, 2, FALSE);
        subtree = proto_item_add_subtree(item,ett_rrm_oam_comp_avl_dl_t);
        offset_counter+=2;
        bitmask = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_comp_avl_dl_bimask , tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
        offset_counter += 2;
        cell_cap_class_val = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_comp_avl_dl_cell_cap_class_val , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        cap_val = tvb_get_guint8(tvb, offset + offset_counter);
        local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_comp_avl_dl_cap_val , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
        offset_counter += 1;
        proto_item_set_len(item, offset_counter);
    	if(NULL != ptr_to_currently_added_item)
    	{         
       		*ptr_to_currently_added_item = item;
    	}                                                                                                                                    
    	return offset_counter;
    }
    int dissect_rrm_oam_load_config_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_LOAD_CONFIG_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    guint16 load_rpt_intrvl = 0;
    guint16 num_enb_cells = 0;
    gint8   ncl_load_ind_intrvl = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_load_config_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_load_config_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_config_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    ncl_load_ind_intrvl = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_config_req_t_ncl_load_ind_intrvl, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    load_rpt_intrvl = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_config_req_t_load_rpt_intrvl, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    num_enb_cells = tvb_get_ntohs(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_config_req_t_num_enb_cells, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    if(num_enb_cells > RRM_MAX_NUM_CELLS )
        num_enb_cells = RRM_MAX_NUM_CELLS  ;
    for(loop_counter = 0; loop_counter < num_enb_cells; loop_counter++ )
       {
        rrm_oam_serving_enb_cell_info_count = loop_counter; 
        offset_counter += dissect_rrm_oam_serving_enb_cell_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
       }
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }


int dissect_rrm_oam_serving_enb_cell_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_serving_enb_cell_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_serving_enb_cell_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_serving_enb_cell_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x01)
    offset_counter += dissect_rrm_oam_over_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x02)
    offset_counter += dissect_rrm_oam_high_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x04)
    offset_counter += dissect_rrm_oam_mid_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x08)
    offset_counter += dissect_rrm_oam_resource_load_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_oam_over_load_def_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint8 load_perctg = 0;
    guint32 action = 0;
    guint8  num_usr = 0;
      item = proto_tree_add_item(tree, hf_rrm_oam_over_load_def_t, tvb,offset + offset_counter, 2, FALSE);
      subtree = proto_item_add_subtree(item,ett_rrm_oam_over_load_def_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    load_perctg = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_load_perctg , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    action = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_load_def_t_action, tvb, offset + offset_counter, 4, action, "action: %d (0x%x)",action,action);
    offset_counter += 4;
    num_usr = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_num_usr , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    
    offset_counter += dissect_rrm_oam_watermark_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_access_barring_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }
int dissect_rrm_oam_high_load_def_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint8 load_perctg = 0;
    guint32 action = 0;
    guint8  num_usr = 0;
      item = proto_tree_add_item(tree, hf_rrm_oam_high_load_def_t, tvb,offset + offset_counter, 2, FALSE);
      subtree = proto_item_add_subtree(item,ett_rrm_oam_high_load_def_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    load_perctg = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_load_perctg , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    action = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_load_def_t_action, tvb, offset + offset_counter, 4, action, "action: %d (0x%x)",action,action);
    offset_counter += 4;
    num_usr = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_num_usr , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    
    offset_counter += dissect_rrm_oam_watermark_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_access_barring_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }
int dissect_rrm_oam_mid_load_def_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint8 load_perctg = 0;
    guint32 action = 0;
    guint8  num_usr = 0;
      item = proto_tree_add_item(tree, hf_rrm_oam_mid_load_def_t, tvb,offset + offset_counter, 2, FALSE);
      subtree = proto_item_add_subtree(item,ett_rrm_oam_mid_load_def_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    if(bitmask & 0x01)
    {
    load_perctg = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_load_perctg , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }
    if(bitmask & 0x02)
    {
    action = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_load_def_t_action, tvb, offset + offset_counter, 4, action, "action: %d (0x%x)",action,action);
    offset_counter += 4;
    }
    if(bitmask & 0x04)
    {
    num_usr = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_load_def_t_num_usr , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    }
    if(bitmask & 0x08)
    offset_counter += dissect_rrm_oam_watermark_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    if(bitmask & 0x10)	
    offset_counter += dissect_rrm_oam_access_barring_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_oam_watermark_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint8  high_watermark = 0;
    guint8  low_watermark = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_watermark_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_watermark_t);
    high_watermark = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_watermark_t_high_watermark , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    low_watermark = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_watermark_t_low_watermark , tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_oam_resource_load_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    gint8   count = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_resource_load_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_resource_load_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_resource_load_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    count = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_resource_load_info_t_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(count > RRM_OAM_MAX_RESOURCE )
        count = RRM_OAM_MAX_RESOURCE  ;
    for(loop_counter = 0; loop_counter < count; loop_counter++ )
       {
        offset_counter += dissect_rrm_oam_resrc_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
       }
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_oam_resrc_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint32 resrc_type = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_resrc_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_resrc_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_resrc_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    
    resrc_type = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_resrc_info_t_resrc_type, tvb, offset + offset_counter, 4, resrc_type, "resrc_type: %d (0x%x)",resrc_type,resrc_type);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_over_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_high_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
//    offset_counter += dissect_rrm_oam_mid_load_def_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }


    int dissect_rrm_oam_access_barring_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_access_barring_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_access_barring_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_barring_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    
    offset_counter += dissect_rrm_oam_access_class_barring_information_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_access_class_barring_information_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_oam_access_ssac_barring_for_mmtel_r9_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_oam_access_class_barring_information_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    guint32 ac_barring_factor = 0;
    guint32 ac_barring_time = 0;
    guint8  ac_barring_for_special_ac = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_access_class_barring_information_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_access_class_barring_information_t);
/*    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_barring_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;*/
    ac_barring_factor = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_class_barring_information_t_ac_barring_factor, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    ac_barring_time = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_class_barring_information_t_ac_barring_time, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    ac_barring_for_special_ac = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_class_barring_information_t_ac_barring_for_special_ac, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_oam_access_ssac_barring_for_mmtel_r9_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_access_ssac_barring_for_mmtel_r9_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_access_ssac_barring_for_mmtel_r9_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
   if(bitmask & 0x01) 
    offset_counter += dissect_rrm_oam_access_class_barring_information_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
   if(bitmask & 0x02) 
    offset_counter += dissect_rrm_oam_access_class_barring_information_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

  //LOAD_CONFIG_RESP
  int dissect_rrm_oam_load_config_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_LOAD_CONFIG_RESP which will direct towards OAM */
  {
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_load_config_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_load_config_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_load_config_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_load_config_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

    int dissect_rrm_oam_cell_ecn_capacity_enhance_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the API RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    gint8   count = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_ecn_capacity_enhance_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_ecn_capacity_enhance_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_ecn_capacity_enhance_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    count = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_cell_ecn_capacity_enhance_req_t_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(count > RRM_MAX_NUM_CELLS )
        count = RRM_MAX_NUM_CELLS  ;
    for(loop_counter = 0; loop_counter < count; loop_counter++ )
       {
        offset_counter += dissect_rrm_ecn_configure_cell_list_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
       }
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_ecn_configure_cell_list_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    gint8   num_of_ue = 0;
    item = proto_tree_add_item(tree, hf_rrm_ecn_configure_cell_list_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_ecn_configure_cell_list_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_ecn_configure_cell_list_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    num_of_ue = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_ecn_configure_cell_list_t_num_of_ue, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    offset_counter += dissect_rrm_qci_bitrate_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_qci_bitrate_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    gint8   count = 0;
    item = proto_tree_add_item(tree, hf_rrm_qci_bitrate_info_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_qci_bitrate_info_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_qci_bitrate_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    count = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_qci_bitrate_info_t_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    if(count > RRM_MAX_QCI )
        count = RRM_MAX_QCI  ;
    for(loop_counter = 0; loop_counter < count; loop_counter++ )
       {
        offset_counter += dissect_rrm_configure_qci_bitrate_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
       }
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_configure_qci_bitrate_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint32 bitmask = 0;
    gint8   qci = 0;
    item = proto_tree_add_item(tree, hf_rrm_configure_qci_bitrate_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_configure_qci_bitrate_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_configure_qci_bitrate_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    qci = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_configure_qci_bitrate_t_qci, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    offset_counter += dissect_rrm_bitrate_ul_dl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    offset_counter += dissect_rrm_bitrate_ul_dl_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

    int dissect_rrm_bitrate_ul_dl_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
    {
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
    guint64 max_bitrate = 0;
    guint64 min_bitrate = 0;
    gint8   qci = 0;
    item = proto_tree_add_item(tree, hf_rrm_bitrate_ul_dl_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_bitrate_ul_dl_t);
    max_bitrate = tvb_get_letoh64(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_bitrate_ul_dl_t_max_bitrate, tvb, offset + offset_counter, 8, IS_LITTLE_ENDIAN);
    offset_counter += 8;
    min_bitrate = tvb_get_letoh64(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_bitrate_ul_dl_t_min_bitrate, tvb, offset + offset_counter, 8, IS_LITTLE_ENDIAN);
    offset_counter += 8;
    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

  //RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP 
  int dissect_rrm_oam_cell_ecn_capacity_enhance_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_CELL_ECN_CAPACITY_ENHANCE_RESP  which will direct towards OAM */
  {
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
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_cell_ecn_capacity_enhance_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_cell_ecn_capacity_enhance_resp_t);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_cell_ecn_capacity_enhance_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
    }

int dissect_rrm_oam_config_kpi_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the RRM_OAM_CONFIG_KPI_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    guint16 duration = 0;
    gint8   periodic_reporting = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_config_kpi_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_config_kpi_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_config_kpi_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    duration = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_config_kpi_req_t_duration, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
    offset_counter += 2;
    periodic_reporting = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_config_kpi_req_t_periodic_reporting, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    offset_counter += dissect_rrm_oam_kpi_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_oam_kpi_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
{
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
    guint8 *bitmap = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_kpi_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_kpi_t);

    temporary_string_holder=tvb_bytes_to_str(tvb, offset + offset_counter, RRM_MAX_KPI);
    bitmap = temporary_string_holder;
    local_ptr_to_currently_added_item = proto_tree_add_text(subtree, tvb, offset+offset_counter,RRM_MAX_KPI,
            "bitmap: %s", bitmap);
    offset_counter += RRM_MAX_KPI;

    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item){
        *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_config_kpi_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_CONFIG_KPI_RESP which will direct towards OAM */
{
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
    guint32 bitmask = 0;
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_config_kpi_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_config_kpi_resp_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_config_kpi_resp_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_config_kpi_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_config_kpi_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_get_kpi_req_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                    /*This function will dissect the RRM_OAM_GET_KPI_REQ which will direct towards RRM */
    {
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
    guint32 bitmask = 0;
    gint8   reset = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_get_kpi_req_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_get_kpi_req_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_get_kpi_req_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    reset = tvb_get_guint8(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_get_kpi_req_t_reset, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
    offset_counter += 1;
    offset_counter += dissect_rrm_oam_kpi_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);

    
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {         
        *ptr_to_currently_added_item = item;
    }                                                                                                                                    
    return offset_counter;
    }

int dissect_rrm_oam_get_kpi_resp_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
                                                            /*This function will dissect the API RRM_OAM_GET_KPI_RESP which will direct towards OAM */
{
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
    guint32 bitmask = 0;
    gint32 response = 0;
    gint32 fail_cause = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_get_kpi_resp_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_get_kpi_resp_t);
    bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_get_kpi_resp_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_eutran_global_cell_id_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    response = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_get_kpi_resp_t_response, tvb, offset + offset_counter, 4, response, "response: %d (0x%x)",response,response);
    offset_counter += 4;
    fail_cause = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_get_kpi_resp_t_fail_cause, tvb, offset + offset_counter, 4, fail_cause, "fail_cause: %d (0x%x)",fail_cause,fail_cause);
    offset_counter += 4;
    offset_counter += dissect_rrm_oam_kpi_data_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}

int dissect_rrm_oam_kpi_data_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item)
{
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
    gint32 num_of_admitted_csg_user = 0;
    gint32 num_of_admitted_non_csg_user = 0;
    gint32 num_of_ue_admission_success = 0;
    gint32 num_of_ue_admission_fail = 0;
    gint32 num_of_erb_setup_success = 0;
    gint32 num_of_erb_setup_fail = 0;
    gint32 num_of_erb_modify_success = 0;
    gint32 num_of_erb_modify_fail = 0;
    gint32 num_of_erb_release_success = 0;
    gint32 num_of_erb_release_fail = 0;
    gint32 total_dl_allocated_gbr_prb = 0;
    gint32 total_ul_allocated_gbr_prb = 0;
    gint32 dl_allocated_ngbr_prb = 0;
    gint32 ul_allocated_ngbr_prb = 0;
    gint32 num_of_geran_ho_success = 0;
    gint32 num_of_geran_ho_fail = 0;
    gint32 num_of_utran_ho_success = 0;
    gint32 num_of_utran_ho_fail = 0;
    gint32 num_of_eutran_ho_attempt = 0;
    gint32 num_of_eutran_ho_fail = 0;
    gint32 num_of_geran_hi_success = 0;
    gint32 num_of_geran_hi_fail = 0;
    gint32 num_of_utran_hi_success = 0;
    gint32 num_of_utran_hi_fail = 0;
    gint32 num_of_eutran_hi_success = 0;
    gint32 num_of_eutran_hi_fail = 0;
    gint32 num_of_enb_init_ho_csg_usr = 0;
    gint32 num_of_enb_init_ho_non_csg_usr = 0;
    gint32 num_of_enb_init_ue_release = 0;
    gint32 num_pucch_res_alloc_attempts = 0;
    gint32 num_of_sr_res_alloc_fail = 0;
    gint32 num_of_sr_cqi_alloc_fail = 0;
    item = proto_tree_add_item(tree, hf_rrm_oam_kpi_data_t, tvb,offset + offset_counter, 2, FALSE);
    subtree = proto_item_add_subtree(item,ett_rrm_oam_kpi_data_t);
    offset_counter += dissect_rrm_oam_kpi_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
    num_of_admitted_csg_user = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_admitted_csg_user, tvb, offset + offset_counter, 4, num_of_admitted_csg_user, "num_of_admitted_csg_user: %d (0x%x)",num_of_admitted_csg_user,num_of_admitted_csg_user);
    offset_counter += 4;
    num_of_admitted_non_csg_user = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_admitted_non_csg_user, tvb, offset + offset_counter, 4, num_of_admitted_non_csg_user, "num_of_admitted_non_csg_user: %d (0x%x)",num_of_admitted_non_csg_user,num_of_admitted_non_csg_user);
    offset_counter += 4;
    num_of_ue_admission_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_ue_admission_success, tvb, offset + offset_counter, 4, num_of_ue_admission_success, "num_of_ue_admission_success: %d (0x%x)",num_of_ue_admission_success,num_of_ue_admission_success);
    offset_counter += 4;
    num_of_ue_admission_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_ue_admission_fail, tvb, offset + offset_counter, 4, num_of_ue_admission_fail, "num_of_ue_admission_fail: %d (0x%x)",num_of_ue_admission_fail,num_of_ue_admission_fail);
    offset_counter += 4;
    num_of_erb_setup_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_setup_success, tvb, offset + offset_counter, 4, num_of_erb_setup_success, "num_of_erb_setup_success: %d (0x%x)",num_of_erb_setup_success,num_of_erb_setup_success);
    offset_counter += 4;
    num_of_erb_setup_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_setup_fail, tvb, offset + offset_counter, 4, num_of_erb_setup_fail, "num_of_erb_setup_fail: %d (0x%x)",num_of_erb_setup_fail,num_of_erb_setup_fail);
    offset_counter += 4;
    num_of_erb_modify_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_modify_success, tvb, offset + offset_counter, 4, num_of_erb_modify_success, "num_of_erb_modify_success: %d (0x%x)",num_of_erb_modify_success,num_of_erb_modify_success);
    offset_counter += 4;
    num_of_erb_modify_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_modify_fail, tvb, offset + offset_counter, 4, num_of_erb_modify_fail, "num_of_erb_modify_fail: %d (0x%x)",num_of_erb_modify_fail,num_of_erb_modify_fail);
    offset_counter += 4;
    num_of_erb_release_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_release_success, tvb, offset + offset_counter, 4, num_of_erb_release_success, "num_of_erb_release_success: %d (0x%x)",num_of_erb_release_success,num_of_erb_release_success);
    offset_counter += 4;
    num_of_erb_release_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_erb_release_fail, tvb, offset + offset_counter, 4, num_of_erb_release_fail, "num_of_erb_release_fail: %d (0x%x)",num_of_erb_release_fail,num_of_erb_release_fail);
    offset_counter += 4;
    total_dl_allocated_gbr_prb = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_total_dl_allocated_gbr_prb, tvb, offset + offset_counter, 4, total_dl_allocated_gbr_prb, "total_dl_allocated_gbr_prb: %d (0x%x)",total_dl_allocated_gbr_prb,total_dl_allocated_gbr_prb);
    offset_counter += 4;
    total_ul_allocated_gbr_prb = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_total_ul_allocated_gbr_prb, tvb, offset + offset_counter, 4, total_ul_allocated_gbr_prb, "total_ul_allocated_gbr_prb: %d (0x%x)",total_ul_allocated_gbr_prb,total_ul_allocated_gbr_prb);
    offset_counter += 4;
    dl_allocated_ngbr_prb = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_dl_allocated_ngbr_prb, tvb, offset + offset_counter, 4, dl_allocated_ngbr_prb, "dl_allocated_ngbr_prb: %d (0x%x)",dl_allocated_ngbr_prb,dl_allocated_ngbr_prb);
    offset_counter += 4;
    ul_allocated_ngbr_prb = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_ul_allocated_ngbr_prb, tvb, offset + offset_counter, 4, ul_allocated_ngbr_prb, "ul_allocated_ngbr_prb: %d (0x%x)",ul_allocated_ngbr_prb,ul_allocated_ngbr_prb);
    offset_counter += 4;
    num_of_geran_ho_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_geran_ho_success, tvb, offset + offset_counter, 4, num_of_geran_ho_success, "num_of_geran_ho_success: %d (0x%x)",num_of_geran_ho_success,num_of_geran_ho_success);
    offset_counter += 4;
    num_of_geran_ho_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_geran_ho_fail, tvb, offset + offset_counter, 4, num_of_geran_ho_fail, "num_of_geran_ho_fail: %d (0x%x)",num_of_geran_ho_fail,num_of_geran_ho_fail);
    offset_counter += 4;
    num_of_utran_ho_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_utran_ho_success, tvb, offset + offset_counter, 4, num_of_utran_ho_success, "num_of_utran_ho_success: %d (0x%x)",num_of_utran_ho_success,num_of_utran_ho_success);
    offset_counter += 4;
    num_of_utran_ho_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_utran_ho_fail, tvb, offset + offset_counter, 4, num_of_utran_ho_fail, "num_of_utran_ho_fail: %d (0x%x)",num_of_utran_ho_fail,num_of_utran_ho_fail);
    offset_counter += 4;
    num_of_eutran_ho_attempt = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_eutran_ho_attempt, tvb, offset + offset_counter, 4, num_of_eutran_ho_attempt, "num_of_eutran_ho_attempt: %d (0x%x)",num_of_eutran_ho_attempt,num_of_eutran_ho_attempt);
    offset_counter += 4;
    num_of_eutran_ho_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_eutran_ho_fail, tvb, offset + offset_counter, 4, num_of_eutran_ho_fail, "num_of_eutran_ho_fail: %d (0x%x)",num_of_eutran_ho_fail,num_of_eutran_ho_fail);
    offset_counter += 4;
    num_of_geran_hi_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_geran_hi_success, tvb, offset + offset_counter, 4, num_of_geran_hi_success, "num_of_geran_hi_success: %d (0x%x)",num_of_geran_hi_success,num_of_geran_hi_success);
    offset_counter += 4;
    num_of_geran_hi_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_geran_hi_fail, tvb, offset + offset_counter, 4, num_of_geran_hi_fail, "num_of_geran_hi_fail: %d (0x%x)",num_of_geran_hi_fail,num_of_geran_hi_fail);
    offset_counter += 4;
    num_of_utran_hi_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_utran_hi_success, tvb, offset + offset_counter, 4,num_of_utran_hi_success, "num_of_utran_hi_success: %d (0x%x)",num_of_utran_hi_success,num_of_utran_hi_success);
    offset_counter += 4;
    num_of_utran_hi_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_utran_hi_fail, tvb, offset + offset_counter, 4, num_of_utran_hi_fail, "num_of_utran_hi_fail: %d (0x%x)",num_of_utran_hi_fail,num_of_utran_hi_fail);
    offset_counter += 4;
    num_of_eutran_hi_success = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_eutran_hi_success, tvb, offset + offset_counter, 4, num_of_eutran_hi_success, "num_of_eutran_hi_success: %d (0x%x)",num_of_eutran_hi_success,num_of_eutran_hi_success);
    offset_counter += 4;
    num_of_eutran_hi_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_eutran_hi_fail, tvb, offset + offset_counter, 4, num_of_eutran_hi_fail, "num_of_eutran_hi_fail: %d (0x%x)",num_of_eutran_hi_fail,num_of_eutran_hi_fail);
    offset_counter += 4;
    num_of_enb_init_ho_csg_usr = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_csg_usr, tvb, offset + offset_counter, 4, num_of_enb_init_ho_csg_usr, "num_of_enb_init_ho_csg_usr: %d (0x%x)",num_of_enb_init_ho_csg_usr,num_of_enb_init_ho_csg_usr);
    offset_counter += 4;
    num_of_enb_init_ho_non_csg_usr = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_enb_init_ho_non_csg_usr, tvb, offset + offset_counter, 4, num_of_enb_init_ho_non_csg_usr, "num_of_enb_init_ho_non_csg_usr: %d (0x%x)",num_of_enb_init_ho_non_csg_usr,num_of_enb_init_ho_non_csg_usr);
    offset_counter += 4;
    num_of_enb_init_ue_release = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_enb_init_ue_release, tvb, offset + offset_counter, 4, num_of_enb_init_ue_release, "num_of_enb_init_ue_release: %d (0x%x)",num_of_enb_init_ue_release,num_of_enb_init_ue_release);
    offset_counter += 4;
    num_pucch_res_alloc_attempts = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_pucch_res_alloc_attempts, tvb, offset + offset_counter, 4, num_pucch_res_alloc_attempts, "num_pucch_res_alloc_attempts: %d (0x%x)",num_pucch_res_alloc_attempts,num_pucch_res_alloc_attempts);
    offset_counter += 4;
    num_of_sr_res_alloc_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_sr_res_alloc_fail, tvb, offset + offset_counter, 4, num_of_sr_res_alloc_fail, "num_of_sr_res_alloc_fail: %d (0x%x)",num_of_sr_res_alloc_fail,num_of_sr_res_alloc_fail);
    offset_counter += 4;
    num_of_sr_cqi_alloc_fail = tvb_get_ntohl(tvb, offset + offset_counter);
    local_ptr_to_currently_added_item = proto_tree_add_int_format(subtree, hf_rrm_oam_kpi_data_t_num_of_sr_cqi_alloc_fail, tvb, offset + offset_counter, 4, num_of_sr_cqi_alloc_fail, "num_of_sr_cqi_alloc_fail: %d (0x%x)",num_of_sr_cqi_alloc_fail,num_of_sr_cqi_alloc_fail);
    offset_counter += 4;
    proto_item_set_len(item, offset_counter);
    if(NULL != ptr_to_currently_added_item)
    {
    *ptr_to_currently_added_item = item;
    }
    return offset_counter;
}
int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_utra_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 t_reselection_utra = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	t_reselection_utra = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_utra_reselection_params_t_t_reselection_utra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x01)
	offset_counter += dissect_rrm_oam_speed_scale_factors_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 num_irat_eutran_to_utran_fdd_carriers = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t);
	num_irat_eutran_to_utran_fdd_carriers = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_list_t_num_irat_eutran_to_utran_fdd_carriers, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        for(loop_counter = 0; loop_counter < num_irat_eutran_to_utran_fdd_carriers;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint16 utra_carrier_arfcn = 0;
	guint8 q_rx_lev_min = 0;
	guint8 q_qual_min = 0;
	guint8 cell_reselection_priority = 0;
	guint8 thresh_x_high = 0;
	guint8 thresh_x_low = 0;
	guint8 p_max_utra = 0;
	guint8 offset_freq = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	utra_carrier_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_utra_carrier_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	q_rx_lev_min = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_rx_lev_min, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	q_qual_min = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_q_qual_min, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x01)
	{
	cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        }
	thresh_x_high = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	thresh_x_low = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_thresh_x_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	p_max_utra = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_p_max_utra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x02)
	{
	offset_freq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_fdd_carriers_t_offset_freq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x04)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 thresh_serving_highq_r9 = 0;
	guint8 thresh_serving_lowq_r9 = 0;
	guint8 preemption_vulnerability = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t);
	thresh_serving_highq_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_highq_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	thresh_serving_lowq_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_thresh_serving_lowq_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	/*preemption_vulnerability = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_thresx_rsrq_r9_t_preemption_vulnerability, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;*/
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 num_irat_eutran_to_utran_tdd_carriers = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t);
	num_irat_eutran_to_utran_tdd_carriers = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_list_t_num_irat_eutran_to_utran_tdd_carriers, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	for(loop_counter = 0; loop_counter < num_irat_eutran_to_utran_tdd_carriers;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint16 utra_carrier_arfcn = 0;
	guint8 q_rx_lev_min = 0;
	guint8 cell_reselection_priority = 0;
	guint8 thresh_x_high = 0;
	guint8 thresh_x_low = 0;
	guint8 p_max_utra = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	utra_carrier_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_utra_carrier_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	q_rx_lev_min = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_q_rx_lev_min, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x01)
	{
	cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	thresh_x_high = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	thresh_x_low = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_thresh_x_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	p_max_utra = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_eutran_to_utran_tdd_carriers_t_p_max_utra, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_geran_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 t_reselection_geran = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	t_reselection_geran = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_irat_eutra_to_geran_reselection_params_t_t_reselection_geran, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        if(bitmask & 0x01)
	offset_counter += dissect_rrm_oam_speed_scale_factors_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 count_geran_carrier = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t);
	count_geran_carrier = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_list_t_count_geran_carrier, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        for(loop_counter =0; loop_counter < count_geran_carrier;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_geran_param_t);
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint16 starting_arfcn = 0;
	guint32 band_indicator = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t);
	starting_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_starting_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	band_indicator = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_info_geran_t_band_indicator, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_geran_following_arfcn_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x04)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 count_explicit_arfcn = 0;
	guint16 data_explicit_arfcn = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t);
	count_explicit_arfcn = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_count_explicit_arfcn, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        for(loop_counter = 0;loop_counter < count_explicit_arfcn;loop_counter++)
	{
	data_explicit_arfcn = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_explicit_list_arfcns_t_data_explicit_arfcn, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 arfcn_spacing = 0;
	guint8 num_of_following_arfcns = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t);
	arfcn_spacing = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_arfcn_spacing, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	num_of_following_arfcns = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_equally_spaced_arfcns_t_num_of_following_arfcns, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 count_var_bit_map = 0;
	guint8 data_var_bitmap = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t);
	count_var_bit_map = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_count_var_bit_map, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        for(loop_counter = 0;loop_counter < count_var_bit_map;loop_counter++)
	{
	data_var_bitmap = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_var_bitmap_of_arfcns_t_data_var_bitmap, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 cell_reselection_priority = 0;
	guint8 ncc_peritted = 0;
	guint8 q_rx_lev_min = 0;
	guint8 p_max_geran = 0;
	guint8 thresh_x_high = 0;
	guint8 thresh_x_low = 0;
	guint8 offset_freq = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	{
	cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	ncc_peritted = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_ncc_peritted, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	q_rx_lev_min = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_q_rx_lev_min, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x02)
	{
	p_max_geran = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_p_max_geran, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	thresh_x_high = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	thresh_x_low = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_thresh_x_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x04)
	{
	offset_freq = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_carrier_freq_comman_info_offset_freq, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 search_window_size = 0;
	guint8 csfb_support_for_dual_rx_ues_r9 = 0;
	guint32 csfb_registration_param_1xrtt_v920 = 0;
	guint32 system_time_info = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        if(bitmask & 0x01)
	{
	search_window_size = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_search_window_size, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        if(bitmask & 0x02)
	{
	csfb_support_for_dual_rx_ues_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_support_for_dual_rx_ues_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        }
        if(bitmask & 0x04)
	{
	csfb_registration_param_1xrtt_v920 = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_csfb_registration_param_1xrtt_v920, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
        if(bitmask & 0x08)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x10)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x20)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x40)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x80)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x100)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x200)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
        if(bitmask & 0x400)
	{
	system_time_info = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_idle_mode_mobility_inter_rat_cdma2000_params_t_system_time_info, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 ac_barring_0_to_9_r9 = 0;
	guint8 ac_barring_10_r9 = 0;
	guint8 ac_barring_11_r9 = 0;
	guint8 ac_barring_12_r9 = 0;
	guint8 ac_barring_13_r9 = 0;
	guint8 ac_barring_14_r9 = 0;
	guint8 ac_barring_15_r9 = 0;
	guint8 ac_barring_msg_r9 = 0;
	guint8 ac_barring_reg_r9 = 0;
	guint8 ac_barring_emg_r9 = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t);
	ac_barring_0_to_9_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_0_to_9_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_10_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_10_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_11_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_11_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_12_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_12_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_13_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_13_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_14_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_14_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_15_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_15_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_msg_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_msg_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_reg_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_reg_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	ac_barring_emg_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_ac_barring_config_1_xrtt_r9_t_ac_barring_emg_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 pre_reg_allowed = 0;
	guint8 pre_reg_zone_id = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	pre_reg_allowed = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_allowed, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	{
	pre_reg_zone_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_pre_reg_info_hrpd_t_pre_reg_zone_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 count = 0;
	guint8 pre_reg_zone_id = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t);
	count = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	for(loop_counter = 0;loop_counter< count;loop_counter++)
	{
	pre_reg_zone_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_secondary_pre_reg_zone_id_list_hrpd_t_pre_reg_zone_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 sid = 0;
	guint8 nid = 0;
	guint8 multiple_sid = 0;
	guint8 multiple_nid = 0;
	guint8 reg_zone = 0;
	guint8 total_zone = 0;
	guint8 zone_timer = 0;
	guint8 packet_zone_id = 0;
	guint8 home_reg = 0;
	guint8 foreign_sid_reg = 0;
	guint8 foreign_nid_reg = 0;
	guint8 parame_reg = 0;
	guint8 power_up_reg = 0;
	guint8 reg_prd = 0;
	guint8 power_down_reg = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
        for(loop_counter = 0;loop_counter < 2;loop_counter++)
	{
	sid = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_sid, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
        for(loop_counter = 0;loop_counter < 2;loop_counter++)
	{
	nid = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_nid, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	multiple_sid = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_sid, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	multiple_nid = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_multiple_nid, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
        for(loop_counter = 0;loop_counter < 2;loop_counter++)
	{
	reg_zone = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_zone, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	total_zone = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_total_zone, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	zone_timer = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_zone_timer, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	{
	packet_zone_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_packet_zone_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	home_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_home_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	foreign_sid_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_sid_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	foreign_nid_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_foreign_nid_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	parame_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_parame_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	power_up_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_up_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	reg_prd = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_reg_prd, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x02)
	{
	power_down_reg = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_mobility_sib_8_params_t_power_down_reg, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_cell_param_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 rand_seed = 0;
	guint32 rand_min = 0;
	guint32 rand_max = 0;
	guint32 rand_regenerate_timer = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t);
	rand_seed = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_seed, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rand_min = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_min, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rand_max = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_max, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rand_regenerate_timer = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_rand_t_rand_regenerate_timer, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 cdma2000_1xrtt_cell_id = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t);
	for(loop_counter = 0;loop_counter < 6;loop_counter++)
	{
	cdma2000_1xrtt_cell_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_1xrtt_cell_identifier_t_cdma2000_1xrtt_cell_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 cdma2000_hrpd_cell_id_length = 0;
	guint8 cdma2000_hrpd_cell_id = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t);
	cdma2000_hrpd_cell_id_length = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id_length, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	for(loop_counter = 0;loop_counter < cdma2000_hrpd_cell_id_length;loop_counter++)
	{
	cdma2000_hrpd_cell_id = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cdma2000_hrpd_cell_identifier_t_cdma2000_hrpd_cell_id, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 eCSFB_1xrtt_r9 = 0;
	guint8 eCSFB_conc_ps_mobility_1xrtt_r9 = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	eCSFB_1xrtt_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_1xrtt_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	{
	eCSFB_conc_ps_mobility_1xrtt_r9 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_irat_parameters_cdma2000_v920_t_eCSFB_conc_ps_mobility_1xrtt_r9, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 t_reselection_cdma2000 = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	t_reselection_cdma2000 = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_cell_reselection_params_cdma2000_t_t_reselection_cdma2000, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	offset_counter += dissect_rrm_oam_speed_scale_factors_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint8 count = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t);
	count = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_list_cdma2000_t_count, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	for(loop_counter = 0;loop_counter< count;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 band_class = 0;
	guint8 cell_reselection_priority = 0;
	guint8 thresh_x_high = 0;
	guint8 thresh_x_low = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	band_class = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_band_class, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	if(bitmask & 0x01)
	{
	cell_reselection_priority = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_cell_reselection_priority, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	thresh_x_high = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_high, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	thresh_x_low = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_idle_mode_mobility_params_t_rrm_oam_band_class_info_cdma2000_t_thresh_x_low, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint8 icic_scheme_type = 0;
	guint32 min_rb_for_pl_phr_calc = 0;
	guint32 ul_mu_mimo_type = 0;
	guint32 msc_threshold_ul_mu_mimo = 0;
	guint16 x2ap_icic_report_periodicity = 0;
	guint32 pa_for_ce_ue = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	icic_scheme_type = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_icic_scheme_type, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	}
	if(bitmask & 0x02)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x04)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x08)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x10)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x20)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x40)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x80)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x100)
	{
	min_rb_for_pl_phr_calc = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_min_rb_for_pl_phr_calc, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x200)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x400)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x800)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x1000)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x2000)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x4000)
	{
	ul_mu_mimo_type = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_ul_mu_mimo_type, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x8000)
	{
	msc_threshold_ul_mu_mimo = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_msc_threshold_ul_mu_mimo, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x10000)
	{
	x2ap_icic_report_periodicity = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_x2ap_icic_report_periodicity, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	}
	if(bitmask & 0x20000)
	{
	pa_for_ce_ue = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_icic_info_t_pa_for_ce_ue, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 num_of_cell_edge_region = 0;
	guint32 num_of_cell_center_region = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	num_of_cell_edge_region = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_edge_region, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	num_of_cell_center_region = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_info_t_num_of_cell_center_region, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter= 0;loop_counter < num_of_cell_edge_region;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x01)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 start_rb = 0;
	guint32 num_of_rb = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t);
	start_rb = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_start_rb, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	num_of_rb = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_resource_partition_t_num_of_rb, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 cell_center_user_power_mask = 0;
	guint32 cell_edge_user_power_mask = 0;
	guint32 qci_delta_power_mask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t);
	cell_center_user_power_mask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_center_user_power_mask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	cell_edge_user_power_mask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_cell_edge_user_power_mask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0;loop_counter < 9;loop_counter++)
	{
	qci_delta_power_mask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_ul_power_mask_t_qci_delta_power_mask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	guint32 rntp_report_on_X2_required = 0;
	guint32 rntp_threshold = 0;
	guint32 max_nominal_epre = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	rntp_report_on_X2_required = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_report_on_X2_required, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	if(bitmask & 0x01)
	{
	rntp_threshold = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_rntp_threshold, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	if(bitmask & 0x02)
	{
	max_nominal_epre = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_rntp_report_config_info_t_max_nominal_epre, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 default_path_loss = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t);
	default_path_loss = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_alpha_based_pathloss_target_sinr_map_t_default_path_loss, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 count = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t);
	count = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_t_count, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0;loop_counter < count;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_path_loss_to_target_sinr_map_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 start_PL = 0;
	guint32 end_PL = 0;
	guint32 target_SINR = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_path_loss_to_target_sinr_map_info_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_path_loss_to_target_sinr_map_info_t);
	start_PL = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_path_loss_to_target_sinr_map_info_t_start_PL, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	end_PL = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_path_loss_to_target_sinr_map_info_t_end_PL, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	start_PL = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_path_loss_to_target_sinr_map_info_t_target_SINR, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}



int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 bitmask = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t);
	bitmask = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_pdcch_aggregation_power_offset_t_bitmask, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter =0;loop_counter< 3;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	if(bitmask & 0x01)
	{
	for(loop_counter =0;loop_counter< 3;loop_counter++)
	{
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	}
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_on_cqi_basis_t);
	for(loop_counter = 0;loop_counter < 15;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 count = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t);
	count = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_t_count, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0;loop_counter < count;loop_counter++)
	offset_counter += dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 aggregation_level = 0;
	guint32 power_offset = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t);
	aggregation_level = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_aggregation_level, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	power_offset = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_aggregation_power_offset_info_t_power_offset, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 cqi_to_phich_power_info = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t);
	for(loop_counter = 0;loop_counter < 15;loop_counter++)
	{
	cqi_to_phich_power_info = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_cqi_to_phich_power_t_cqi_to_phich_power_info, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 max_dl_sps_dci_per_tti = 0;
	guint32 max_dl_sps_Occasion_Per_tti = 0;
	guint32 max_dl_sps_rbs_per_tti = 0;
	guint32 max_dl_sps_rbs_per_tti_per_interval = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t);
	max_dl_sps_dci_per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_dci_per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	max_dl_sps_Occasion_Per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_Occasion_Per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	max_dl_sps_rbs_per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0;loop_counter < 16;loop_counter++)
	{
	max_dl_sps_rbs_per_tti_per_interval = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_dl_scheduling_Info_per_tti_t_max_dl_sps_rbs_per_tti_per_interval, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 max_ul_sps_dci_per_tti = 0;
	guint32 max_ul_sps_Occasion_Per_tti = 0;
	guint32 max_ul_sps_rbs_per_tti = 0;
	guint32 max_ul_sps_rbs_per_tti_per_interval = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t);
	max_ul_sps_dci_per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_dci_per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	max_ul_sps_Occasion_Per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_Occasion_Per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	max_ul_sps_rbs_per_tti = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	for(loop_counter = 0; loop_counter < 16;loop_counter++)
	{
	max_ul_sps_rbs_per_tti_per_interval = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_sps_ul_scheduling_Info_per_tti_t_max_ul_sps_rbs_per_tti_per_interval, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint32 cce_correction_step_up_factor = 0;
	guint32 cce_correction_step_down_factor = 0;
	guint32 cce_adjust_factor = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t);
	for(loop_counter = 0;loop_counter < 4;loop_counter++)
	{
	cce_correction_step_up_factor = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_up_factor, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	for(loop_counter = 0;loop_counter < 4;loop_counter++)
	{
	cce_correction_step_down_factor = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_correction_step_down_factor, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	for(loop_counter = 0;loop_counter < 4;loop_counter++)
	{
	cce_adjust_factor = tvb_get_ntohl(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_dynamic_cfi_extension_params_t_cce_adjust_factor, tvb, offset + offset_counter, 4, IS_LITTLE_ENDIAN);
	offset_counter += 4;
	}
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

int dissect_enb_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
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
	guint16 min_mcs_index_for_atb = 0;
	guint16 min_prb_val_for_atb = 0;
	item = proto_tree_add_item(tree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t);
	min_mcs_index_for_atb = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_mcs_index_for_atb, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	min_prb_val_for_atb = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_rrm_oam_dynamic_icic_info_t_rrm_oam_atb_config_t_min_prb_val_for_atb, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
/*- Puneet adding -*/
