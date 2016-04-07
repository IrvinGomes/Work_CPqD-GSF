/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (c) Aricent.
 *
 ****************************************************************************
 *
 *  $Id: added_api.h,v 1.1.4.1 2010/05/11 03:25:38 gur19836 Exp $ 

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
rrm_oam_set_trans_mode_req_count = -1;
static gint ett_enb_rrm_oam_set_trans_mode_req = -1;
rrm_oam_generic_resp_count = -1;
static gint ett_enb_rrm_oam_generic_resp = -1;
oam_pdcp_parameters_count = -1;
static gint ett_enb_oam_pdcp_parameters = -1;
static gint ett_enb_oam_pdcp_parameters_rohc_profiles = -1;
rrm_oam_ue_semi_static_params_count = -1;
static gint ett_enb_rrm_oam_ue_semi_static_params = -1;
static gint ett_enb_rrm_oam_ue_semi_static_params_pusch_config_dedicated = -1;
static gint *ett[] = {
	&ett_enb_rrm_oam_set_trans_mode_req,
	&ett_enb_rrm_oam_generic_resp,
	&ett_enb_oam_pdcp_parameters,
	&ett_enb_oam_pdcp_parameters_rohc_profiles,
	&ett_enb_rrm_oam_ue_semi_static_params,
	&ett_enb_rrm_oam_ue_semi_static_params_pusch_config_dedicated
};

static int hf_enb_rrm_oam_set_trans_mode_req = -1;
static int hf_enb_rrm_oam_set_trans_mode_req_trans_mode = -1;

static const range_string enb_rrm_oam_set_trans_mode_req_trans_mode_values[] = {
	{ 0,0,"SISO" },
	{ 1,1,"MIMO_2"},
	{ 0,0, NULL }
};
static int hf_enb_rrm_oam_generic_resp = -1;
static int hf_enb_rrm_oam_generic_resp_response = -1;
static int hf_enb_oam_pdcp_parameters = -1;
static int hf_enb_oam_pdcp_parameters_rohc_enable = -1;

static const range_string enb_oam_pdcp_parameters_rohc_enable_values[] = {
	{ 0,0,"FALSE" },
	{ 1,1,"TRUE"},
	{ 0,0, NULL }
};
static int hf_enb_oam_pdcp_parameters_rohc_profiles = -1;
static int hf_enb_oam_pdcp_parameters_max_cid = -1;
static int hf_enb_rrm_oam_ue_semi_static_params = -1;
static int hf_enb_rrm_oam_ue_semi_static_params_pusch_config_dedicated = -1;


static hf_register_info hf[] = {
{ &hf_enb_rrm_oam_set_trans_mode_req, 
	{ "rrm_oam_set_trans_mode_req","enb.rrm_oam_set_trans_mode_req",FT_NONE, BASE_HEX_DEC, NULL, 0x0,"rrm_oam_set_trans_mode_req", HFILL }},
{ &hf_enb_rrm_oam_set_trans_mode_req_trans_mode, 
	{ "trans_mode","enb.rrm_oam_set_trans_mode_req.trans_mode",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&added_api_rrm_oam_set_trans_mode_req_trans_mode_values), 0x0,"trans_mode", HFILL }},
{ &hf_enb_rrm_oam_generic_resp, 
	{ "rrm_oam_generic_resp","enb.rrm_oam_generic_resp",FT_NONE, BASE_HEX_DEC, NULL, 0x0,"rrm_oam_generic_resp", HFILL }},
{ &hf_enb_rrm_oam_generic_resp_response, 
	{ "response","enb.rrm_oam_generic_resp.response",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"response", HFILL }},
{ &hf_enb_oam_pdcp_parameters, 
	{ "oam_pdcp_parameters","enb.oam_pdcp_parameters",FT_NONE, BASE_HEX_DEC, NULL, 0x0,"oam_pdcp_parameters", HFILL }},
{ &hf_enb_oam_pdcp_parameters_rohc_enable, 
	{ "rohc_enable","enb.oam_pdcp_parameters.rohc_enable",FT_UINT8,BASE_HEX_DEC|BASE_RANGE_STRING,RVALS(&added_api_oam_pdcp_parameters_rohc_enable_values), 0x0,"rohc_enable", HFILL }},
{ &hf_enb_oam_pdcp_parameters_rohc_profiles, 
	{ "rohc_profiles","enb.oam_pdcp_parameters.rohc_profiles",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"rohc_profiles", HFILL }},
{ &hf_enb_oam_pdcp_parameters_max_cid, 
	{ "max_cid","enb.oam_pdcp_parameters.max_cid",FT_UINT16,BASE_HEX_DEC ,NULL,0x0,"max_cid", HFILL }},
{ &hf_enb_rrm_oam_ue_semi_static_params, 
	{ "rrm_oam_ue_semi_static_params","enb.rrm_oam_ue_semi_static_params",FT_NONE, BASE_HEX_DEC, NULL, 0x0,"rrm_oam_ue_semi_static_params", HFILL }},
{ &hf_enb_rrm_oam_ue_semi_static_params_pusch_config_dedicated, 
	{ "pusch_config_dedicated","enb.rrm_oam_ue_semi_static_params.pusch_config_dedicated",FT_UINT8,BASE_HEX_DEC ,NULL,0x0,"pusch_config_dedicated", HFILL }}
};



static int dissect_enb_rrm_oam_set_trans_mode_req (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 trans_mode = 0;
	item = proto_tree_add_item(tree, hf_enb_rrm_oam_set_trans_mode_req, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_enb_rrm_oam_set_trans_mode_req);
	trans_mode = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_enb_rrm_oam_set_trans_mode_req_trans_mode, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

static int dissect_enb_rrm_oam_generic_resp (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 response = 0;
	item = proto_tree_add_item(tree, hf_enb_rrm_oam_generic_resp, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_enb_rrm_oam_generic_resp);
	response = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_enb_rrm_oam_generic_resp_response, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

static int dissect_enb_oam_pdcp_parameters (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	guint8 rohc_enable = 0;
	guint16 max_cid = 0;
	item = proto_tree_add_item(tree, hf_enb_oam_pdcp_parameters, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_enb_oam_pdcp_parameters);
	rohc_enable = tvb_get_guint8(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_enb_oam_pdcp_parameters_rohc_enable, tvb, offset + offset_counter, 1, IS_LITTLE_ENDIAN);
	offset_counter += 1;
	offset_counter += dissect_enb_rohc_profiles(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	max_cid = tvb_get_ntohs(tvb, offset + offset_counter);
	local_ptr_to_currently_added_item = proto_tree_add_item(subtree, hf_enb_oam_pdcp_parameters_max_cid, tvb, offset + offset_counter, 2, IS_LITTLE_ENDIAN);
	offset_counter += 2;
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}

static int dissect_enb_rrm_oam_ue_semi_static_params (tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int offset, int len, proto_item **ptr_to_currently_added_item){
	proto_item *item;
	proto_tree *subtree;

	guint offset_counter = 0;
	guint loop_counter = 0;
	guint loop_counter_backup = 0;
	guint padding_bytes = 0;
	guint temp_start_offset_holder = 0;
	proto_item *local_ptr_to_currently_added_item = NULL;
	int MAX_TEMP_STRING_LEN = 50;
	char *temporary_string_holder = ep_alloc(MAX_TEMP_STRING_LEN);
	item = proto_tree_add_item(tree, hf_enb_rrm_oam_ue_semi_static_params, tvb,offset + offset_counter, 2, FALSE);
	subtree = proto_item_add_subtree(item,ett_enb_rrm_oam_ue_semi_static_params);
	offset_counter += dissect_enb_rrc_phy_pusch_configuration_dedicated(tvb, pinfo, subtree, offset + offset_counter, -1, &local_ptr_to_currently_added_item);
	proto_item_set_len(item, offset_counter);
	if(NULL != ptr_to_currently_added_item){
		*ptr_to_currently_added_item = item;
	}
	return offset_counter;
}
