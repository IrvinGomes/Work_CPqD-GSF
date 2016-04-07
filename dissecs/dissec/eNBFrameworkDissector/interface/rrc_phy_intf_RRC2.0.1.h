/******************************************************************************
*
*   FILE NAME:
*       rrc_phy_intf.h
*
*   DESCRIPTION:
*       This file contains types used for representation of PHY API inside RRC
*       Based on LTE_RRC_API_0_31.doc.
*
*   DATE            AUTHOR      REFERENCE       REASON
*   28 Apr 2009     VasylS      ---------       Initial
*
*   Copyright (c) 2009, Aricent Inc. All Rights Reserved
*
******************************************************************************/

#ifndef _RRC_PHY_INTF_H_
#define _RRC_PHY_INTF_H_

#include "rrc_defines.h"

typedef enum
{
    DUPLEXING_MODE_TDD = 0,
    DUPLEXING_MODE_FDD = 1
} duplexing_mode_et;

typedef enum
{
    UL_TX_BANDWIDTH_6RB = 0,
    UL_TX_BANDWIDTH_16RB = 1,
    UL_TX_BANDWIDTH_25RB = 2,
    UL_TX_BANDWIDTH_50RB = 3,
    UL_TX_BANDWIDTH_75RB = 4,
    UL_TX_BANDWIDTH_100RB = 5
} ul_tx_bandwidth_et;

typedef enum
{
    DL_TX_BANDWIDTH_6RB = 0,
    DL_TX_BANDWIDTH_16RB = 1,
    DL_TX_BANDWIDTH_25RB = 2,
    DL_TX_BANDWIDTH_50RB = 3,
    DL_TX_BANDWIDTH_75RB = 4,
    DL_TX_BANDWIDTH_100RB = 5
} dl_tx_bandwidth_et;

typedef enum
{
    SUBCARRIER_SPACING_FREQ15 = 0,
    SUBCARRIER_SPACING_FREQ7DOT15 = 1
} subcarrier_spacing_et;

typedef enum
{
    CYCLIC_PREFIX_NORMAL = 0,
    CYCLIC_PREFIX_EXTENDED = 1
} cyclic_prefix_et;

typedef enum
{
    RB_SIZE_12 = 0,
    RB_SIZE_24 = 1
} rb_size_et;

typedef enum
{
    SRS_BW_CONFIG_BW0,
    SRS_BW_CONFIG_BW1,
    SRS_BW_CONFIG_BW2,
    SRS_BW_CONFIG_BW3,
    SRS_BW_CONFIG_BW4,
    SRS_BW_CONFIG_BW5,
    SRS_BW_CONFIG_BW6,
    SRS_BW_CONFIG_BW7
} srs_bw_config_et;

typedef enum
{
    RS_NO_HOPPING = 0,
    RS_GROUP_HOPPING = 1,
    RS_SEQUENCE_HOPPING = 2
} uplink_rs_hopping_et;

typedef enum
{
    DS_1 = 1,
    DS_2 = 2,
    DS_3 = 3
} pucch_delta_shift_et;

typedef enum
{
    PHICH_R_ONE_SIXTH = 0,
    PHICH_R_HALF = 1,
    PHICH_R_ONE = 2,
    PHICH_R_TWO = 3
} phich_resource_et;

typedef enum
{
    PHICH_D_NORMAL = 0,
    PHICH_D_EXTENDED = 1
} phich_duration_et;

typedef enum
{
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_6 = 0,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_4DOT77 = 1,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_3 = 2,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB_M_1DOT77 = 3,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB0 = 4,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB1 = 5,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB2 = 6,
    PDSCH_CONFIGURATION_DEDICATED_P_A_DB3 = 7
} pdsch_configuration_dedicated_p_a_et;

typedef enum
{
    TDD_ACK_NACK_FEEDBACK_MODE_BUNDLING = 0,
    TDD_ACK_NACK_FEEDBACK_MODE_MULTIPLEXING = 1
} tdd_ack_nack_feedback_mode_et;

typedef enum
{
    ACK_NACK_REPETITION_FACTOR_N2 = 0,
    ACK_NACK_REPETITION_FACTOR_N4 = 1,
    ACK_NACK_REPETITION_FACTOR_N6 = 2
} ack_nack_repetition_factor_et;

typedef enum
{
    DELTA_MCS_EN0 = 0,
    DELTA_MCS_EN1 = 1
} delta_mcs_enabled_et;

typedef enum
{
    CQI_REPORTING_MODE_APERIODIC_RM12 = 0,
    CQI_REPORTING_MODE_APERIODIC_RM20 = 1,
    CQI_REPORTING_MODE_APERIODIC_RM22 = 2,
    CQI_REPORTING_MODE_APERIODIC_RM30 = 3,
    CQI_REPORTING_MODE_APERIODIC_RM31 = 4
} cqi_reporting_mode_aperiodic_et;

typedef enum
{
    SRS_BANDWIDTH_BW0 = 0,
    SRS_BANDWIDTH_BW1 = 1,
    SRS_BANDWIDTH_BW2 = 2,
    SRS_BANDWIDTH_BW3 = 3
} srs_bandwidth_et;

typedef enum
{
    SRS_HOPPING_BANDWIDTH_HBW0 = 0,
    SRS_HOPPING_BANDWIDTH_HBW1 = 1,
    SRS_HOPPING_BANDWIDTH_HBW2 = 2,
    SRS_HOPPING_BANDWIDTH_HBW3 = 3
} srs_hopping_bandwidth_et;

typedef enum
{
    CYCLIC_SHIFT_CS0 = 0,
    CYCLIC_SHIFT_CS1 = 1,
    CYCLIC_SHIFT_CS2 = 2,
    CYCLIC_SHIFT_CS3 = 3,
    CYCLIC_SHIFT_CS4 = 4,
    CYCLIC_SHIFT_CS5 = 5,
    CYCLIC_SHIFT_CS6 = 6,
    CYCLIC_SHIFT_CS7 = 7
} cyclic_shift_et;

typedef enum
{
    TRANSMISSION_MODE_TM1 = 0,
    TRANSMISSION_MODE_TM2 = 1,
    TRANSMISSION_MODE_TM3 = 2,
    TRANSMISSION_MODE_TM4 = 3,
    TRANSMISSION_MODE_TM5 = 4,
    TRANSMISSION_MODE_TM6 = 5,
    TRANSMISSION_MODE_TM7 = 6
} transmission_mode_et;

typedef enum
{
    N2_TX_ANTENNA_TM3 = 0,
    N4_TX_ANTENNA_TM3 = 1,
    N2_TX_ANTENNA_TM4 = 2,
    N4_TX_ANTENNA_TM4 = 3,
    N2_TX_ANTENNA_TM5 = 4,
    N4_TX_ANTENNA_TM5 = 5,
    N2_TX_ANTENNA_TM6 = 6,
    N4_TX_ANTENNA_TM6 = 7
} codebook_subset_restriction_type_et;

typedef enum
{
    CLOSE_LOOP = 0,
    OPEN_LOOP = 1
} ue_transmit_antenna_selection_type_et;

typedef enum
{
    DSR_TRANS_MAX_N4 = 0,
    DSR_TRANS_MAX_N8 = 1,
    DSR_TRANS_MAX_N16 = 2,
    DSR_TRANS_MAX_N32 = 3,
    DSR_TRANS_MAX_N64 = 4
} dsr_trans_max_et;

#pragma pack(push, 1)

/******************************************************************************
*   PHY Cell messages
******************************************************************************/


/******************************************************************************
*   RRC_PHY_CONFIG_CELL_REQ
******************************************************************************/
typedef struct _rrc_phy_config_cell_req_t
{
 
    rrc_cell_index_t                cell_index;
    rrc_config_phy_cell_parameters_t cell_parameters;
    rrc_phy_sync_signals_t          sync_signals;
    rrc_phy_prach_configuration_t   prach_configuration;
    rrc_phy_pusch_configuration_t   pusch_configuration;
    rrc_phy_pucch_configuration_t   pucch_configuration;
    rrc_phy_phich_configuration_t   phich_configuration;
    pdsch_config_common_t           pdsch_configuration;
} rrc_phy_config_cell_req_t; /*^ API, RRC_PHY_CONFIG_CELL_REQ ^*/



/******************************************************************************
*   RRC_PHY_CONFIG_CELL_CNF
******************************************************************************/
typedef struct _rrc_phy_config_cell_cnf_t
{
    rrc_cell_index_t    cell_index;
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_phy_config_cell_cnf_t; /*^ API, RRC_PHY_CONFIG_CELL_CNF ^*/

/***************************************************************************
 * RRC_PHY_RECONFIG_CELL_PARAMETERS
 * ***********************************************************************/

typedef struct _rrc_phy_reconfig_cell_parameters_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_RECONFIG_PHY_UL_EARFCN                               0x01
#define RRC_RECONFIG_PHY_DL_EARFCN                               0x02
#define RRC_RECONFIG_PHY_NUM_OF_ANTENNAS                         0x04
#define RRC_RECONFIG_PHY_UL_TX_BANDWIDTH_PRESENT                 0x08
#define RRC_RECONFIG_PHY_DL_TX_BANDWIDTH_PRESENT                 0x10
#define RRC_RECONFIG_PHY_UL_CYCLIC_PREFIX                        0x20
#define RRC_RECONFIG_PHY_DL_CYCLIC_PREFIX                        0x40
#define RRC_RECONFIG_PHY_SRS_BANDWIDTH_CONFIGURATION_PRESENT     0x80
#define RRC_RECONFIG_PHY_DUPLEX_MODE                             0x100   
#define RRC_RECONFIG_PHY_CELL_ID                                 0x200

    U8  duplexing_mode;  /*^ O, RRC_RECONFIG_PHY_DUPLEX_MODE, H, 0, 1 ^*/ 
            /* duplexing_mode_et */

    U16 ul_earfcn;                          
    /*^ O,RRC_RECONFIG_PHY_UL_EARFCN ^*/    

    U16 dl_earfcn;
    /*^ O,RRC_RECONFIG_PHY_DL_EARFCN ^*/    

    U8  num_of_antennas;                    
    /*^ O,RRC_RECONFIG_PHY_NUM_OF_ANTENNAS , B, 1, 4 ^*/
    
    U8  ul_tx_bandwidth;
    /*^ O, RRC_RECONFIG_PHY_UL_TX_BANDWIDTH_PRESENT, H, 0, 5 ^*/  /* ul_tx_bandwidth_et */
    
    U8  dl_tx_bandwidth;
    /*^ O, RRC_RECONFIG_PHY_DL_TX_BANDWIDTH_PRESENT, H, 0, 5 ^*/  /* dl_tx_bandwidth_et */

    U8  ul_cyclic_prefix;
    /*^ O, RRC_RECONFIG_PHY_UL_CYCLIC_PREFIX, H, 0, 1 ^*/ 
    /* cyclic_prefix_et */

    U8  dl_cyclic_prefix;
    /*^ O, RRC_RECONFIG_PHY_DL_CYCLIC_PREFIX, H, 0, 1 ^*/     
    /* cyclic_prefix_et */

    sounding_rs_ul_config_common_t        srs_bandwidth_configuration;
    /*^ O, RRC_RECONFIG_PHY_SRS_BANDWIDTH_CONFIGURATION_PRESENT, H, 0, 7 ^*/

    rrc_phys_cell_id_t  phys_cell_id;
    /*^ O, RRC_RECONFIG_PHY_CELL_ID ^*/

} rrc_phy_reconfig_cell_parameters_t;
/******************************************************************************
*   RRC_PHY_RECONFIG_CELL_REQ
******************************************************************************/
typedef struct _rrc_phy_reconfig_cell_req_t
{

    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_RECONFIG_PHY_CELL_PARAMETERS_PRESENT                 0x01
#define RRC_RECONFIG_PHY_SYNC_SIGNAL_PRESENT                     0x02
#define RRC_RECONFIG_PHY_PRACH_CONFIGURATION_PRESENT             0x04
#define RRC_RECONFIG_PHY_PUSCH_CONFIGURATION_PRESENT             0x08
#define RRC_RECONFIG_PHY_PUCCH_CONFIGURATION_PRESENT             0x10
#define RRC_RECONFIG_PHY_PHICH_CONFIGURATION_PRESENT             0x20
#define RRC_RECONFIG_PHY_PDSCH_CONFIGURATION_PRESENT             0x40

    rrc_cell_index_t                            cell_index;
    U16                                         sfn;
    U8						sf;	
    rrc_phy_reconfig_cell_parameters_t          phy_recfg_cell_parameters;
    /*^ O,RRC_RECONFIG_PHY_CELL_PARAMETERS_PRESENT  ^*/
    rrc_phy_sync_signals_t                      sync_signals;
    /*^ O,RRC_RECONFIG_PHY_SYNC_SIGNAL_PRESENT^*/
    rrc_phy_prach_configuration_t               prach_configuration;
    /*^ O,RRC_RECONFIG_PHY_PRACH_CONFIGURATION_PRESENT^*/
    rrc_phy_pusch_configuration_t               pusch_configuration;
    /*^ O,RRC_RECONFIG_PHY_PUSCH_CONFIGURATION_PRESENT^*/
    rrc_phy_pucch_configuration_t               pucch_configuration;
    /*^ O,RRC_RECONFIG_PHY_PUCCH_CONFIGURATION_PRESENT^*/
    rrc_phy_phich_configuration_t               phich_configuration;
    /*^ O,RRC_RECONFIG_PHY_PHICH_CONFIGURATION_PRESENT^*/
    pdsch_config_common_t               pdsch_configuration;
    /*^ O,RRC_RECONFIG_PHY_PDSCH_CONFIGURATION_PRESENT^*/
} rrc_phy_reconfig_cell_req_t; /*^ API, RRC_PHY_RECONFIG_CELL_REQ ^*/

/******************************************************************************
*   RRC_PHY_RECONFIG_CELL_CNF
******************************************************************************/
typedef struct _rrc_phy_reconfig_cell_cnf_t
{
    rrc_cell_index_t    cell_index;
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_phy_reconfig_cell_cnf_t; /*^ API, RRC_PHY_RECONFIG_CELL_CNF ^*/

/******************************************************************************
*   RRC_PHY_DELETE_CELL_REQ
******************************************************************************/
typedef struct _rrc_phy_delete_cell_req_t
{
    rrc_cell_index_t    cell_index;
} rrc_phy_delete_cell_req_t; /*^ API, RRC_PHY_DELETE_CELL_REQ ^*/

/******************************************************************************
*   RRC_PHY_DELETE_CELL_CNF
******************************************************************************/
typedef struct _rrc_phy_delete_cell_cnf_t
{
    rrc_cell_index_t    cell_index;
    U8                  response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_phy_delete_cell_cnf_t; /*^ API, RRC_PHY_DELETE_CELL_CNF ^*/

/******************************************************************************
*   PHY UE messages
******************************************************************************/

/******************************************************************************
*   RRC_PHY_CREATE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_phy_create_ue_entity_req_t
{
    rrc_ue_index_t  ue_index;

    rrc_phy_physical_config_dedicated_t physical_config_dedicated;
} rrc_phy_create_ue_entity_req_t; /*^ API, RRC_PHY_CREATE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_PHY_CREATE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_phy_create_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    U8              response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_phy_create_ue_entity_cnf_t; /*^ API, RRC_PHY_CREATE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   RRC_PHY_DELETE_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_phy_delete_ue_entity_req_t
{
    rrc_ue_index_t  ue_index;
} rrc_phy_delete_ue_entity_req_t; /*^ API, RRC_PHY_DELETE_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_PHY_DELETE_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_phy_delete_ue_entity_cnf_t
{
    rrc_ue_index_t  ue_index;
    U8              response;
/*^ M, 0, H, 0, 1 ^*/ /* rrc_return_et */

} rrc_phy_delete_ue_entity_cnf_t; /*^ API, RRC_PHY_DELETE_UE_ENTITY_CNF ^*/

/******************************************************************************
*   RRC_PHY_RECONFIG_UE_ENTITY_REQ
******************************************************************************/
typedef struct _rrc_phy_reconfig_ue_entity_req_t
{
    rrc_ue_index_t  ue_index;

    rrc_phy_physical_config_dedicated_t physical_config_dedicated;
} rrc_phy_reconfig_ue_entity_req_t; /*^ API, RRC_PHY_RECONFIG_UE_ENTITY_REQ ^*/

/******************************************************************************
*   RRC_PHY_RECONFIG_UE_ENTITY_CNF
******************************************************************************/
typedef struct _rrc_phy_reconfig_ue_entity_cnf_t
{
    rrc_bitmask_t   bitmask;    /*^ BITMASK ^*/
#define RRC_PHY_FAIL_CAUSE_PRESENT          0x01

    rrc_ue_index_t  ue_index;
    U8              response;

    U8              fail_cause;
/*^ O, RRC_PHY_FAIL_CAUSE_PRESENT ^*/

} rrc_phy_reconfig_ue_entity_cnf_t; /*^ API, RRC_PHY_RECONFIG_UE_ENTITY_CNF ^*/

#pragma pack(pop)

#endif /* _RRC_PHY_INTF_H_ */

