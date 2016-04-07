/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (C) 2009 Aricent Inc. All Rights Reserved.
 *
 ****************************************************************************
 *
 *  $Id: s1ap_api.h,v 1.1.2.1 2010/05/11 04:55:38 gur19836 Exp $
 *
 ****************************************************************************
 *
 *  File Description : 
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------
 *
 * $Log: s1ap_api.h,v $
 * Revision 1.1.2.1  2010/05/11 04:55:38  gur19836
 * Files added for RRC 1.0 Integration
 *
 * Revision 1.2  2010/01/04 16:10:05  ukr15916
 * no message
 *
 * Revision 1.1.2.6  2009/12/28 05:09:42  gur18569
 * fixed indentation
 *
 * Revision 1.1.2.5  2009/12/11 04:47:50  gur21006
 * Added API for sctp shutdown message type
 *
 * Revision 1.1.2.4  2009/12/03 10:11:36  gur18569
 * integration changes
 *
 * Revision 1.1.2.3  2009/12/03 09:24:08  ukr18877
 * Points 5, 10 and 3MM (CSC) from mail "Questions about S1AP" fixed. Parameter RUNNER_RRC_UECC_FT set to 0 (for SSIT testing), OAM connect and cleanup SSIT tests added
 *
 * Revision 1.1.2.2  2009/12/01 15:07:24  gur18569
 * integration changes
 *
 * Revision 1.1.2.1  2009/11/25 13:11:02  gur18569
 * Shifted to level of rrc dir
 *
 * Revision 1.1.2.2  2009/11/17 04:30:47  gur20470
 * Modified value of S1AP_OAM_API_BASE
 *
 * Revision 1.1.2.1  2009/10/23 16:11:39  gur18569
 * Initial version
 *
 *
 *
 ****************************************************************************/

#ifndef _S1AP_API_H_
#define _S1AP_API_H_

/****************************************************************************
 * Project Includes
 ****************************************************************************/
//#include "rrc_defines.h"
//#include "rrc_ext_api.h"
//#include "rrc_intrl_api.h"

/****************************************************************************
 * Exported Includes
 ****************************************************************************/



/****************************************************************************
 * Exported Definitions
 ****************************************************************************/
/********************************************************************
 *                        EXTERNAL APIs
 *******************************************************************/
/********************************************************************
 * S1AP - OAM APIs
 *******************************************************************/
#define S1AP_OAM_API_BASE                      0x0500

#define S1AP_OAM_INIT_IND                      (S1AP_OAM_API_BASE + 1)
#define S1AP_OAM_INIT_CNF                      (S1AP_OAM_API_BASE + 2)
#define S1AP_OAM_PROVISION_REQ                 (S1AP_OAM_API_BASE + 3)
#define S1AP_OAM_PROVISION_RESP                (S1AP_OAM_API_BASE + 4)
#define S1AP_OAM_RESET_REQ                     (S1AP_OAM_API_BASE + 5)
#define S1AP_OAM_RESET_RESP                    (S1AP_OAM_API_BASE + 6)
#define S1AP_OAM_CLEANUP_REQ                   (S1AP_OAM_API_BASE + 7)
#define S1AP_OAM_CLEANUP_RESP                  (S1AP_OAM_API_BASE + 8)
#define S1AP_OAM_STATS_IND                     (S1AP_OAM_API_BASE + 9)
#define S1AP_OAM_STATS_RESP                    (S1AP_OAM_API_BASE + 10)


/********************************************************************
 *                        INTERNAL APIs
 *******************************************************************/
/* S1AP - UECC and S1AP - CSC API IDs defined in rrc_intrl_api.h */

/********************************************************************
 * S1AP - CMES ASSOCIATED
 *******************************************************************/
#if 0

#define MME_MESSAGE                        0
#define SCTP_CONN_FAILURE_IND              1
#define SCTP_CONN_RECOVERY_IND             2
#define SCTP_CONN_SHUTDOWN_EVENT           3
#endif

/****************************************************************************
 * Exported Types
 ****************************************************************************/

/****************************************************************************
 * Exported Constants
 ****************************************************************************/

/****************************************************************************
 * Exported Variables
 ****************************************************************************/

/****************************************************************************
 * Exported Functions
 ****************************************************************************/

#endif  /* _S1AP_API_H_ */
