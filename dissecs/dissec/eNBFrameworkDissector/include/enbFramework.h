/****************************************************************************
 *
 *  ARICENT -
 *
 *  Copyright (c) Aricent.
 *
 ****************************************************************************
 *
 *  $Id: lteOamSimulator.h,v 1.1.4.1 2010/05/11 03:25:38 gur19836 Exp $ 

 ****************************************************************************
 *
 *  File Description : This file contains declarations for the OAM Interface
 *                     of MAC & RLC and OAM simulator
 *
 ****************************************************************************
 *
 * Revision Details
 * ----------------

 *
 ****************************************************************************/
#ifndef _ENB_FRAMEWORK_H_
#define  _ENB_FRAMEWORK_H_
#define guintipv4 guint32
#define guintip guint32
#define guintipinc15 guint32
#define guintcardbasic guint16
#define guintcardextend guint16
#define guintpad guint16
#define guintpadone guint16
#define guintpad24 guint16
#define guintpad6500 guint16
#define guintsdmcardstate guint16
#define IS_LITTLE_ENDIAN 0
	#if(IS_LITTLE_ENDIAN)
	#define tvb_get_ntohs tvb_get_letohs
	#define tvb_get_ntoh24 tvb_get_letoh24 
	#define tvb_get_ntohl tvb_get_letohl
	#define tvb_get_ntoh64 tvb_get_letoh64 
	#endif
#define HIBYTE(x) (0x0FF&(x>>8))
#define LOBYTE(x) (0x0FF&x)
#define REVERSE_BYTE(x) ((LOBYTE(x)<<8)|(HIBYTE(x)))

static int      IS_LITTLE_ENDIAN_OAM    = 1;
static int      IS_LITTLE_ENDIAN_RRM    = 1;
#endif

