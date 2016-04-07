#ifndef _RRM_EXT_API_H_
#define _RRM_EXT_API_H_

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "ueTags.h"

typedef struct _ext_api_hdr_t
{
    unsigned short      transaction_id;
    unsigned short      source_id;
    unsigned short      dest_id;
    unsigned short     api_id;
    unsigned short      buf_len;
}ext_api_hdr_t;

//#define RRM_MODULE_ID 2
#define OAM_MODULE_ID 201

#endif
