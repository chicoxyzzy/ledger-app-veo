#ifndef _VEO_H_
#define _VEO_H_

#include "cx.h"

#include "parse.h"
#include "config.h"

extern char curr_tx_desc[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
extern unsigned char raw_tx[MAX_TX_RAW_LENGTH];

#define ARRAYLEN(array) (sizeof(array) / sizeof(array[0]));

extern void prepare_text_description(void);
extern void derive_amoveo_keys(unsigned char*,
                               cx_ecfp_private_key_t*,
                               cx_ecfp_public_key_t*);

#endif // _VEO_H_
