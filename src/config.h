#ifndef _CONFIG_H_
#define _CONFIG_H_

#define BIP44_PATH_LEN 5
#define BIP44_BYTE_LENGTH (3 * sizeof(unsigned int))
#define APDU_HEADER_LENGTH 5
/** offset in the APDU header which says the length of the body. */
#define APDU_BODY_LENGTH_OFFSET 4
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER

/** max width of a single line of text. */
#define MAX_TX_TEXT_WIDTH 92

/** max lines of text to display. */
#define MAX_TX_TEXT_LINES 3
#define CURR_TX_DESC_LEN (MAX_TX_TEXT_LINES * MAX_TX_TEXT_WIDTH)

#define MAX_TX_RAW_LENGTH 1024

/** for signing, indicates this is the last part of the transaction. */
#define P1_LAST 0x80

/** for signing, indicates this is not the last part of the transaction, there are more parts coming. */
#define P1_MORE 0x00

#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00

#endif // _CONFIG_H_
