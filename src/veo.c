#include "os.h"

#include "string.h"

#include "veo.h"
#include "utils.h"

typedef unsigned int uint;

char curr_tx_desc[MAX_TX_TEXT_LINES][MAX_TX_TEXT_WIDTH];
unsigned char raw_tx[MAX_TX_RAW_LENGTH];

static const char *tx_types[] = {"create_acc_tx", "spend", "oracle_new", "oracle_bet", "oracle_close", "unmatched", "oracle_winnings"};
static const char not_supported[] = "tx type not supported";

void format_veo(const uint, char*, unsigned char);

static void parse_tx_data(char dst[][92], unsigned char fields,
                          const unsigned char *src) {
  const unsigned char *start = src + 1;

  unsigned int i = 0;
  unsigned char k = 0;
  unsigned char len = 0;

  for (i = 1; i < MAX_TX_RAW_LENGTH && k < fields; i++) {
    if (src[i] == ',' || src[i] == '\0' || src[i] == ']') {
      if (k == 0 || k == 1 || k == 4) { // strip quotes
        len = src + i - start - 2;
        os_memmove(dst[k], start + 1, len);
      } else { // store value as is
        len = src + i - start;
        os_memmove(dst[k], start, len);
      }
      dst[k++][len] = '\0';
      start = src + i + 1;
    }

    if (src[i] == '\0' || src[i] == ']')
      break;
  }
}

//static int contains(char **arr, const char *target) {
//  int i = 0;
//  int arr_len = ARRAYLEN(arr[0]);
//  int target_len = strlen(target);
//  for(i = 0; i < arr_len; i++) {
//    if(os_memcmp(arr[i], target, target_len) == 0) {
//      return 1;
//    }
//  }
//  return 0;
//}

void prepare_text_description(void) {
  char data[10][92];
  parse_tx_data(data, 10, raw_tx);

  // TODO insure length is enough for all cases
  char page1[50];
  char page2[50];
  char page3[50];

//  if (contains(tx_types, data[0]) == 1) {
  const unsigned char len = strlen(data[0]);
  // create_acc_tx, spend
  if ( (os_memcmp(data[0], tx_types[0], len) == 0) ||
       (os_memcmp(data[0], tx_types[1], len) == 0) ) {
    // address
    data[4][21] = '\0';
    snprintf(page1, 50, "%s...%s", data[4], data[4] + 68);
    // amount
    char amount[20];
    format_veo(atoi(data[5]), amount, 20);
    snprintf(page2, 50, "%s VEO", amount);
    // fee
    char fee[20];
    format_veo(atoi(data[3]), fee, 20);
    snprintf(page3, 50, "%s VEO for %s", fee, data[0]);

    os_memmove(curr_tx_desc[0], page1, 50);
    os_memmove(curr_tx_desc[1], page2, 50);
    os_memmove(curr_tx_desc[2], page3, 50);
  // oracle_new
  } else if ( (os_memcmp(data[0], tx_types[2], len) == 0) ) {
    // TODO oracle_new
  // oracle_bet
  } else if ( (os_memcmp(data[0], tx_types[3], len) == 0) ) {
//    // id
//    char oracle_id[20];
//    format_veo(atoi(data[1]), oracle_id, 20);
//    snprintf(page1, 50, "%s", oracle_id);
//    // type
//    snprintf(page2, 50, "%d", data[5]);
//    // fee
//    char fee[20];
//    format_veo(atoi(data[3]), fee, 20);
//    snprintf(page3, 50, "%s VEO for %s", fee, data[0]);
  // oracle_close, unmatched, unmatched, oracle_winnings
  } else if ( (os_memcmp(data[0], tx_types[4], len) == 0) ||
              (os_memcmp(data[0], tx_types[5], len) == 0) ||
              (os_memcmp(data[0], tx_types[6], len) == 0) ) {
    // id
    char oracle_id[20];
    format_veo(atoi(data[1]), oracle_id, 20);
    snprintf(page1, 50, "%s", oracle_id);
    // fee
    char fee[20];
    format_veo(atoi(data[3]), fee, 20);
    snprintf(page2, 50, "%s VEO for %s", fee, data[0]);

    os_memmove(curr_tx_desc[3], page1, 50);
    os_memmove(curr_tx_desc[1], page2, 50);
  } else {
    os_memmove(page1, not_supported, strlen(not_supported));
//    os_memmove(page2, not_supported, strlen(not_supported));
//    os_memmove(page3, not_supported, strlen(not_supported));
  }
}


void derive_amoveo_keys(unsigned char *bip44_in,
                        cx_ecfp_private_key_t *privateKey,
                        cx_ecfp_public_key_t *publicKey) {
  /** BIP44 path, used to derive the private key from the
      mnemonic by calling os_perso_derive_node_bip32. */

  unsigned int bip44_path[BIP44_PATH_LEN];
  bip44_path[0] = 0x8000002c;  // `m` in derivation path
  bip44_path[1] = 0x800001e8;  // VEO id in SLIP-44
  uint32_t i;
  for (i = 2; i < BIP44_PATH_LEN; i++) {
    bip44_path[i] = (bip44_in[0] << 24) | (bip44_in[1] << 16) | (bip44_in[2] << 8) | (bip44_in[3]);
    bip44_in += 4;
  }
  unsigned char privateKeyData[32];
  os_perso_derive_node_bip32(CX_CURVE_256K1, bip44_path, BIP44_PATH_LEN, privateKeyData, NULL);
  cx_ecdsa_init_private_key(CX_CURVE_256K1, privateKeyData, 32, privateKey);

  if (publicKey != NULL) {
    // generate the public key.
    cx_ecdsa_init_public_key(CX_CURVE_256K1, NULL, 0, publicKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, publicKey, privateKey, 1);
  }
}

void format_veo(const uint amount, char* out, unsigned char len) {
  const uint int_part = amount / 100000000;
  const uint frac_part = amount - int_part * 100000000;

  if (frac_part == 0) {
    snprintf(out, len, "%d", int_part);
  } else {
    snprintf(out, len, "%d.%08d", int_part, frac_part);

    char *p;
    for (p = out + strlen(out) - 1; p > out; p--) {
      if (*p != '0') break;
      else *p = '\0';
    }
  }
}
