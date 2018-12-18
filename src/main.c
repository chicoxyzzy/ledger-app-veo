/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"
#include "u2f_service.h"

#include "config.h"

#include "base64.h"
#include "ui.h"
#include "veo.h"

#include "glyphs.h"

unsigned int ux_step;
unsigned int ux_step_count;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/** the hash. */
static cx_sha256_t hash;

/** current index into raw transaction. */
static unsigned int raw_tx_ix;
/** current length of raw transaction. */
static unsigned int raw_tx_len;

static unsigned char fullAddress[92];
static unsigned char globalPublicKey[65];

ux_state_t ux;

static void ui_idle(void);
static unsigned int ui_approval_nanos_button(unsigned int, unsigned int);
static unsigned int ui_approval_prepro(const bagl_element_t*);

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *);
static const bagl_element_t *io_seproxyhal_touch_approve(const bagl_element_t *);
static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *);

unsigned int get_apdu_buffer_length() {
        unsigned int len0 = G_io_apdu_buffer[APDU_BODY_LENGTH_OFFSET];
        return len0;
}

// ********************************************************************************
// Ledger Nano S specific UI
// ********************************************************************************
const bagl_element_t ui_approval_nanos[] = {
  // type                               userid    x    y   w    h  str rad fill      fg        bg      fid iid  txt   touchparams...       ]
  {{BAGL_RECTANGLE                      , 0x00,   0,   0, 128,  32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_ICON                           , 0x00,   3,  12,   7,   7, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS  }, NULL, 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_ICON                           , 0x00, 117,  13,   8,   6, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK  }, NULL, 0, 0, 0, NULL, NULL, NULL },

  //{{BAGL_ICON                           , 0x01,  31,   9,  14,  14, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE  }, NULL, 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x01,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Confirm", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x01,   0,  26, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "transaction", 0, 0, 0, NULL, NULL, NULL },

  {{BAGL_LABELINE                       , 0x02,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Pubkey", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x02,  23,  26,  82,  12, 0x80|25, 0, 0  , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 96  }, curr_tx_desc[0], 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x03,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Amount", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x03,  23,  26,  82,  12, 0x80|10, 0, 0  , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 26  }, curr_tx_desc[1], 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x04,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Fee & type", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x04,  23,  26,  82,  12, 0x80|10, 0, 0  , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 26  }, curr_tx_desc[2], 0, 0, 0, NULL, NULL, NULL },
};

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
  {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

const ux_menu_entry_t menu_main[] = {
  {NULL, NULL, 0, &C_nanos_veo_badge, "Use wallet to", "view accounts", 33, 12},
  // {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
  //  {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
  {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
  {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
  UX_MENU_END
};

static const bagl_element_t*
io_seproxyhal_touch_approve(const bagl_element_t *e) {
  unsigned int tx = 0;

  unsigned int data_len_except_bip44 = raw_tx_len - BIP44_BYTE_LENGTH;

  cx_ecfp_private_key_t privateKey;
  derive_amoveo_keys(raw_tx + data_len_except_bip44,
                     &privateKey, NULL);

  unsigned char serialized[1024];
  data_len_except_bip44 = parse(raw_tx, data_len_except_bip44, serialized);

  if (data_len_except_bip44 > 10) {
  // Hash is finalized, send back the signature
  unsigned char result[32];
  cx_hash(&hash.header, CX_LAST, serialized, data_len_except_bip44, result);
  tx = cx_ecdsa_sign((void*) &privateKey, CX_RND_RFC6979 | CX_LAST,
                       CX_SHA256, result, sizeof(result), G_io_apdu_buffer, NULL);
  G_io_apdu_buffer[0] &= 0xF0; // discard the parity information

  } else {
    G_io_apdu_buffer[tx++] = data_len_except_bip44;
  }

  hashTainted = 1;
  raw_tx_ix = 0;

  G_io_apdu_buffer[tx++] = 0x90;
  G_io_apdu_buffer[tx++] = 0x00;
  // Send back the response, do not restart the event loop
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
  // Display back the original UX
  ui_idle();
  return 0; // do not redraw the widget
}

static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *e) {
    hashTainted = 1;
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return NULL;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

static void ui_idle(void) {
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {

    } else {
        UX_MENU_DISPLAY(0, menu_main, NULL);
    }
}

// ======================= ADDRESS ACTIONS ===========================

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    uint32_t tx = 65;
    os_memmove(G_io_apdu_buffer, globalPublicKey, 65);

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

const bagl_element_t ui_address_nanos[] = {
  // type                               userid    x    y   w    h  str rad fill      fg        bg      fid iid  txt   touchparams...       ]
  {{BAGL_RECTANGLE                      , 0x00,   0,   0, 128,  32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_ICON                           , 0x00,   3,  12,   7,   7, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS  }, NULL, 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_ICON                           , 0x00, 117,  13,   8,   6, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK  }, NULL, 0, 0, 0, NULL, NULL, NULL },

  //{{BAGL_ICON                           , 0x01,  31,   9,  14,  14, 0, 0, 0        , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE  }, NULL, 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x01,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Confirm", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x01,   0,  26, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "pubkey", 0, 0, 0, NULL, NULL, NULL },

  {{BAGL_LABELINE                       , 0x02,   0,  12, 128,  12, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Pubkey", 0, 0, 0, NULL, NULL, NULL },
  {{BAGL_LABELINE                       , 0x02,  23,  26,  82,  12, 0x80|20, 0, 0  , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 96  }, (char*)fullAddress, 0, 0, 0, NULL, NULL, NULL },
};

static unsigned int
ui_address_prepro(const bagl_element_t* element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid-1);
        if(display) {
          switch(element->component.userid) {
          case 1:
            UX_CALLBACK_SET_INTERVAL(2000);
            break;
          case 2:
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000+bagl_label_roundtrip_duration_ms(element, 7)));
            break;
          }
        }
        return display;
    }
    return 1;
}

static unsigned int
ui_address_nanos_button(unsigned int button_mask,
                        unsigned int button_mask_counter) {
    switch(button_mask) {
        case BUTTON_EVT_RELEASED|BUTTON_LEFT: // CANCEL
          io_seproxyhal_touch_address_cancel(NULL);
          break;

        case BUTTON_EVT_RELEASED|BUTTON_RIGHT: { // OK
          io_seproxyhal_touch_address_ok(NULL);
          break;
        }
    }
    return 0;
}

// ==============================================================================

// ========================== APPPROVAL =====================

static unsigned int
ui_approval_prepro(const bagl_element_t* element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid-1);
        if(display) {
          switch(element->component.userid) {
          case 1:
            UX_CALLBACK_SET_INTERVAL(2000);
            break;
          case 2:
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000+bagl_label_roundtrip_duration_ms(element, 7)));
            break;
          case 3:
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 2000+bagl_label_roundtrip_duration_ms(element, 7)));
            break;
          case 4:
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000+bagl_label_roundtrip_duration_ms(element, 7)));
            break;
          }
        }
        return display;
    }
    return 1;
}

static unsigned int
ui_approval_nanos_button(unsigned int button_mask,
                        unsigned int button_mask_counter) {
    switch(button_mask) {
        case BUTTON_EVT_RELEASED|BUTTON_LEFT: // CANCEL
          io_seproxyhal_touch_deny(NULL);
          break;

        case BUTTON_EVT_RELEASED|BUTTON_RIGHT: { // OK
          io_seproxyhal_touch_approve(NULL);
          break;
        }
    }
    return 0;
}

// ===========================================================================


static void amoveo_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                  hashTainted = 1;
                  THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != 0x80) {
                  hashTainted = 1;
                  THROW(0x6E00);
                }

                PRINTF("Buffer: %.*h\n", 5, G_io_apdu_buffer);

                // unauthenticated instruction
                switch (G_io_apdu_buffer[1]) {
                case 0x00: // reset
                    flags |= IO_RESET_AFTER_REPLIED;
                    THROW(0x9000);
                    break;

                case 0x01: { // get public key
                  if ((G_io_apdu_buffer[2] != P1_CONFIRM) &&
                      (G_io_apdu_buffer[2] != P1_NON_CONFIRM)) {
                    THROW(0x6B00);
                  }

                  cx_ecfp_public_key_t publicKey;
                  cx_ecfp_private_key_t privateKey;

                  derive_amoveo_keys(G_io_apdu_buffer + APDU_HEADER_LENGTH,
                                     &privateKey, &publicKey);

                  PRINTF("Pubkey: %.*h\n\n", 65, publicKey.W);

                  if (G_io_apdu_buffer[2] == P1_NON_CONFIRM) {
                    // push the public key onto the response buffer.
                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    tx = 65;

                    // return 0x9000 OK.
                    THROW(0x9000);

                  } else {
                    os_memmove(globalPublicKey, publicKey.W, 65);
                    Base64encode(fullAddress, publicKey.W, 65);

                    ux_step = 0;
                    ux_step_count = 2;
                    UX_DISPLAY(ui_address_nanos, ui_address_prepro);

                    flags |= IO_ASYNCH_REPLY;
                  }
                }
                  break;

                case 0x02: {// got tx to sign
                  if ((G_io_apdu_buffer[2] != P1_MORE) &&
                      (G_io_apdu_buffer[2] != P1_LAST)) {
                    hashTainted = 1;
                    THROW(0x6A86);
                  }

                  if (hashTainted) {
                    cx_sha256_init(&hash);
                    hashTainted = 0;
                    raw_tx_ix = 0;
                    raw_tx_len = 0;
                  }

                  unsigned int len = get_apdu_buffer_length();
                  unsigned char * in = G_io_apdu_buffer + APDU_HEADER_LENGTH;
                  unsigned char * out = raw_tx + raw_tx_ix;
                  if (raw_tx_ix + len > MAX_TX_RAW_LENGTH) {
                    hashTainted = 1;
                    THROW(0x6D08);
                  }

                  os_memmove(out, in, len);
                  raw_tx_ix += len;

                  /* if (raw_tx[0] != '[') { */
                  /*   hashTainted = 1; */
                  /*   THROW(0x6A80); */
                  /* } */

                  if (G_io_apdu_buffer[2] == P1_LAST) {
                    out[len] = '\0';

                    raw_tx_len = raw_tx_ix;
                    raw_tx_ix = 0;

                    prepare_text_description();

                    ux_step = 0;
                    ux_step_count = 4;
                    UX_DISPLAY(ui_approval_nanos, ui_approval_prepro);

                    flags |= IO_ASYNCH_REPLY;

                    hashTainted = 1;

                  } else {
                    THROW(0x9000);
                  }
                }
                  break;

                case 0xFF: // return to dashboard
                    goto return_to_dashboard;

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

return_to_dashboard:
    return;
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
      UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
          if (UX_ALLOWED) {
            if (ux_step_count) {
              // prepare next screen
              ux_step = (ux_step+1)%ux_step_count;
              // redisplay screen
              UX_REDISPLAY();
            }
          }
        });
      break;

    // unknown events are acknowledged
    default:
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

#ifdef LISTEN_BLE
            if (os_seph_features() &
                SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
                BLE_power(0, NULL);
                // restart IOs
                BLE_power(1, NULL);
            }
#endif

            USB_power(0);
            USB_power(1);

            ui_idle();

            amoveo_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
}
