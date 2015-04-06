/*
 * This file is part of Foren6, a 6LoWPAN Diagnosis Tool
 * Copyright (C) 2013, CETIC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * \file
 *         PCAP input interface
 * \author
 *         Foren6 Team <foren6@cetic.be>
 */

#ifndef INTERFACE_PCAP_H
#define	INTERFACE_PCAP_H

#include <interface_reader/interfaces_mgr.h>
#include <stdint.h>

int interface_get_version();
interface_t interface_register();


/* Macros & Defines */

/** \brief These are some definitions of values used in the FCF.  See the 802.15.4 spec for details.
 *  \name FCF element values definitions
 *  @{
 */
#define FRAME802154_BEACONFRAME     (0x00)
#define FRAME802154_DATAFRAME       (0x01)
#define FRAME802154_ACKFRAME        (0x02)
#define FRAME802154_CMDFRAME        (0x03)

#define FRAME802154_BEACONREQ       (0x07)

#define FRAME802154_IEEERESERVED    (0x00)
#define FRAME802154_NOADDR          (0x00)      /**< Only valid for ACK or Beacon frames. */
#define FRAME802154_SHORTADDRMODE   (0x02)
#define FRAME802154_LONGADDRMODE    (0x03)

#define FRAME802154_NOBEACONS       (0x0F)

#define FRAME802154_BROADCASTADDR   (0xFFFF)
#define FRAME802154_BROADCASTPANDID (0xFFFF)

#define FRAME802154_IEEE802154_2003 (0x00)
#define FRAME802154_IEEE802154_2006 (0x01)

#define FRAME802154_SECURITY_LEVEL_NONE (0)
#define FRAME802154_SECURITY_LEVEL_128  (3)

#define FRAME802154_SECURITY_LEVEL_NONE        (0)
#define FRAME802154_SECURITY_LEVEL_MIC_32      (1)
#define FRAME802154_SECURITY_LEVEL_MIC_64      (2)
#define FRAME802154_SECURITY_LEVEL_MIC_128     (3)
#define FRAME802154_SECURITY_LEVEL_ENC         (4)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_32  (5)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_64  (6)
#define FRAME802154_SECURITY_LEVEL_ENC_MIC_128 (7)

#define FRAME802154_IMPLICIT_KEY               (0)
#define FRAME802154_1_BYTE_KEY_ID_MODE         (1)
#define FRAME802154_5_BYTE_KEY_ID_MODE         (2)
#define FRAME802154_9_BYTE_KEY_ID_MODE         (3)

#define NODE_6LBR_FRAME802154_SECURITY_ENABLE   1



/**
 *    @brief  The IEEE 802.15.4 frame has a number of constant/fixed fields that
 *            can be counted to make frame construction and max payload
 *            calculations easier.
 *
 *            These include:
 *            1. FCF                  - 2 bytes       - Fixed
 *            2. Sequence number      - 1 byte        - Fixed
 *            3. Addressing fields    - 4 - 20 bytes  - Variable
 *            4. Aux security header  - 0 - 14 bytes  - Variable
 *            5. CRC                  - 2 bytes       - Fixed
*/

/**
 * \brief Defines the bitfields of the frame control field (FCF).
 */
typedef struct {
  uint8_t frame_type;        /**< 3 bit. Frame type field, see 802.15.4 */
  uint8_t security_enabled;  /**< 1 bit. True if security is used in this frame */
  uint8_t frame_pending;     /**< 1 bit. True if sender has more data to send */
  uint8_t ack_required;      /**< 1 bit. Is an ack frame required? */
  uint8_t panid_compression; /**< 1 bit. Is this a compressed header? */
  /*   uint8_t reserved; */  /**< 3 bit. Unused bits */
  uint8_t dest_addr_mode;    /**< 2 bit. Destination address mode, see 802.15.4 */
  uint8_t frame_version;     /**< 2 bit. 802.15.4 frame version */
  uint8_t src_addr_mode;     /**< 2 bit. Source address mode, see 802.15.4 */
} frame802154_fcf_t;

/** \brief 802.15.4 security control bitfield.  See section 7.6.2.2.1 in 802.15.4 specification */
typedef struct {
  uint8_t  security_level; /**< 3 bit. security level      */
  uint8_t  key_id_mode;    /**< 2 bit. Key identifier mode */
  uint8_t  reserved;       /**< 3 bit. Reserved bits       */
} frame802154_scf_t;

/** \brief 802.15.4 Aux security header */
typedef struct {
  frame802154_scf_t security_control;  /**< Security control bitfield */
  uint32_t frame_counter;   /**< Frame counter, used for security */
  uint8_t  key_source[8];
  uint8_t  key_index;          /**< The key itself, or an index to the key */
} frame802154_aux_hdr_t;

/** \brief Parameters used by the frame802154_create() function.  These
 *  parameters are used in the 802.15.4 frame header.  See the 802.15.4
 *  specification for details.
 */
typedef struct {
  frame802154_fcf_t fcf;            /**< Frame control field  */
  uint8_t seq;          /**< Sequence number */
  uint16_t dest_pid;    /**< Destination PAN ID */
  uint8_t dest_addr[8];     /**< Destination address */
  uint16_t src_pid;     /**< Source PAN ID */
  uint8_t src_addr[8];      /**< Source address */
  frame802154_aux_hdr_t aux_hdr;    /**< Aux security header */
  uint8_t *payload;     /**< Pointer to 802.15.4 frame payload */
  int payload_len;  /**< Length of payload field */
} frame802154_t;


#ifdef LINKADDR_CONF_SIZE
#define LINKADDR_SIZE LINKADDR_CONF_SIZE
#else /* LINKADDR_SIZE */
#define LINKADDR_SIZE 2
#endif /* LINKADDR_SIZE */

typedef union {
  unsigned char u8[LINKADDR_SIZE];
} linkaddr_t;

#if LINKADDR_SIZE == 2
const linkaddr_t linkaddr_null = { { 0, 0 } };
#else /*LINKADDR_SIZE == 2*/
#if LINKADDR_SIZE == 8
const linkaddr_t linkaddr_null = { { 0, 0, 0, 0, 0, 0, 0, 0 } };
#endif /*LINKADDR_SIZE == 8*/
#endif /*LINKADDR_SIZE == 2*/

#endif /* INTERFACE_PCAP_H */

unsigned char galois_mul2(unsigned char value);
int aes_enc_dec(unsigned char *state, int inlen, unsigned char *key, unsigned char dir, unsigned char *output);
int add(int a, int b);
void add_string (char *a, char *b, char *c); 
