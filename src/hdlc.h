/*
 * hdlc.h - the HDLC-style framing Reticulum uses on TCP and local sockets
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_HDLC_H
#define RRC_HDLC_H

#include <stddef.h>
#include <stdint.h>

#define HDLC_FLAG 0x7e
#define HDLC_ESC 0x7d
#define HDLC_ESC_MASK 0x20

/* Largest frame accepted from the wire. Reticulum's own TCP interface allows
 * far more (its HW_MTU), but nothing an RRC client handles exceeds the 500
 * byte packet MTU, so anything much larger is dropped. */
#define HDLC_MAX_FRAME 2048

/* Frame len bytes into out (which must hold 2 * len + 2). Returns the size. */
size_t hdlc_frame(const uint8_t *in, size_t len, uint8_t *out);

struct hdlc_rx {
    uint8_t buf[HDLC_MAX_FRAME];
    size_t len;
    int in_frame;
    int escape;
    int overflow;
};

typedef void (*hdlc_frame_cb)(void *ctx, const uint8_t *frame, size_t len);

void hdlc_rx_init(struct hdlc_rx *rx);
/* Feed received bytes; calls cb once per complete, non-empty frame. */
void hdlc_rx_feed(struct hdlc_rx *rx, const uint8_t *data, size_t len,
                  hdlc_frame_cb cb, void *ctx);

#endif
