/*
 * hdlc.c - the HDLC-style framing Reticulum uses on TCP and local sockets
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "hdlc.h"

size_t
hdlc_frame(const uint8_t *in, size_t len, uint8_t *out)
{
    size_t i, n = 0;

    out[n++] = HDLC_FLAG;
    for (i = 0; i < len; i++) {
        if (in[i] == HDLC_FLAG || in[i] == HDLC_ESC) {
            out[n++] = HDLC_ESC;
            out[n++] = in[i] ^ HDLC_ESC_MASK;
        } else {
            out[n++] = in[i];
        }
    }
    out[n++] = HDLC_FLAG;
    return n;
}

void
hdlc_rx_init(struct hdlc_rx *rx)
{
    rx->len = 0;
    rx->in_frame = 0;
    rx->escape = 0;
    rx->overflow = 0;
}

void
hdlc_rx_feed(struct hdlc_rx *rx, const uint8_t *data, size_t len,
             hdlc_frame_cb cb, void *ctx)
{
    size_t i;
    uint8_t b;

    for (i = 0; i < len; i++) {
        b = data[i];
        if (b == HDLC_FLAG) {
            /* A flag both ends one frame and starts the next. */
            if (rx->in_frame && rx->len > 0 && !rx->overflow && !rx->escape)
                cb(ctx, rx->buf, rx->len);
            rx->in_frame = 1;
            rx->len = 0;
            rx->escape = 0;
            rx->overflow = 0;
            continue;
        }
        if (!rx->in_frame)
            continue;
        if (rx->escape) {
            b ^= HDLC_ESC_MASK;
            rx->escape = 0;
        } else if (b == HDLC_ESC) {
            rx->escape = 1;
            continue;
        }
        if (rx->len < sizeof(rx->buf))
            rx->buf[rx->len++] = b;
        else
            rx->overflow = 1;
    }
}
