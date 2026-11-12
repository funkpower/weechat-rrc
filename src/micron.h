/*
 * micron.h - Micron formatting in RRC messages, turned into terminal colours
 *
 * NomadNet renders Micron in RRC messages. Because its Markdown pass reads a
 * backtick as inline code, senders write the Micron tag character as U+00A6
 * (broken bar, "¦") on the wire; the backtick form appears too. Supported:
 * ¦Fxxx ¦Bxxx (12-bit colour), ¦FTxxxxxx ¦BTxxxxxx (24-bit), ¦f ¦b (default
 * colour), ¦! ¦* ¦_ (bold, italic, underline toggles), `` (reset). Layout and
 * link tags (¦< ¦> ¦{ ¦c ¦l ¦r) are dropped.
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RRC_MICRON_H
#define RRC_MICRON_H

#include <stddef.h>

/* Returns the terminal codes for a WeeChat colour name: "214", "214,22",
 * "default,22", "reset", "bold", "-bold", "italic", "-italic", "underline",
 * "-underline". In the plugin this is weechat_color(). */
typedef const char *(*micron_color_fn)(const char *name);

/* Nearest xterm-256 colour index to an RGB colour. */
int micron_xterm256(int r, int g, int b);

/* Render text into out. Returns 1 if any Micron was found, else 0 (out is
 * then a plain copy). out is always NUL-terminated. */
int micron_render(const char *in, char *out, size_t out_size, micron_color_fn color);

/* Does the text contain Micron formatting at all? */
int micron_present(const char *in);

#endif
