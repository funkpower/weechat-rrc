/*
 * micron.c - Micron formatting in RRC messages, turned into terminal colours
 *
 * Copyright (C) 2026 funkpower
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "micron.h"

static const char BROKEN_BAR[] = "\xc2\xa6";

static int
hexval(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static int
hex_run(const char *p, int n)
{
    int i;

    for (i = 0; i < n; i++)
        if (hexval(p[i]) < 0)
            return 0;
    return 1;
}

int
micron_xterm256(int r, int g, int b)
{
    static const int level[6] = { 0, 95, 135, 175, 215, 255 };
    int ci[3], c[3] = { r, g, b }, i, k, best, d, cube_d = 0, gray, gray_i, gray_d;

    for (i = 0; i < 3; i++) {
        best = 0;
        for (k = 1; k < 6; k++)
            if ((c[i] - level[k]) * (c[i] - level[k]) < (c[i] - level[best]) * (c[i] - level[best]))
                best = k;
        ci[i] = best;
        d = c[i] - level[best];
        cube_d += d * d;
    }
    gray = (r + g + b) / 3;
    gray_i = gray < 8 ? 0 : gray > 238 ? 23 : (gray - 8 + 5) / 10;
    gray = 8 + 10 * gray_i;
    gray_d = (r - gray) * (r - gray) + (g - gray) * (g - gray) + (b - gray) * (b - gray);
    if (gray_d < cube_d)
        return 232 + gray_i;
    return 16 + 36 * ci[0] + 6 * ci[1] + ci[2];
}

/* A colour tag at p (just after the tag character): "Fxxx", "FTxxxxxx",
 * "Bxxx" or "BTxxxxxx". Returns its length, or 0. */
static int
colour_tag(const char *p, int *is_bg, int *index)
{
    int r, g, b;

    if (p[0] != 'F' && p[0] != 'B')
        return 0;
    *is_bg = p[0] == 'B';
    if (p[1] == 'T' && hex_run(p + 2, 6)) {
        r = hexval(p[2]) * 16 + hexval(p[3]);
        g = hexval(p[4]) * 16 + hexval(p[5]);
        b = hexval(p[6]) * 16 + hexval(p[7]);
        *index = micron_xterm256(r, g, b);
        return 8;
    }
    if (hex_run(p + 1, 3)) {
        *index = micron_xterm256(hexval(p[1]) * 17, hexval(p[2]) * 17, hexval(p[3]) * 17);
        return 4;
    }
    return 0;
}

/* Length of the tag character at p: 2 for "¦", 1 for a backtick (when
 * backticks count), else 0. */
static int
tag_char(const char *p, int raw_backticks)
{
    if (p[0] == BROKEN_BAR[0] && p[1] == BROKEN_BAR[1])
        return 2;
    if (p[0] == '`' && raw_backticks)
        return 1;
    return 0;
}

/* Backticks count as Micron only in a message that carries at least one
 * backtick colour tag, so prose like `code` stays as typed. */
static int
raw_colour_present(const char *in)
{
    const char *p;
    int is_bg, index;

    for (p = strchr(in, '`'); p; p = strchr(p + 1, '`'))
        if (colour_tag(p + 1, &is_bg, &index))
            return 1;
    return 0;
}

int
micron_present(const char *in)
{
    const char *p;
    int is_bg, index;

    for (p = strstr(in, BROKEN_BAR); p; p = strstr(p + 2, BROKEN_BAR))
        if (colour_tag(p + 2, &is_bg, &index) || strchr("fb!*_", p[2]))
            return 1;
    return raw_colour_present(in);
}

struct out {
    char *buf;
    size_t size, len;
    int full;
};

/* Append whole pieces only, so a colour code or a UTF-8 sequence is never
 * cut in half when out runs short. */
static void
put(struct out *o, const char *s, size_t n)
{
    if (o->full || o->len + n >= o->size) {
        o->full = 1;
        return;
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = '\0';
}

static void
put_colour(struct out *o, micron_color_fn color, int fg, int bg)
{
    char name[32], f[12], b[12];

    if (fg < 0)
        snprintf(f, sizeof(f), "default");
    else
        snprintf(f, sizeof(f), "%d", fg);
    if (bg < 0)
        snprintf(b, sizeof(b), "default");
    else
        snprintf(b, sizeof(b), "%d", bg);
    snprintf(name, sizeof(name), "%s,%s", f, b);
    put(o, color(name), strlen(color(name)));
}

int
micron_render(const char *in, char *out, size_t out_size, micron_color_fn color)
{
    struct out o = { out, out_size, 0, 0 };
    int raw = raw_colour_present(in), found = 0;
    int fg = -1, bg = -1, bold = 0, italic = 0, underline = 0, styled = 0;
    int is_bg, index, n, t;
    const char *p = in;
    const char *s;

    if (!out_size)
        return 0;
    out[0] = '\0';
    while (*p) {
        t = tag_char(p, raw);
        if (!t) {
            /* copy a whole UTF-8 sequence at once */
            n = 1;
            while (((unsigned char)p[n] & 0xc0) == 0x80)
                n++;
            put(&o, p, (size_t)n);
            p += n;
            continue;
        }
        s = p + t;
        if ((n = colour_tag(s, &is_bg, &index))) {
            if (is_bg)
                bg = index;
            else
                fg = index;
            put_colour(&o, color, fg, bg);
            styled = found = 1;
            p = s + n;
            continue;
        }
        switch (*s) {
        case 'f':
            fg = -1;
            put_colour(&o, color, fg, bg);
            break;
        case 'b':
            bg = -1;
            put_colour(&o, color, fg, bg);
            break;
        case '!':
            bold = !bold;
            put(&o, color(bold ? "bold" : "-bold"), strlen(color(bold ? "bold" : "-bold")));
            break;
        case '*':
            italic = !italic;
            put(&o, color(italic ? "italic" : "-italic"), strlen(color(italic ? "italic" : "-italic")));
            break;
        case '_':
            underline = !underline;
            put(&o, color(underline ? "underline" : "-underline"),
                strlen(color(underline ? "underline" : "-underline")));
            break;
        case '`':
            fg = bg = -1;
            bold = italic = underline = 0;
            put(&o, color("reset"), strlen(color("reset")));
            break;
        case '<': case '>': case '{': case 'c': case 'l': case 'r': case 'a': case '=':
            break;   /* layout, fields, links: dropped */
        default:
            /* not a tag: keep the character as written */
            put(&o, p, (size_t)t);
            p += t;
            continue;
        }
        styled = found = 1;
        p = s + 1;
    }
    if (styled)
        put(&o, color("reset"), strlen(color("reset")));
    return found;
}
