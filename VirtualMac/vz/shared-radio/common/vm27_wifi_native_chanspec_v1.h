#ifndef VM27_WIFI_NATIVE_CHANSPEC_V1_H
#define VM27_WIFI_NATIVE_CHANSPEC_V1_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// 20B101 AppleBCMWLANChanSpec::getBCMChannelSpec (RVA 0x237530)
// packs center | sideband<<8 | widthEnum<<11 | bandEnum<<14.
// CHANNEL is the primary channel, not the center for a 40/80/160 MHz BSS.
// The native scan's flags and HT/VHT operation must describe the same BSS.
static inline bool vm27_wifi_native_chanspec_v1(unsigned primary, unsigned flags,
    unsigned width, const uint8_t *ies, size_t length, uint16_t *output) {
    if (!output || !primary || primary > 196 || length > 4096 || (length && !ies)) return false;
    unsigned band = flags & (8u | 16u | 8192u);
    if (band != (primary <= 14 ? 8u : 16u)) return false;
    unsigned htPrimary = 0, htSecondary = 0, htWidth40 = 0;
    unsigned vhtWidth = 0, segment0 = 0, segment1 = 0;
    bool haveHT = false, haveVHT = false;
    for (size_t at = 0; at < length;) {
        if (length - at < 2 || ies[at + 1] > length - at - 2) return false;
        size_t n = ies[at + 1];
        if (ies[at] == 61) {
            if (haveHT || n < 2) return false;
            haveHT = true; htPrimary = ies[at + 2];
            htSecondary = ies[at + 3] & 3; htWidth40 = ies[at + 3] & 4;
        } else if (ies[at] == 192) {
            if (haveVHT || n < 5) return false;
            haveVHT = true; vhtWidth = ies[at + 2];
            segment0 = ies[at + 3]; segment1 = ies[at + 4];
        }
        at += n + 2;
    }
    if (haveHT && htPrimary != primary) return false;
    unsigned center = primary, sideband = 0, widthEnum = 0;
    if (width == 20 && (flags & 2u)) widthEnum = 2;
    else if (width == 40 && (flags & 4u)) {
        bool lower = (flags & 512u) != 0;
        if (!haveHT || !htWidth40 || htSecondary != (lower ? 1u : 3u) || (!lower && primary <= 2)) return false;
        center = lower ? primary + 2 : primary - 2;
        sideband = lower ? 0 : 1; widthEnum = 3;
    } else if ((width == 80 && (flags & 1024u)) || (width == 160 && (flags & 2048u))) {
        if (primary <= 14 || !haveVHT) return false;
        if (width == 80 && vhtWidth == 1) center = segment0;
        else if (width == 160 && vhtWidth == 2) center = segment0;
        else if (width == 160 && vhtWidth == 1 && segment1 &&
                 (segment1 + 8 == segment0 || segment0 + 8 == segment1)) center = segment1;
        else return false; // Do not reinterpret discontiguous 80+80 as 160.
        unsigned halfSpan = width == 80 ? 6 : 14;
        if (center <= halfSpan || primary < center - halfSpan) return false;
        unsigned delta = primary - (center - halfSpan);
        if (delta % 4 || delta > 2 * halfSpan) return false;
        sideband = delta / 4; widthEnum = width == 80 ? 4 : 5;
    } else return false;
    if (!center || center > (primary <= 14 ? 14u : 196u)) return false;
    *output = (uint16_t)(center | sideband << 8 | widthEnum << 11 | (primary > 14 ? 3u << 14 : 0));
    return true;
}
#endif
