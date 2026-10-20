#include "vm27_own_uikit_ingress_values_v2_buttons.h"
#include <math.h>

static double unit(double v) { return fmax(0.0, fmin(1.0, v)); }
VM27InputResult vm27_own_pointer_arguments_v1(const VM27InputPacket *packet,
    VM27InputViewportV1 viewport, const VM27OwnPointerStateV1 *state,
    VM27OwnPointerArgumentsV1 *output, VM27OwnPointerStateV1 *next) {
    if (!packet || !state || !output || !next || packet->version != 1 ||
        !isfinite(viewport.x) || !isfinite(viewport.y) || !isfinite(viewport.width) ||
        !isfinite(viewport.height) || viewport.width <= 0 || viewport.height <= 0 ||
        !isfinite(state->normalizedX) || !isfinite(state->normalizedY) ||
        (state->hasPosition && (state->normalizedX < 0 || state->normalizedX > 1 ||
                                state->normalizedY < 0 || state->normalizedY > 1)) ||
        (state->pressed && !state->hasPosition) || (state->buttons & ~UINT32_C(7)) ||
        (state->pressed != (state->buttons != 0)))
        return VM27InputInvalid;
    VM27OwnPointerStateV1 result = *state;
    if (packet->source == VM27InputPointerButtons) {
        if ((packet->present & (VM27InputHasPosition|VM27InputHasPointerButtons|VM27InputHasPhase)) !=
            (VM27InputHasPosition|VM27InputHasPointerButtons|VM27InputHasPhase) ||
            !isfinite(packet->view_x_points) || !isfinite(packet->view_y_points) ||
            (packet->pointer_buttons & ~UINT32_C(7)) ||
            packet->phase<VM27InputBegan || packet->phase>VM27InputCancelled ||
            ((packet->phase==VM27InputEnded || packet->phase==VM27InputCancelled) && packet->pointer_buttons))
            return VM27InputInvalid;
        if (state->primaryContact) return VM27InputEmpty;
        result.buttons=packet->pointer_buttons;result.pressed=result.buttons!=0;
        result.normalizedX=unit((packet->view_x_points-viewport.x)/viewport.width);
        result.normalizedY=unit((packet->view_y_points-viewport.y)/viewport.height);
        result.hasPosition=true;
    } else if (packet->source == VM27InputHover) {
        if (!(packet->present & VM27InputHasPosition) || !isfinite(packet->view_x_points) ||
            !isfinite(packet->view_y_points)) return VM27InputInvalid;
        /* Surface6 suppresses physical hover while a finger/Pencil owns a
         * direct contact. An actual indirect-pointer hover while its button
         * is held must move with buttons=1; only its real End/Cancel releases.
         * Preserve the original contact generation and pressed state. */
        result.normalizedX = unit((packet->view_x_points-viewport.x)/viewport.width);
        result.normalizedY = unit((packet->view_y_points-viewport.y)/viewport.height);
        result.hasPosition = true;
    } else if (packet->source == VM27InputTouch) {
        if (!(packet->present & VM27InputHasContacts) || packet->contact_count > 32 ||
            (packet->contact_count && !packet->contacts)) return VM27InputInvalid;
        const VM27InputContact *primary = NULL;
        for (size_t i = 0; i < packet->contact_count; ++i) {
            const VM27InputContact *contact = &packet->contacts[i];
            if (!contact->contact_generation || contact->owner_epoch != packet->owner_epoch ||
                !isfinite(contact->view_x_points) || !isfinite(contact->view_y_points) ||
                contact->phase < VM27InputBegan || contact->phase > VM27InputCancelled)
                return VM27InputInvalid;
            for (size_t j = 0; j < i; ++j)
                if (packet->contacts[j].contact_generation == contact->contact_generation)
                    return VM27InputInvalid;
            if (contact->contact_generation == state->primaryContact) primary = contact;
        }
        if (state->pressed && !state->primaryContact) return VM27InputEmpty;
        if (!state->pressed) {
            if (packet->contact_count != 1 || packet->contacts[0].phase != VM27InputBegan)
                return VM27InputEmpty;
            primary = &packet->contacts[0]; result.primaryContact = primary->contact_generation;
            result.pressed = true;result.buttons=1;
        } else if (!primary || packet->contact_count != 1 ||
                   primary->phase == VM27InputEnded || primary->phase == VM27InputCancelled) {
            /* Release only this profile's own pressed contact; never guess a
             * different user's location or another hardware button's state. */
            result.pressed = false; result.primaryContact = 0;result.buttons=0;
        }
        if (primary) {
            result.normalizedX = unit((primary->view_x_points-viewport.x)/viewport.width);
            result.normalizedY = unit((primary->view_y_points-viewport.y)/viewport.height);
            result.hasPosition = true;
        }
    } else return VM27InputUnsupported;
    if (state->hasPosition && state->normalizedX == result.normalizedX &&
        state->normalizedY == result.normalizedY && state->pressed == result.pressed && state->buttons == result.buttons)
        return VM27InputEmpty;
    *output = (VM27OwnPointerArgumentsV1){result.normalizedX, result.normalizedY, result.buttons};
    *next = result;
    return VM27InputOK;
}

static int mac_keycode(uint32_t usage);
VM27InputResult vm27_own_key_arguments_v1(const VM27InputPacket *packet,
    int64_t *type, uint16_t *keycode) {
    if (!packet || !type || !keycode || packet->version != 1) return VM27InputInvalid;
    if (packet->source != VM27InputKey) return VM27InputUnsupported;
    if (!(packet->present & VM27InputHasHIDUsage) || packet->hid_usage_page != 7)
        return VM27InputUnsupported;
    if (!(packet->present & VM27InputHasPhase) ||
        (packet->pressed ? packet->phase != VM27InputBegan :
         (packet->phase != VM27InputEnded && packet->phase != VM27InputCancelled)))
        return VM27InputInvalid;
    int code = mac_keycode(packet->hid_usage);
    if (code < 0) return VM27InputUnsupported;
    *type = packet->pressed ? 0 : 1; *keycode = (uint16_t)code;
    return VM27InputOK;
}

/* Reused verbatim cases from VirtualMacApp.m macVirtualKeyCode. */
static int mac_keycode(uint32_t usage) {
    static const int16_t alphaAndNumberRow[] = {
        0, 11, 8, 2, 14, 3, 5, 4, 34, 38, 40, 37, 46,
        45, 31, 35, 12, 15, 1, 17, 32, 9, 13, 7, 16, 6,
        18, 19, 20, 21, 23, 22, 26, 28, 25, 29,
    };
    int64_t raw = usage;
    if (raw >= 0x04 && raw <= 0x27)
        return alphaAndNumberRow[raw - 0x04];
    switch (raw) {
    case 0x28: return 36;  // Return
    case 0x29: return 53;  // Escape
    case 0x2a: return 51;  // Delete / Backspace
    case 0x2b: return 48;  // Tab
    case 0x2c: return 49;  // Space
    case 0x2d: return 27;  // -
    case 0x2e: return 24;  // =
    case 0x2f: return 33;  // [
    case 0x30: return 30;  // ]
    case 0x31: return 42;  // Backslash
    case 0x33: return 41;  // ;
    case 0x34: return 39;  // Quote
    case 0x35: return 50;  // Grave
    case 0x36: return 43;  // Comma
    case 0x37: return 47;  // Period
    case 0x38: return 44;  // Slash
    case 0x39: return 57;  // Caps Lock
    case 0x3a: return 122; // F1
    case 0x3b: return 120; // F2
    case 0x3c: return 99;  // F3
    case 0x3d: return 118; // F4
    case 0x3e: return 96;  // F5
    case 0x3f: return 97;  // F6
    case 0x40: return 98;  // F7
    case 0x41: return 100; // F8
    case 0x42: return 101; // F9
    case 0x43: return 109; // F10
    case 0x44: return 103; // F11
    case 0x45: return 111; // F12
    case 0x46: return 105; // Print Screen / F13
    case 0x47: return 107; // Scroll Lock / F14
    case 0x48: return 113; // Pause / F15
    case 0x49: return 114; // Insert / Help
    case 0x4a: return 115; // Home
    case 0x4b: return 116; // Page Up
    case 0x4c: return 117; // Forward Delete
    case 0x4d: return 119; // End
    case 0x4e: return 121; // Page Down
    case 0x4f: return 124; // Right Arrow
    case 0x50: return 123; // Left Arrow
    case 0x51: return 125; // Down Arrow
    case 0x52: return 126; // Up Arrow
    case 0x53: return 71;  // Keypad Clear / Num Lock
    case 0x54: return 75;  // Keypad /
    case 0x55: return 67;  // Keypad *
    case 0x56: return 78;  // Keypad -
    case 0x57: return 69;  // Keypad +
    case 0x58: return 76;  // Keypad Enter
    case 0x59: return 83;  // Keypad 1
    case 0x5a: return 84;  // Keypad 2
    case 0x5b: return 85;  // Keypad 3
    case 0x5c: return 86;  // Keypad 4
    case 0x5d: return 87;  // Keypad 5
    case 0x5e: return 88;  // Keypad 6
    case 0x5f: return 89;  // Keypad 7
    case 0x60: return 91;  // Keypad 8
    case 0x61: return 92;  // Keypad 9
    case 0x62: return 82;  // Keypad 0
    case 0x63: return 65;  // Keypad decimal
    case 0x64: return 10;  // ISO non-US backslash
    case 0x67: return 81;  // Keypad =
    case 0x87: return 94;  // JIS underscore / Ro
    case 0x89: return 93;  // JIS Yen
    case 0x8a: return 104; // JIS Kana / conversion
    case 0x8b: return 102; // JIS Eisu / non-conversion
    case 0x8c: return 95;  // JIS keypad comma
    case 0x90: return 104; // LANG1 / Kana
    case 0x91: return 102; // LANG2 / Eisu
    case 0xe0: return 59;  // Left Control
    case 0xe1: return 56;  // Left Shift
    case 0xe2: return 58;  // Left Option
    case 0xe3: return 55;  // Left Command
    case 0xe4: return 62;  // Right Control
    case 0xe5: return 60;  // Right Shift
    case 0xe6: return 61;  // Right Option
    case 0xe7: return 54;  // Right Command
    default: return -1;
    }
}
