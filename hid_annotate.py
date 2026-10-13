#!/usr/bin/env python3
"""Annotate USB HID report descriptors (and USB device and configuration descriptors).

Reads hex bytes from a file, or from standard input if no file is given, and prints one line
per descriptor item, indented to show the collection nesting.

Example usage:
    python hid_annotate.py descriptor.txt
    python hid_annotate.py --binary descriptor.bin
    echo 05 01 09 02 A1 01 ... C0 | python hid_annotate.py

Text-format input is in hexadecimal format and can be "05 01 09 02", "0x05, 0x01, 0x09, 0x02"
or "05010902". Other text isn't allowed.

Options:
    --config
        Input is a configuration descriptor (with its interface, HID and endpoint descriptors).
    --device
        Input is an 18-byte device descriptor.
    --binary
        Read raw binary input instead of hex text. When a filename is given the specified file is
        read as raw bytes, or when no filename is provided standard input is read as raw bytes.

Written by Claude Code on behalf of Big Mess o' Wires for the USB HID device corpus. Public domain.
"""
import re
import sys

PAGES = {
    0x01: 'Generic Desktop', 0x02: 'Simulation Controls', 0x03: 'VR Controls', 0x04: 'Sport Controls',
    0x05: 'Game Controls', 0x06: 'Generic Device Controls', 0x07: 'Keyboard', 0x08: 'LED', 0x09: 'Button',
    0x0A: 'Ordinal', 0x0B: 'Telephony', 0x0C: 'Consumer', 0x0D: 'Digitizer', 0x0E: 'Haptics',
    0x0F: 'Physical Input Device', 0x10: 'Unicode', 0x12: 'Eye and Head Trackers', 0x14: 'Auxiliary Display',
    0x20: 'Sensors', 0x40: 'Medical Instrument', 0x41: 'Braille Display', 0x59: 'Lighting and Illumination',
    0x80: 'Monitor', 0x81: 'Monitor Enumerated', 0x82: 'VESA Virtual Controls', 0x84: 'Power Device',
    0x85: 'Battery System', 0x8C: 'Barcode Scanner', 0x8D: 'Scales', 0x8E: 'Magnetic Stripe Reader',
    0x90: 'Camera Control', 0x91: 'Arcade', 0x92: 'Gaming Device', 0xF1D0: 'FIDO Alliance',
}

GENERIC_DESKTOP = {
    0x01: 'Pointer', 0x02: 'Mouse', 0x04: 'Joystick', 0x05: 'Game Pad', 0x06: 'Keyboard', 0x07: 'Keypad',
    0x08: 'Multi-axis Controller', 0x09: 'Tablet PC System Controls', 0x0E: 'System Multi-Axis Controller',
    0x30: 'X', 0x31: 'Y', 0x32: 'Z', 0x33: 'Rx', 0x34: 'Ry', 0x35: 'Rz', 0x36: 'Slider', 0x37: 'Dial',
    0x38: 'Wheel', 0x39: 'Hat Switch', 0x3A: 'Counted Buffer', 0x3B: 'Byte Count', 0x3C: 'Motion Wakeup',
    0x3D: 'Start', 0x3E: 'Select', 0x40: 'Vx', 0x41: 'Vy', 0x42: 'Vz', 0x43: 'Vbrx', 0x44: 'Vbry',
    0x45: 'Vbrz', 0x46: 'Vno', 0x47: 'Feature Notification', 0x48: 'Resolution Multiplier',
    0x80: 'System Control', 0x81: 'System Power Down', 0x82: 'System Sleep', 0x83: 'System Wake Up',
    0x84: 'System Context Menu', 0x85: 'System Main Menu', 0x86: 'System App Menu', 0x87: 'System Menu Help',
    0x88: 'System Menu Exit', 0x89: 'System Menu Select', 0x8A: 'System Menu Right', 0x8B: 'System Menu Left',
    0x8C: 'System Menu Up', 0x8D: 'System Menu Down', 0x90: 'D-pad Up', 0x91: 'D-pad Down',
    0x92: 'D-pad Right', 0x93: 'D-pad Left', 0xA8: 'System Do Not Disturb',
}

KEYS = ('No event', 'ErrorRollOver', 'POSTFail', 'ErrorUndefined') + tuple('abcdefghijklmnopqrstuvwxyz') + \
    tuple('1234567890') + ('Enter', 'Escape', 'Backspace', 'Tab', 'Space', '- _', '= +', '[ {', '] }', '\\ |',
    'Non-US # ~', '; :', "' \"", '` ~', ', <', '. >', '/ ?', 'Caps Lock') + \
    tuple('F%d' % i for i in range(1, 13)) + ('Print Screen', 'Scroll Lock', 'Pause', 'Insert', 'Home',
    'Page Up', 'Delete', 'End', 'Page Down', 'Right Arrow', 'Left Arrow', 'Down Arrow', 'Up Arrow', 'Num Lock',
    'Keypad /', 'Keypad *', 'Keypad -', 'Keypad +', 'Keypad Enter') + \
    tuple('Keypad ' + c for c in '1234567890') + ('Keypad .', 'Non-US \\ |', 'Application', 'Power', 'Keypad =') + \
    tuple('F%d' % i for i in range(13, 25))
KEYBOARD = dict(enumerate(KEYS))
KEYBOARD.update({0x74: 'Execute', 0x75: 'Help', 0x76: 'Menu', 0x77: 'Select', 0x78: 'Stop', 0x79: 'Again',
    0x7A: 'Undo', 0x7B: 'Cut', 0x7C: 'Copy', 0x7D: 'Paste', 0x7E: 'Find', 0x7F: 'Mute', 0x80: 'Volume Up',
    0x81: 'Volume Down', 0x85: 'Keypad ,', 0x87: 'International1', 0x88: 'International2', 0x89: 'International3',
    0x8A: 'International4', 0x8B: 'International5', 0x90: 'LANG1', 0x91: 'LANG2',
    0xE0: 'Left Control', 0xE1: 'Left Shift', 0xE2: 'Left Alt', 0xE3: 'Left GUI', 0xE4: 'Right Control',
    0xE5: 'Right Shift', 0xE6: 'Right Alt', 0xE7: 'Right GUI'})

LED = {0x01: 'Num Lock', 0x02: 'Caps Lock', 0x03: 'Scroll Lock', 0x04: 'Compose', 0x05: 'Kana', 0x06: 'Power',
       0x07: 'Shift', 0x08: 'Do Not Disturb', 0x09: 'Mute', 0x4B: 'Generic Indicator'}

CONSUMER = {
    0x01: 'Consumer Control', 0x02: 'Numeric Key Pad', 0x03: 'Programmable Buttons', 0x04: 'Microphone',
    0x05: 'Headphone', 0x06: 'Graphic Equalizer', 0x20: '+10', 0x21: '+100', 0x30: 'Power', 0x31: 'Reset',
    0x32: 'Sleep', 0x34: 'Sleep Mode', 0x40: 'Menu', 0x41: 'Menu Pick', 0x42: 'Menu Up', 0x43: 'Menu Down',
    0x44: 'Menu Left', 0x45: 'Menu Right', 0x46: 'Menu Escape', 0x60: 'Data On Screen', 0x65: 'Snapshot',
    0x6F: 'Display Brightness Increment', 0x70: 'Display Brightness Decrement', 0x72: 'Backlight Toggle',
    0x80: 'Selection', 0xB0: 'Play', 0xB1: 'Pause', 0xB2: 'Record', 0xB3: 'Fast Forward', 0xB4: 'Rewind',
    0xB5: 'Scan Next Track', 0xB6: 'Scan Previous Track', 0xB7: 'Stop', 0xB8: 'Eject', 0xCD: 'Play/Pause',
    0xCF: 'Voice Command', 0xE0: 'Volume', 0xE2: 'Mute', 0xE3: 'Bass', 0xE9: 'Volume Increment',
    0xEA: 'Volume Decrement', 0x183: 'AL Consumer Control Configuration', 0x18A: 'AL Email Reader',
    0x192: 'AL Calculator', 0x194: 'AL Local Machine Browser', 0x196: 'AL Internet Browser',
    0x19E: 'AL Terminal Lock/Screensaver', 0x1AE: 'AL Keyboard Layout', 0x201: 'AC New', 0x202: 'AC Open',
    0x203: 'AC Close', 0x207: 'AC Save', 0x208: 'AC Print', 0x21F: 'AC Find', 0x221: 'AC Search',
    0x223: 'AC Home', 0x224: 'AC Back', 0x225: 'AC Forward', 0x226: 'AC Stop', 0x227: 'AC Refresh',
    0x22A: 'AC Bookmarks', 0x22D: 'AC Zoom In', 0x22E: 'AC Zoom Out', 0x22F: 'AC Zoom', 0x232: 'AC Full Screen View',
    0x238: 'AC Pan', 0x279: 'AC Redo', 0x29D: 'AC Next Keyboard Layout Select',
}

DIGITIZER = {
    0x01: 'Digitizer', 0x02: 'Pen', 0x03: 'Light Pen', 0x04: 'Touch Screen', 0x05: 'Touch Pad', 0x06: 'Whiteboard',
    0x0E: 'Device Configuration', 0x20: 'Stylus', 0x21: 'Puck', 0x22: 'Finger', 0x23: 'Device Settings',
    0x30: 'Tip Pressure', 0x31: 'Barrel Pressure', 0x32: 'In Range', 0x33: 'Touch', 0x34: 'Untouch',
    0x35: 'Tap', 0x38: 'Transducer Index', 0x39: 'Tablet Function Keys', 0x3B: 'Battery Strength',
    0x3C: 'Invert', 0x3D: 'X Tilt', 0x3E: 'Y Tilt', 0x41: 'Twist', 0x42: 'Tip Switch', 0x43: 'Secondary Tip Switch',
    0x44: 'Barrel Switch', 0x45: 'Eraser', 0x46: 'Tablet Pick', 0x47: 'Confidence', 0x48: 'Width', 0x49: 'Height',
    0x51: 'Contact Identifier', 0x52: 'Device Mode', 0x53: 'Device Identifier', 0x54: 'Contact Count',
    0x55: 'Contact Count Maximum', 0x56: 'Scan Time', 0x57: 'Surface Switch', 0x58: 'Button Switch',
    0x59: 'Pad Type', 0x5B: 'Transducer Serial Number', 0x5C: 'Preferred Color',
}

USAGES = {0x01: GENERIC_DESKTOP, 0x07: KEYBOARD, 0x08: LED, 0x0C: CONSUMER, 0x0D: DIGITIZER}

COLLECTIONS = {0: 'Physical', 1: 'Application', 2: 'Logical', 3: 'Report', 4: 'Named Array', 5: 'Usage Switch',
               6: 'Usage Modifier'}

# Main item flag bits: (name when 0, name when 1); unset bits from 3 up are left out of the listing
FLAGS = [('Data', 'Const'), ('Array', 'Var'), ('Abs', 'Rel'), (None, 'Wrap'), (None, 'NonLinear'),
         (None, 'NoPref'), (None, 'Null'), (None, 'Volatile'), (None, 'BufBytes')]

UNIT_SYSTEMS = {0: 'None', 1: 'SI Linear', 2: 'SI Rotation', 3: 'English Linear', 4: 'English Rotation'}
UNIT_NAMES = {1: ('cm', 'rad', 'in', 'deg'), 2: ('g', 'g', 'slug', 'slug'), 3: ('s', 's', 's', 's'),
              4: ('K', 'K', 'F', 'F'), 5: ('A', 'A', 'A', 'A'), 6: ('cd', 'cd', 'cd', 'cd')}


def page_name(page):
    if page in PAGES:
        return PAGES[page]
    if page >= 0xFF00:
        return 'Vendor-defined 0x%04X' % page
    return '0x%02X' % page


def usage_name(page, usage):
    if page == 0x09:
        return 'No button' if usage == 0 else 'Button %d' % usage
    if page == 0x0A:
        return 'Instance %d' % usage
    name = USAGES.get(page, {}).get(usage)
    if name:
        return name
    if page == 0x07:
        return 'Key 0x%02X' % usage
    return '0x%02X' % usage


def signed(value, size):
    bits = size * 8
    return value - (1 << bits) if size and value & (1 << (bits - 1)) else value


def unit_text(value):
    system = value & 0xF
    if system == 0:
        return 'None'
    if system not in UNIT_SYSTEMS:
        return '0x%X' % value
    parts = []
    for nibble in range(1, 7):
        exp = (value >> (nibble * 4)) & 0xF
        if exp:
            exp = exp - 16 if exp > 7 else exp
            name = UNIT_NAMES[nibble][system - 1]
            parts.append(name if exp == 1 else '%s^%d' % (name, exp))
    return '%s: %s' % (UNIT_SYSTEMS[system], ' '.join(parts) or 'no units')


def flags_text(value):
    names = []
    for bit, (zero, one) in enumerate(FLAGS):
        name = one if value & (1 << bit) else zero
        if name:
            names.append(name)
    return ','.join(names)


def parse_hex(text):
    text = re.sub(r'0[xX]', ' ', text).replace(',', ' ')
    out = []
    for token in text.split():
        if not re.fullmatch(r'[0-9a-fA-F]+', token) or len(token) % 2:
            raise ValueError('not a hex byte: %r' % token)
        out.extend(int(token[i:i + 2], 16) for i in range(0, len(token), 2))
    return out


def hexstr(data):
    return ' '.join('%02X' % b for b in data)


def hex_block(data, per_line=16):
    """The bytes as plain hex, 16 to a line."""
    return [hexstr(data[i:i + per_line]) for i in range(0, len(data), per_line)]


def annotate_report(data):
    """Annotated listing of a HID report descriptor, one line per item."""
    lines = []          # [hex, depth, text]
    pending = []        # lines with 1-2 byte usages, named when the next Main item is reached
    page = 0
    page_stack = []
    depth = 0
    logical_min = 0
    i = 0

    def resolve(at_page):
        # A 1 or 2 byte usage normally uses the Usage Page in effect where it is declared. Like Linux
        # (hid_concatenate_last_usage_page), the usages at the end of the list that were declared before a
        # later Usage Page change take that page instead, for descriptors that put the Usage Page after its usages.
        for n in range(len(pending) - 1, -1, -1):
            if pending[n][3] == at_page:
                break
            pending[n][3] = at_page
        for line, label, usage, upage in pending:
            line[2] = '%s (%s)' % (label, usage_name(upage, usage))
        del pending[:]

    while i < len(data):
        prefix = data[i]
        if prefix == 0xFE:      # long item
            size = data[i + 1] if i + 1 < len(data) else 0
            item = data[i:i + 3 + size]
            lines.append([hexstr(item), depth, 'Long item (tag 0x%02X, %d data bytes)' % (item[2] if len(item) > 2 else 0, size)])
            i += 3 + size
            continue
        size = (0, 1, 2, 4)[prefix & 3]
        item = data[i:i + 1 + size]
        i += 1 + size
        if len(item) < 1 + size:
            lines.append([hexstr(item), depth, 'Truncated item (descriptor ends in the middle of it)'])
            break
        value = 0
        for n, b in enumerate(item[1:]):
            value |= b << (8 * n)
        kind = (prefix >> 2) & 3
        tag = prefix >> 4
        line = [hexstr(item), depth, None]
        if kind == 0:   # Main
            resolve(page)
            if tag in (8, 9, 11):
                line[2] = '%s (%s)' % ({8: 'Input', 9: 'Output', 11: 'Feature'}[tag], flags_text(value))
            elif tag == 10:
                ctype = COLLECTIONS.get(value, 'Vendor-defined 0x%02X' % value if value >= 0x80 else '0x%02X' % value)
                line[2] = 'Collection (%s)' % ctype
                depth += 1
            elif tag == 12:
                depth -= 1
                line[1] = max(depth, 0)
                line[2] = 'End Collection' + (' (no open collection)' if depth < 0 else '')
                depth = max(depth, 0)
            else:
                line[2] = 'Unknown Main item (tag 0x%X)' % tag
        elif kind == 1:   # Global
            if tag == 0:
                page = value
                line[2] = 'Usage Page (%s)' % page_name(value)
            elif tag == 1:
                logical_min = signed(value, size)
                line[2] = 'Logical Minimum (%d)' % logical_min
            elif tag == 2:
                v = signed(value, size)
                if v < 0 <= logical_min:
                    line[2] = 'Logical Maximum (%d signed, %d unsigned)' % (v, value)
                else:
                    line[2] = 'Logical Maximum (%d)' % v
            elif tag == 3:
                line[2] = 'Physical Minimum (%d)' % signed(value, size)
            elif tag == 4:
                line[2] = 'Physical Maximum (%d)' % signed(value, size)
            elif tag == 5:
                line[2] = 'Unit Exponent (%d)' % (value - 16 if size == 1 and 8 <= value <= 15 else signed(value, size))
            elif tag == 6:
                line[2] = 'Unit (%s)' % unit_text(value)
            elif tag == 7:
                line[2] = 'Report Size (%d)' % value
            elif tag == 8:
                line[2] = 'Report ID (%d)' % value + (' (reserved, not allowed)' if value == 0 else '')
            elif tag == 9:
                line[2] = 'Report Count (%d)' % value
            elif tag == 10:
                page_stack.append(page)
                line[2] = 'Push'
            elif tag == 11:
                page = page_stack.pop() if page_stack else page
                line[2] = 'Pop'
            else:
                line[2] = 'Unknown Global item (tag 0x%X)' % tag
        elif kind == 2:   # Local
            label = {0: 'Usage', 1: 'Usage Minimum', 2: 'Usage Maximum'}.get(tag)
            if label and size == 4:
                line[2] = '%s (%s: %s)' % (label, page_name(value >> 16), usage_name(value >> 16, value & 0xFFFF))
            elif label:
                line[2] = label
                pending.append([line, label, value, page])
            elif tag in (3, 4, 5):
                line[2] = '%s (%d)' % ({3: 'Designator Index', 4: 'Designator Minimum', 5: 'Designator Maximum'}[tag], value)
            elif tag in (7, 8, 9):
                line[2] = '%s (%d)' % ({7: 'String Index', 8: 'String Minimum', 9: 'String Maximum'}[tag], value)
            elif tag == 10:
                line[2] = 'Delimiter (%s)' % ('Open' if value else 'Close')
            else:
                line[2] = 'Unknown Local item (tag 0x%X)' % tag
        else:
            line[2] = 'Reserved item type (prefix 0x%02X)' % prefix
        lines.append(line)
    resolve(page)
    width = max([len(l[0]) for l in lines] + [8]) + 2
    return ['%-*s%s%s' % (width, h, '  ' * d, t) for h, d, t in lines]


COUNTRIES = ('not localized', 'Arabic', 'Belgian', 'Canadian-Bilingual', 'Canadian-French', 'Czech', 'Danish',
             'Finnish', 'French', 'German', 'Greek', 'Hebrew', 'Hungary', 'International (ISO)', 'Italian',
             'Japan (Katakana)', 'Korean', 'Latin American', 'Netherlands/Dutch', 'Norwegian', 'Persian (Farsi)',
             'Poland', 'Portuguese', 'Russia', 'Slovakia', 'Spanish', 'Swedish', 'Swiss/French', 'Swiss/German',
             'Switzerland', 'Taiwan', 'Turkish-Q', 'UK', 'US', 'Yugoslavia', 'Turkish-F')

CLASSES = {0x00: 'per interface', 0x01: 'Audio', 0x02: 'CDC', 0x03: 'HID', 0x08: 'Mass Storage', 0x09: 'Hub',
           0x0A: 'CDC Data', 0xE0: 'Wireless', 0xEF: 'Miscellaneous', 0xFE: 'Application Specific',
           0xFF: 'Vendor-specific'}


def interface_text(cls, sub, proto):
    text = 'class %02X (%s), subclass %02X, protocol %02X' % (cls, CLASSES.get(cls, '?'), sub, proto)
    if cls == 3:
        text = 'class 03 (HID), subclass %02X%s, protocol %02X%s' % (
            sub, ' (boot)' if sub == 1 else '', proto, {1: ' (keyboard)', 2: ' (mouse)'}.get(proto, '') if sub == 1 else '')
    return text


def bcd(value):
    return '%X.%02X' % (value >> 8, value & 0xFF)


def annotate_device(data):
    """Annotated listing of an 18-byte device descriptor."""
    if len(data) < 18 or data[1] != 1:
        return [hexstr(data), '  (not a device descriptor)']
    w = lambda n: data[n] | data[n + 1] << 8
    return [hexstr(data),
            '  USB %s, device %s, endpoint 0 max packet %d' % (bcd(w(2)), interface_text(data[4], data[5], data[6]), data[7]),
            '  VID %04X, PID %04X, device release %s' % (w(8), w(10), bcd(w(12))),
            '  string indexes: manufacturer %d, product %d, serial number %d; %d configuration%s' % (
                data[14], data[15], data[16], data[17], '' if data[17] == 1 else 's')]


def annotate_config(data):
    """Annotated listing of a configuration descriptor and the descriptors that follow it."""
    lines = []
    i = 0
    depth = 0
    while i < len(data):
        length = data[i]
        dtype = data[i + 1] if i + 1 < len(data) else 0
        d = data[i:i + max(length, 2)]
        i += max(length, 2)
        if length < 2 or len(d) < length:
            lines.append((d, 0, 'Bad descriptor length'))
            break
        w = lambda n: d[n] | d[n + 1] << 8
        if dtype == 2 and length >= 9:
            attrs = 'self-powered' if d[7] & 0x40 else 'bus-powered'
            if d[7] & 0x20:
                attrs += ', remote wakeup'
            text = 'Configuration %d: total length %d, %d interface%s, %s, max power %d mA' % (
                d[5], w(2), d[4], '' if d[4] == 1 else 's', attrs, d[8] * 2)
            depth = 0
        elif dtype == 4 and length >= 9:
            text = 'Interface %d%s: %d endpoint%s, %s' % (
                d[2], ' alternate %d' % d[3] if d[3] else '', d[4], '' if d[4] == 1 else 's', interface_text(d[5], d[6], d[7]))
            depth = 1
        elif dtype == 0x21 and length >= 9:
            country = COUNTRIES[d[4]] if d[4] < len(COUNTRIES) else str(d[4])
            text = 'HID %s, country code %d (%s), ' % (bcd(w(2)), d[4], country)
            subs = ['descriptor type %02X, %d bytes' % (d[6 + 3 * n], d[7 + 3 * n] | d[8 + 3 * n] << 8)
                    for n in range(d[5]) if 8 + 3 * n < length]
            text += '; '.join(s.replace('descriptor type 22,', 'report descriptor') for s in subs)
            depth = 2
        elif dtype == 5 and length >= 7:
            types = ('control', 'isochronous', 'bulk', 'interrupt')
            text = 'Endpoint %02X %s, %s, max packet %d, interval %d' % (
                d[2], 'IN' if d[2] & 0x80 else 'OUT', types[d[3] & 3], w(4) & 0x7FF, d[6])
            depth = 2
        else:
            text = 'Descriptor type %02X' % dtype
        lines.append((d, depth, text))
    width = max([len(hexstr(d)) + 2 * dp for d, dp, _ in lines] + [8]) + 2
    return ['%-*s%s' % (width, '  ' * dp + hexstr(d), t) for d, dp, t in lines]


def main(args):
    mode = annotate_report
    binary = False
    args = list(args)

    """Accept options in any order, before or after the filename."""
    i = 0
    while i < len(args):
        if args[i] == '--binary':
            binary = True
            args.pop(i)
            continue
        if args[i] in ('--config', '--device'):
            mode = annotate_config if args[i] == '--config' else annotate_device
            args.pop(i)
            continue
        i += 1

    if args:
        filename = args[0]
        if binary:
            data = open(filename, 'rb').read()
            out = mode(list(data))
        else:
            text = open(filename, 'r').read()
            out = mode(parse_hex(text))
    else:
        if binary:
            data = sys.stdin.buffer.read()
            out = mode(list(data))
        else:
            text = sys.stdin.read()
            out = mode(parse_hex(text))

    for line in out:
        print(line)


if __name__ == '__main__':
    main(sys.argv[1:])
