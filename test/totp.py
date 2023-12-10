#!/usr/bin/env python3

import argparse, time, struct
from smartcard.System import readers

if __name__ == '__main__':
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description = 'Apex-TOTP testing tool')
    parser.add_argument('-n', '--name', nargs='?', dest='name', type=str, 
        help='Name of the entry to generate a TOTP code from', required = True)
    parser.add_argument('-l', '--list-readers', action='store_true', dest='listreaders', 
        help='list available PC/SC readers')
    parser.add_argument('-r', '--reader', nargs='?', dest='reader', type=int, 
        const=0, default=0, 
        required=False, help='index of the PC/SC reader to use (default: 0)')
    args = parser.parse_args()

    if(args.listreaders):
        # List readers
        redlist = readers()
        if(len(redlist) == 0):
            print('warning: No PC/SC readers found')
            exit(1)
        redlist.sort(key=str)
        print('info: Available PC/SC readers (' + str(len(redlist)) + '):')
        for i, reader in enumerate(redlist):
            print(str(i) + ': ' + str(reader))
    else:
        # Read usage
        redlist = readers()
        if(len(redlist) == 0):
            print('error: No PC/SC readers found')
            exit(1)
        if(args.reader < 0 or args.reader >= len(redlist)):
            print('error: Specified reader index is out of range')
            exit(1)
        redlist.sort(key=str)
        red = redlist[args.reader]
        print('info: Using reader ' + str(args.reader) + ': ' + str(red))

        connection = red.createConnection()
        connection.connect()
        # Select the applet
        print('info: Sending applet selection')
        data, sw1, sw2 = connection.transmit(
            [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01])
        if(sw1 == 0x90 and sw2 == 0x00):
            print('success: Applet selected, card response is ok')
            # COMPUTE TRUNCATED
            timestamp = (int(time.time()) // 30).to_bytes(8, "big")
            name = list(args.name.encode("ASCII"))
            reqdata = [ 0x71, len(name) ] + name + [ 0x74, 0x08 ] + list(timestamp)
            data, sw1, sw2 = connection.transmit(
                [0x00, 0xA2, 0x00, 0x01, len(reqdata)] + reqdata + [ 0x00 ])
            if(sw1 == 0x90 and sw2 == 0x00):
                print('success: Computed code, card response is ok')
                digits = data[2]
                code = (int.from_bytes(data[-4:]) & 0x7FFFFFFF) % (10 ** digits)
                print('info: Code is ' + str(code))
            else:
                print('error: Card computation response: ' + f'{sw1:02x}' + ' ' + f'{sw2:02x}')
        else:
            print('error: Card selection response: ' + f'{sw1:02x}' + ' ' + f'{sw2:02x}')
        connection.disconnect()

