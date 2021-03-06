import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver


logging.basicConfig(
            format='%(asctime)s [%(levelname)s]: %(message)s',
            datefmt='%y-%m-%d %H:%M',
            level=logging.INFO
        )


def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", help='specify destination ip')
    parser.add_argument('--port', action="store", help='specify destination port')
    parser.add_argument('--nic', action="store", help='nic where we capture the packets')
    parser.add_argument('--sT', action="store_true", help='sT port scanning technique deceiver')
    parser.add_argument('--scan', action="store", help='attacker\'s port scanning technique') #new
    parser.add_argument('--status', action="store", help='designate port status') #new
    parser.add_argument('--hs', action="store_true", help='port and host scanning technique deceiver')
    parser.add_argument('--open', action="store_true", help='designate port status -> open')
    parser.add_argument('--close', action="store_true", help='designate port status -> close')
    args = parser.parse_args()

    if args.nic:
        settings.NIC = args.nic

    if args.scan:
        port_scan_tech = args.scan
        if args.status:
            deceive_status = args.status
            deceiver = PortDeceiver(args.host)
            if port_scan_tech == 's':
                deceiver.sT(deceive_status)
            elif port_scan_tech == 'hs':
                deceiver.deceive_ps_hs(deceive_status)
            elif port_scan_tech == 'proxy':
                deceiver.test_proxy()
        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No port scan technique is designated')

    # if args.sT:
    #     deceiver = PortDeceiver(args.host, args.port)
    #     if args.open:
    #         deceiver.sT('open')
    #     elif args.close:
    #         deceiver.sT('close')
    #     else:
    #         logging.info('no port status is received')
    #
    # if args.hs:
    #     deceiver = PortDeceiver(args.host, args.port)
    #     if args.open:
    #         deceiver.deceive_ps_hs('open')
    #     elif args.close:
    #         deceiver.deceive_ps_hs('close')


if __name__ == '__main__':
    main()
