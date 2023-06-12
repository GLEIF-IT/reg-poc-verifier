# -*- encoding: utf-8 -*-
"""
kara.app.commands module

"""
import multicommand
import logging

from keri.app import directing

from verifier.app.cli import commands
from keri import help


help.ogler.level = logging.CRITICAL
help.ogler.reopen(name="verifer", temp=True, clear=True)


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    try:
        doers = args.handler(args)
        directing.runController(doers=doers, expire=0.0)

    except Exception as ex:
        # print(f"ERR: {ex}")
        # return -1
        raise ex


if __name__ == "__main__":
    main()