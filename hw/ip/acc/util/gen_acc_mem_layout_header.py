#!/usr/bin/env python3
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys

from mako.template import Template  # type: ignore
from mako import exceptions  # type: ignore

from shared.mem_layout import get_memory_layout
'''
Generate a C header from the ACC IMEM/DMEM size and starting address.
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        'Get the memory layout for an ACC hardware configuration including '
        'the IMEM/DMEM size and their starting addresses as defined in the '
        'hjson. Makes an auto-generated C header that can be used by the '
        'ACC memutil.'))
    parser.add_argument('--template',
                        '-t',
                        metavar='FILE',
                        required=True,
                        type=argparse.FileType('r'),
                        help='Read header template from this file.')
    parser.add_argument('--headerfile',
                        '-o',
                        metavar='FILE',
                        required=True,
                        type=argparse.FileType('w'),
                        help='Write output to this file.')

    args = parser.parse_args()
    mems = get_memory_layout()

    # Write out the resulting filled header template.
    try:
        template = Template(args.template.read())
        rendered = template.render(imem_lma=mems.imem_address,
                                   imem_length=mems.imem_size_bytes,
                                   dmem_lma=mems.dmem_address,
                                   dmem_length=mems.dmem_size_bytes)
    except OSError as err:
        raise RuntimeError(str(err)) from None
    except:  # noqa: E722
        raise RuntimeError(exceptions.text_error_template().render()) from None

    args.headerfile.write(rendered)

    args.headerfile.close()
    args.template.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
