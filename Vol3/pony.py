#!/usr/bin/env python
'''
Created on 23 Oct 2019
Updated on 02 Feb 2021 for Vol3 1.0.1

# Copyright (C) 2011-2021 DoomedRaven.
# This file is part of Tools - https://github.com/doomedraven/Tools
# See the file 'LICENSE.md' for copying permission.

This is demo plugin of volatility3 to show community how to easilly upgrade/make an vol3 plugin
Special huge thanks to @ikelos and @xabiugarte for help/fixes

https://github.com/doomedraven/Tools/Vol3/pony.py
'''
import os
import re
import io
import sys
import json

import logging
from typing import Any, List, Tuple, Dict, Optional, Union, Iterable
from urllib.request import pathname2url
import volatility3.plugins
import volatility3.symbols
from volatility3 import framework
from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan, vadinfo

log = logging.getLogger(__name__)

try:
    import yara
    has_yara=True
except ImportError:
    log.info("Python Yara module not found, plugin (and dependent plugins) not available")
    has_yara=False

def standalone_extractor(data):
    return Pony.get_config(data)

class Pony(interfaces.plugins.PluginInterface):
    """ Extracts Pony config """
    _version=(1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description="Memory layer for the kernel",
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
            requirements.IntRequirement(name="max_size",
                                        default=0x40000000,
                                        description="Set the maximum size (default is 1GB)",
                                        optional=True),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
            requirements.IntRequirement(name='pid',
                                        description="Process ID to include (all other processes are excluded)",
                                        optional=True),
            requirements.URIRequirement(name="yara_file", description="Yara rules (as a file)", optional=True),
            requirements.PluginRequirement(name = 'vadyarascan', plugin = vadyarascan.VadYaraScan, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'vadinfo', component = vadinfo.VadInfo, version = (2, 0, 0)),
        ]

    @staticmethod
    def get_config(pe):
        # https://github.com/Xyl2k/Pony-gate-extractor/blob/master/PonyExtractor.py
        config = {
            "cncs": [],
            "downloads": [],
        }

        start = pe.find(b"YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0")
        if not start:
            return dict()

        pe = pe[start-600:start+500]
        gate_url = re.compile(b".*\.php$")
        exe_url = re.compile(b".*\.exe$")
        dll_url = re.compile(b".*\.dll$")
        output = re.findall(b"(https?:\/\/.[A-Za-z0-9-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\\=]+(?:\.php|\.exe|\.dll))", pe)
        if not output:
            return config

        for url in output:
            try:
                if b'\x00' not in url:
                    if url is None:
                        continue
                    if gate_url.match(url):
                        config['cncs'].append(url.lower())
                    elif exe_url.match(url):
                        config['downloads'].append(url.lower())
                    elif dll_url.match(url):
                        config['downloads'].append(url.lower())
            except Exception as e:
                print(e)

        config["cncs"] = list(set(config["cncs"]))
        config["downloads"] = list(set(config["downloads"]))
        return config

    def _generator(self):
        if not has_yara:
            log.error("You must install yara")
            return

        config = dict()

        if self.config.get('yara_file', None) is not None:
            RULES = yara.compile(file=resources.ResourceAccessor().open(self.config['yara_file'], "rb"))
        else:
            # https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Pony.yar
            SIGS = {
                'pony': '''

                    rule pony {
                        meta:
                            author = "Brian Wallace @botnet_hunter"
                            author_email = "bwall@ballastsecurity.net"
                            date = "2014-08-16"
                            description = "Identify Pony"
                        strings:
                            $ = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
                        condition:
                            all of them
                }
                '''
            }

            RULES = yara.compile(sources=SIGS)

        #filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        for task in pslist.PsList.list_processes(
                context=self.context,
                layer_name=self.config['primary'],
                symbol_table=self.config['nt_symbols'],
                filter_func=filter_func):
            try:
                proc_layer_name = task.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            for offset, rule_name, name, value in proc_layer.scan(
                    context=self.context,
                    scanner=yarascan.YaraScanner(rules=RULES),
                    sections=vadyarascan.VadYaraScan.get_vad_maps(task)):
                log.debug("Got a Yara match!")

                vad, vad_start, vad_end = self.get_vad(task, offset)
                if vad is None:
                    log.debug("VAD not found")
                    return

                full_pe = io.BytesIO()
                chunk_size = 1024 * 1024 * 10
                #vadinfo.VadInfo.vad_dump(self.context, task, vad, full_pe)
                offset = vad_start
                while offset < vad_end:
                    to_read = min(chunk_size, vad_end - offset)
                    data = proc_layer.read(offset, to_read, pad = True)
                    if not data:
                        break
                    full_pe.write(data)
                    offset += to_read
                if not full_pe:
                    continue
                config = self.get_config(full_pe.getvalue())
                if not config:
                    log.debug("Config extraction failed")
                    continue

                yield (0, (format_hints.Hex(offset), task.UniqueProcessId, str(config)))

    #replace with list_vads and write correct filter func
    @staticmethod
    def get_vad(task: interfaces.objects.ObjectInterface, address: int):# vad
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.
        Args:
            task: The EPROCESS object of which to traverse the vad tree
        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            if end > address >= start:
                return vad, start, end
        return None, None, None

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex), ('PID', int), ('Config', str)], self._generator())

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    config = standalone_extractor(data)
    print(json.dumps(config, indent=4))
