# Volatility
#
# Zeus support:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Citadel 1.3.4.5 support:
# Santiago Vicente <smvicente@invisson.com>
#
# Generic detection, Citadel 1.3.5.1 and ICE IX support:
# Juan C. Montes <jcmontes@cert.inteco.es>
#
# Port to volatility3 by @doomedraven
# https://github.com/doomedraven
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import re
import io
import sys
import time
import logging
import binascii
import struct
import hashlib

# VOLATILITY IMPORTS
from typing import Iterable, List, Tuple
from volatility3.framework.objects import utility
from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources
from volatility3.framework.symbols import intermed
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, vadyarascan  # , procdump, dlllist
from volatility3.plugins.windows.vadinfo import VadInfo, winnt_protections


try:
    import pefile
except ImportError:
    print("Missed pefile library -> pip3 install pefile")

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

log = logging.getLogger(__name__)

# CONSTANTS
RC4_KEYSIZE = 0x102

ZEUS_STURCTURE = {
    "_ZEUS2_CONFIG": 0x1E6,
    "_CITADEL1345_CONFIG": 0x11C,
    "_CITADEL1351_CONFIG": 0x130,
}

ZEUS_STURCTURE_size = {
    0x1E6: "_ZEUS2_CONFIG",
    0x11C: "_CITADEL1345_CONFIG",
    0x130: "_CITADEL1351_CONFIG",
}

def _parsed_struct_read_str(data, start, length):
    return data[start: start+length].split(b"\x00")[0].decode("utf-8")

def parsed_struct(decoded_config, decoded_magic, zbotversion):
    # https://en.wikipedia.org/wiki/C_data_types
    parsed = dict()
    if zbotversion == "_ZEUS2_CONFIG":
        """
            "struct_size": [0x0, ["unsigned int"]],
            "guid": [0x4, ["array", 0x30, ["unsigned short"]]],
            "guid2": [0x7C, ["array", 0x10, ["unsigned char"]]],
            "rc4key": [0x8C, ["array", 0x100, ["unsigned char"]]],
            "exefile": [0x18E, ["String", dict(length=0x14)]],
            "datfile": [0x1A2, ["String", dict(length=0x14)]],
            "keyname": [0x1B6, ["String", dict(length=0xA)]],
            "value1": [0x1C0, ["String", dict(length=0xA)]],
            "value2": [0x1CA, ["String", dict(length=0xA)]],
            "value3": [0x1D4, ["String", dict(length=0xA)]],
            "guid_xor_key": [0x1DE, ["unsigned int"]],
            "xorkey": [0x1E2, ["unsigned int"]],
        """
        parsed = {
            "struct_size": struct.unpack("=I", decoded_magic[:4])[0],
            "guid": decoded_magic[4:0x40].decode("utf-16le").split("\x00")[0],
            "guid2": decoded_magic[0x7c:0x7c+0x10],
            "rc4key": decoded_magic[0x8C: 0x8C+0x100],
            "exefile": _parsed_struct_read_str(decoded_magic, 0x18E, 0x14),
            "datfile": _parsed_struct_read_str(decoded_magic, 0x1A2, 0x14),
            "keyname": _parsed_struct_read_str(decoded_magic, 0x1B6, 0xa),
            "value1": _parsed_struct_read_str(decoded_magic, 0x1C0, 0xa),
            "value2": _parsed_struct_read_str(decoded_magic, 0x1CA, 0xa),
            "value3": _parsed_struct_read_str(decoded_magic, 0x1D4, 0xa),
            "guid_xor_key": struct.unpack("=I", decoded_magic[0x1de:0x1de+4])[0],
            "xorkey": struct.unpack("=I", decoded_magic[0x1e2:0x1e2+4])[0],
        }

    elif zbotversion in ("_CITADEL1345_CONFIG", "_CITADEL1351_CONFIG"):
        """
            "struct_size": [0x0, ["unsigned int"]],
            "guid": [0x4, ["array", 0x30, ["unsigned short"]]],
            "guid2": [0x7C, ["array", 0x10, ["unsigned char"]]],
            "exefile": [0x9C, ["String", dict(length=0x14)]],
            "datfile": [0xB0, ["String", dict(length=0x14)]],
            "keyname": [0xEC, ["String", dict(length=0xA)]],
            "value1": [0xF6, ["String", dict(length=0xA)]],
            "value2": [0x100, ["String", dict(length=0xA)]],
            "value3": [0x10A, ["String", dict(length=0xA)]],
            "guid_xor_key": [0x114, ["unsigned int"]],
            "xorkey": [0x118, ["unsigned int"]],

            _CITADEL1351_CONFIG has 4 extra fields
                "value4": [0x11C, ["unsigned int"]],
                "value5": [0x120, ["unsigned int"]],
                "value6": [0x124, ["unsigned int"]],
                "value7": [0x128, ["unsigned int"]],
                "value8": [0x12C, ["unsigned int"]],
        """
        parsed = {
            "struct_size": struct.unpack("=I", decoded_magic[:4])[0],
            "guid": decoded_magic[4:0x40].decode("utf-16le").split("\x00")[0],
            "guid2": decoded_magic[0x7c:0x7c+0x10],
            "exefile": _parsed_struct_read_str(decoded_magic, 0x9c, 0x14),
            "datfile": _parsed_struct_read_str(decoded_magic, 0xb0, 0x14),
            "keyname": _parsed_struct_read_str(decoded_magic, 0xec, 0xa),
            "value1": _parsed_struct_read_str(decoded_magic, 0xF6, 0xa),
            "value2": _parsed_struct_read_str(decoded_magic, 0x100, 0xa),
            "value3": _parsed_struct_read_str(decoded_magic, 0x10A, 0xa),
            "guid_xor_key": struct.unpack("=I", decoded_magic[0x114:0x114+4])[0],
            "xorkey": struct.unpack("=I", decoded_magic[0x118:0x118+4])[0],
        }

        if zbotversion == "_CITADEL1351_CONFIG":
            parsed.update({
                "value4": struct.unpack("=I", decoded_magic[0x11c:0x11c+4])[0],
                "value5": struct.unpack("=I", decoded_magic[0x120:0x120+4])[0],
                "value6": struct.unpack("=I", decoded_magic[0x124:0x124+4])[0],
                "value7": struct.unpack("=I", decoded_magic[0x128:0x128+4])[0],
                "value8": struct.unpack("=I", decoded_magic[0x12c:0x12c+4])[0],
            })


    return parsed

class ZBOTScan(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    """ Locate and Decrypt Configs for: ZeuS v2, Citadel
           * ZeuS 2.0.8.9 (z4 & z5)
           * ZeuS 2.1.0.1 (z3 & z5)
           * Ice IX (ZeuS 2.1.0.1 + mod RC4)
            Citadel 1.3.4.5
           * Citadel 1.3.5.1
    """

    # Internal vars
    signatures = {
        # ZeuS v2
        'namespace01':'rule zeus2_1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
        'namespace02':'rule zeus2_2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
        'namespace03':'rule zeus2_3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
        'namespace04':'rule zeus2_4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
        'namespace05':'rule zeus2_5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}',
        # Citadel
        'namespace06':'rule citadel_1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}',
        'namespace07':'rule citadel_2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}',
        'namespace08':'rule citadel_3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
    }

    zbot = ""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer for the kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
            requirements.IntRequirement(
                name="max_size", default=0x40000000, description="Set the maximum size (default is 1GB)", optional=True
            ),
            requirements.PluginRequirement(name="pslist", plugin=pslist.PsList, version=(2, 0, 1)),
            requirements.IntRequirement(
                name="pid", description="Process ID to include (all other processes are excluded)", optional=True
            ),
            requirements.URIRequirement(name="yara_file", description="Yara rules (as a file)", optional=True),
            requirements.PluginRequirement(name="vadyarascan", plugin=vadyarascan.VadYaraScan, version=(1, 0, 0)),
        ]

    @staticmethod
    def get_vad(task: interfaces.objects.ObjectInterface, address: int):  # vad
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

            # put a max size as 500mb
            if end - start > 0x500000:
                continue

            if start <= address < end:
                return vad, start, end
        return None, None, None

    @staticmethod
    def carve_data(vad_start, vad_end, proc_layer):
        chunk_size = 1024 * 1024 * 10
        full_vad = io.BytesIO()
        tmp_offset = vad_start
        while tmp_offset < vad_end:
            to_read = min(chunk_size, vad_end - tmp_offset)
            data = proc_layer.read(tmp_offset, to_read, pad=True)
            if not data:
                break
            full_vad.write(data)
            tmp_offset += to_read

        return full_vad.getvalue()

    def injection_filter(self, vad):
        """
        This is a callback that's executed by get_vads()
        when searching for injected code / hidden DLLs.
        This looks for private allocations that are committed,
        memory-resident, non-empty (not all zeros) and with an
        original protection that includes write and execute.
        It is important to note that protections are applied at
        the allocation granularity (page level). Thus the original
        protection might not be the current protection, and it
        also might not apply to all pages in the VAD range.
        @param vad: an MMVAD object.
        @returns: True if the MMVAD looks like it might
        contain injected code.
        """

        protect = vad.get_protection(VadInfo.protect_values(self.context, self.config['primary'], self.config['nt_symbols']), winnt_protections)
        write_exec = "EXECUTE" in protect and "WRITE" in protect

        # The Write/Execute check applies to everything
        if not write_exec:
            return False

        # This is a typical VirtualAlloc'd injection
        try:
            if vad.get_private_memory() == 1 and vad.vad.get_tag() == "VadS":
                return True
        except Exception as e:
            print(e)
        # This is a stuxnet-style injection
        if vad.get_private_memory() == 0 and protect != "PAGE_EXECUTE_WRITECOPY":  # noqa: W504
            return True

        return False

    def check_zbot(self):
        """ Detect the zbot version """

        rules = yara.compile(sources=self.signatures)

        p_round = self.context.config.get("sandbox_round", 1)
        if self.context.config.get('sandbox_pids', None):
            pids = self.context.config.get("sandbox_pids")
        else:
            pids = [self.config.get('pid', None)]

        filter_func = pslist.PsList.create_pid_filter(pids, True if p_round == 2 else False)
        list_tasks = pslist.PsList.list_processes(
            context=self.context,
            layer_name=self.config["primary"],
            symbol_table=self.config["nt_symbols"],
            filter_func = filter_func,
        )

        for task in list_tasks:
            try:
                proc_layer_name = task.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            for vad_start, vad_len in vadyarascan.VadYaraScan.get_vad_maps(task):
                vad, vad_start, vad_end = self.get_vad(task, vad_start)
                if not vad_start or not vad_end:
                    continue

                if vad_end - vad_start == 0xFFFF or vad_end - vad_start >= 1000000000:
                    continue

                data = self.carve_data(vad_start, vad_end, proc_layer)
                if not data.startswith(b"MZ") and not self.injection_filter(vad):
                    continue

                # check for the signature with YARA, both hits must be present
                matches = rules.match(data=data)
                if not matches:
                    continue


                hits = dict((m.rule, m.strings[0][0]) for m in matches)
                log.debug("yara rules")
                log.debug(hits)

                # Rules for CITADEL
                if ('citadel_1' in hits) & ('citadel_2' in hits) & ('citadel_3' in hits):
                    self.zbot = 'CITADEL'
                    log.debug('CITADEL DETECTED')
                    return task

                # Rules for ZEUS2
                if ( (('zeus2_1' in hits) | ('zeus2_2' in hits) | ('zeus2_5' in hits)) &
                        (('zeus2_3' in hits) | ('zeus2_4' in hits)) ):
                    self.zbot = 'ZEUS'
                    log.debug('ZEUS v2 DETECTED')
                    return task

    def run(self):
        return renderers.TreeGrid([("PID", int), ("Config", str)], self._generator())

    def _generator(self):
        """ Check the zbot version and analyze it """

        task = self.check_zbot()
        malware = None

        if self.zbot == 'CITADEL':
            malware = Citadel(self.config, self.context)
        elif self.zbot == 'ZEUS':
            malware = ZeuS2(self.config, self.context)
        elif malware.zbot == 'ICEIX':
            malware = ICEIX(self.config, self.context)

        if malware:
            config = malware.calculate(task)
            # malware.render_text(sys.stdout, data)
            yield (0, (task.UniqueProcessId, str(config)))


class ZbotCommon():
    """ Common functions for all zbot versions """

    params = dict(
        # This contains the C2 URL, RC4 key for decoding
        # local.ds and the magic buffer
        decoded_config = None,
        # This contains the hardware lock info, the user.ds
        # RC4 key, and XOR key
        encoded_magic = None,
        # The decoded version of the magic structure
        decoded_magic = None,
        # The key for decoding the configuration
        config_key = None,
        # The login key (citadel only)
        login_key = None,
        # The AES key (citadel only)
        aes_key = None,

        )

    # Depricated
    def get_hex(self, buf):
        return "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)])

    def decode_config(self, encoded_config, last_sec_data):
        """Decode the config with data from the last PE section.

        @param encoded_config: the encoded configuration
        @param last_sec_data: last PE section data.
        """

        return bytes([(last_sec_data[i] ^ encoded_config[i]) for i in range(len(encoded_config))])


    def decode_magic(self, config_key):
        """Decode the magic structure using the configuration key.

        @param config_key: the config RC4 key.
        """

        return self.rc4(config_key, self.params['encoded_magic'])

    def rc4(self, key, encoded, login_key=0):
        """Perform a basic RC4 operation"""
        # Turn the buffers into lists so the elements are mutable
        key_copy = [c for c in key]
        enc_copy = [c for c in encoded]

        # Start with the last two bytes in the key
        var1 = key_copy[0x100]
        var2 = key_copy[0x101]
        var3 = 0
        # ICE IX MOD
        mod1 = 0
        mod2 = 0
        if self.zbot == "ICEIX":
            mod1 = 3
            mod2 = 7

        # Do the RC4 algorithm
        for i in range(0, len(enc_copy)):
            var1 += 1 + mod1
            a = var1 & 0xFF
            b = key_copy[a]
            var2 += b
            var2 &= 0xFF
            key_copy[a] = key_copy[var2]
            key_copy[var2] = b
            enc_copy[i] ^= key_copy[(key_copy[a] + b + mod2) & 0xFF]

            # CITADEL MOD
            if self.zbot == "CITADEL":
                if not login_key:
                    login_key = self.params["login_key"]
                enc_copy[i] ^= login_key[var3]
                var3 += 1
                if var3 == len(login_key):
                    var3 = 0

        # Return the decoded bytes as a string
        decoded = [c for c in enc_copy]
        return bytes(decoded)

    def get_only_hex(self, buf, start=0, length=16):
        """Hexdump formula seen at http://code.activestate.com/recipes/142812-hex-dumper"""
        result = ""
        for i in range(0, len(buf), length):
            s = buf[i : i + length]
            result = result + "".join(["%02x" % x for x in s])
        return result

    def rc4_init(self, data):
        """Initialize the RC4 keystate"""
        # The key starts off as a mutable list
        key = list()
        for i in range(0, 256):
            key.append(i)
        # Add the trailing two bytes
        key.append(0)
        key.append(0)
        # Make a copy of the data so its mutable also
        data_copy = [ord(c) for c in data]
        var1 = 0
        var2 = 0
        for i in range(0, 256):
            a = key[i]
            var2 += data_copy[var1] + a
            var2 &= 0xFF
            var1 += 1
            key[i] = key[var2]
            key[var2] = a
        # Return a copy of the key as a string
        return "".join([chr(c) for c in key])


class ZeuS2(ZbotCommon):
    """ Scanner for ZeuS v2 """

    def __init__(self, config, context):
        self.zbot = "ZEUS"
        self.zbotversion = ""
        self.config = config
        self.context = context

        self.signatures = {
            "namespace1": r"rule z1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}",
            "namespace5": r"rule z5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}",
            "namespace2": r"rule z2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}",
            "namespace3": r"rule z3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}",
            "namespace4": r"rule z4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}",
        }

        self.magic_struct = "_ZEUS2_CONFIG"
        self.magic_struct_size = ZEUS_STURCTURE[self.magic_struct]

    def check_matches_zeus2(self, proc_layer, vad_start, matches, last_sec_data):
        """Check the Yara matches and derive the encoded/decoded
        config objects and magic structures.

        @param task_space: the process AS
        @param vad: the containing MMVAD
        @param matches: list of YARA hits
        @param last_sec_data: buffer of the last PE section's data
        """

        hits = dict((m.rule, m.strings[0][0] + vad_start) for m in matches)
        # Check version
        if ("z3" in hits) & ("z5" in hits):
            self.zbotversion = " 2.1.0.1"
        elif ("z4" in hits) & ("z5" in hits):
            self.zbotversion = " 2.0.8.9"

        if "z3" in hits:
            addr = struct.unpack("=I", proc_layer.read(hits["z3"] + 30, 0x4))[0]
            self.params["encoded_magic"] = proc_layer.read(addr, self.magic_struct_size)
        elif "z4" in hits:
            addr = struct.unpack("=I", proc_layer.read(hits["z4"] + 31, 0x4))[0]
            self.params["encoded_magic"] = proc_layer.read(addr, self.magic_struct_size)
        else:
            return False

        if "z1" in hits:
            addr = struct.unpack("=I", proc_layer.read(hits["z1"] + 8, 0x4))[0]
            size = struct.unpack("=I", proc_layer.read(hits["z1"] + 2, 0x4))[0]
            encoded_config = proc_layer.read(addr, size)
            self.params["decoded_config"] = self.decode_config(encoded_config, last_sec_data)
        elif "z2" in hits:
            addr = struct.unpack("=I", proc_layer.read(hits["z2"] + 26, 0x4))[0]
            encoded_config = proc_layer.read(addr, 0x3C8)
            rc4_init = self.rc4_init(encoded_config)
            self.params["decoded_config"] = self.rc4(rc4_init, last_sec_data[2:])
        elif "z5" in hits:
            addr = struct.unpack("=I", proc_layer.read(hits["z5"] + 8, 0x4))[0]
            size = struct.unpack("=I", proc_layer.read(hits["z5"] + 2, 0x4))[0]
            encoded_config = proc_layer.read(addr, size)
            self.params["decoded_config"] = self.decode_config(encoded_config, last_sec_data)
        else:
            return False

        # We found at least one of each category
        return True

    def scan_key_zeus2(self, task_space):
        """Find the offset of the RC4 key and use it to
        decode the magic buffer.

        @param task_space: the process AS
        """

        offset = 0
        found = False

        while offset < len(self.params["decoded_config"]) - RC4_KEYSIZE:
            config_key = self.params["decoded_config"][offset : offset + RC4_KEYSIZE]
            decoded_magic = self.decode_magic(config_key)

            # When the first four bytes of the decoded magic buffer
            # equal the size of the magic buffer, then we've found
            # a winning RC4 key
            (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

            if self.magic_struct_size != struct_size & struct_size < 1500:
                log.debug("size error")
                log.debug(struct_size)
                log.debug(self.magic_struct_size)

            if struct_size == self.magic_struct_size:
                found = True
                self.params["config_key"] = config_key
                self.params["decoded_magic"] = decoded_magic
                break

            offset += 1

        return found

    def calculate(self, task):  # noqa: C901
        """ Analyze zbot process """
        rules = yara.compile(sources=self.signatures)
        config = dict()

        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException:
            return

        proc_layer = self.context.layers[proc_layer_name]
        for vad_start, vad_len in vadyarascan.VadYaraScan.get_vad_maps(task):

            vad, vad_start, vad_end = ZBOTScan.get_vad(task, vad_start)
            # check for the signature with YARA, both hits must be present
            if not vad_start or not vad_end:
                log.debug("missed VAD details")
                continue

            if vad_end - vad_start == 0xFFFF or vad_end - vad_start >= 1000000000 :
                log.debug("VAD is too big")
                continue

            data = ZBOTScan.carve_data(vad_start, vad_end, proc_layer)
            # check for the signature with YARA, both hits must be present
            matches = rules.match(data=data)
            if not matches:
                continue

            if not data.startswith(b"MZ"):
                log.debug("NOT MZ")
                continue

            if len(matches) < 2:
                log.debug("don't have 2 matches")
                continue
            try:
                # There must be more than 2 sections
                pe = pefile.PE(data=data, fast_load=True)
                if len(pe.sections) < 2:
                    log.debug("less than 2 sections")
                    continue
            except Exception as e:
                print(e)
                continue

            # Get the last PE section's data
            last_sec = pe.sections[-1]
            last_sec_data = proc_layer.read((last_sec.VirtualAddress + vad_start), last_sec.Misc_VirtualSize)
            if len(last_sec_data) == 0:
                log.debug("empty section")
                continue

            # CITADEL
            if self.zbot == "CITADEL":
                success = self.check_matches_citadel(proc_layer, vad_start, matches, last_sec_data)
                if not success:
                    continue
                success = self.scan_key_citadel(proc_layer)
                if not success:
                    continue
            # ZEUS v2 or ICE IX
            elif self.zbot == "ZEUS":
                success = self.check_matches_zeus2(proc_layer, vad_start, matches, last_sec_data)
                if not success:
                    log.debug("check_matches_zeus2 false")
                    continue
                success = self.scan_key_zeus2(proc_layer)
                if not success:
                    # Check ICEIX
                    if self.zbotversion == " 2.1.0.1":
                        self.zbot = "ICEIX"
                        self.zbotversion = ""
                        log.debug("Checking ICE IX")
                        malware = ICEIX(self.config, self.context)
                        config = malware.calculate(task, vad_start, data, proc_layer)
                    else:
                        continue
                else:
                    # Parse zbotv2 here
                    parsed = parsed_struct(self.params["decoded_config"], self.params["decoded_magic"], self.magic_struct)
                    registry_dict = {
                        "key_path": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\%s" % "{0}".format(parsed["keyname"]),
                        # .v() Do the actual reading and decoding of this member
                        "Value1": "{0}".format(parsed["value1"]),
                        "Value2": "{0}".format(parsed["value2"]),
                        "Value3": "{0}".format(parsed["value3"]),
                    }

                    urls = []
                    conf_blob = self.params["decoded_config"]
                    while b"http" in conf_blob:
                        url = conf_blob[conf_blob.find(b"http") :]
                        urls.append(url[:url.find(b"\x00")].decode("utf-8"))
                        conf_blob = url[url.find(b"\x00") :]

                    config_rc4_key_hex = self.params["config_key"]
                    # quitamos el padding de volatility ..:76:a:d9:bf:0:0 -> 76:a:d9:bf
                    if config_rc4_key_hex[-2:] == b"\x00\x00":
                        config_rc4_key_hex = config_rc4_key_hex[:-2]

                    creds_key = self.params["decoded_magic"][0x8C : 0x8C + RC4_KEYSIZE]

                    config = {
                        "urls": urls,
                        "malware_zbot": "ZEUS",
                        "zbot_version": self.zbotversion,
                        "process_name": utility.array_to_string(task.ImageFileName),
                        "process_id": str(task.UniqueProcessId),
                        "process_address": str(vad_start),
                        "computer_identifier": parsed["guid"],
                        "mutant_key": str(parsed["guid_xor_key"]),
                        "xor_key": str(parsed["xorkey"]),
                        "registry": registry_dict,
                        "executable": parsed["exefile"],
                        "data_file": parsed["datfile"],
                        "creds_key": binascii.hexlify(creds_key).decode("utf-8"),
                        "config_rc4_keystream_plaintext": binascii.hexlify(config_rc4_key_hex).decode("utf-8"),
                    }

            return config

    def render_text(self, outfd, config):
        """Render the plugin's default text output"""

        # Check for data
        if config:
            # Get a magic object from the buffer
            outfd.write("*" * 50 + "\n")
            outfd.write("{0:<30} : {1}\n".format("ZBot", self.zbot + self.zbotversion))
            # outfd.write("{0:<30} : {1}\n".format("Process", utility.array_to_string(task.ImageFileName)))
            # outfd.write("{0:<30} : {1}\n".format("Pid", task.UniqueProcessId))
            # outfd.write("{0:<30} : {1}\n".format("Address", vad_start))

            for i, url in enumerate(config["urls"]):
                outfd.write("{0:<30} : {1}\n".format("URL {0}".format(i), url))

            outfd.write("{0:<30} : {1}\n".format("Identifier", config["guid"]))
            outfd.write("{0:<30} : {1}\n".format("Mutant key", config["guid_xor_key"]))
            outfd.write("{0:<30} : {1}\n".format("XOR key", config["xorkey"]))
            outfd.write(
                "{0:<30} : {1}\n".format(
                    "Registry",
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}".format(config["keyname"]),
                )
            )
            outfd.write("{0:<30} : {1}\n".format(" Value 1", config["value1"]))
            outfd.write("{0:<30} : {1}\n".format(" Value 2", config["value2"]))
            outfd.write("{0:<30} : {1}\n".format(" Value 3", config["value3"]))
            outfd.write("{0:<30} : {1}\n".format("Executable", config["exefile"]))
            outfd.write("{0:<30} : {1}\n".format("Data file", config["datfile"]))
            """
            outfd.write(
                "{0:<30} : \n{1}\n".format(
                    "Config RC4 key",
                    "\n".join(
                        [
                            "{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, "".join(c))
                            for o, h, c in utils.Hexdump(params["config_key"])
                        ]
                    ),
                )
            )

            outfd.write(
                "{0:<30} : \n{1}\n".format(
                    "Credential RC4 key",
                    "\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, "".join(c)) for o, h, c in utils.Hexdump(config["creds_key"])]
                    ),
                )
            )
            """


class Citadel(ZbotCommon):
    """ Scanner for Citadel version """

    def __init__(self, config, context):
        self.zbot = "CITADEL"
        self.zbotversion = " 1.3.5.1"
        self.magic_struct = ""
        self.config = config
        self.context = context

        self.signatures = {
            "namespace1": r"rule z1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}",
            "namespace2": r"rule z2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}",
            "namespace3": r"rule z3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}",
            "namespace4": r"rule z4 {strings: $a = {68 ?? ?? 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}",
            "namespace5": r"rule z5 {strings: $a = {81 30 ?? ?? ?? ?? 0F B6 50 03 0F B6 78 02 81 70 04 ?? ?? ?? ?? 81 70 08 ?? ?? ?? ?? 81 70 0c ?? ?? ?? ?? C1 E2 08 0B D7} condition: $a}",
            "namespace6": r"rule z6 {strings: $a = {33 F6 C7 45 ?? ?? ?? ?? ?? 5B 8A 4C 3D ?? 8A D1 80 E2 07 C0 E9 03 47 83 FF 04} condition: $a}",
        }
        """
        botnet offset:
        EB 11                                   jmp     short loc_3C9FDBA
        8D 85 48 FA FF FF                       lea     eax, [ebp+var_5B8]
        E8 FD FD FF FF                          call    XorDecryptionIntoEAX ; No APIs
        8D 8D 64 FD FF FF                       lea     ecx, [ebp+var_29C]
        8B 55 08                                mov     edx, [ebp+arg_0]
        83 C8 FF                                or      eax, 0FFFFFFFFh
        E8 86 16 01 00                          call    CopyUnicodeStringECX2EDX ; No APIs
        """
        self.CITADEL_GET_BOTNET_PATTERNS = [
            re.compile(
                br".*\xeb.\x8d\x85(....)\xe8....\x8d\x8d(....)\x8b.\x08\x83\xc8\xff\xe8.*",
                re.DOTALL,
            )
        ]

    def rc4_init_cit(self, key, magicKey):  # noqa: C901
        """ Initialize the RC4 keystate """

        hash = []
        box = []
        keyLength = len(key)
        magicKeyLen = len(magicKey)

        for i in range(0, 256):
            hash.append(key[i % keyLength])
            box.append(i)

        y = 0
        for i in range(0, 256):
            y = (y + box[i] + hash[i]) % 256
            tmp = box[i]
            box[i] = box[y]
            box[y] = tmp

        y = 0
        for i in range(0, 256):
            magicKeyPart1 = magicKey[y] & 0x07
            magicKeyPart2 = magicKey[y] >> 0x03
            y += 1
            if y == magicKeyLen:
                y = 0

            if magicKeyPart1 == 0:
                box[i] = ~box[i]
            elif magicKeyPart1 == 1:
                box[i] ^= magicKeyPart2
            elif magicKeyPart1 == 2:
                box[i] += magicKeyPart2
            elif magicKeyPart1 == 3:
                box[i] -= magicKeyPart2
            elif magicKeyPart1 == 4:
                box[i] = box[i] >> (magicKeyPart2 % 8) | (box[i] << (8 - (magicKeyPart2 % 8)))
            elif magicKeyPart1 == 5:
                box[i] = box[i] << (magicKeyPart2 % 8) | (box[i] >> (8 - (magicKeyPart2 % 8)))
            elif magicKeyPart1 == 6:
                box[i] += 1
            elif magicKeyPart1 == 7:
                box[i] -= 1

            box[i] = box[i] & 0xFF

        return bytes([c for c in box])

    def get_urls(self, base_config, data):

        urls = []

        """
        8D 84 24 50 01 00 00                    lea     eax, [esp+668h+var_518]
        C6 44 24 12 00                          mov     [esp+668h+var_656], 0
        C6 44 24 13 01                          mov     [esp+668h+var_655], 1
        E8 2D 95 00 00                          call    XorDecryptionIntoEAX ; No APIs
        8B 9C 24 58 05 00 00                    mov     ebx, [esp+668h+var_110]
        8D 84 24 A8 03 00 00                    lea     eax, [esp+668h+var_2C0] ; url1
        89 44 24 38                             mov     [esp+668h+var_630], eax
        C1 EB 0C                                shr     ebx, 0Ch
        8D 84 24 8B 01 00 00                    lea     eax, [esp+668h+var_4DD] ; url2
        83 E3 01                                and     ebx, 1
        89 44 24 3C                             mov     [esp+668h+var_62C], eax
        8D 84 24 CD 05 00 00                    lea     eax, [esp+668h+var_9B] ; url3
        """
        URL_SEARCH_PATTERNS = [
            re.compile(
                br".*\x8d\x84\x24(....)\xc6\x44\x24.\x00\xc6\x44\x24.\x01\xe8....\x8b.\x24....\x8d.\x24(....).{2,10}\x8d\x84\x24(....).{2,10}\x8d\x84\x24(....).*",
                re.DOTALL,
            )
        ]

        for pattern in URL_SEARCH_PATTERNS:
            m = re.match(pattern, data)
            if m:
                base = struct.unpack("I", m.group(1))[0]
                for x in range(2, 5):
                    offset = struct.unpack("I", m.group(x))[0] - base
                    url = self.get_string_from_data(base_config, offset=offset)
                    log.debug("got url: %s" % url)
                    if url != "" and url not in urls:
                        urls.append(url.split("\x00")[0])

        # blunt tool way in case something broke
        while b"http" in base_config:
            url = base_config[base_config.find(b"http") :]
            url_trim = url[: url.find(b"\x00")].decode("utf-8")
            log.debug("found through dumb way: %s" % url_trim)
            if url_trim not in urls:
                urls.append(url_trim)
            base_config = url[url.find(b"\x00") :]

        return list(filter(None, urls))

    def get_string_from_data(self, data, offset=0, widechar=False):

        out = ""
        count = offset
        while count < len(data):
            char = data[count]
            if char == 0:
                break
            out += chr(char)
            if widechar:
                count += 2
            else:
                count += 1

        return out

    def search_botnet(self, base_config, data):

        botnet = ""
        for pattern in self.CITADEL_GET_BOTNET_PATTERNS:
            m = re.match(pattern, data)
            if m:
                offset = struct.unpack("I", m.group(2))[0] - struct.unpack("I", m.group(1))[0]
                log.debug("botnet offset: %x" % offset)
                botnet = ""
                count = 0
                while count < 20:  # BOTNET_MAX_CHARS - 20
                    char = base_config[offset + count]
                    if char == 0:
                        break
                    botnet += chr(char)
                    count += 2  # widechar
                log.debug("found botnet: %s" % botnet)

        return botnet

    def calculate(self, task):  # noqa: C901

        p = task
        rules = yara.compile(sources=self.signatures)

        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException:
            return

        proc_layer = self.context.layers[proc_layer_name]

        for vad_start, vad_len in vadyarascan.VadYaraScan.get_vad_maps(task):

            vad, vad_start, vad_end = ZBOTScan.get_vad(task, vad_start)

            start = vad.StartingVpn << 12
            # check for the signature with YARA, both hits must be present
            if not vad_start or not vad_end:
                continue

            if vad_end - vad_start == 0xFFFF or vad_end - vad_start >= 1000000000 :
                continue

            data = ZBOTScan.carve_data(vad_start, vad_end, proc_layer)
            matches = rules.match(data=data)
            if not matches or len(matches) != 5:
                continue

            if not data.startswith(b"MZ"):
                continue


            try:
                # There must be more than 2 sections
                pe = pefile.PE(data=data, fast_load=True)
                if len(pe.sections) < 2:
                    continue
            except Exception as e:
                print(e)
                continue

            last_sec = pe.sections[-1]
            last_sec_data = proc_layer.read((last_sec.VirtualAddress + start), last_sec.Misc_VirtualSize)
            if len(last_sec_data) == 0:
                continue

            # contains C2 URL, RC4 key for decoding local.ds and the magic buffer
            decoded_config = ""
            # contains hw lock info, the user.ds RC4 key, and XOR key
            encoded_magic = ""
            # contains BO_LOGIN_KEY
            # contains de AES XOR key
            aes_xor_key = ""
            # Length of the Zeus Magic Object
            zeus_magic = ""
            # contains Salt RC4 Init key
            salt_rc4_initKey = ""

            for match in matches:
                sigaddr = match.strings[0][0] + start
                log.debug("Found {0} at {1:#x}".format(match.rule, sigaddr))
                if match.rule == "z1":
                    addr = struct.unpack("=I", proc_layer.read(sigaddr+30, 4))[0]
                    loginKey = proc_layer.read(addr, 0x20)
                elif match.rule == "z2":
                    address = struct.unpack("=I", proc_layer.read(sigaddr + 8, 0x4))[0]
                    size = struct.unpack("=I", proc_layer.read(sigaddr + 2, 0x4))[0]
                    encoded_config = proc_layer.read(address, size)
                    decoded_config = self.decode_config(encoded_config, last_sec_data)
                elif match.rule == "z3":
                    zeus_magic = proc_layer.read(sigaddr + 25, 0x4)
                    (zeus_magic,) = struct.unpack("=I", zeus_magic[0:4])
                    addr = struct.unpack("=I", proc_layer.read(sigaddr+31, 4))[0]
                    encoded_magic = proc_layer.read(addr, zeus_magic)
                elif match.rule == "z4":
                    zeus_magic = proc_layer.read(sigaddr + 24, 0x4)
                    (zeus_magic,) = struct.unpack("=I", zeus_magic[0:4])
                    addr = struct.unpack("=I", proc_layer.read(sigaddr+30, 4))[0]
                    encoded_magic = proc_layer.read(sigaddr + 30, zeus_magic,)
                elif match.rule == "z5":
                    aes_xor_key = proc_layer.read(sigaddr + 2, 0x4)
                    aes_xor_key += proc_layer.read(sigaddr + 17, 0x4)
                    aes_xor_key += proc_layer.read(sigaddr + 24, 0x4)
                    aes_xor_key += proc_layer.read(sigaddr + 31, 0x4)
                elif match.rule == "z6":
                    salt_rc4_initKey = proc_layer.read(sigaddr + 5, 0x4)
                    salt_rc4_initKey_hex = self.get_only_hex(salt_rc4_initKey).upper()

            if not decoded_config or not encoded_magic:
                continue

            offset = 0

            decoded_magic = ""
            config_key = ""
            aes_key = ""
            rc4_comKey = ""

            found = False

            while offset < len(decoded_config) - RC4_KEYSIZE:

                config_key = decoded_config[offset : offset + RC4_KEYSIZE]
                decoded_magic = self.rc4(config_key, encoded_magic, loginKey)
                # when the first four bytes of the decoded magic buffer equal the size
                # of the magic buffer, then we've found a winning RC4 key
                (struct_size,) = struct.unpack("=I", decoded_magic[0:4])
                if struct_size in ZEUS_STURCTURE_size and ZEUS_STURCTURE_size[struct_size].startswith("_CITADEL"):
                    if ZEUS_STURCTURE_size[struct_size] == "_CITADEL1345_CONFIG":
                        self.magic_struct = "_CITADEL1345_CONFIG"
                        self.zbotversion = " 1.3.4.5"
                    elif ZEUS_STURCTURE_size[struct_size] == "_CITADEL1351_CONFIG":
                        self.magic_struct = "_CITADEL1351_CONFIG"
                        self.zbotversion = " 1.3.5.1"
                    found = True
                if found:
                    aes_key = self.rc4(config_key, hashlib.md5(loginKey).digest(), loginKey)
                    rc4_comKey = self.rc4_init_cit(aes_key, salt_rc4_initKey)
                    break

                offset += 1

            if not found:
                log.debug("Error, cannot decode magic")
                continue

            # grab the URLs from the decoded buffer
            urls = []
            urls = self.get_urls(decoded_config, data)
            botnet = self.search_botnet(decoded_config, data)
            clean_urls = []
            config_file_paths = []
            for u in urls:
                f_path = ""
                clean_u = u
                if "|" in u:
                    clean_u = u[: u.find("|")]
                    f_path = u[u.find("|") + 1 :]
                clean_urls.append(clean_u)
                config_file_paths.append(f_path)

            parsed = parsed_struct(decoded_config, decoded_magic, self.magic_struct)

            registry_dict = {
                "key_path": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\%s" % "{0}".format(parsed["keyname"]),
                # .v() Do the actual reading and decoding of this member
                "Value1": "{0}".format(parsed["value1"]),
                "Value2": "{0}".format(parsed["value2"]),
                "Value3": "{0}".format(parsed["value3"]),
            }
            config = {
                "urls": clean_urls,
                "botnet": botnet,
                "malware_zbot": "CITADEL",
                "zbot_version": self.zbotversion,
                "process_name": utility.array_to_string(task.ImageFileName),
                "process_id": str(p.UniqueProcessId),
                "process_address": str(start),
                "computer_identifier": parsed["guid"],
                "mutant_key": str(parsed["guid_xor_key"]),
                "xor_key": str(parsed["xorkey"]),
                "config_rc4_keystream_plaintext": binascii.hexlify(config_key[:0x100]).decode("utf-8"),
                "comm_rc4_key_plaintext": binascii.hexlify(rc4_comKey).decode("utf-8"),
                "registry": registry_dict,
                "executable": parsed["exefile"],
                "login_key": loginKey.decode("utf-8").upper(),
                "aes_key": binascii.hexlify(aes_key).decode("utf-8").upper(),
                "aes_xor_key": binascii.hexlify(aes_xor_key).decode("utf-8").upper(),
                "config_file_paths": config_file_paths,
                "salt_rc4_initKey_hex": loginKey.decode("utf-8").upper(),
            }

            return config


class ICEIX(ZbotCommon):
    """ Scanner for ICE IX """

    def __init__(self, config, context):
        self.zbot = "ICEIX"
        self.zbotversion = ""
        self.config = config
        self.context = context

        self.signatures = {
            "namespace1": r"rule z1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}",
            "namespace5": r"rule z5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}",
            "namespace2": r"rule z2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}",
            "namespace3": r"rule z3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}",
            "namespace4": r"rule z4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}",
        }

        self.magic_struct = "_ZEUS2_CONFIG"
        self.magic_struct_size = ZEUS_STURCTURE[self.magic_struct]

    def rc4(self, key, data, offset1=3, offset2=7):
        """ Perform a basic RC4 operation """
        state = list(range(256))
        x = 0
        y = 0

        for i in list(range(256)):
            state[i] = key[i]

        out = [None] * len(data)

        for i in range(len(data)):
            x = (x + offset1) & 0xFF
            y = (state[x] + y + offset2) & 0xFF
            state[x], state[y] = state[y], state[x]
            out[i] = (data[i] ^ state[(state[x] + state[y]) & 0xFF])

        return bytes(out)

    def calculate(self, p, start, data, ps_ad):  # noqa: C901

        # check for the signature with YARA, both hits must be present
        rules = yara.compile(sources=self.signatures)
        matches = rules.match(data=data)
        try:
            # There must be more than 2 sections
            pe = pefile.PE(data=data, fast_load=True)
        except Exception as e:
            print(e)
            return

        # Get the last PE section's data
        last_sec = pe.sections[-1]
        last_sec_data = ps_ad.read((last_sec.VirtualAddress + start), last_sec.Misc_VirtualSize)
        if len(last_sec_data) == 0:
            log.debug("Last section is empty")
            return

        # contains C2 URL, RC4 key for decoding local.ds and the magic buffer
        decoded_config = ""
        # contains hw lock info, the user.ds RC4 key, and XOR key
        encoded_magic = ""

        for match in matches:
            sigaddr = match.strings[0][0] + start
            log.debug("Found {0} at {1:#x}".format(match.rule, sigaddr))

            if match.rule == "z1":
                address = struct.unpack("=I", ps_ad.read(sigaddr + 8, 0x4))[0]
                size = struct.unpack("=I", ps_ad.read(sigaddr + 2, 0x4))[0]
                encoded_config = ps_ad.read(address, size)
                decoded_config = self.decode_config(encoded_config, last_sec_data)
            elif match.rule == "z2":
                config_ptr = struct.unpack("=I", ps_ad.read(sigaddr + 26, 0x4))[0]
                config_ptr = struct.unpack("=I", ps_ad.read(config_ptr, 0x4))[0]
                encoded_config = ps_ad.read(config_ptr, 0x3C8)
                decoded_config = self.rc4(self.rc4_init(encoded_config), last_sec_data[2:])
            elif match.rule == "z5":
                address = struct.unpack("=I", ps_ad.read(sigaddr + 8, 0x4))[0]
                size = struct.unpack("=I", ps_ad.read(sigaddr + 2, 0x4))[0]
                encoded_config = ps_ad.read(address, size)
                decoded_config = self.decode_config(encoded_config, last_sec_data)
            elif match.rule == "z3":
                address = struct.unpack("=I", ps_ad.read(sigaddr + 30, 0x4))[0]
                encoded_magic = ps_ad.read(address, ZEUS_STURCTURE[self.magic_struct])
            elif match.rule == "z4":
                address = struct.unpack("=I", ps_ad.read(sigaddr + 31, 0x4))[0]
                encoded_magic = ps_ad.read(address, ZEUS_STURCTURE[self.magic_struct])

        if not decoded_config or not encoded_magic:
            log.debug("ICEIX not decoded_config or not encoded_magic")
            return None

        offset = 0

        decoded_magic = ""
        config_key = ""

        found = False
        while offset < len(decoded_config) - RC4_KEYSIZE:

            config_key = decoded_config[offset : offset + RC4_KEYSIZE]
            decoded_magic = self.rc4(config_key, encoded_magic)
            # when the first four bytes of the decoded magic buffer equal the size
            # of the magic buffer, then we've found a winning RC4 key
            (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

            if struct_size == ZEUS_STURCTURE[self.magic_struct]:
                found = True
                break

            offset += 1

        if not found:
            log.debug("Error, cannot decode magic")
            return None

        # grab the URL from the decoded buffer
        url = decoded_config[decoded_config.find(b"http") :]
        url = url[:url.find(b"\x00")].decode("utf-8")

        # use list for url (sames as others families)
        urls = [url]
        creds_key = decoded_magic[0x8C : 0x8C + RC4_KEYSIZE]
        # add parsing here

        parsed = parsed_struct(decoded_config, decoded_magic, self.magic_struct)
        parsed["urls"] = urls
        parsed["guid2"] = binascii.hexlify(parsed["guid2"]).decode("utf-8")
        parsed["rc4key"] = binascii.hexlify(parsed["rc4key"]).decode("utf-8")


        registry_dict = {
            "key_path": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\%s" % "{0}".format(parsed["keyname"]),
            # .v() Do the actual reading and decoding of this member
            "Value1": "{0}".format(parsed["value1"]),
            "Value2": "{0}".format(parsed["value2"]),
            "Value3": "{0}".format(parsed["value3"]),
        }

        config = {
            "urls": urls,
            "malware_zbot": self.zbot,
            "zbot_version": self.zbotversion,
            "process_name": utility.array_to_string(p.ImageFileName),
            "process_id": str(p.UniqueProcessId),
            "process_address": str(start),
            "computer_identifier": parsed["guid"],
            "mutant_key": str(parsed["guid_xor_key"]),
            "xor_key": str(parsed["xorkey"]),
            "registry": registry_dict,
            "executable": parsed["exefile"],
            "data_file": parsed["datfile"],
            "urls": urls,
            "config_rc4_keystream_plaintext": binascii.hexlify(config_key[:0x100]).decode("utf-8"),
            "cred_rc4_key_plaintext": binascii.hexlify(creds_key[:0x100]).decode("utf-8"),
        }
        return p, start, config

