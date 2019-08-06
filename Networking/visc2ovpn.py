#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converts viscosity export files into an open vpn package
Usage: viscosity-to-openvpn.py <input> <output>
# source https://gist.github.com/brianbruggeman/f032f5b8e4b7fc1c63c8691071be5946
"""
import io
import os
import sys
import tarfile

import click

if sys.version.startswith('3'):
    unicode = str


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class ConversionError(Exception):
    """Base conversion error"""
    pass


class NoConnectionName(ConversionError):
    """No connection name was available"""
    pass


class NoCertificateData(ConversionError):
    """No certificate data was found within certificate file"""
    pass


class NoCertificateFile(ConversionError):
    """File was not available within archive"""
    pass

# ----------------------------------------------------------------------
# Command-line Interface
# ----------------------------------------------------------------------
@click.command()
@click.argument('input-path', type=click.Path(exists=True))
@click.argument('output', required=False, type=click.Path(), default=None)
def convert(input_path, output=None):
    '''Converts Viscosity package
    Args:
        input (str): path to folder or file input
        output (str): path to folder output  [default: None]
    '''
    if input_path.endswith('.visc'):
        output = input_path if output is None else output
        if output and not os.path.exists(output):
            output = input_path
        files = [os.path.join(input_path, filename) for filename in os.listdir(input_path)]
        for config_fp in files:
            new_config = []
            if config_fp.endswith('.conf'):
                with io.open(config_fp, encoding='utf-8') as stream:
                    connection_name = extract(stream, new_config, input_path=input_path)

                new_config.insert(0, '# OpenVPN Config for {}'.format(connection_name))
                new_config = '\n'.join(new_config) + '\n'
                output_filepath = os.path.join(output, '{}.ovpn'.format(connection_name))
                with io.open(output_filepath, 'w', encoding='utf-8') as out:
                    out.write(unicode(new_config))

                print('Wrote: {}'.format(output_filepath))

    elif input_path.endswith('.visz'):
        if output is None:
            output = os.path.dirname(input_path)

        data = {}
        with tarfile.open(input_path) as zipped:
            for filepath, fileinfo in zip(zipped.getnames(), zipped.getmembers()):
                if not fileinfo.isfile():
                    continue
                filename = filepath.split(os.path.sep)[-1]
                data[filename] = zipped.extractfile(filepath).read()

        for key in data:
            if not key.endswith('.conf') or key.startswith('.'):
                continue

            new_config = []
            lines = data[key].split('\n')
            connection_name = extract(lines, new_config, file_data=data)

            new_config.insert(0, '# OpenVPN Config for {}'.format(connection_name))
            new_config = '\n'.join(new_config) + '\n'
            output_filepath = os.path.join(output, '{}.ovpn'.format(connection_name))
            with io.open(output_filepath, 'w', encoding='utf-8') as out:
                out.write(unicode(new_config))

            print('Wrote: {}'.format(output_filepath))


# ----------------------------------------------------------------------
# CLI Support
# ----------------------------------------------------------------------
def extract(data, new_config, input_path=None, file_data={}):
    certificate_files = ['ca', 'cert', 'key', 'tls-auth']
    connection_name = ''
    for line in data:
        line = line.rstrip()

        if not line.strip():
            continue

        # This was an invalid configuration, for some reason
        elif line == 'compress lzo':
            continue

        elif line.startswith('#'):
            if line.startswith('#viscosity name'):
                connection_name = line.split('#viscosity name ', 1)[-1]
                connection_name = connection_name.strip()
            continue

        try:
            key, value = line.split(' ', 1)
            value = value.strip()
        except ValueError:
            key, value = line, ''

        if key in certificate_files:
            if key == 'tls-auth':
                try:
                    value, direction = value.split(' ', 1)
                    new_config.append('key-direction {}'.format(direction))
                except ValueError:
                    pass

            if input_path:
                cert_filepath = os.path.join(input_path, value)
                with io.open(cert_filepath, encoding='utf-8') as cf:
                    certificate = cf.read()
            else:
                if value not in file_data:
                    raise NoCertificateFile('Could not find certificate file in archive')
                certificate = file_data.get(value)

            if not certificate:
                raise NoCertificateData('Could not find certificate data')

            new_config.append('<%s>' % key)
            new_config.append(certificate)
            new_config.append('</%s>' % key)
            continue

        new_config.append(line)

    if not connection_name.strip():
        raise NoConnectionName('Could not find connection name in file.  Aborting')

    return connection_name


if __name__ == '__main__':
    convert()
