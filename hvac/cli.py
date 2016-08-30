"""HVAC CLI commands"""
# pragma: no cover
import argparse
import sys
import os
import json
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from requests import exceptions

import hvac

VAULT_ENV_VAR = 'VAULT_ADDR'
VAULT_TOKEN = 'VAULT_TOKEN'

EPILOG = ('If the VAULT_ADDR environment variable is set, it will be '
          'parsed and used for default values when connecting.')


def on_error(message, exit_code=2):
    """Write out the specified message to stderr and exit the specified
    exit code, defaulting to ``2``.

    :param str message: The exit message
    :param int exit_code: The numeric exit code

    """
    sys.stderr.write(message + '\n')
    sys.exit(exit_code)


def connection_error():
    """Common exit routine when hvac can't connect to vault"""
    on_error('Could not connect to vault', 1)

AUTH_PARSERS = [
    ('ec2', 'Authenticate to ec2', [
        [['pkcs7'], {'help': 'The ec2 pkcs7 cert to send in return for a token'}],
        [['--nonce', '-n'], {'help': 'The nonce created by a client of this backend'}],
        [['--role', '-r'], {'help': 'Name of the role against which the login is being attempted'}],
        [['--out', '-o'], {'help': 'Print the token',
                             'action': 'store_true'}]])
]

SECRET_PARSERS = [
    ('read', 'Read a secret value from a key located at a path', [
        [['path'], {'help': 'The path to retrieve a key from'}],
        [['--key', '-k'], {'help': 'The key to retreive'}]]),
    ('write', 'write a key and value to a path', [
        [['path'], {'help': 'The path to retrieve a key from'}],
        [['kv'], {'help': 'The key value pairs must be in k=v format',
                  'nargs': '+'}]]),
    ('ls', 'list objects on path', [
        [['path'], {'help': 'The path to list'}]])
]

def add_auth_args(parser):
    """Add the auth command and arguments.

    :param argparse.Subparser parser: parser

    """
    auth_parser = parser.add_parser('auth', help='Auth Utilities')

    subparsers = auth_parser.add_subparsers(dest='action',
                                          title='Auth Utilities')

    for (name, help_text, arguments) in AUTH_PARSERS:
        parser = subparsers.add_parser(name, help=help_text)
        for (args, kwargs) in arguments:
            parser.add_argument(*args, **kwargs)

def add_secret_args(parser):
    """Add the secret command and arguments.

    :param argparse.Subparser parser: parser

    """
    secret_parser = parser.add_parser('secret', help='Secret Utilities')

    subparsers = secret_parser.add_subparsers(dest='action',
                                            title='Secret Utilities')

    for (name, help_text, arguments) in SECRET_PARSERS:
        parser = subparsers.add_parser(name, help=help_text)
        for (args, kwargs) in arguments:
            parser.add_argument(*args, **kwargs)

def parse_cli_args():
    """Create the argument parser and add the arguments"""
    parser = argparse.ArgumentParser(description='CLI utilities for Vault',
                                     epilog=EPILOG)

    env_var = os.environ.get(VAULT_ENV_VAR, '')
    parsed_defaults = urlparse.urlparse(env_var)

    parser.add_argument('--api-scheme',
                        default=parsed_defaults.scheme or 'http',
                        help='The scheme to use for connecting to Vault with')
    parser.add_argument('--api-host',
                        default=parsed_defaults.hostname or 'localhost',
                        help='The vault host to connect on')
    parser.add_argument('--api-port',
                        default=parsed_defaults.port or 8200,
                        help='The vault API port to connect to')

    vault_token = os.environ.get(VAULT_TOKEN, '')
    parser.add_argument('--token', default=vault_token, help='vault token')

    sparser = parser.add_subparsers(title='Commands', dest='command')
    add_auth_args(sparser)
    add_secret_args(sparser)
    return parser.parse_args()

def auth_ec2(vault, args): 
    """Authenticate to Vault using EC2

    :param string vault: The Vault instance
    :param argparser.namespace args: The cli args

    """
    handle = sys.stdout
    try:
        result = vault.auth_ec2(args.pkcs7, args.nonce, args.role)
        token = result['auth']['client_token']
        os.environ['VAULT_TOKEN'] = token
        if args.out:
            handle.write(token)

    except exceptions.ConnectionError:
        connection_error()


AUTH_ACTIONS = {
    'ec2': auth_ec2
}

def secret_read(vault, args): 
    """Read key from path

    :param string vault: The Vault instance
    :param argparser.namespace args: The cli args

    """
    handle = sys.stdout
    try:
        result = vault.read(args.path)
        if args.key:
            print(result['data'][args.key])
        else:
            for k, v in result['data'].iteritems():
                print('{0}: {1}'.format(k, v))


    except exceptions.ConnectionError:
        connection_error()

def secret_write(vault, args): 
    """write key to path

    :param string vault: The Vault instance
    :param argparser.namespace args: The cli args

    """
    handle = sys.stdout
    try:
        _kwargs = {}
        for secret in args.kv:
            pair = secret.split('=')
            if (len(pair) > 1):
                _kwargs[pair[0]] = pair[1]
            else:
                on_error('K/V pairs must be separated by an = sign, multiple pairs may be specified separated by a single space', 1)

        result = vault.write(args.path, **_kwargs)

    except exceptions.ConnectionError:
        connection_error()

def secret_list(vault, args): 
    """list objects on path

    :param string vault: The Vault instance
    :param argparser.namespace args: The cli args

    """
    handle = sys.stdout
    try:
        result = vault.list(args.path)
        for key in result['data']['keys']:
            print(key)

    except exceptions.ConnectionError:
        connection_error()

SECRET_ACTIONS = {
    'read': secret_read,
    'write': secret_write,
    'ls': secret_list
}

def main():
    """Entrypoint for the vault cli application"""
    args = parse_cli_args()
    port = args.api_port

    api_host = 'localhost'
    if args.api_host:
        api_host = args.api_host

    api_scheme = 'http'
    if args.api_scheme:
        api_scheme = args.api_scheme

    api_port = '8200'
    if args.api_port:
        api_port = args.api_port
    
    vault_token = None
    if args.token:
        vault_token = args.token

    vault = hvac.Client(url='%s://%s:%s' % (api_scheme, api_host, api_port), token=vault_token)

    if args.command == 'auth':
        AUTH_ACTIONS[args.action](vault, args)
    if args.command == 'secret':
        SECRET_ACTIONS[args.action](vault, args)
