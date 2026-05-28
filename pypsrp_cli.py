# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

#!/usr/bin/env python3

import argparse
import requests
import json
import krb5
import pypsrp
import sys
import logging
import re

from pypsrp.client import Client


class SensitiveFormatter(logging.Formatter):
    """Formatter that removes sensitive information in urls."""

    def __init__(
        self,
    ):
        super().__init__()
        self.sensitive_information = []

    def _filter(self, s):
        for info in self.sensitive_information:
            s = re.sub(rf"{info}", "*******", s)
        return s

    def format(self, record):
        original = logging.Formatter.format(self, record)
        return self._filter(original)


logger = logging.getLogger("WinRM")
handler = logging.StreamHandler(sys.stdout)  # default is stderr
formatter = SensitiveFormatter()
handler.setFormatter(formatter)
handler.terminator = "\n-------\n"
logger.addHandler(handler)
handler.setLevel(logging.INFO)
logger.setLevel(logging.INFO)


def prepare_parser():
    parser = argparse.ArgumentParser(description="Pypsrp CLI wrapper")
    # nb: on purpose does not use 'choices' kwarg, to ensure that the logger format
    #     remains consistent across failure kinds and we do not need to try to extract
    #     CLI-library error cases from the stdout response separately on the NASL side.
    parser.add_argument(
        "--interpreter", type=str, help="Command interpreter. Specify as 'CMD' or 'PS'"
    )
    parser.add_argument("-c", "--command", help="Command to execute on the host")
    parser.add_argument("-t", "--target", help="Target host")
    parser.add_argument("--port", help="Port")
    parser.add_argument("--path", help="URL path")
    parser.add_argument("--ssl", type=str, help="Forces HTTPS. Specify as '0' or '1'")
    parser.add_argument(
        "--authentication",
        help="Authentication algorithm. Currently supported: 'NTLM', 'Kerberos'",
    )
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    return parser


def execute_command(args, client):
    """executes command and logs interpreter errors"""

    # nb: Do *NOT* sanitize main result, because
    #   - username will likely occur in paths and various file contents
    #   - passwords will occur, if a bad password was chosen
    #     E.g., if the password is "Admin" and we sanitize any occurance
    #     of "Admin", WSC will have a bad time.
    if args.interpreter.lower() == "cmd":
        stdout, stderr, code = client.execute_cmd(args.command)
        if code != 0:
            logger.info("ERROR IN LIBRARY / INTERPRETER / COMMAND")
            logger.info("UNKNOWN")
            logger.info(str(stdout) + "\n" + str(stderr))
            exit(1)
        else:
            print(stdout)

    else:
        output, streams, had_errors = client.execute_ps(args.command)

        if had_errors:
            # e.g., powershell error due to bad path on the target system or invalid powershell command
            logger.info("ERROR IN LIBRARY / INTERPRETER / COMMAND")
            logger.info("UNKNOWN")
            msg = ""
            if streams.error:
                error_msgs = [str(e) for e in streams.error]
                msg += "Error Message(s):\n"
                msg += "\n".join(error_msgs)

            if streams.warning:
                warning_msgs = [str(e) for e in streams.warning]
                msg += "Warning Message(s):\n"
                msg += "\n".join(warning_msgs)

            if not msg:
                if streams.debug:
                    debug_msgs = [str(e) for e in streams.debug]
                    msg += "Debug Message(s):\n"
                    msg += debug_msgs
                else:
                    msg += "Unknown cause."

            logger.info(msg)
            exit(1)
        else:
            print(output)


def log_error(error_kind: str):
    """ Prefixes the error with the base ERROR IN LIBRARY log message """
    logger.info("ERROR IN LIBRARY")
    logger.info(error_kind)


def main():
    """
    Executes the command and provides 2 different outputs formout via stdout:

    Case 1: successful execution:
    stdout == interpreter output; no additional sanitization / cleanup

    Case 2: Some form of error
    Case 2a): non-0 exit status when executing the command: Unknown, whether due to interpreter or library
    '''
    ERRROR IN LIBARRY / INTERPRETER / COMMAND
    ------
    UNKNOWN
    ------
    {sanitized stdout & stderr / data from client}
    '''

    Case 2b: Python exception when trying to execute the command: Library-internal error
    '''
    ERROR IN LIBRARY
    -----
    {error name / UNKNOWN}
    -----
    {sanitized error string}
    -----
    Library arguments:
    {sanitized JSON argument dump (username, password, auth, path, port, ...)}
    -----
    '''
    """
    parser = prepare_parser()
    # ensures to not fail if CLI version < feed version w.r.t. pypsrp features used
    args, unrecognised_args = parser.parse_known_args()

    # Minimal check for all mandatory argumnents existence
    if not (
        args.target
        and args.username
        and args.password
        and args.port
        and args.authentication
        and args.path
        and args.port
        and args.ssl is not None
    ):
        logger.info("ERROR IN LIBRARY / CALLEE")
        logger.info("BAD ARGUMENTS")
        logger.info("Insufficient inputs provided.")
        exit(1)

    if not (
        args.ssl in ("0", "1")
        and args.authentication in ("NTLM", "Kerberos")
        and args.interpreter in ("CMD", "PS")
    ):
        logger.info("ERROR IN LIBRARY / CALLEE")
        logger.info("BAD ARGUMENTS")
        logger.info("Unsupported choice for authentication or SSL argument.")
        exit(1)

    formatter.sensitive_information = [args.username, args.password]

    kwargs = {
        "username": args.username,
        "password": args.password,
        # basic, certificate, credssp, kerberos, negotiate, ntlm
        "auth": args.authentication.lower(),
        "ssl": bool(int(args.ssl)),
        "path": args.path,
        "port": args.port,
    }

    client = Client(args.target, **kwargs)
    err = None

    try:
        execute_command(args, client)
    except requests.exceptions.SSLError as e:
        err = e
        log_error("SSL FAILURE")

    except requests.exceptions.ConnectionError as e:
        err = e
        if (
            "Failed to establish a new connection: [Errno 111] Connection refused"
            in str(e)
        ):
            log_error("CONNECTION REFUSED")
        else:
            log_error("UNKNOWN CONNECTION ERROR")

    except krb5._exceptions.Krb5Error as e:
        err = e
        if "not found in Kerberos database" in str(e) and "Client '" in str(e):
            log_error("KRB CRED NOT IN DB")
        elif "Preauthentication failed" in str(e):
            log_error("KRB PREAUTH FAILURE")
        else:
            log_error("UNKNOWN KRB FAILURE")

    except pypsrp.exceptions.WinRMTransportError as e:
        err = e
        if "Bad HTTP response returned from the server. Code: 404" in str(e):
            log_error("WinRM Path not available (HTTP 404)")
        elif "Bad HTTP response returned from the server." in str(e):
            log_error("WinRM HTTP Failure")
        else:
            log_error("UNKNOWN TRANSPORT ERROR")

    except Exception as e:
        err = e
        log_error("UNKNOWN")

    if err is not None:
        logger.info(str(err))
        # safety measure, since they def. exist here
        kwargs["password"] = "******"
        kwargs["username"] = "******"
        logger.info("Library arguments:" + "\n" + json.dumps(kwargs, indent=4))
        exit(1)

    handler.flush()


if __name__ == "__main__":
    main()
