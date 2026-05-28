![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Pypsrp CLI

This is a simple CLI for [pypsrp](https://github.com/jborean93/pypsrp).

## Description

Pypsrp exposes the [WinRM (Windows Remote Management)](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) API as Python library. This CLI provides the corresponding interface called by the [OpenVAS Scanner](https://github.com/greenbone/openvas-scanner).

## Installing

### Requirements Dependencies

* Inherited from Pypsrp
* Python 3.10 and later are supported
* Forces Kerberos support in its dependency chain

#### Packages

Kerberos and build-dependencies

```
apt install -y krb5-user libkrb5-dev gcc python3-pip python3-dev
```

The following python packages also exist as Debian packages thus should be less conflict prone in case of system-wide installations like Docker.

```
apt install -y python3-cryptography python3-gssapi python3-requests
```


```
pip install .
```

Note: in case of system-wide installations, use `--break-system-packages` at your own risk

### Executing program

All arguments currently supported are mandatory. Certain non-pythonic design choicies were made to ensure easier integration into the OpenVAS stack w.r.t. parsing errors.

```
usage: pypsrp_cli [-h] [--interpreter INTERPRETER] [-c COMMAND] [-t TARGET] [--port PORT] [--path PATH] [--ssl SSL] [--authentication AUTHENTICATION] [-u USERNAME] [-p PASSWORD]

Pypsrp CLI wrapper

options:
  -h, --help            show this help message and exit
  --interpreter INTERPRETER
                        Command interpreter. Specify as 'CMD' or 'PS'
  -c, --command COMMAND
                        Command to execute on the host
  -t, --target TARGET   Target host
  --port PORT           Port
  --path PATH           URL path
  --ssl SSL             Forces HTTPS. Specify as '0' or '1'
  --authentication AUTHENTICATION
                        Authentication algorithm. Currently supported: 'NTLM', 'Kerberos'
  -u, --username USERNAME
                        Username
  -p, --password PASSWORD
                        Password
```

Ensure that your target has WinRM enabled. Non-Server versions of Windows have it disabled by default.


## Version History

* 0.1
    * Initial Release

## Maintainer

This project is maintained by [Greenbone AG][Greenbone]

## License

Copyright (C) 2024 [Greenbone AG][Greenbone]

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

[Greenbone]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[pipx]: https://pypa.github.io/pipx/
[autohooks]: https://github.com/greenbone/autohooks

## Acknowledgments

Thanks to the authors of [pypsrp](https://pypi.org/project/pypsrp/) for providing a WinRM-based API in Python.
