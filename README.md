# pyvpn
A simple vpn made using python

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com)


# Installation
```
git clone https://github.com/krishpranav/pyvpn
cd pyvpn
sudo chmod +x *
python3 setup.py install
```
```
Features
--------

- Clean, lightweight
- IKEv1, IKEv2, L2TP auto-detection
- WireGuard
- TCP stack
- TCP/UDP tunnel
- DNS cache
```

```
Examples
--------

- TCP Tunnel

  .. code:: rst

    If the remote host match in file "rules.country", tunnel through http proxy.

    $ pyvpn -r http://remote_server:port?rules.country

- UDP Tunnel

  .. code:: rst

    Redirect all DNS requests to 8.8.8.8.

    $ pyvpn -ur tunnel://8.8.8.8:53?{53}
```
