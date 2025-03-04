# server-exec
It was developed for shutting down my Homelab servers/routers/switches initially, and was also suitable for some simple automation (if you have lots of servers)
## Features
- connect servers via ssh and execute single commands in specific sequence
- suppprt timeout settings
- support gathering password from environment variable
- support binding to specific address/interface
## Example Configuration
```
[
  {
    "server": "blog.xhyh.me",
    "port": 22,
    "username": "root",
    "password": "12345678",
    "command": "cat /proc/cpuinfo",
    "priority": 1,
    "bind_interface": "eth1",
    "connect_timeout": 5,
    "command_timeout": 10
  },
  {
    "server": "127.0.0.1",
    "port": 2222,
    "username": "wty",
    "password_env": "SERVER_PASSWORD",
    "command": "bash ak_ioi.sh",
    "priority": 1,
    "connect_timeout": 114,
    "command_timeout": 514
  },
  {
    "server": "10.1.1.10",
    "username": "root",
    "key_path": "/home/xhyh/.ssh/id_ed25519"
    "command": "sudo pacman -Syu",
    "priority": 2,
    "bind_address": "10.1.1.20",
    "connect_timeout": 5,
    "command_timeout": 3600
    
  }
]
```
**Notice:** You can use `./start.sh` (It's an example) to start the script and don't forget to export env password.
