import os
import sys
import socket
import json
import logging
import time
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko


def load_config(config_path):
    config_fields = {
        "server": str,
        "port": int,
        "username": str,
        "password": str,
        "password_env": str,
        "key_path": str,
        "command": str,
        "priority": int,
        "bind_address": str,
        "bind_interface": str,
        "connect_timeout": (int, float),
        "command_timeout": (int, float),
    }

    with open(config_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Config file must be a list")

    for entry in data:
        for key in entry:
            if key not in config_fields:
                raise KeyError(f"Unknown field: {key} (entry: {entry})")
            if not isinstance(entry[key], config_fields[key]):
                raise TypeError(f"Field type invalid: {key} (entry: {entry})")

        required_keys = ["server", "username", "command"]
        for key in required_keys:
            if key not in entry:
                raise ValueError(f"Missing field: {key} (entry: {entry})")

        # 认证信息检查：密码和密钥至少提供一个
        if (
            "password" not in entry
            and "password_env" not in entry
            and "key_path" not in entry
        ):
            raise ValueError(
                f"Missing password (password_env) or key_path for {entry.get('server')}:{entry.get('port',22)}"
            )
        if entry.get("password_env"):
            if not os.environ.get(entry.get("password_env")):
                raise ValueError(
                    f"No env password for {entry.get('server')}:{entry.get('port',22)}"
                )
            entry["password"] = os.environ.get(entry.get("password_env"))

    return data


def execute_remote_command(server_config):
    start_time = time.time()

    server = server_config.get("server")
    port = server_config.get("port", 22)
    username = server_config.get("username")
    password = server_config.get("password")
    key_path = server_config.get("key_path")
    command = server_config.get("command")
    bind_address = server_config.get("bind_address")
    bind_interface = server_config.get("bind_interface")
    connect_timeout = server_config.get("connect_timeout", 10)
    command_timeout = server_config.get("command_timeout", 10)
    failure = None

    try:
        # 如果指定了bind_interface，则创建socket手动连接
        sock = None
        client = None

        if bind_address or bind_interface:
            logging.info(
                f"[{server}:{port}] Bind address/interface set, creating socket"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout + 1)
            if bind_address:
                socket.inet_aton(bind_address)  # 验证是否为有效IP
                sock.bind((bind_address, 0))
            else:
                # 若bind_interface不是IP（可能是网卡名称），尝试绑定网卡
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bind_interface.encode()
                )
            sock.connect((server, port))

        # 使用 Paramiko 建立 SSH 连接
        logging.info(f"[{server}:{port}] Connecting")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if sock:
            # 使用已有的socket连接
            client.connect(
                server,
                port=port,
                username=username,
                password=password,
                key_filename=key_path,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                sock=sock,
            )
        else:
            client.connect(
                server,
                port=port,
                username=username,
                password=password,
                key_filename=key_path,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
            )

        logging.info(f"[{server}:{port}] SSH connected, running: {command}")
        stdin, stdout, stderr = client.exec_command(command, timeout=connect_timeout)

        channel = stdout.channel
        cmd_start_time = time.time()
        while not channel.exit_status_ready():
            if time.time() - cmd_start_time > command_timeout:
                raise TimeoutError(f"Command timeout, exceeded {command_timeout} sec")
            time.sleep(0.1)

        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="ignore")
        error_output = stderr.read().decode("utf-8", errors="ignore")

        logging.info(f"[{server}:{port}] Exit: {exit_status}")
        logging.info(f"[{server}:{port}] Stdout:\n{output}")
        logging.info(f"[{server}:{port}] Stderr:\n{error_output}")
    except Exception as e:
        logging.warning(f"[{server}:{port}] Exception: {e}")
        failure = True
    finally:
        with suppress(Exception):
            if server_config.get("password_env"):
                os.environ.pop(server_config.get("password_env"))
            if client:
                client.close()
            if "sock" in locals() and sock:
                sock.close()

    end_time = time.time()
    if failure:
        return f"[{server}:{port}] Something wrong, took {end_time-start_time} sec"
    return f"[{server}:{port}] Done, took {end_time-start_time} sec"


def run_ssh_commands(config_path):
    servers = load_config(config_path)

    # 按优先级排序服务器列表
    servers.sort(key=lambda x: x.get("priority", 0))

    # 根据优先级分组服务器
    priority_groups = {}
    for server in servers:
        prio = server.get("priority", 0)
        priority_groups.setdefault(prio, []).append(server)
    sorted_prios = sorted(priority_groups.keys())

    for _, prio in enumerate(sorted_prios):
        logging.info(f"=============== Start group {prio} ===============")
        # 并发执行当前优先级组内的所有服务器命令
        group = priority_groups[prio]
        futures = []
        results = []
        with ThreadPoolExecutor(max_workers=len(group)) as executor:
            for server in group:
                futures.append(executor.submit(execute_remote_command, server))
            for future in as_completed(futures):
                results.append(future.result())
        logging.info(f"==== Group {prio} done, Statistics as follows ====")
        for entry in results:
            logging.info(entry)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python server-exec.py <config file>")
        sys.exit(1)

    logging.getLogger("paramiko").disabled = True
    logging.getLogger("paramiko.transport").disabled = True
    logging.getLogger("concurrent").setLevel(logging.CRITICAL)
    logging.getLogger("concurrent.futures").setLevel(logging.CRITICAL)
    logging.addHandler(logging.StreamHandler(sys.stdout))
    logging.addHandler(logging.FileHandler("automation.log", encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    try:
        run_ssh_commands(sys.argv[1])
    except Exception as e:
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        raise
