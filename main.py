import os
import paramiko
import socket
import json
import logging
import time
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_config(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        raise ValueError("配置文件的顶层结构必须是列表")
    
    for entry in data:
        required_keys = ["ip", "username", "command", "priority"]
        for key in required_keys:
            if key not in entry:
                raise ValueError(f"配置缺少必需字段: {key} (条目: {entry})")
        
        # 认证信息检查：密码和密钥至少提供一个
        if "password" not in entry and "password_env" not in entry and "key_path" not in entry:
            raise ValueError(f"{entry.get('ip')} 未提供密码或密钥路径")
        if entry.get("password_env"):
            if not os.environ.get(entry.get("password_env")):
                raise ValueError(f"环境变量中没有 {entry.get('ip')} 的密码")
            entry["password"] = os.environ.get(entry.get("password_env"))
    
    return data

def execute_remote_command(server_config):
    start_time = time.time();

    ip = server_config.get("ip")
    port = server_config.get("port", 22)
    username = server_config.get("username")
    password = server_config.get("password")
    key_path = server_config.get("key_path")
    command = server_config.get("command")
    bind_interface = server_config.get("bind_interface")
    connect_timeout = server_config.get("connect_timeout", 10)
    command_timeout = server_config.get("command_timeout", 10)
    success = None

    try:
        # 如果指定了bind_interface，则创建socket手动连接
        logging.info(f"[{ip}] 尝试连接")
        sock = None
        client = None
        
        if bind_interface:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)
            try:
                # 尝试将bind_interface当作IP地址绑定
                socket.inet_aton(bind_interface)  # 验证是否为有效IP
                sock.bind((bind_interface, 0))
            except OSError:
                # 若bind_interface不是IP（可能是网卡名称），尝试绑定网卡
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bind_interface.encode())
            # 发起 TCP 连接
            sock.settimeout(connect_timeout + 1)
            sock.connect((ip, port))
        
        # 使用 Paramiko 建立 SSH 连接
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if sock:
            # 使用已有的socket连接
            client.connect(ip, port=port, username=username, password=password, 
                           key_filename=key_path, timeout=connect_timeout, 
                           banner_timeout=connect_timeout, sock=sock)
        else:
            client.connect(ip, port=port, username=username, password=password, 
                           key_filename=key_path, timeout=connect_timeout, 
                           banner_timeout=connect_timeout)
        logging.info(f"[{ip}] SSH连接已建立，开始执行命令")
        
        # 执行远程命令
        stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
        
        # 读取命令输出和错误输出
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')
        
        logging.info(f"[{ip}] 命令返回值： {exit_status}")
        logging.info(f"[{ip}] 命令标准输出:\n{output}")
        logging.info(f"[{ip}] 命令标准错误输出：\n{error_output}")
    except Exception as e:
        # 捕获所有异常，记录错误信息
        logging.warning(f"[{ip}] 出现异常: {e}")
        success = True
    finally:
        # 清理SSH客户端和socket
        with suppress(Exception):
            os.environ.pop(server_config.get("password_env"))
            if client:
                client.close()
            if 'sock' in locals() and sock:
                sock.close()
    
    end_time = time.time();
    if success:
        return f"[{ip}] 命令执行有错误，用时 {end_time-start_time} 秒"
    return f"[{ip}] 命令已执行，用时 {end_time-start_time} 秒"


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

    # 顺序执行各优先级组
    for i, prio in enumerate(sorted_prios):
        logging.info(f"=== 开始执行优先级 {prio} 组 ===")
        # 并发执行当前优先级组内的所有服务器命令
        group = priority_groups[prio]
        futures = []
        results = []
        with ThreadPoolExecutor(max_workers=len(group)) as executor:
            for server in group:
                futures.append(executor.submit(execute_remote_command, server))
            for future in as_completed(futures):
                results.append(future.result())
        logging.info(f"=== 优先级 {prio} 组执行完毕,统计信息如下 ===")
        logging.info(results);
        # 在不同优先级组之间等待（如果有配置等待时间）
    

def main():
    logging.basicConfig(filename='ssh_automation.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    try:
        run_ssh_commands('config.json')
    except Exception as e:
        logging.error(f"无法处理的异常：{e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()

