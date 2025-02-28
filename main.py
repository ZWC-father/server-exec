import paramiko
import socket
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_config(config_path):
    """加载并验证JSON配置文件。返回服务器配置列表。"""
    with open(config_path, 'r') as f:
        data = json.load(f)
    # 配置应为列表，每个元素是一个服务器配置字典
    if not isinstance(data, list):
        raise ValueError("配置文件的顶层结构必须是列表。")
    for entry in data:
        # 必需字段检查
        required_keys = ["ip", "username", "command", "priority"]
        for key in required_keys:
            if key not in entry:
                raise ValueError(f"配置缺少必需字段: {key} (条目: {entry})")
        # 认证信息检查：密码和密钥至少提供一个
        if "password" not in entry and "key_path" not in entry:
            raise ValueError(f"服务器 {entry.get('ip')} 未提供密码或密钥路径。")
    return data

def execute_remote_command(server_config):
    """通过SSH连接目标服务器并执行命令，返回结果。"""
    ip = server_config["ip"]
    port = server_config.get("port", 22)
    username = server_config["username"]
    password = server_config.get("password")
    key_path = server_config.get("key_path")
    command = server_config["command"]
    bind_interface = server_config.get("bind_interface")
    connect_timeout = server_config.get("connect_timeout", 10)
    command_timeout = server_config.get("command_timeout", 10)
    result = {"ip": ip, "output": "", "error": ""}
    client = None
    print("")
    print(ip, "  ", port, "  ", username, "  ", password, "  ", key_path, "  ", command, "  ", bind_interface, "  ", connect_timeout, "  ", command_timeout);
    print("")

    try:
        # 如果指定了bind_interface，则创建socket手动连接
        sock = None
        if bind_interface:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)
            try:
                # 尝试将bind_interface当作IP地址绑定
                socket.inet_aton(bind_interface)  # 验证是否为有效IP
                sock.bind((bind_interface, 0))
            except OSError:
                # 若bind_interface不是IP（可能是网卡名称），尝试绑定网卡
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bind_interface.encode())
                except Exception as e:
                    logging.error(f"[{ip}] 无法绑定到 {bind_interface}: {e}")
                    raise
            # 发起 TCP 连接
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
        logging.info(f"[{ip}] SSH连接已建立。")
        # 执行远程命令
        stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
        # 读取命令输出和错误输出
        try:
            output = stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            output = ""
            logging.error(f"[{ip}] 读取标准输出时出错: {e}")
        try:
            error_output = stderr.read().decode('utf-8', errors='ignore')
        except Exception as e:
            error_output = ""
            logging.error(f"[{ip}] 读取错误输出时出错: {e}")
        # 获取命令退出状态码
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logging.info(f"[{ip}] 命令执行成功，退出状态码 0。")
        else:
            logging.warning(f"[{ip}] 命令执行完成，退出状态码 {exit_status}。")
        if error_output:
            logging.error(f"[{ip}] 命令错误输出: {error_output.strip()}")
        result["output"] = output
        result["error"] = error_output
    except Exception as e:
        # 捕获所有异常，记录错误信息
        result["error"] = str(e)
        logging.error(f"[{ip}] 执行过程中出现异常: {e}", exc_info=True)
    finally:
        # 清理SSH客户端和socket
        if client:
            client.close()
        if 'sock' in locals() and sock:
            try:
                sock.close()
            except Exception:
                pass

    return result

def run_ssh_commands(config_path):
    """根据配置文件批量执行SSH命令。"""
    # 配置日志记录
    logging.basicConfig(filename='ssh_automation.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    # 加载并验证配置
    servers = load_config(config_path)
    # 按优先级排序服务器列表
    servers.sort(key=lambda x: x.get("priority", 0))
    # 根据优先级分组服务器
    priority_groups = {}
    for server in servers:
        prio = server.get("priority", 0)
        priority_groups.setdefault(prio, []).append(server)
    results = []
    sorted_prios = sorted(priority_groups.keys())
    # 可选：设置不同优先级之间的等待时间（秒）
    priority_waits = {
        1: 2,
        2: 4
        # 示例: 1: 5 表示优先级1组执行完后等待5秒
        # 可以根据需要添加不同优先级的等待时间
    }
    # 顺序执行各优先级组
    for i, prio in enumerate(sorted_prios):
        logging.info(f"=== 开始执行优先级 {prio} 组 ===")
        # 并发执行当前优先级组内的所有服务器命令
        group = priority_groups[prio]
        futures = []
        with ThreadPoolExecutor(max_workers=len(group)) as executor:
            for server in group:
                futures.append(executor.submit(execute_remote_command, server))
            for future in as_completed(futures):
                res = future.result()
                results.append(res)
        logging.info(f"=== 优先级 {prio} 组执行完毕 ===")
        # 在不同优先级组之间等待（如果有配置等待时间）
        if i < len(sorted_prios) - 1:
            wait_time = priority_waits.get(prio, 0)
            if wait_time > 0:
                logging.info(f"等待 {wait_time} 秒后执行下一个优先级组...")
                time.sleep(wait_time)
    return results

# 示例：调用主函数（实际使用时，可以通过命令行参数指定配置文件路径）
# results = run_ssh_commands('config.json')
# for res in results:
#     print(res["ip"], "输出:", res["output"], "错误:", res["error"])
def main():
    results = run_ssh_commands('config.json')
    for res in results:
        print(res["ip"], " output: ", res["output"], " error: ", res["error"])

if __name__ == "__main__":
    main()
