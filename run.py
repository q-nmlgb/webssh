from webssh.main import main
import os
import subprocess
import sys

def setup_ssh_and_run():
    print("=== [System Setup] Checking and configuring SSH Server ===")
    try:
        # 1. 确保 sshd 目录存在
        os.makedirs("/var/run/sshd", exist_ok=True)

        # 2. 修改 SSH 配置文件，允许 root 密码登录
        sshd_config_path = "/etc/ssh/sshd_config"
        if os.path.exists(sshd_config_path):
            with open(sshd_config_path, "r") as f:
                config = f.read()
            
            # 确保允许 root 登录和密码认证
            modified = False
            if "PermitRootLogin yes" not in config:
                config = config.replace("#PermitRootLogin prohibit-password", "PermitRootLogin yes")
                config = config.replace("PermitRootLogin prohibit-password", "PermitRootLogin yes")
                modified = True
            if "PasswordAuthentication yes" not in config:
                config = config.replace("#PasswordAuthentication yes", "PasswordAuthentication yes")
                modified = True
                
            if modified:
                with open(sshd_config_path, "w") as f:
                    f.write(config)
                print("[System Setup] Updated sshd_config permissions.")

        # 3. 强制修改 root 密码为 admin123
        # 使用 chpasswd 避免交互式输入
        subprocess.run(
            "echo 'root:admin123' | chpasswd", 
            shell=True, 
            check=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        print("[System Setup] Root password updated successfully.")

        # 4. 启动 SSH 服务（如果未运行）
        # 使用 nohup 或 subproccess.Popen 确保 sshd 作为守护进程在后台运行
        subprocess.Popen(["/usr/sbin/sshd", "-D"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[System Setup] SSH daemon started in background.")

    except Exception as e:
        # 如果因为权限不足（非 root 运行）或者缺少 apt 导致失败，打印警告但不阻碍主程序启动
        print(f"[System Setup] Warning: Failed to set up SSH daemon: {e}")
        print("[System Setup] This usually happens if the container is not running as root user.")

    # 5. 移交控制权给原生的 webssh 启动逻辑
    print("=== [System Setup] Launching WebSSH application... ===")
    from webssh.main import main
    main()

if __name__ == '__main__':
    setup_ssh_and_run()

