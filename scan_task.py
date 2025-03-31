#所有的工具路径根据subprocess命令自定义修改
import sqlite3
import subprocess
import logging
import shlex
import sys
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# === 配置类 ===
@dataclass
class ScannerConfig:
    project_name: str
    base_dir: Path = Path("./scan_project")
    tool_dir: Path = Path("./tools")
    
    def __post_init__(self):
        self.validate_project_name()
        self.project_dir = self.base_dir / self.project_name
        self.project_dir.mkdir(parents=True, exist_ok=True)
        
        # 工具路径
        self.subfinder = self.tool_dir / "subfinder"
        self.oneforall = self.tool_dir / "OneForAll/oneforall.py"
        self.httpx = self.tool_dir / "httpx/httpx"
        self.nuclei = self.tool_dir / "nuclei/nuclei"
        self.anew = self.tool_dir / "anew/anew"
        
        # 链路1文件
        self.domain_file = self.project_dir / "domain.txt"
        self.subfinder_out = self.project_dir / "result_1_subfinder.txt"
        self.oneforall_out = self.project_dir / "result_1_oneforall.txt"
        self.httpx_out = self.project_dir / "result_1_httpx.txt"
        self.uro_out = self.project_dir / "result_1_uro.txt"
        
        # 其他路径根据需要添加...

    def validate_project_name(self):
        if not re.match(r"^[\w-]+$", self.project_name):
            raise ValueError("Invalid project name. Only alphanumeric, underscores and hyphens allowed.")

# === 基础类 ===
class BaseScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def run_cmd(self, command: str, check: bool = True) -> bool:
        """安全执行shell命令"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=check,
                capture_output=True,
                text=True,
                executable='/bin/bash' if sys.platform != 'win32' else None
            )
            if result.returncode != 0:
                self.logger.error(f"命令执行失败: {command}\n错误: {result.stderr}")
                return False
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"命令返回非零状态码: {e.cmd}\n错误码: {e.returncode}")
            return False
        except Exception as e:
            self.logger.exception(f"执行命令时发生意外错误: {command}")
            return False

# === 信息收集模块 ===
class PassiveCollector(BaseScanner):
    def collect_subdomains(self):
        """收集子域名"""
        # 使用subfinder
        cmd = f"{self.config.subfinder} -dL {self.config.domain_file} -o {self.config.subfinder_out}"
        if not self.run_cmd(cmd):
            raise RuntimeError("Subfinder执行失败")
        
        # 使用OneForAll
        cmd = f"python3 {self.config.oneforall} --targets {self.config.domain_file} run"
        if not self.run_cmd(cmd):
            raise RuntimeError("OneForAll执行失败")
        
        self._process_oneforall_results()

    def _process_oneforall_results(self):
        """处理OneForAll的数据库结果"""
        db_path = self.config.tool_dir / "OneForAll/results/result.sqlite3"
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 获取主域名数量
            with open(self.config.domain_file) as f:
                domain_count = sum(1 for _ in f)
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()[-domain_count:]]
            
            domains = []
            for table in tables:
                cursor.execute(f"SELECT url FROM '{table}' WHERE port=443")
                domains.extend(urlparse(row[0]).netloc for row in cursor.fetchall())
            
            with open(self.config.oneforall_out, "w") as f:
                f.write("\n".join(domains))
                
        except sqlite3.Error as e:
            self.logger.error(f"数据库错误: {str(e)}")
            raise
        finally:
            conn.close()

        # 合并结果
        merge_cmd = f"cat {self.config.subfinder_out} | {self.config.anew} {self.config.oneforall_out}"
        if not self.run_cmd(merge_cmd):
            raise RuntimeError("结果合并失败")

    def check_alive_domains(self):
        """使用httpx检查存活域名"""
        cmd = f"cat {self.config.oneforall_out} | {self.config.httpx} -silent > {self.config.httpx_out}"
        if not self.run_cmd(cmd):
            raise RuntimeError("HTTPX执行失败")

# === 配置扫描模块 ===
class ConfigScanner(BaseScanner):
    def scan_cors(self):
        """扫描CORS配置"""
        cors_out = self.config.project_dir / "result_2_cors.json"
        cmd = f"cat {self.config.httpx_out} | python3 {self.config.tool_dir}/corsy/corsy.py -o {cors_out}"
        self.run_cmd(cmd, check=False)  # 允许非关键任务失败

    def scan_directories(self):
        """目录扫描"""
        dirsearch_out = self.config.project_dir / "result_2_dirsearch.txt"
        cmd = f"python3 {self.config.tool_dir}/dirsearch/dirsearch.py -l {self.config.httpx_out} -o {dirsearch_out}"
        self.run_cmd(cmd, check=False)

# === 漏洞扫描模块 ===
class VulnerabilityScanner(BaseScanner):
    def run_gf_scans(self):
        """并行执行GF扫描"""
        cmds = [
            f"cat {self.config.uro_out} | gf xss > {self.config.project_dir}/result_1_xss.txt",
            f"cat {self.config.uro_out} | gf sqli > {self.config.project_dir}/result_1_sqli.txt",
            # 添加其他GF扫描命令...
        ]
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.run_cmd, cmd) for cmd in cmds]
            for future in futures:
                future.result()  # 等待所有任务完成

# === 主程序 ===
class ScanManager:
    def __init__(self, project_name: str):
        self.config = ScannerConfig(project_name)
        self.logger = logging.getLogger("ScanManager")
        
        # 初始化扫描器
        self.collector = PassiveCollector(self.config)
        self.config_scanner = ConfigScanner(self.config)
        self.vuln_scanner = VulnerabilityScanner(self.config)
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self.config.project_dir / "scan.log"),
                logging.StreamHandler()
            ]
        )

    def run_full_scan(self):
        """执行完整扫描流程"""
        self.logger.info("=== 开始安全扫描 ===")
        
        try:
            # 链路1：信息收集
            self.logger.info("步骤1/4：子域名收集")
            self.collector.collect_subdomains()
            self.logger.info("步骤2/4：存活检测")
            self.collector.check_alive_domains()
            
            # 链路2：配置扫描
            self.logger.info("步骤3/4：配置扫描")
            self.config_scanner.scan_cors()
            self.config_scanner.scan_directories()
            
            # 链路3：漏洞扫描
            self.logger.info("步骤4/4：漏洞扫描")
            self.vuln_scanner.run_gf_scans()
            
        except Exception as e:
            self.logger.critical(f"扫描终止: {str(e)}")
            sys.exit(1)
            
        self.logger.info("=== 扫描完成 ===")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python scanner.py <project_name>")
        sys.exit(1)
    
    project = sys.argv[1]
    manager = ScanManager(project)
    manager.setup_logging()
    manager.run_full_scan()
