#所有的工具路径根据subprocess命令自定义修改
import sqlite3
import subprocess
from urllib.parse import urlparse

##链路1：：：-------------------------------------------------------------------------------------------------------------------------------
##基本信息收集
def passive_info_collection(domain_file, subfinder_txt_file, oneforall_txt_file, httpx_txt_file, naabu_txt_file, katana_txt_file, uro_txt_file, xss_txt_file, sqli_txt_file, ssrf_txt_file, redirect_txt_file, rce_txt_file):
    #第一部分： 子域名收集（oneforall、subfinder）【result_1_oneforall.txt、result_1_subfinder.txt】；
    # subfinder收集子域名
    command_subfinder = f'./subfinder/subfinder -dL {domain_file}  -o {subfinder_txt_file}'
    try:
        subprocess.run(command_subfinder, shell=True)
    except Exception as e:
        print("An unexpected error occurred:\n", str(e))
    # oneforall收集子域名
    command_oneforall = f'python3 ./OneForAll/oneforall.py --targets {domain_file} run'
    try:
        subprocess.run(command_oneforall, shell=True)
    except Exception as e:
        print("An unexpected error occurred:\n", str(e))
    # 获取主域名个数
    count = sum(1 for _ in open(domain_file))
    conn = sqlite3.connect("./OneForAll/results/result.sqlite3")
    cursor = conn.cursor()
    domain_url = []
    try:
        # 获取所有表名
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table';")
        table_name = cursor.fetchall()
    except:
        pass
    finally:
        # 获取给定主域名对应的子域名
        for tb_name in table_name[-count:]:
            sql = "SELECT url FROM '%s' where port = 443" % (tb_name)
            cursor.execute(sql)
            rows = cursor.fetchall()
            for urls in rows:
                domain_url.append(urls[0])
    cursor.close()
    conn.close()
    try:
        with open(oneforall_txt_file, "w") as file:
            for item in domain_url:
                # 解析 URL 并提取 netloc 部分
                parsed_url = urlparse(item)
                domain = parsed_url.netloc
                file.write(f"{domain}\n")
    except Exception as e:
        print(f"An error occurred: {e}")

    # 将result_1_subfinder.txt与result_1_oneforall.txt的内容取并集，将并集保存在result_1_oneforall.txt
    command = f'cat {subfinder_txt_file} | ./anew/anew {oneforall_txt_file}'
    try:
        subprocess.run(command, shell=True, text=True)
    except Exception as e:
        print("An unexpected error occurred:\n", str(e))    # 最终合并后的结果保存在result_1_oneforall.txt中


    #第二部分： httpx子域名存活检查【result_2_httpx.txt】；
    httpx_cmd = f"cat {oneforall_txt_file} | ./httpx/httpx > {httpx_txt_file}"
    subprocess.run(
        httpx_cmd,
        shell=True,
    )

    #第三部分： 存活子域名端口扫描【result_3_naabu.txt】；
    #command = f'cat {httpx_txt_file} | ./naabu/naabu -o {naabu_txt_file} -p 1-65535  -silent'
    #try:
        #subprocess.run(command, shell=True, text=True)
    #except Exception as e:
        #print("An unexpected error occurred:\n", str(e))

    #第四部分： 4、存活子域名进行爬虫收集url信息【result_4_katana.txt】；
    katana_cmd = f"cat {httpx_txt_file} | ./katana/katana -o {katana_txt_file} -d 5"
    subprocess.run(
        katana_cmd,
        shell=True
    )
    gau_cmd = f"cat {httpx_txt_file} | gau --threads 50 >> {katana_txt_file}"
    subprocess.run(
        gau_cmd,
        shell=True
    )
    uro_cmd = f"cat {katana_txt_file} | uro -o {uro_txt_file}"
    subprocess.run(
        uro_cmd,
        shell=True
    )

    #第五部分： 5、gf过滤出xss、sqli、ssrf、redirect、xxe、rce链接
    xss_cmd = f"cat {uro_txt_file} | gf xss > {xss_txt_file}"
    sqli_cmd = f"cat {uro_txt_file} | gf sqli > {sqli_txt_file}"
    ssrf_cmd = f"cat {uro_txt_file} | gf ssrf > {ssrf_txt_file}"
    redirect_cmd = f"cat {uro_txt_file} | gf redirect > {redirect_txt_file}"
    rce_cmd = f"cat {uro_txt_file} | gf rce > {rce_txt_file}"
    subprocess.run(xss_cmd, shell=True)
    subprocess.run(sqli_cmd, shell=True)
    subprocess.run(ssrf_cmd, shell=True)
    subprocess.run(redirect_cmd, shell=True)
    subprocess.run(rce_cmd, shell=True)

##链路2：：：-------------------------------------------------------------------------------------------------------------------------------
##基础配置扫描
def scan_configuration(httpx_txt_file, cors_json_file, crlf_txt_file, dirsearch_txt_file, nuclei_txt_file):
    # 输入：result_httpx.txt  输出：result_cors.txt, result_crlfuzz.txt, result_dirsearch.txt, result_nuclei.txt

    #第一部分：：：cors扫描
    cmd = f"cat {httpx_txt_file} | python3 ./corsy/corsy.py  -o {cors_json_file}"
    subprocess.run(
        cmd,
        shell=True,
    )

    #第二部分：：：crlf扫描，为啥扫描vulhub的nginx漏洞（crlf）扫描不出结果
    cmd = f"cat  {httpx_txt_file} | ./crlfuzz/crlfuzz -o {crlf_txt_file}"
    subprocess.run(
        cmd,
        shell=True,
    )

    #第三部分：：：dirsearch扫描,,,或者有新的wordlist，可以指定wordlist单独扫描 auth/jwt/register auth-demo/register/classic auth-demo/register/modern
    cmd = f"python3 ./dirsearch/dirsearch.py -l {httpx_txt_file} -o {dirsearch_txt_file}"
    subprocess.run(
        cmd,
        shell=True,
    )

    #第四部分：：：nuclei扫描
    cmd = f"cat {httpx_txt_file} | ./nuclei/nuclei  -o {nuclei_txt_file}"  #-es info, low -ept ssl,dns
    subprocess.run(
        cmd,
        shell=True,
    )

##链路3：：：-------------------------------------------------------------------------------------------------------------------------------
##gf过滤出uro文件中的链接，来扫描sqli、xss、openredirect
def uro_gf_scan(uro_txt_file, sqlmap_txt_dir, dalfox_txt_file, openredirect_txt_file):
    # 链路3：：：扫描gf过滤出的链接
    # 输入：result_uro_bak.txt gf过滤链接 输出：result_sqlmap.txt, result_xss.txt, result_ssrf.txt, result_openredirect.txt, result_nuclei.txt

    #sqlmap扫描
    uro_sqli_cmd = f"cat {uro_txt_file} | gf sqli | python3 ./sqlmap/sqlmap.py --random-agent --batch --answers 'others=y,already=n' --flush-session -v 0 --tamper=space2comment --time-sec=5  --proxy http://127.0.0.1:8086 --output-dir={sqlmap_txt_dir}"
    subprocess.run(
        uro_sqli_cmd,
        shell=True,
    )

    # xss扫描   cat urls.txt | gf xss | ./dalfox pipe -o result.txt
    ruo_xss_cmd = f"cat {uro_txt_file} | gf xss | ./dalfox/dalfox pipe -o {dalfox_txt_file}"
    subprocess.run(
        ruo_xss_cmd,
        shell=True,
    )

    #openredirect扫描  cat ../scan_project/codemao_cn/result_katana_bak.txt | openredirex -p payloads.txt > result_openredirect.txt
    ruo_redirect_cmd = f"cat {uro_txt_file} | gf redirect | openredirex -p ./OpenRedireX/payloads.txt > {openredirect_txt_file}"
    subprocess.run(
        ruo_redirect_cmd,
        shell=True,
    )

##链路4：：：-------------------------------------------------------------------------------------------------------------------------------
#把katana爬取到的链接过滤出js文件，nuclei扫描这些js文件
def js_scan(uro_txt_file, js_txt_file):

    js_cmd = f"cat {uro_txt_file} | grep '\.js$' | ./nuclei/nuclei -es info,low -ept ssl,dns -o {js_txt_file}"
    subprocess.run(js_cmd,shell=True)

##链路5：：：-------------------------------------------------------------------------------------------------------------------------------
#指定nuclei模版（如xss、openredirect、ssrf）来进行nuclei扫描

if __name__ == '__main__':
    banner = '''
                    TOOL
===========================================
| [1] passive_info_collection             |
| [2] scan_configuration                  |
| [3] uro_gf_scan                         |
| [4] js_scan                             |
==========================================='''
    print(banner)

    project_path = 'byteplus'
    domain_file = f'./scan_project/{project_path}/domain.txt'   # 链路一输入的域名列表文件
    subfinder_txt_file = f'./scan_project/{project_path}/result_1_subfinder.txt'  # 链路一保存subfinder子域名文件
    oneforall_txt_file = f'./scan_project/{project_path}/result_1_oneforall.txt'  # 链路一保存oneforall子域名文件
    httpx_txt_file = f'./scan_project/{project_path}/result_1_httpx.txt'    # 链路一保存httpx存活域名
    naabu_txt_file = f'./scan_project/{project_path}/result_1_naabu.txt'     # 链路一保存域名的端口扫描信息
    katana_txt_file = f'./scan_project/{project_path}/result_1_katana.txt'    # 链路一保存的存活域名爬虫后链接
    uro_txt_file = f'./scan_project/{project_path}/result_1_uro.txt'    # 链路一保存的存活域名爬虫链接经过uro处理的结果
    xss_txt_file = f'./scan_project/{project_path}/result_1_xss_input.txt'   #链路一保存的gf过滤的xss待扫描链接
    sqli_txt_file = f'./scan_project/{project_path}/result_1_sqli_input.txt'  #链路一保存的gf过滤的sqli待扫描链接
    ssrf_txt_file = f'./scan_project/{project_path}/result_1_ssrf_input.txt'   #链路一保存的gf过滤的ssrf待扫描链接
    redirect_txt_file = f'./scan_project/{project_path}/result_1_redirect_input.txt'   #链路一保存的gf过滤的redirect待扫描链接
    rce_txt_file = f'./scan_project/{project_path}/result_1_rce_input.txt'    #链路一保存的gf过滤的rce待扫描链接

    cors_json_file = f'./scan_project/{project_path}/result_2_cors.json'   # 链路二保存的httpx存活域名cors扫描结果
    crlf_txt_file = f'./scan_project/{project_path}/result_2_crlf.txt'      # 链路二保存的httpx存活域名crlf扫描结果
    dirsearch_txt_file = f'./scan_project/{project_path}/result_2_dirsearch.txt'    # 链路二保存的httpx存活域名web路径扫描结果
    nuclei_txt_file = f'./scan_project/{project_path}/result_2_nuclei.txt'         # 链路二保存的httpx存活域名nuclei扫描结果

    sqlmap_txt_dir = f'./scan_project/{project_path}/result_3_sqlmap_dir'        # 链路三保存的gf过滤后链接的sqlmap扫描结果
    dalfox_txt_file = f'./scan_project/{project_path}/result_3_dalfox.txt'     # 链路三保存的gf过滤后链接的xss扫描结果
    openredirect_txt_file = f'./scan_project/{project_path}/result_3_openredirect.txt'     # 链路三保存的gf过滤后链接的openredirect扫描结果

    js_txt_file = f'./scan_project/{project_path}/result_4_js.txt'      #链路四保存的js扫描结果

    input = input("select an option (1-4):\n")
    #链路1
    if input == "1":
        passive_info_collection(domain_file, subfinder_txt_file, oneforall_txt_file, httpx_txt_file, naabu_txt_file, katana_txt_file, uro_txt_file, xss_txt_file, sqli_txt_file, ssrf_txt_file, redirect_txt_file, rce_txt_file)
    #链路2
    elif input == "2":
        scan_configuration(httpx_txt_file, cors_json_file, crlf_txt_file, dirsearch_txt_file, nuclei_txt_file)
    #链路3
    elif input == "3":
        uro_gf_scan(uro_txt_file, sqlmap_txt_dir, dalfox_txt_file, openredirect_txt_file)
    #链路4
    elif input == "4":
        js_scan(uro_txt_file, js_txt_file)
