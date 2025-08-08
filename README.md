# WebSec_Tools
# 工具介绍：
-------------------------------------------------------
## ·子域名扫描工具：
    - OneForAll    eg--->python3 oneforall.py --target baidu.com run
        OneForAll 是一款功能强大的子域收集工具
    - subfinder    eg--->./subfinder -d baidu.com
        subfinder 是一款大型的子域名收集工具,通过调用大量在线资源来被动发现合法的子域名
    - assetfinder    eg--->./assetfinder ***.com > domain.txt
        assetfinder 是一种基于 Go 的工具，用于从各种来源（包括 Facebook、ThreatCrowd、Virustotal 等）中查找可能与给定域相关的相关域和子域。
    - dnsub        可自定义扫描字典、域名前缀等
## ·端口扫描工具：
    - naabu    eg--->./naabu -host ***.***.***.***
        Naabu 是一款用 Go 编写的端口扫描工具，可让您快速可靠地枚举主机的有效端口

## ·资产攻击面绘制工具:
    - amass

## ·子域名接管工具：
    - subzy    已经安装到环境变量，直接使用。
        subzy run --target test.google.com,https://test.yahoo.com   --指定域名扫描
        subzy run --targets subdomains.txt                          --扫描文件中的域名
        
## ·xss扫描工具：
    - xsstrike    eg--->python3 xsstrike.py --url 'https://***.***/***'  --fuzzer
                  eg---> python3 xsstrike.py -u 'url'
        XSStrike 是一个xss扫描工具，使用多个解析器分析响应，可以进行反射和 DOM XSS 扫描
    - dalfox    eg--->./dalfox url 'https://***.***/***'
                支持管道输入，批量扫描文件中多个url：：：
                cat urls.txt | gf xss | ./dalfox pipe -o result.txt
## ·sqli扫描工具：
    - sqlmap    eg--->单个包扫描：
                    python3 sqlmap.py -r test.txt --delay=3 --risk 3 --level 5 --random-agent --batch

                eg--->扫描文件中多个url：
                    cat urls.txt | python3 sqlmap.py --batch --answers "others=y,already=n" --flush-session -v 0 --output-dir=result/

    - ghauri    -u URL, --url URL   目标URL (例如'http://www.site.com/vuln.php?id=1)
                -r REQUESTFILE     从文件加载HTTP请求
## ·ssrf扫描工具：
    - ssrfmap    eg---> python3 ssrfmap.py -r test.txt -p url -m readfiles,portscan(对test.txt包扫描，扫描参数url，进行文件读取和端口扫描)
        ssrfmap 是一款自动 SSRF 模糊测试器和利用工具
        参考 https://blog.csdn.net/qq_32812063/article/details/128031912
## ·目录扫描工具：
    - dirsearch    eg--->python3 dirsearch.py -u https://www.baidu.com
        dirsearch是一款路径扫描工具
## ·CORS配置扫描工具：
    - corsy    eg--->python3 corsy.py -u https://www.shequ.codemao.cn
        Corsy 是一个轻量级程序，可以扫描 CORS 实现中所有已知的错误配置
## ·CRLF扫描工具
    - CRLFUZZ   
## ·openredirect扫描工具：
    - OpenRedireX    eg--->cat list_of_urls.txt |  openredirex -p payloads.txt -k "FUZZ" -c 50   需要提前将bp的collaborator地址放入payloads中
        OpenRedireX是一款用于检测开放重定向漏洞的模糊测试器
## ·域名存活扫描工具：
    - httpx    eg--->cat testdomain.txt | ./httpx -status-code -title -tech-detect
        httpx是一款对URL进行批量识别存活、常见端口、标题、Banner等信息的工具

## ·anew工具：
    - 取两个文件中新增的内容，也可取两个文件内容并集
## ·uro工具：
    - 筛选出url列表中有价值的url（排除掉重复或者无意义或者无需测试的url）
    - before：
        http://example.com/page.php?id=1
        http://example.com/page.php?id=2
        http://example.com/page.php?id=3&page=2
        http://example.com/cat/9/details.html
        http://example.com/cat/11/details.html
        http://example.com/blog/why-people-suck-a-study
        http://example.com/blog/how-to-lick-your-own-toes
        http://example.com/banner.jpg
        http://example.com/assets/background.jpg
    - after：
        http://example.com/page.php?id=1
        http://example.com/page.php?id=3&page=2
        http://example.com/cat/9/details.html

## ·爬虫工具：
    - katana    eg--->./katana -u testdomain.txt
        Katana 是由 projectdiscovery 开发的一款先进的网页爬虫框架
    - waybackurls    eg--->./waaybackurls https://www.baidu.com
        waybackurls 获取 Wayback Machine 所知道的某个域名的所有 URL,国内结果较少
    - paramspider:已经安装到环境变量，直接使用，eg--->paramspider -d baidu.com
        ParamSpider是一款功能强大的Web参数挖掘工具，利用ParamSpider来从Web文档的最深处挖掘出目标参数
## ·规则匹配工具
    - gf    eg--->cat domain.txt | gf xss （匹配出url中xss关键字）
        gf 是一款grep 的包装器，帮助你 grep 东西
## ·web扫描工具：
    - xray    eg--->./xray webscan --basic-crawler http://xxx.com --html-output v.html(爬虫扫描)
            eg--->./xray webscan --listen 127.0.0.1:7891 --html-output proxybp.html(代理扫描)
    - nuclei    eg--->./nuclei -u https://***.*** -t 对应扫描模板 ｜ -es info,low：排除info、low级别的扫描，-ept ssl,dns：排除ssl、dns类型的扫描
## ·网络空间搜索工具
    - fofamap    eg--->python3 fofamap.py -q 'title="GeoServer"'
        FofaMap 是一款基于 Python3 开发的 FOFA API 数据采集器，支持普通、网站存活检测、聚合、网站主题、订单等功能。
## ·字典
    - SecLists
        SecLists 是安全测试人员的好帮手。它是安全评估期间使用的多种列表类型的集合，收集在一个地方。列表类型包括用户名、密码、URL、敏感数据模式、模糊测试负载、Web Shell 等等。
-------------------------------------------------------

# APP测试工具
-------------------------------------------------------
## MobSF
    - https://github.com/MobSF/Mobile-Security-Framework-MobSF
-------------------------------------------------------

# 内网安全测试工具
-------------------------------------------------------
    - https://gobies.org/
-------------------------------------------------------

# pikachu靶场测试：
-------------------------------------------------------
## 1、ssrf漏洞
    提前在collaborator生成一个域名，放入openredirex的payloads.txt中，执行命令：
    echo 'http://localhost:8765/vul/urlredirect/urlredirect.php?url=unsafere.php' | openredirex -p payloads.txt
    发现collaborator的域名被解析，可判断存在ssrf漏洞
    ![img.png](img.png)
## 2、xss漏洞（反射+dom）
    2.1、xsstrike
        python3 xsstrike.py --url 'http://localhost:8765/vul/xss/xss_reflected_get.php?message=123&submit=submit' --fuzzer
        遍历所有的参数，跑payload，如果参数存在xss，会返回payload，不能对文件中的多个url进行扫描，只针对单个url
        python3 xsstrike.py -u "" --skip-dom    跳过dom型xss扫描
    2.2、dalfox    
        ./dalfox url 'http://localhost:8765/vul/xss/xss_reflected_get.php?message=123&submit=submit'
        ![img_2.png](img_2.png)
## 3、sql注入漏洞
    3.1、单个包扫描
    python3 sqlmap.py -r test.txt --batch
    先抓包保存为test.txt，执行 python3 sqlmap.py -r test.txt --batch
    ![img_3.png](img_3.png)
    3.2、结合burpsuite多个包批量扫描
    先在burpsuite导出需要扫描的数据包到文件，如log.txt
    python3 sqlmap.py -l log.txt --batch --answers "others=y,already=n"   批量扫描数据包里的参数，get请求参数、post请求参数
    python3 sqlmap.py -l log.txt --batch --answers "others=y,already=n" -p "cookie,useragent"   批量只扫描多个数据包的指定参数cookie,useragent
## 4、xxe漏洞
    手工测试，目前没有发现好用的工具
    payload：https://github.com/payloadbox/xxe-injection-payload-list/tree/master/Intruder
-------------------------------------------------------
