# 导入IBurpExtender类，它是编写每一个Burp扩展工具时必须使用的类
from burp import IBurpExtender
# 导入IContextMenuFactory类，它允许我们在鼠标右键单击Burp中的请求时提供上下文菜单
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import socket
import urllib
import json
import re
import base64

bing_api_key = "817f*******************ce5"     # 此处存放你申请的Bing API

# 这个类部署了基本的IBurpExtender接口和IContextMenuFactory，IContextMenuFactory允许我们在鼠标右键单击Burp中的请求时提供上下文菜单
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        # 建立起扩展工具
        callbacks.setExtensionName("Burp Bing")
        callbacks.registerContextMenuFactory(self)      # 注册菜单句柄，这样我们就可以判定用户点击了哪个网站，从而完成Bing查询语句的构造

        return

    # 建立createMenuItems函数，该函数接收IContextMenuInvocation对象，用来判定用户选中了哪个HTTP请求
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Bing", actionPerformed=self.bing_menu))       # 渲染菜单并让我们的bing_menu函数处理点击事件

        return menu_list

    def bing_menu(self, event):

        # 获取用户点击的详细信息，接收所有高亮显示的HTTP请求
        http_traffic = self.context.getSelectedMessages()

        print ("%d requests highlighted" % len(http_traffic))

        # 检索每一个请求的域名部分并将它们发送到bing_search函数进行进一步处理
        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()

            print ("User selected host: %s" % host)


            self.bing_search(host)

        return


    def bing_search(self, host):

        # 检查参数是否为IP地址或者主机名
        is_ip = re.match("[0-9]+(?:\.[0-9]+){3}", host)

        # 判断我们传递的是否是IP地址或者是域名
        if is_ip:
            ip_address = host
            domain = False
        else:
            ip_address = socket.gethostbyname(host)
            domain = True

        bing_query_string = "'ip:%s'" % ip_address

        # 通过Bing查询在同一个IP地址上是否存在不同的虚拟主机
        self.bing_query(bing_query_string)

        # 如果传递给扩展工具是域名，那么进行二次搜索，将Bing检索结果中的子域名找出来
        if domain:
            bing_query_string = "'domain:%s'" % host
            self.bing_query(bing_query_string)

    def bing_query(self, bing_query_string):

        print ("Performing Bing search: %s" % bing_query_string)

        # 编码我们的查询
        quoted_query = urllib.quote(bing_query_string)

        http_request = "GET https://api.datamarket.azure.com/Bing/Search/Web?$format=json&$top=20&Query=%s HTTP/1.1\r\n" % quoted_query
        http_request += "Host: api.datamarket.azure.com\r\n"
        http_request += "Connection: close\r\n"
        http_request += "Authorization: Basic %s\r\n" % base64.b64encode(":%s" % bing_api_key)      # Bing的API密钥需要用到Base64进行编码，同时使用HTTP基础认证方式调用API

        http_request += "User-Agent: Blackhat Python\r\n\r\n"

        # 将HTTP请求提交到微软的服务器上，当响应返回时，我们可以得到全部的响应包括HTTP头部
        json_body = self._callbacks.makeHttpRequest("api.datamarket.azure.com", 443, True, http_request).tostring()

        # 将HTTP响应头分离
        json_body = json_body.split("\r\n\r\n", 1)[1]

        try:

            # 把响应头剩余部分传递给JSON解析器
            r = json.loads(json_body)

            if len(r["d"]["results"]):
                for site in r["d"]["results"]:

                    # 输出查找的目标网站的相关信息
                    print ("*" * 100)

                    print (site['Title'])

                    print (site['Url'])

                    print (site['Description'])

                    print ("*" * 100)


                    j_url = URL(site['Url'])

                    # 如果我们发现结果网站还不在Burp的目标盘列表中，就自动添加进去
                    if not self._callbacks.isInScope(j_url):
                        print ("Adding to Burp scope")

                        self._callbacks.includeInScope(j_url)

        except:
            print ("No results from Bing")

            pass

        return
