# 导入IBurpExtender类，它是编写每一个Burp扩展工具时必须使用的类
from burp import IBurpExtender
# 导入Intruder载荷生成器必须要的类
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import requests
import os
import re

# 自己定义BurpExtender类，它继承和扩展了IBurpExtender类和IIntruderPayloadGeneratorFactory
class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    # 使用registerIntruderPayloadGeneratorFactory函数注册BurpExtender类，这样Intruder工具才能生成攻击载荷
    callbacks.registerIntruderPayloadGeneratorFactory(self)

    return

  # 部署getGeneratorName函数让它返回载荷生成器的名称
  def getGeneratorName(self):
    return "Burp Vcode"

  # 创建createNewInstance函数接收攻击相关参数，返回IIntruderPayloadGenerator类型的实例，命名为BurpVcode
  def createNewInstance(self, attack):
    return BurpVcode(self, attack)

# 定义自己的BurpVcode类，扩展了IIntruderPayloadGenerator类
class BurpVcode(IIntruderPayloadGenerator):
    def __init__(self,attack):
        # 获取原始请求，attack.getRequestTemplate()返回的是array类型
        # chr(abs(x))abs取绝对值主要是因为返回的内容不知道为什么会有负数，负数放到chr(x)这个函数里面又会报错所以只能取绝对值
        tem = "".join(chr(abs(x)) for x in attack.getRequestTemplate())
        # 获取cookie
        cookie = re.findall("Cookie: (.+?)\r\n",tem)[0]
        self.img_url = "http://www.6zhiyun.com/yimaoinclude/code.php?t=0.09701541587602969"     # 验证码链接
        self.cookie = cookie
        self.max = 1
        self.num = 0
        self.attack = attack

    def hasMorePayload(self):
        if self.num == self.max:
            return False        # 当达到最大次数的时候就调用reset
        else:
            return True         # 当没有达到最大次数的时候就调用getNextPayload

    def getNextPayload(self,payload):
        headers = {'Cookie':self.cookie}
        r = requests.get(self.img_url,headers=headers)      # 访问验证码，用当前用户的会话获取验证码
        f = open('d:\\img_code.jpg','w')
        f.write(r.content)      # 写入图片
        f.close()

        # 调用本机识别验证码程序，获取得到的结果
        os.system('i:\\python_security\\venv\\Scripts\\python.exe i:\\python_security\\know_code.py')
        f = open('d:\\result.txt','r')      # 读入结果
        code = f.read()
        f.close()

        self.num +=1
        return code
    def reset(self):
        print("reset")
        self.num = 0        # 清零
        return
