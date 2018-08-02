# 导入IBurpExtender类，它是编写每一个Burp扩展工具时必须使用的类
from burp import IBurpExtender
# 导入Intruder载荷生成器必须要的类
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random

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
        return "Fuzzer Payload Generator"

    # 创建createNewInstance函数接收攻击相关参数，返回IIntruderPayloadGenerator类型的实例，命名为BurpFuzzer
    def createNewInstance(self,attack):
        return BurpFuzzer(self,attack)


# 定义自己的BurpFuzzer类，扩展了IIntruderPayloadGenerator类
class BurpFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        # 定义需要的类变量
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        # 定义变量让它们用来对模糊测试的过程进行追踪，让Burp了解模糊测试完成的时间
        self.max_payloads = 1000
        self.num_payloads = 0

        return

    # hasMorePayloads函数检查模糊测试时迭代的数量是否到达上限
    def hasMorePayloads(self):
        print("hasMorePayloads called.")
        if self.num_payloads == self.max_payloads:
            print("No more payloads.")
            return False
        else:
            print("More payloads. Continuing.")
            return True
    # getNextPayload函数负责接收原始的http载荷，这里是进行模糊测试的地方
    def getNextPayload(self, current_payload):

        # current_payload是数组格式，需要转换成字符串
        payload = "".join(chr(x) for x in current_payload)

        # 调用简单的变形器对POST请求进行模糊测试
        payload = self.mutate_payload(payload)

        # 增加fuzz的次数
        self.num_payloads += 1

        return payload

    def reset(self):

        self.num_payloads = 0

        return

    def mutate_payload(self,original_payload):

        # 仅生成随机数或者调用一个外部脚本
        picker = random.randint(1, 3)

        # 在载荷中选取一个随机的偏移量去变形
        offset = random.randint(0, len(original_payload) - 1)
        payload = original_payload[:offset]

        # 在随机偏移位置插入SQL注入尝试
        if picker == 1:
            payload += "'"

            # 插入跨站尝试
        if picker == 2:
            payload += "<script>alert('BHP!');</script>"

            # 随机重复原始载荷
        if picker == 3:

            chunk_length = random.randint(len(payload[offset:]), len(payload) - 1)
            repeater = random.randint(1, 10)

            for i in range(repeater):
                payload += original_payload[offset:offset + chunk_length]

        # 添加载荷中剩余的字节
        payload += original_payload[offset:]

        return payload
