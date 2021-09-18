# -*- coding: utf-8 -*-
import base64
import requests
import sys
import json
import os


class ParseException(Exception):
    """
    解析错误异常
    """

    def __init__(self):
        pass

    def __str__(self):
        return "只能解析ssr"


class ParseSSR(object):
    """
    解析ssr
    """

    def __init__(self, ssr_str):
        self.ssr_str = ssr_str
        self.result_dict = {}

    def run(self):
        try:
            if self.ssr_str.startswith('ssr://'):
                base64_encode_str = self.ssr_str[6:]
                self.parse_ssr(base64_encode_str)
                return self.result_dict
            else:
                raise ParseException
        except Exception as e:
            print("解析失败:%s" % e)
            return None

    @staticmethod
    def fill_padding(base64_encode_str):
        need_padding = len(base64_encode_str) % 4 != 0

        if need_padding:
            missing_padding = 4 - need_padding
            base64_encode_str += '=' * missing_padding
        return base64_encode_str

    def base64_decode(self, base64_encode_str):
        base64_encode_str = self.fill_padding(base64_encode_str)
        return base64.urlsafe_b64decode(base64_encode_str).decode('utf-8')

    def parse_ssr(self, base64_encode_str):
        decode_str = self.base64_decode(base64_encode_str)

        parts = decode_str.split(':')
        if len(parts) != 6:
            return '不能解析SSR链接: %s' % base64_encode_str

        server = parts[0]
        port = parts[1]
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_and_params = parts[5]

        obfs_param = ""
        protocol_param = ""
        group = ""

        if "/?" in password_and_params:
            password_and_params = password_and_params.split("/?")

            password_encode_str = password_and_params[0]
            encrypt_param = password_and_params[1]
            encrypt_param_list = encrypt_param.split("&")

            for i in encrypt_param_list:
                if "obfs_param" in i:
                    obfs_param = i.split("=")[1]
                elif "protocol_param" in i:
                    protocol_param = i.split("=")[1]
                elif "group" in i:
                    group = self.base64_decode(i.split("=")[1])
        else:
            password_encode_str = password_and_params

        password = self.base64_decode(password_encode_str)
        self.result_dict = {
            "server": server,
            "port": port,
            "password": password,
            "method": method,
            "protocol": protocol,
            "obfs": obfs,
            "password_and_params": password_and_params,
            "obfs_param": obfs_param,
            "protocol_param": protocol_param,
            "group": group
        }


class ParseLocation(object):
    """
    解析ip位置
    """
    def __init__(self, ip_add_str):
        self.ip_add = ip_add_str

    def run(self):
        try:
            if self.ip_add is None:
                return "地址不正确"
            url = "http://www.cip.cc/{}".format(self.ip_add)
            headers = {
                'User-Agent': 'curl/7.68.0'
            }
            response = requests.get(url, headers=headers).content.decode()
            print(response)
        except Exception as e:
            print("定位IP失败:%s" % e)


class Connection(object):
    """
    连接ssr
    """
    def __init__(self, para, model):
        self.para = para
        self.model = model
        self.content = {}
        self.path = ""

    def package(self):
        self.content = {
            "password": self.para["password"],
            "method": self.para["method"],
            "protocol": self.para["protocol"],
            "protocol_param": self.para.get("protocol_param"),
            "obfs": self.para["obfs"],
            "obfs_param": self.para.get("obfs_param"),

            "udp": True,
            "idle_timeout": 300,
            "connect_timeout": 6,
            "udp_timeout": 6,

            "server_settings": {
                "listen_address": "0.0.0.0",
                "listen_port": 15678
            },

            "client_settings": {
                "server": self.para.get("server"),
                "server_port": int(self.para.get("port")),
                "listen_address": "0.0.0.0",
                "listen_port": 1080
            },

            "over_tls_settings": {
                "enable": False,
                "server_domain": "goodsitesample.com",
                "path": "/udg151df/",
                "root_cert_file": ""
            }
        }

    def write_conf(self, config_name):
        content = json.dumps(self.content)
        self.path = "/home/deep/cache/ssr_config/%s.json" % config_name
        with open(self.path, "w") as f:
            f.write(content)

    def con(self):
        if self.model is None:
            os.system("ssr-client -c %s" % self.path)
        else:
            os.system("ssr-client -d -c %s &" % self.path)

    def run(self):
        # 1打包参数
        self.package()
        # 2写配置文件
        cn = self.para.get("group") if self.para.get("group") == "" else "config"
        if self.model == "-gen":
            self.write_conf(config_name=cn)
        else:
            self.write_conf(config_name=cn)
            # 3运行文件
            self.con()


class MainT(object):
    """
    主流程
    """
    def __init__(self):
        pass

    @staticmethod
    def run(ssr_str, model=None):
        # 1解析ssr
        result_dict = ParseSSR(ssr_str).run()
        print(result_dict)

        # 2解析ip
        ip = result_dict.get("server")
        if ip is None or "":
            pass
        else:
            ParseLocation(ip_add_str=ip).run()

        if model == "-che":
            pass
        else:
            # 3进行连接
            Connection(result_dict, model).run()


if __name__ == '__main__':
    sample = """
    请按照正确的格式输入 --> python3 ssr_client.py -d 'ssr://123' 
    -d 后台运行ssr
    -gen 生成相应的config json文件
    -che 获取当前ssr地址
    """
    param_list = sys.argv
    if len(param_list) == 1:
        print(sample)
    elif len(param_list) == 2:
        ssr = param_list[-1]
        MainT.run(ssr)
    elif len(param_list) == 3:
        model_str = param_list[1]
        if model_str in ["-d", "-gen", "-che"]:
            ssr = param_list[-1]
            MainT.run(ssr, model=model_str)
        else:
            print(sample)
    else:
        print(sample)

