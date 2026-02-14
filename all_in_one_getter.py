#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
美的云设备一体化获取工具
同时获取Lua文件和生成Status属性文件
"""

import requests
import json
import hashlib
import hmac
import time
from secrets import token_hex
import datetime
import os
import sys
from pathlib import Path

def get_password_with_asterisk(prompt="请输入密码: "):
    """带*号显示的密码输入（Windows）"""
    import msvcrt
    password = []
    print(prompt, end='', flush=True)
    while True:
        ch = msvcrt.getch()
        if ch == b'\r':  # Enter
            print()
            break
        elif ch == b'\x08':  # Backspace
            if password:
                password.pop()
                print('\b \b', end='', flush=True)
        else:
            password.append(ch.decode('utf-8'))
            print('*', end='', flush=True)
    return ''.join(password)

def get_account_password():
    """获取账号密码 - 支持命令行参数或人工输入"""
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]
    else:
        account = input("请输入美的美居账号: ").strip()
        password = get_password_with_asterisk("请输入密码: ")
        if not account or not password:
            print("账号和密码不能为空")
            sys.exit(1)
        return account, password

class MideaAllInOneGetter:
    """美的云一体化获取器"""
    
    def __init__(self):
        # 获取账号密码
        self.account, self.password = get_account_password()
        
        self.access_token = None
        self.session = requests.Session()
        
        # AES会话密钥
        self._aes_key = None
        self._aes_iv = None
        
        # API配置
        self.api_base = "https://mp-prod.smartmidea.net/mas/v5/app/proxy"
        self.app_key = "46579c15"
        self.login_key = "ad0ee21d48a64bf49f4fb583ab76e799"
        self.iot_key = bytes.fromhex(format(9795516279659324117647275084689641883661667, 'x')).decode()
        self.hmac_key = bytes.fromhex(format(117390035944627627450677220413733956185864939010425, 'x')).decode()
        
        # 输出目录 - 以账号命名
        self.output_dir = Path(f"results_{self.account}")
        self.output_dir.mkdir(exist_ok=True)
        
        # 清理根目录旧的Lua文件
        self._clean_root_lua_files()
    
    def _clean_root_lua_files(self):
        """清理根目录旧的Lua文件"""
        for item in self.output_dir.iterdir():
            if item.is_file() and item.suffix == ".lua":
                item.unlink()
                print(f"      已清理旧文件: {item.name}")
    
    def _generate_device_id(self, username):
        return hashlib.md5(f"Hello, {username}!".encode("ascii")).digest().hex()[:16]
    
    def _sign_request(self, data, random):
        msg = self.iot_key + data + random
        return hmac.new(self.hmac_key.encode("ascii"), msg.encode("ascii"), hashlib.sha256).hexdigest()
    
    def _encrypt_password(self, login_id, pwd):
        m = hashlib.sha256()
        m.update(pwd.encode("ascii"))
        login_hash = login_id + m.hexdigest() + self.login_key
        m = hashlib.sha256()
        m.update(login_hash.encode("ascii"))
        return m.hexdigest()
    
    def _encrypt_iam_password(self, pwd):
        md = hashlib.md5()
        md.update(pwd.encode("ascii"))
        md_second = hashlib.md5()
        md_second.update(md.hexdigest().encode("ascii"))
        return md_second.hexdigest()
    
    def login(self):
        """登录认证"""
        print("🔐 正在登录美的云服务...")
        
        login_data = {
            "loginAccount": self.account,
            "type": "1",
            "reqId": token_hex(16),
            "stamp": datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        }
        
        data = json.dumps(login_data, separators=(',', ':'))
        random = str(int(time.time()))
        signature = self._sign_request(data, random)
        
        headers = {
            "content-type": "application/json; charset=utf-8",
            "secretVersion": "1",
            "sign": signature,
            "random": random,
        }
        
        response = self.session.post(
            f"{self.api_base}?alias=/v1/user/login/id/get",
            headers=headers,
            data=data,
            timeout=30
        )
        
        result = response.json()
        if result.get("code") != 0:
            print(f"❌ 获取登录ID失败: {result}")
            return False
        
        login_id = result["data"]["loginId"]
        
        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        encrypted_pwd = self._encrypt_password(login_id, self.password)
        encrypted_iam = self._encrypt_iam_password(self.password)
        
        auth_data = {
            "iotData": {
                "clientType": 1,
                "deviceId": self._generate_device_id(self.account),
                "iampwd": encrypted_iam,
                "iotAppId": "900",
                "loginAccount": self.account,
                "password": encrypted_pwd,
                "reqId": token_hex(16),
                "stamp": stamp
            },
            "data": {
                "appKey": self.app_key,
                "deviceId": self._generate_device_id(self.account),
                "platform": 2
            },
            "timestamp": stamp,
            "stamp": stamp,
            "reqId": token_hex(16)
        }
        
        data = json.dumps(auth_data, separators=(',', ':'))
        random = str(int(time.time()))
        signature = self._sign_request(data, random)
        
        headers = {
            "content-type": "application/json; charset=utf-8",
            "secretVersion": "1",
            "sign": signature,
            "random": random,
        }
        
        response = self.session.post(
            f"{self.api_base}?alias=/mj/user/login",
            headers=headers,
            data=data,
            timeout=30
        )
        
        result = response.json()
        if result.get("code") != 0:
            print(f"❌ 登录失败: {result}")
            return False
        
        self.access_token = result["data"]["mdata"]["accessToken"]
        
        # 设置AES会话密钥
        encrypted_key = result["data"]["key"]
        self._set_aes_keys(encrypted_key)
        
        print("✅ 登录成功!")
        return True
    
    def _set_aes_keys(self, encrypted_key):
        """根据登录响应中的key设置AES会话密钥"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            # 固定key: 10864842703515613082 -> 转换为ascii bytes
            fixed_key = format(10864842703515613082, 'x').encode("ascii")
            
            # 解密key
            encrypted_bytes = bytes.fromhex(encrypted_key)
            cipher = AES.new(fixed_key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), len(fixed_key))
            self._aes_key = decrypted
            self._aes_iv = None
            print(f"      AES会话密钥已设置")
        except Exception as e:
            print(f"      设置AES密钥失败: {e}")
            self._aes_key = None
    
    def _decrypt_sn(self, encrypted_sn):
        """解密设备SN"""
        if not self._aes_key:
            return encrypted_sn  # 返回原始加密SN
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            encrypted_bytes = bytes.fromhex(encrypted_sn)
            cipher = AES.new(self._aes_key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), len(self._aes_key))
            return decrypted.decode("ascii")
        except:
            return encrypted_sn  # 解密失败返回原始值
    
    def process_all_devices(self):
        """处理所有设备 - 一体化获取"""
        print("\n🔄 开始获取设备列表...")
        
        # 动态获取设备列表
        devices = self._get_device_list()
        if not devices:
            print("❌ 无法获取设备列表")
            return False
        
        print(f"✅ 发现 {len(devices)} 台设备")
        
        headers = {
            "content-type": "application/json; charset=utf-8",
            "secretVersion": "1",
            "accesstoken": self.access_token,
        }
        
        results = []
        
        for i, device in enumerate(devices, 1):
            print(f"\n[{i}/{len(devices)}] 处理设备: {device['name']} ({device['type']})")
            
            # 一体化处理：同时获取Lua文件和Status属性
            device_result = self.get_device_lua_and_status(device, headers)
            if device_result:
                results.append(device_result)
                print(f"  ✅ 处理完成")
            else:
                print(f"  🔴 处理失败")
        
        # 生成总报告
        self.generate_summary_report(results)
        
        return len(results) > 0
    
    def _get_device_list(self):
        """从API获取设备列表"""
        headers = {
            "content-type": "application/json; charset=utf-8",
            "secretVersion": "1",
            "accesstoken": self.access_token,
        }
        
        data = {
            "reqId": token_hex(16),
            "stamp": datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        }
        json_data = json.dumps(data, separators=(',', ':'))
        random = str(int(time.time()))
        signature = self._sign_request(json_data, random)
        
        headers_copy = headers.copy()
        headers_copy["random"] = random
        headers_copy["sign"] = signature
        
        try:
            response = self.session.post(
                f"{self.api_base}?alias=/v1/appliance/home/list/get",
                headers=headers_copy,
                data=json_data,
                timeout=15
            )
            result = response.json()
            
            if result.get("code") != 0:
                print(f"❌ 获取设备列表失败: {result}")
                return []
            
            devices = []
            home_list = result.get("data", {}).get("homeList", [])
            for home in home_list:
                for room in home.get("roomList", []):
                    for appliance in room.get("applianceList", []):
                        # 解密SN
                        encrypted_sn = appliance.get("sn", "")
                        decrypted_sn = self._decrypt_sn(encrypted_sn) if encrypted_sn else ""
                        
                        device = {
                            "name": appliance.get("name", ""),
                            "type": appliance.get("type", "0x00"),
                            "applianceCode": appliance.get("applianceCode", ""),
                            "sn": decrypted_sn if decrypted_sn else encrypted_sn,
                            "sn8": appliance.get("sn8", ""),
                            "modelNumber": appliance.get("modelNumber", "0"),
                            "productModel": appliance.get("productModel", ""),
                            "enterpriseCode": appliance.get("enterpriseCode", "0000"),
                            "online": appliance.get("onlineStatus") == "1",
                        }
                        devices.append(device)
            
            return devices
            
        except Exception as e:
            print(f"❌ 获取设备列表异常: {e}")
            return []
    
    def get_device_lua_and_status(self, device, headers):
        """一体化获取设备的Lua文件和Status属性"""
        print(f"  📥 下载Lua文件...")
        lua_file_name = self.download_device_lua(device, headers)
        
        print(f"  📊 获取Status属性...")
        status_data = self.get_device_status(device, headers)
        
        if lua_file_name and status_data:
            return {
                "device": device,
                "lua_file": lua_file_name,
                "status_attributes": len(status_data),
                "success": True
            }
        elif status_data:  # 至少Status获取成功
            return {
                "device": device,
                "lua_file": "下载失败",
                "status_attributes": len(status_data),
                "success": True
            }
        elif lua_file_name:  # 至少Lua获取成功
            return {
                "device": device,
                "lua_file": lua_file_name,
                "status_attributes": 0,
                "success": True
            }
        else:
            return None
    
    def format_lua_code(self, lua_code):
        """解密Lua代码"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            # 先尝试AES解密（使用fixed_key）
            fixed_key = format(10864842703515613082, 'x').encode("ascii")
            encrypted_bytes = bytes.fromhex(lua_code.strip())
            cipher = AES.new(fixed_key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), len(fixed_key))
            return decrypted.decode("utf-8", errors="ignore")
        except Exception:
            return lua_code  # 如果解密失败，返回原始内容
    
    def download_device_lua(self, device, headers):
        """下载设备Lua文件"""
        # 使用解密的SN
        encrypted_sn = device["sn"]
        decrypted_sn = self._decrypt_sn(encrypted_sn)
        
        lua_data = {
            "applianceSn": decrypted_sn if decrypted_sn else encrypted_sn,
            "applianceType": device["type"],
            "applianceMFCode": device["enterpriseCode"],
            "version": "0",
            "iotAppId": "900",  # 使用美的美居
            "modelNumber": device["modelNumber"],
            # 添加reqId和stamp（在签名之前）
            "reqId": token_hex(16),
            "stamp": datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        }
        
        json_data = json.dumps(lua_data, separators=(',', ':'))
        random = str(int(time.time()))
        signature = self._sign_request(json_data, random)
        
        headers_copy = headers.copy()
        headers_copy["random"] = random
        headers_copy["sign"] = signature
        
        try:
            response = self.session.post(
                f"{self.api_base}?alias=/v1/appliance/protocol/lua/luaGet",
                headers=headers_copy,
                data=json_data,
                timeout=15
            )
            
            result = response.json()
            if str(result.get("code")) == "0" and "data" in result:
                data_section = result["data"]
                if "url" in data_section and "fileName" in data_section:
                    lua_url = data_section["url"]
                    file_name = data_section["fileName"]
                    
                    # 下载Lua文件内容
                    lua_response = self.session.get(lua_url, timeout=15)
                    if lua_response.status_code == 200:
                        lua_content = lua_response.text
                        
                        # 创建设备文件夹（与Status一致）
                        sn8 = device.get("sn8", "") or device.get("modelNumber", "")
                        product_model = device.get("productModel", "") or device.get("modelNumber", "")
                        # 替换不能作为文件夹名的字符
                        product_model = product_model.replace("/", "_").replace("\\", "_").replace(":", "_").replace("*", "_").replace("?", "_").replace("\"", "_").replace("<", "_").replace(">", "_").replace("|", "_")
                        device_folder_name = f"T{device['type']}_{sn8}_{product_model}_{device['name'].replace(' ', '_')}"
                        lua_folder = self.output_dir / device_folder_name
                        
                        # 清理旧文件
                        if lua_folder.exists():
                            for f in lua_folder.iterdir():
                                if f.is_file():
                                    f.unlink()
                        else:
                            lua_folder.mkdir(parents=True)
                        
                        # 保存Lua文件到设备文件夹（格式化后）
                        formatted_lua = self.format_lua_code(lua_content)
                        lua_file_path = lua_folder / file_name
                        with open(lua_file_path, 'w', encoding='utf-8') as f:
                            f.write(formatted_lua)
                        
                        print(f"    ✅ Lua文件保存: {file_name}")
                        return file_name  # 返回文件名
            
            print(f"    🔴 下载失败")
            return False
            
        except Exception as e:
            print(f"    💥 下载异常: {e}")
            return False
    
    def get_device_status(self, device, headers):
        """获取设备Status属性"""
        lua_data = {
            "clientType": "1",
            "appId": "1010",
            "format": "2",
            "deviceId": self._generate_device_id(self.account),
            "iotAppId": "900",
            "applianceMFCode": device["enterpriseCode"],
            "applianceType": device["type"],
            "modelNumber": device["modelNumber"],
            "applianceSn": device["sn"].encode("ascii").hex(),
            "version": "0",
            "encryptedType ": "2",
            "applianceCode": device["applianceCode"],
            "command": {
                "query": {}
            }
        }
        
        json_data = json.dumps(lua_data, separators=(',', ':'))
        random = str(int(time.time()))
        signature = self._sign_request(json_data, random)
        
        headers_copy = headers.copy()
        headers_copy["random"] = random
        headers_copy["sign"] = signature
        
        try:
            response = self.session.post(
                f"{self.api_base}?alias=/mjl/v1/device/status/lua/get",
                headers=headers_copy,
                data=json_data,
                timeout=15
            )
            
            result = response.json()
            if str(result.get("code")) == "0" and "data" in result:
                attributes = result["data"]
                
                # 创建设备专属文件夹
                sn8 = device.get("sn8", "") or device.get("modelNumber", "")
                product_model = device.get("productModel", "") or device.get("modelNumber", "")
                # 替换不能作为文件夹名的字符
                product_model = product_model.replace("/", "_").replace("\\", "_").replace(":", "_").replace("*", "_").replace("?", "_").replace("\"", "_").replace("<", "_").replace(">", "_").replace("|", "_")
                device_folder_name = f"T{device['type']}_{sn8}_{product_model}_{device['name'].replace(' ', '_')}"
                device_folder = self.output_dir / device_folder_name
                device_folder.mkdir(exist_ok=True)
                
                # 保存JSON格式的Status属性（按键名字母排序）
                status_data = {
                    "device_info": {
                        "name": device["name"],
                        "type": device["type"],
                        "appliance_code": device["applianceCode"],
                        "serial_number": device["sn"],
                        "sn8": device["sn8"],
                        "model": device["modelNumber"],
                        "enterprise_code": device["enterpriseCode"]
                    },
                    "attributes": dict(sorted(attributes.items())),  # 按字母排序
                    "total_attributes": len(attributes),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "data_source": "real_time_from_cloud"
                }
                
                json_file = device_folder / "status_attributes.json"
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(status_data, f, ensure_ascii=False, indent=2)
                
                # 创建易读的文本文件
                self.create_readable_status_file(status_data, device_folder)
                
                print(f"    ✅ Status属性保存 ({len(attributes)}个属性)")
                return attributes
            else:
                print(f"    🔴 获取失败: {result.get('msg', '未知错误')}")
                return None
                
        except Exception as e:
            print(f"    💥 获取异常: {e}")
            return None
    
    def create_readable_status_file(self, status_data, device_folder):
        """创建易读的Status属性文件"""
        content = f"""设备Status属性清单
================

设备信息:
  名称: {status_data['device_info']['name']}
  类型: {status_data['device_info']['type']}
  序列号: {status_data['device_info']['serial_number']}
  位置: 未知

连接状态: 🟢 在线

属性列表 ({status_data['total_attributes']}个，按键名字母排序):
"""
        
        for attr_name, attr_value in status_data['attributes'].items():
            content += f"  {attr_name}: {attr_value}\n"
        
        txt_file = device_folder / "status_attributes.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def generate_summary_report(self, results):
        """生成总览报告"""
        print("\n📋 生成一体化处理报告...")
        
        report_data = {
            "process_time": datetime.datetime.now().isoformat(),
            "account": self.account,
            "total_devices": len(results),
            "successful_devices": len([r for r in results if r["success"]]),
            "results": [
                {
                    "device_name": result["device"]["name"],
                    "device_type": result["device"]["type"],
                    "online": result["device"].get("online", False),
                    "lua_file": result["lua_file"],
                    "status_attributes": result["status_attributes"],
                    "folder": f"{result['device']['type']}_{result['device']['name'].replace(' ', '_')}"
                }
                for result in results
            ]
        }
        
        # 保存JSON报告
        report_file = self.output_dir / "all_in_one_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        # 生成易读报告
        self.generate_readable_report(report_data)
        
        print("✅ 一体化报告生成完成!")
    
    def generate_readable_report(self, report_data):
        """生成易读报告"""
        content = f"""美的云设备一体化获取报告
======================

处理时间: {report_data['process_time']}
账号: {report_data['account']}

📊 处理统计:
  总设备数: {report_data['total_devices']}
  成功设备: {report_data['successful_devices']}

📱 设备详情:
"""
        
        for result in report_data['results']:
            content += f"\n设备: {result['device_name']} ({result['device_type']})\n"
            content += f"  Lua文件: {result['lua_file']}\n"
            content += f"  Status属性: {result['status_attributes']}个\n"
            content += f"  数据文件夹: {result['folder']}\n"
        
        txt_file = self.output_dir / "all_in_one_report.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def run_all_in_one(self):
        """运行一体化获取流程"""
        print("="*60)
        print("美的云设备一体化获取工具")
        print("同时获取Lua文件和Status属性文件")
        print("="*60)
        
        # 1. 登录
        if not self.login():
            return False
        
        # 2. 一体化处理
        success = self.process_all_devices()
        
        # 3. 显示最终结果
        if success:
            print(f"\n{'='*60}")
            print("🏁 一体化获取完成!")
            print(f"{'='*60}")
            print(f"📁 输出目录: {self.output_dir.absolute()}")
            
            # 显示目录结构
            print(f"\n📂 生成的文件结构:")
            for item in self.output_dir.iterdir():
                if item.is_dir():
                    print(f"  📁 {item.name}/")
                    for sub_item in item.iterdir():
                        print(f"    📄 {sub_item.name}")
                else:
                    print(f"  📄 {item.name}")
            
            return True
        else:
            print("\n❌ 一体化获取失败!")
            return False

def main():
    getter = MideaAllInOneGetter()
    success = getter.run_all_in_one()
    
    if success:
        print("\n🎉 一体化获取完成!")
    else:
        print("\n❌ 获取过程失败!")

if __name__ == "__main__":
    main()