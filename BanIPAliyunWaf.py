import requests
import os
import json
import urllib3

# 禁用SSL证书验证的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置字典，用于存储需要替换的信息
config = {
    "burp0_url": "https://yundun.console.aliyun.com:443/openapi/waf-openapi/2019-09-10/CreateProtectionModuleRule.json",
    
    # 替换为实际的cookies
    "burp0_cookies": {
    
    },
    
    # 替换为实际的burp0_data
    "burp0_data" : {
    
    },
    
    # 替换为实际的burp0_headers
    "burp0_headers" : {
    
    },
 
    "domains": [
        "your_domain1",  # 替换为实际的域名1
        "your_domain2"   # 替换为实际的域名2
    ],
    
    "ip_list_path": "ip_list.txt",  # IP列表文件路径
    
    "rule_name_prefix": "2025HW攻击ip情报_",  # 规则名称前缀
    "rule_name_start": 1  # 规则名称起始编号
}

def request_waf(ip_list, rule_name, domain, cookies, headers):
    """
    向阿里云WAF的API发送请求，创建自定义ACL规则。
    
    :param ip_list: IP地址列表
    :param rule_name: 规则名称
    :param domain: 域名
    :param cookies: 请求的cookies
    :param headers: 请求的headers
    :return: 响应的状态码
    """
    ip_str = ",".join(ip_list)
    rule = {
        "action": "block",
        "name": rule_name,
        "scene": "custom_acl",
        "conditions": [
            {
                "opCode": 1,
                "key": "IP",
                "values": ip_str
            }
        ]
    }
    data_tmp = json.loads(config["burp0_data"]["data"])
    
    data_dict = {
        "Region": "cn",
        "InstanceId": data_tmp["InstanceId"],
        "Domain": domain,
        "Rule": rule,
        "DefenseType": "ac_custom"
    }

    config["burp0_data"]["data"] = json.dumps(data_dict, ensure_ascii=False)
    
    response = requests.post(config["burp0_url"], headers=headers, cookies=cookies, data=config["burp0_data"], verify=False)
    print(f"Rule name: {rule_name}, Status: {response.status_code}, Response: {response.text}")
    return response.status_code

def main():
    if not os.path.isfile(config["ip_list_path"]):
        print("文件不存在")
        return
    
    with open(config["ip_list_path"], "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    group_size = 50  # 每组IP的数量，最多50
    name_start = int(config["rule_name_start"])  # 确保起始编号为整数
    cookies = config["burp0_cookies"]
    headers = config["burp0_headers"]
    
    for domain in config["domains"]:
        for idx, i in enumerate(range(0, len(ips), group_size)):
            ip_group = ips[i:i + group_size]
            rule_name = f"{config['rule_name_prefix']}{name_start + idx}"
            request_waf(ip_group, rule_name, domain, cookies, headers)

if __name__ == "__main__":
    main()
