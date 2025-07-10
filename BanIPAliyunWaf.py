import requests
import sys
import os
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def request_waf(ip_list, rule_name, domain):
    url = "https://yundun.console.aliyun.com:443/openapi/waf-openapi/2019-09-10/CreateProtectionModuleRule.json"
    cookies = {
    your_cookies
    }
    burp0_headers = {
    your_headers
    }
    ip_str = ",".join(ip_list)
    rule = {
        "action": "block",
        "name": rule_name,
        "scene": "custom_acl",
        "conditions": [{
            "opCode": 1,
            "key": "IP",
            "values": ip_str
        }]
    }
    data_dict = {
        "Region": "cn",
        "InstanceId": your_InstanceId,
        "Domain": domain,
        "Rule": rule,
        "DefenseType": "ac_custom"
    }
    burp0_data = {
        "regionId": your_regionId,
        "data": json.dumps(data_dict, ensure_ascii=False),
        "secToken": your_secToken,
        "token": your_token,
        "collina": "your_collina"
    }
    response = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=proxy, verify=False)
    print(f"Rule name: {rule_name}, Status: {response.status_code}, Response: {response.text}")
    return response.status_code

def main(txt_path, name_prefix, name_start):
    if not os.path.isfile(txt_path):
        print("文件不存在")
        return
    with open(txt_path, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    group_size = 50
    domains = [
        "your_domain1",
        "your_domain2",
    ]
    for domain in domains:
        for idx, i in enumerate(range(0, len(ips), group_size)):
            ip_group = ips[i:i+group_size]
            rule_name = f"{name_prefix}{name_start+idx}"
            request_waf(ip_group, rule_name, domain)


if __name__ == "__main__":

    txt_path = "your_ip_list_file_path"
    name_prefix = "your_rule_name_prefix"
    # int
    name_start = your_rule_name_prefix
    main(txt_path, name_prefix, name_start)

