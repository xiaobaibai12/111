#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, json, sys, time, socket
from time import strftime, gmtime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
import os
import logging
import threading
import difflib
import subprocess
from typing import List
import shlex
import time

# Global variables
Token = ''
# Configuration
arl_url = ''
username = 'admin'
password = 'yang199912'
time_sleep = 1800
get_size = 100


# 设置日志级别为DEBUG，日志格式包括时间、日志级别和消息内容，并输出到控制台和文件中
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    handlers=[
                        logging.StreamHandler(sys.stdout),
                        logging.FileHandler('example.log')
                    ])

def login_arl(username, password):
    url = arl_url + 'api/user/login'
    data = {
        "username": username,
        "password": password
    }
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    session = requests.Session()

    try:
        response = session.post(url, data=json.dumps(data), headers=headers, verify=False, timeout=30)
        if response.status_code == 200:
            logging.debug("Response data from ARL: {}".format(response.content))
            json_data = response.json()
            token = json_data.get('data').get('token')
            return session, token
        else:
            return None, None
    except Exception as e:
        logging.exception(e)
        return None, None

def push_wechat_group(content):
    global wechat_key  # 添加此行以使用全局变量
    webhook_url = ""
    try:
        resp = requests.post(webhook_url,
                             json={"msgtype": "markdown",
                                   "markdown": {"content": content}})
        if 'invalid webhook url' in str(resp.text):
            logging.error('企业微信key 无效,无法正常推送')
            sys.exit()
        if resp.json()["errcode"] != 0:
            raise ValueError("push wechat group failed, %s" % resp.text)
    except Exception as e:
        logging.exception(e)

def nuclei(scan_list):
    logging.debug('Starting nuclei scan.')
    with open("newurls.txt", "w", encoding='utf-8') as f:
        for scan in scan_list:
            if scan != '':
                f.writelines(scan + "\n")
    output_file = f"res-all-vulnerability-results-{strftime('%F-%T', gmtime())}.txt"
    os.system(f"cat newurls.txt | /usr/local/bin/nuclei_2.9.1_linux_amd64/nuclei -rl 300 -bs 35 -c 30  -mhe 10 -ni -o {output_file} -stats -silent -severity critical,medium,high,low")

    with open(output_file, "r") as f:
        scan_result = f.read()

    if scan_result:
        push_content = f"**Nuclei 漏洞扫描结果：**\n\n{'<br>'.join(scan_result.splitlines())}"
    else:
        push_content = f"**Nuclei 漏洞扫描结果：**\n本次扫描没有发现漏洞。"
    push_wechat_group(push_content)

    os.system("rm -rf newurls.txt")
 
    os.system(f"rm -rf {output_file}")
#  AWVS登录的实现代码
def start_awvs_scan(base_url, token, scan_list):
    headers = {
        "Content-Type": "application/json",
        "X-Auth": token
    }

    target_api = base_url + "/api/v1/targets"

    scan_ids = []  # 存储所有扫描ID
    
    for url in scan_list:
        data = {
            "address": url,
            "description": "",
            "criticality": "10"
        }

        response = requests.post(target_api, json=data, headers=headers, verify=False)
        
        if response.status_code == 201:
            target_id = response.json()['target_id']

            scan_api = base_url + "/api/v1/scans"
            data = {
                "target_id": target_id,
                "profile_id": "11111111-1111-1111-1111-111111111111",  # Replace with a valid profile_id in UUID4 format
                "schedule": {"disable": False, "start_date": None, "time_sensitive": False}
            }
            
            scan_response = requests.post(scan_api, json=data, headers=headers, verify=False)

            if scan_response.status_code == 201:
                scan_id = json.loads(scan_response.text)['scan_id']
                print(f'Scan has been started with ID: {scan_id} for target: {url}')
                scan_ids.append(scan_id)  # 添加扫描ID到列表中
            else:
                print(f'Scan could not be started for target: {url}. Reason: {scan_response.text}')
        else:
            print(f'Target could not be created for {url}. Reason: {response.text}')

    return scan_ids
# 获取扫描详情
def get_scan_details(base_url, token, scan_id):
    endpoint = '/api/v1/scans/{}'.format(scan_id)
    headers = {'X-Auth': token}
    response = requests.get(base_url + endpoint, headers=headers)
    
    if response.status_code == 200:
        return json.loads(response.text)
    else:
        print('Could not get scan details. Reason:', response.text)
        return False

# 检查是否存在高危漏洞
def has_high_risk_vulnerabilities(scan_details):
    vulnerabilities = scan_details.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        if vuln['severity'] == '10.0':
            return True
    return False
# AWVS扫描和推送企业微信的主要功能
def awvs_scan_and_notify(base_url, api_key, target_urls):
    scan_ids = start_awvs_scan(base_url, api_key, target_urls)
    
    for scan_id in scan_ids:
        scan_details = None
        while not scan_details:
            scan_details = get_scan_details(base_url, api_key, scan_id)
        if has_high_risk_vulnerabilities(scan_details):
            notify_wework('High risk vulnerabilities found in scan of {}'.format(target_url))
# 修改main函数以包括awvs_scan_and_notify的调用
def main():
    # ARL部分保持不变
    target_urls = get_all_urls(arl_session, arl_token)

    # AWVS部分
    awvs_base_url = ""
    awvs_api_key = "1986ad8c0a5b3df4d7028d5f3c06e936c12f6ee42367544859c857e146cd90094"

    awvs_scan_and_notify(awvs_base_url, awvs_api_key, target_urls)
def get_urls_from_arl(session, token, page=1, size=100):
    url = arl_url + f'api/domain/export/?page={page}&size={size}&tabIndex=1'
    headers = {
        'Accept': 'application/json',
        'Token': token  # 使用Token字段及其值
    }

    try:
        response = session.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            logging.debug("Response content from ARL when fetching URLs: {}".format(content))
            if not content.strip():
                logging.error("Empty response content from ARL when fetching URLs.")
                return []

            urls = [url.strip() for url in content.split('\n')]
            return urls
        else:
            logging.error("Failed to get URLs from ARL: {}".format(response.content))
            return []
    except Exception as e:
        logging.exception(e)
        return []
def get_all_urls(session, token, current_page=1, size=100, urls=None):
    if urls is None:
        urls = []

    fetched_urls = get_urls_from_arl(session, token, current_page, size)
    
    if not fetched_urls:  # 当返回空列表时，表示没有更多数据
        return urls  # 如果响应内容为空，直接返回已获取的URL列表
    
    urls.extend(fetched_urls)
    return get_all_urls(session, token, current_page + 1, size, urls)
def get_new_assets(old_assets, new_assets):
    differ = difflib.Differ()
    diff_result = list(differ.compare(old_assets, new_assets))
    added_assets = [line[2:].strip() for line in diff_result if line.startswith('+ ')]
    return added_assets
def execute_httpx_command(output_file: str):
    httpx_command = f'httpx -l quanbuURL.txt -threads 50 -silent -no-color | tee {output_file}'
    exit_code = subprocess.run(httpx_command, shell=True)  
    if exit_code.returncode != 0:
        logging.error("HTTPX execution failed.")
# 添加一个新的函数从文件中读取URL，并将列表返回
def read_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]
def main():
    check_and_initialize_quanbu_url_txt()

    arl_session, arl_token = login_arl(username, password)
    all_urls = get_all_urls(arl_session, arl_token)

    quanbu_url_txt = read_file('quanbuURL.txt')
    added_assets = get_new_assets(quanbu_url_txt, all_urls)

    execute_httpx_command("URL.txt")  # 修改此处，将结果直接保存到 URL.txt

    url_txt = read_file('URL.txt')
    saomiao_txt = read_file('saomiao.txt')

    added_assets = get_new_assets(saomiao_txt, url_txt)

    if added_assets:
        nuclei_thread = threading.Thread(target=nuclei, args=(added_assets,))
        wechat_key = ""  # 将其替换为你的企业微信群组密钥
        awvs_base_url = ""  # 将其替换为你的AWVS服务器地址
        awvs_api_key = "1986ad8c0a5b3df4d7028d5f3c06e936c12f6ee42367544859c857e146cd90094"  # 将其替换为你的Acunetix API key
        awvs = threading.Thread(target=awvs_scan_and_notify, args=(awvs_base_url, awvs_api_key, added_assets))

        nuclei_thread.start()
        awvs.start()

        nuclei_thread.join()
        awvs.join()

        with open("saomiao.txt", "a") as file:
            for asset in added_assets:
                file.write(f"{asset}\n")

    time.sleep(21600)
    # 删除 "linshiquanbu.txt" 文件
    try:
        os.remove("linshiquanbu.txt")
    except FileNotFoundError:
        print("linshiquanbu.txt not found. Skipping deletion.")
def check_and_initialize_quanbu_url_txt():
    # 在 ARL 中登录并获取资产
    arl_session, arl_token = login_arl(username, password)
    all_urls = get_all_urls(arl_session, arl_token)

    # 将从ARL获取到的资产写入临时文件"linshiquanbu.txt"
    with open("linshiquanbu.txt", "w") as file:
        for url in all_urls:
            file.write(f"{url}\n")

    try:
        with open("quanbuURL.txt", "r") as file:
            content = file.read()
            if not content.strip():  # 如果文件为空
                print("quanbuURL.txt is empty. Initializing with current assets...")
                with open("linshiquanbu.txt", "r") as linshi_file:
                    initial_assets = linshi_file.read()
                with open("quanbuURL.txt", "w") as quanbu_file:
                    quanbu_file.write(initial_assets)
                print("Initialization complete.")
            else:
                # 比较两个文件并将新增的资产添加到 "quanbuURL.txt"
                linshi_assets = read_file("linshiquanbu.txt")
                quanbu_assets = read_file("quanbuURL.txt")
                new_assets = get_new_assets(quanbu_assets, linshi_assets)

                if new_assets:
                    print("Adding new assets to quanbuURL.txt...")
                    with open("quanbuURL.txt", "a") as quanbu_file:
                        for asset in new_assets:
                            quanbu_file.write(f"{asset}\n")
                    print("New assets added.")
    except FileNotFoundError:
        print("quanbuURL.txt not found. Please create the file and run the script again.")

if __name__ == "__main__":
    while True:
        main()