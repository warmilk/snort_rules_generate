
"""
 python version = 3.7
 author: warmilk
 github: https://github.com/warmilk
"""

import subprocess
from datetime import datetime
import os
import shutil
import traceback




# Get the path separator for the current system
os_sep = os.path.sep


source_PCAP_folder = 'PCAPsample'


def check_protocol(pcap_path, protocol, type):
    # 这个命令有东西返回
    # tshark -r "PCAPsample/(4-53-8)HPE_Network_Automation_PermissionFilter_Authentication_Bypass/CVE2017-5812(ip1-1-35-36).pcap" -Y ssl
    # 这个命令没东西返回
    # tshark -r "PCAPsample/(9)X97EmbedAn_Excel_Document_(http)/CVE2006-3059(ip1-1-72-88).pcap" -Y ssl

    # command = ''.join(['tshark -r "', pcap_path, '" -Y "', protocol, '"'])
    # print(datetime.now().strftime("%H:%M:%S"), '当前执行的命令是：', command)
    # subprocess.check_output(command)
    try:
        out_bytes = subprocess.check_output(['tshark', '-r', pcap_path, '-Y', protocol])
    except subprocess.CalledProcessError as e:
        out_bytes = e.output
    if len(out_bytes) > 0:
        parent = pcap_path[0:pcap_path.rfind(os_sep)] + os_sep + type
        if not os.path.exists(parent):
            os.makedirs(parent)
        else:
            output_path = parent + pcap_path[pcap_path.rfind(os_sep):pcap_path.rfind('.')] + '.txt'
            if not os.path.exists(output_path):
                command = 'tshark -r "' + pcap_path + '" -qz follow,' + protocol + ',' + type + ',0  > "' + output_path + '"'
                subprocess.call(command, shell=True)
                print('当前执行的命令是', command)
    else:
        print('不存在', protocol)


def recursive_all_pcap_file():
    global source_PCAP_folder
    for root, ds, fs in os.walk(source_PCAP_folder):
        file_count = 0
        for f in fs:
            file_count += 1
            path = os.path.join(root, f)
            # print(path)
            if path.find('.pcap') == -1:
                print('我不是pcap文件')
            else:
                check_protocol(path, 'udp', 'hex') # 左边hex右边ASCII
                check_protocol(path, 'tcp', 'hex')
                check_protocol(path, 'udp', 'raw') # 纯hex
                check_protocol(path, 'tcp', 'raw')


if __name__ == '__main__':
    recursive_all_pcap_file()