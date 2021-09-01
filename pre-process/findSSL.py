
"""
 python version = 3.7
 author: warmilk
 github: https://github.com/warmilk
"""

import os
import subprocess
from datetime import datetime
import os
import shutil
import traceback




# Get the path separator for the current system
os_sep = os.path.sep


source_PCAP_folder = 'PCAPsample'
ssl_PCAP_folder = 'SSL'

def check_protocol(pcap_path, protocol):
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
        global ssl_PCAP_folder
        global source_PCAP_folder
        dst_path = pcap_path.replace(source_PCAP_folder, ssl_PCAP_folder)
        dst_path_folder = dst_path[0:dst_path.rfind(os_sep)]
        if not os.path.exists(dst_path_folder):
            os.makedirs(dst_path_folder)
        shutil.move(pcap_path, dst_path)
        print('我加密了')
    else:
        print('没tls')




def recursive_all_pcap_file():
    global source_PCAP_folder
    for root, ds, fs in os.walk(source_PCAP_folder):
        for f in fs:
            path = os.path.join(root, f)
            # print(path)
            check_protocol(path, 'ssl')





if __name__ == '__main__':
    # check_protocol("PCAPsample/(4-53-8)HPE_Network_Automation_PermissionFilter_Authentication_Bypass/CVE2017-5812(ip1-1-35-36).pcap", 'ssl')
    # check_protocol("PCAPsample/(9)X97EmbedAn_Excel_Document_(http)/CVE2006-3059(ip1-1-72-88).pcap", 'ssl')
    recursive_all_pcap_file()