
"""
 python version = 3.7
 author: warmilk
 github: https://github.com/warmilk
"""

import subprocess
import os




# Get the path separator for the current system
os_sep = os.path.sep


source_PCAP_folder = 'PCAPsample'


def convert_pcap_to_json(pcap_path):
    # 这个命令将pcap转换为json
    # tshark -x -r 'Shellcode__Windows_x86_Bind_Stage_-_metasploit_(UDP)_Variant_1(ip1-1-113-19).pcap'  -T json > uuu.json
    try:
        parent = pcap_path[0:pcap_path.rfind(os_sep)] + os_sep + 'JSON'
        if not os.path.exists(parent):
            os.makedirs(parent)
        else:
            output_path = parent + pcap_path[pcap_path.rfind(os_sep):pcap_path.rfind('.')] + '.json'
            if not os.path.exists(output_path):
                command = 'tshark -x -r "' + pcap_path + '" -T json' + ' > "' + output_path + '"'
                subprocess.call(command, shell=True)
                print('当前执行的命令是', command)
            else:
                print('已经生成过啦', output_path)
    except subprocess.CalledProcessError as e:
        print('执行命令失败')


def recursive_all_pcap_file():
    global source_PCAP_folder
    for root, ds, fs in os.walk(source_PCAP_folder):
        file_count = 0
        for f in fs:
            file_count += 1
            path = os.path.join(root, f)
            # print(path)
            if not path.find('.pcap') == -1:
                convert_pcap_to_json(path)


if __name__ == '__main__':
    recursive_all_pcap_file()