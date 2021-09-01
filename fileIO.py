# -*- coding: UTF-8 -*-

import os
import re



# Get the path separator for the current system
os_sep = os.path.sep


source_PCAP_folder = 'subSET' + os_sep + '6-2-1'
sub_folder = 'HexRaw'



# 将 474554202f696e6465782e6a 变成 47 45 54 20 2f 69 6e 64 65 78 2e 6a
def insert_space(str_origin):
    str_list = list(str_origin.strip())    # 字符串string转list
    for n in range(len(str_list)):
        str_list.insert(2 * n + n, " ")
    str_out = ''.join(str_list).strip() + '\n' # 将list转换为string
    print(str_out)
    return str_out


# 对单个txt文件进行处理（读取指定行数，并且给每两个字符中间加空格）
def read_txt_file(path):
    sample = ''
    lines_num = sum(1 for line in open(path))
    with open(path) as txt:
        for line in txt.readlines()[6:lines_num - 1]:
            sample = sample + insert_space(line)
        # print('单个txt最终生成的成品：', sample)
        s = re.sub(r'\\n*?\\t', '', sample)
        # print(s)
        return sample


def recursive_all_hex_file():
    global source_PCAP_folder
    for root, ds, fs in os.walk(source_PCAP_folder):
        for d in ds:
            path = os.path.join(root, d)
            if not path.find(os_sep + sub_folder) == -1:
                #遍历HexRaw文件夹内的txt文件
                for sub_root, sub_ds, sub_fs in os.walk(path):
                    branches_list = []
                    for sub_f in sub_fs:
                        sub_path = os.path.join(sub_root, sub_f)
                        print('txt为', sub_path)
                        sample_str = read_txt_file(sub_path)
                        branches_list.append(sample_str)
                    print(branches_list)
            else:
                print('这个路径不包括HexRaw，没必要继续遍历')


# 遍历rules
def recursive_all_rule_file():
    global source_PCAP_folder
    for root, ds, fs in os.walk(source_PCAP_folder):
        for f in fs:
            path = os.path.join(root, f)
            if not path.find('.rules') == -1:
                print('rules为', path)


if __name__ == '__main__':
    recursive_all_hex_file()
    # recursive_all_rule_file()
    # read_txt_file()