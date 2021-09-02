# -*- coding: UTF-8 -*-

import os
import re
import time

import suffixTree
from postProcess import commonPostProcess

import sys
import threading
# 增加递归深度和线程堆栈大小，suffixTree.recursive(branches_list)有使用到递归
sys.setrecursionlimit(10**7) # max depth of recursion
threading.stack_size(2**27)  # new thread will get stack of such size

os_sep = os.path.sep # Get the path separator for the current system


# source_PCAP_folder = 'subSET' + os_sep + '6-2-1'
# result_rules_file_path = 'subSET' + os_sep + time.strftime('%Y-%m-%d__%H:%M:%S', time.localtime(time.time())) + '.rules'
source_PCAP_folder = 'PCAPsample' + os_sep + '(9)'
result_rules_file_path = 'PCAPsample' + os_sep + '(9)' + '__' + time.strftime('%Y-%m-%d__%H-%M', time.localtime(time.time())) + '.rules'



sub_folder = 'HexRaw'

is_current_sample_has_feature = False # 当前样本是否能找到特征值

allow_txt_sample_count = 2  # 允许使用的txt样本个数（算法性能问题导致的，有待优化）
file_size_limit = 3000 # 允许读取的样本文件大小的限制（算法性能问题导致的，有待优化）

# ========= 分页 ==============
rule_result_file_count = 1 # 当前有多少个rules文件
current_rule_count = 0 # 现在是第几条rule
one_file_rule_count_limit = 100 # 最终生成的rules文件一个文件内限制放多少条rule，因为一次放7000条文件会超级大

current_rule_content = '' # 构造生成的rules的content字段
current_rule = '' # 当前读取到的rules文件内容
rule_result = '' # 最终生成的rules内容


# 将 474554202f696e6465782e6a 变成 47 45 54 20 2f 69 6e 64 65 78 2e 6a
def insert_space(str_origin):
    str_list = list(str_origin.strip())    # 字符串string转list
    for n in range(len(str_list)):
        str_list.insert(2 * n + n, " ")
    str_out = ''.join(str_list).strip() + '\n' # 将list转换为string
    return str_out


# 对单个txt文件进行处理（读取指定行数，并且给每两个字符中间加空格）
def read_txt_file(path):
    sample = ''
    lines_num = sum(1 for line in open(path))
    with open(path) as txt:
        for line in txt.readlines()[6:lines_num - 1]:
            sample = sample + insert_space(line)
        return sample


# 遍历8000个攻击文件夹
def recursive_all_strike_folder():
    global source_PCAP_folder
    global current_rule_content
    global rule_result
    global current_rule
    for root, ds, fs in os.walk(source_PCAP_folder):
        # ==============遍历HexRaw文件夹内的txt文件 开始 ===================
        for d in ds:
            path = os.path.join(root, d)
            branches_list = [] # 用于接收多个txt样本拼接出来的 suffixTree算法的 输入
            if not path.find(os_sep + sub_folder) == -1:
                if len(os.listdir(path)) > 1: #HexRaw里面要有至少两个txt才允许遍历
                    for sub_root, sub_ds, sub_fs in os.walk(path):
                        txt_count = 0
                        for sub_f in sub_fs:
                            sub_path = os.path.join(sub_root, sub_f)
                            global file_size_limit
                            if os.path.getsize(sub_path) < file_size_limit and txt_count < allow_txt_sample_count:
                                txt_count += 1
                                print('【txt文件】：', sub_path)
                                sample_str = read_txt_file(sub_path)
                                branches_list.append(sample_str)
                            else:
                                continue
                    print('suffixTree的输入（多txt的预处理输出）：', branches_list)
                    # ======== 调用 suffixTree核心算法构造 current_rules_content 开始 =========
                    if len(branches_list) > 2:
                        suffix_set = suffixTree.recursive(branches_list)
                        print('suffixTree的输出（后期处理的输入）：', suffix_set)
                        if len(suffix_set) > 1:
                            global is_current_sample_has_feature
                            is_current_sample_has_feature = True
                            rules_content_set = commonPostProcess.line_break_cut(suffix_set) # \n 分割
                            # print('最终输出（rules的content字段值）：', rules_content_set)
                            rules_content_set = commonPostProcess.find_mini(rules_content_set) # 只要长度小于10的
                            current_rule_content = commonPostProcess.join_content(rules_content_set)
                            print('最终拼接的字符串：', current_rule_content)
                    else:
                        print('************************** 生成rules失败 ', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), ' ****************************\n')
                else:
                    continue
            else:
                print('\n')  # 这个路径不包括HexRaw，没必要继续遍历
                continue
        # ==============遍历HexRaw文件夹内的txt文件 结束 ===================
        # ==============遍历每个攻击文件夹下的rules文件 开始 ===================
        if is_current_sample_has_feature:
            for f in fs:
                path = os.path.join(root, f)
                if not path.find('.rules') == -1:
                    print('【rules文件】：', path)
                    with open(path) as f:
                        current_rule = f.readlines()[0]
                    # ============ 将单个strike文件夹生成的 current_rules_content 和 current_rules 拼接在一起写入指定路径 开始 ========
                    rule_result = current_rule.replace('content:"";', current_rule_content) + '\n'

                    def auto_write_file():
                        global one_file_rule_count_limit
                        global result_rules_file_path
                        global rule_result_file_count
                        global current_rule_count
                        filepath = result_rules_file_path[0:result_rules_file_path.rfind('.')] + '_' + str(rule_result_file_count) + '.rules'
                        with open(filepath, 'a') as new_rule:
                            if current_rule_count < one_file_rule_count_limit:
                                new_rule.write(f'{rule_result}')
                                current_rule_count += 1
                            else:
                                rule_result_file_count += 1
                                current_rule_count = 0
                                auto_write_file()

                    auto_write_file()
                    print('************************** 生成rules结束 ', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), ' ****************************\n')
                    # ============ 将单个strike文件夹生成的 current_rules_content 和 current_rules 拼接在一起写入指定路径 结束 ========
                else:
                    continue
        # ==============遍历每个攻击文件夹下的rules文件 结束 ===================


if __name__ == '__main__':
    recursive_all_strike_folder()