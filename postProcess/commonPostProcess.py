# -*- coding: UTF-8 -*-



# 用了suffixTree之后取出来的重复子串里面会包含这种含有\n的子串，要再进一步用\n作为分隔符，对子串进行切割
# {'45 54', '47 45 54 20\n 2f 7e 6a'}
delimiter = '\n'
def line_break_cut(suffix_set):
    result = set()
    child_set = set()
    global delimiter
    for item in suffix_set:
        if item.find(delimiter):
            newlist = item.split(delimiter)
            child_set.update(newlist)
        else:
            result.add(item)
    result.update(child_set)
    return result


def find_mini(suffix_set):
    result = set()
    for item in suffix_set:
        if len(item) > 5:
            result.add(item)
    # result = set()
    # result.add(max(list(suffix_set)))
    return result


# 将最终生成的content字段的set拼接成rules要用的字符串
def join_content(content_set):
    result = ''
    if len(content_set) > 0:
        for item in content_set:
            if len(item) > 2:
                result = result + 'content:"|' + item + '|"; '
    else:
        result = 'content:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; '
    return result