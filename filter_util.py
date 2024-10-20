import re
from functools import reduce
# 求字典值
def query_dict(data, query):
    # 拆分路径
    keys = query.split(".")
    data = {key.lower(): value for key, value in data.items()}
    # 逐级查找
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]  # 进入下一层
        else:
            return None  # 路径不匹配
    
    return data  # 路径存在

# 解析形如a.b=的表达式
def parse_atomic(data:dict, query:str):
    # 使用正则表达式匹配 = 或 ==
    parts = re.split(r'(==|=|!=)', query)
    
    
    # 获取键值对的路径和最终的值
    path = parts[0].strip()
    oracle = query_dict(data, path)
    if len(parts)==1:
        return oracle is not None
    if len(parts)!=3:
        return False
    condation = parts[1].strip()
    value = parts[2].strip()
    if condation=="!=":        
        return oracle!=value
    if condation=="=" or condation=="==":
        return oracle==value or str(oracle)==value
    return False


# 解析or
def parse_or(data:dict, query:str):
    logic_or = lambda x,y:x or y
    query = query.strip().lower()
    # 使用正则表达式匹配 && 或 &
    parts = re.split(r'(?:\|\||\|)', query)
    return reduce(logic_or, 
           [parse_atomic(data, sub_query) for sub_query in parts]
           )

# 解析and
def parse_and(data:dict, query:str):
    logic_and = lambda x,y:x and y
    query = query.strip().lower()
    # 使用正则表达式匹配 && 或 &
    parts = re.split(r'(?:&&|&)', query)
    
    return reduce(logic_and, 
           [parse_or(data, sub_query) for sub_query in parts]
           )

def parse_exp(data:dict, query):
    if query is None or query=="":
        return True
    return parse_and(data, query.lower())