"""Bounded JSON for offline evidence files. This does not authenticate their contents."""
import json
import math
from pathlib import Path

MAX_DEPTH = 32
MAX_NODES = 1_000_000

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError("duplicate JSON field")
        result[key]=value
    return result

def _constant(_value):
    raise ValueError("non-finite JSON number")

def _integer(value):
    if len(value)>128:raise ValueError("JSON integer outside evidence bounds")
    return int(value)

def _float(value):
    result=float(value)
    if not math.isfinite(result):raise ValueError("non-finite JSON number")
    return result

def loads(data,limit):
    if type(limit) is not int or limit<1:raise ValueError("invalid evidence size limit")
    if not isinstance(data,bytes) or not data or len(data)>limit:
        raise ValueError("evidence JSON outside size bounds")
    try:
        result=json.loads(data.decode("utf-8"),object_pairs_hook=_pairs,
                          parse_constant=_constant,parse_float=_float,parse_int=_integer)
        pending=[(result,0)];nodes=0
        while pending:
            item,depth=pending.pop();nodes+=1
            if depth>MAX_DEPTH or nodes>MAX_NODES:
                raise ValueError("evidence JSON too deep or complex")
            if isinstance(item,dict):
                for key,value in item.items():
                    key.encode("utf-8")
                    pending.append((value,depth+1))
            elif isinstance(item,list):
                pending.extend((value,depth+1) for value in item)
            elif isinstance(item,str):
                item.encode("utf-8")
        return result
    except (UnicodeError,RecursionError,OverflowError,json.JSONDecodeError) as error:
        raise ValueError("invalid evidence JSON") from error

def read_json(path,limit):
    # A bounded read still holds if the file grows after an earlier stat.
    with Path(path).open("rb") as source:
        data=source.read(limit+1)
    return loads(data,limit)
