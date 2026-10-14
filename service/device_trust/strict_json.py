"""Bounded strict JSON for signed protocol documents (never canonicalize before verification)."""
import json
import math

def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out

def _constant(_value):
    raise ValueError("non-finite JSON number")

def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number

def strict_loads(data: bytes, limit: int):
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise ValueError("signed document outside size bounds")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant, parse_float=_float)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 32 or nodes > 8192:
                raise ValueError("JSON structure too deep or complex")
            if isinstance(item, dict):
                for k, v in item.items():
                    k.encode("utf-8")
                    pending.append((v, depth + 1))
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):
                item.encode("utf-8")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise ValueError("invalid signed JSON") from exc
