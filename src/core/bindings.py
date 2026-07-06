# -*- coding: utf-8 -*-
import ctypes
import json
import os
import sys
from typing import Dict, Any

# Dinamik kütüphane adı ve yolları
lib_name = "starfall_core"
lib_filenames = []
if sys.platform.startswith("win"):
    lib_filenames = [f"{lib_name}.dll", f"lib{lib_name}.dll"]
elif sys.platform.startswith("darwin"):
    lib_filenames = [f"lib{lib_name}.dylib"]
else:
    lib_filenames = [f"lib{lib_name}.so"]

# Arama yapılacak yollar. Sadece proje içindeki güvenilir mutlak yollar denenir;
# cwd veya sistem DLL yollarını kullanmak DLL hijacking riskini artırır.
module_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(module_dir, os.pardir, os.pardir))
search_paths = []
for filename in lib_filenames:
    search_paths.extend([
        os.path.join(module_dir, filename),
        os.path.join(project_root, filename),
        os.path.join(project_root, "native", filename),
        os.path.join(project_root, "build", filename),
        os.path.join(project_root, "build", "Release", filename),
        os.path.join(project_root, "build", "Debug", filename),
    ])

_lib = None
for path in search_paths:
    if os.path.exists(path):
        try:
            _lib = ctypes.CDLL(path)
            break
        except Exception:
            pass

if not _lib:
    raise ImportError(
        f"Flare hızlandırma kütüphanesi ({', '.join(lib_filenames)}) yüklenemedi. "
        f"Paket eksik olabilir; uygulama Python yedek motoruyla çalışmaya devam eder."
    )

# Fonksiyonların c-type tanımları
_lib.starfall_similarity.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.starfall_similarity.restype = ctypes.c_double

_lib.starfall_check_iban.argtypes = [ctypes.c_char_p]
_lib.starfall_check_iban.restype = ctypes.c_bool

_lib.starfall_check_phone.argtypes = [ctypes.c_char_p]
_lib.starfall_check_phone.restype = ctypes.c_bool

_lib.starfall_add_iban.argtypes = [ctypes.c_char_p]
_lib.starfall_add_iban.restype = None

_lib.starfall_add_phone.argtypes = [ctypes.c_char_p]
_lib.starfall_add_phone.restype = None

_lib.starfall_scan_text_json.argtypes = [ctypes.c_char_p]
_lib.starfall_scan_text_json.restype = ctypes.c_char_p

_lib.starfall_ml_analyze_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.starfall_ml_analyze_json.restype = ctypes.c_char_p

# Python sarmalayıcıları (Wrapper)
def starfall_similarity(a: str, b: str) -> float:
    return _lib.starfall_similarity(a.encode("utf-8"), b.encode("utf-8"))

def starfall_check_iban(iban: str) -> bool:
    return _lib.starfall_check_iban(iban.encode("utf-8"))

def starfall_check_phone(phone: str) -> bool:
    return _lib.starfall_check_phone(phone.encode("utf-8"))

def starfall_add_iban(iban: str) -> None:
    _lib.starfall_add_iban(iban.encode("utf-8"))

def starfall_add_phone(phone: str) -> None:
    _lib.starfall_add_phone(phone.encode("utf-8"))

def starfall_scan_text(text: str) -> Dict[str, Any]:
    json_res = _lib.starfall_scan_text_json(text.encode("utf-8"))
    if json_res:
        return json.loads(json_res.decode("utf-8"))
    return {}

def starfall_ml_analyze(text: str, model_path: str) -> Dict[str, Any]:
    json_res = _lib.starfall_ml_analyze_json(text.encode("utf-8"), model_path.encode("utf-8"))
    if json_res:
        return json.loads(json_res.decode("utf-8"))
    return {}
