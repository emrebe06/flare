#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flame (Powered by Starfall Core)
Pasif ilan/link dolandırıcılık risk analiz aracı.
"""

import sys
import json
from typing import List

from src.core.models import AnalysisInput, APP_NAME, APP_VERSION
from src.core.engine import RiskEngine
from src.core.scanners import is_probably_url
from src.gui.app import FlameGUI

def cli_analyze(args: List[str]) -> int:
    if not args:
        print(f"{APP_NAME} v{APP_VERSION}")
        print("GUI Başlatmak için: python main.py")
        print("CLI Analiz için: python main.py --cli <url veya metin>")
        return 0
    
    text = " ".join(args)
    url = args[0] if args and is_probably_url(args[0]) else ""
    data = AnalysisInput(
        url=url,
        pasted_text=text, 
        allow_network_fetch=False
    )
    result = RiskEngine().analyze(data)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0

def main() -> int:
    if "--cli" in sys.argv:
        idx = sys.argv.index("--cli")
        return cli_analyze(sys.argv[idx + 1:])
    
    # Arayüzü başlat
    app = FlameGUI()
    app.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
