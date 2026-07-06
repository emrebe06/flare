# -*- coding: utf-8 -*-
from html.parser import HTMLParser
from typing import List, Optional, Tuple

class LinkAndTextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.texts: List[str] = []
        self.links: List[str] = []

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self.texts.append(text)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "a":
            for attr, val in attrs:
                if attr == "href" and val:
                    self.links.append(val)

def parse_html_file(file_path: str) -> Tuple[str, List[str]]:
    """
    HTML dosyasını okur, içindeki düz metni ve linkleri (href) ayıklar.
    Dönen değerler: (birleştirilmiş_metin, link_listesi)
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        parser = LinkAndTextHTMLParser()
        parser.feed(content)
        joined_text = " ".join(parser.texts)
        return joined_text, parser.links
    except Exception as e:
        return f"HTML Okuma Hatası: {str(e)}", []

def parse_pdf_file(file_path: str) -> Tuple[str, List[str]]:
    """
    PDF dosyasını okur, içindeki düz metni ve linkleri ayıklar.
    Dış kütüphane 'pypdf' kurulu ise kullanır, değilse hata ve yönlendirme döner.
    """
    try:
        import pypdf
    except ImportError:
        return (
            "HATA: PDF analizi yapabilmek için 'pypdf' paketi kurulu olmalıdır. "
            "Lütfen terminalde 'pip install pypdf' komutunu çalıştırın.", 
            []
        )

    try:
        reader = pypdf.PdfReader(file_path)
        texts: List[str] = []
        links: List[str] = []
        
        for page in reader.pages:
            # Metni çek
            text = page.extract_text()
            if text:
                texts.append(text)
            
            # Linkleri (Annotations) çek
            if "/Annots" in page:
                annots = page["/Annots"]
                # pypdf bazen liste bazen dolaylı nesne dönebilir
                if isinstance(annots, list):
                    for annot in annots:
                        try:
                            obj = annot.get_object()
                            if obj.get("/Subtype") == "/Link" and "/A" in obj:
                                action = obj["/A"].get_object()
                                if action.get("/S") == "/URI" and "/URI" in action:
                                    links.append(action["/URI"])
                        except Exception:
                            pass
                else:
                    try:
                        # Tekil nesne durumunda
                        obj = annots.get_object()
                        # Eğer array ise döngüye sok
                        if hasattr(obj, "__iter__"):
                            for annot in obj:
                                try:
                                    o = annot.get_object()
                                    if o.get("/Subtype") == "/Link" and "/A" in o:
                                        act = o["/A"].get_object()
                                        if act.get("/S") == "/URI" and "/URI" in act:
                                            links.append(act["/URI"])
                                except Exception:
                                    pass
                    except Exception:
                        pass
        
        return " ".join(texts), links
    except Exception as e:
        return f"PDF Okuma Hatası: {str(e)}", []
