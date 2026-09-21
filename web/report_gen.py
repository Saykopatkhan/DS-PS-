"""Portable PDF reports using the built-in Latin-1 fonts."""
import unicodedata
from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos


def _pdf_text(value):
    """Transliterate Turkish and replace unsupported glyphs instead of crashing."""
    text = str(value).translate(str.maketrans('ıİşŞğĞ', 'iIsSgG'))
    return unicodedata.normalize('NFKD', text).encode('ascii', 'replace').decode('ascii').replace('\n', ' ')


class PDFReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'DS-IPS SOC Siber Olay Raporu', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Sayfa {self.page_no()}/{{nb}}', align='C')


def generate_pdf_report(alerts_data, output_path):
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, f'Rapor Tarihi: {datetime.now():%Y-%m-%d %H:%M:%S}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 8, f'Bu rapora dahil edilen alarm sayisi: {min(len(alerts_data), 50)}.', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, 'Tespit edilen en yeni 50 olay:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    widths = [38, 44, 36, 36, 36]
    row_height = 8

    def table_header():
        pdf.set_font('helvetica', 'B', 9)
        for width, title in zip(widths, ['Tarih', 'Tur', 'Kaynak', 'Hedef', 'Ciddiyet']):
            pdf.cell(width, row_height, title, border=1, align='C')
        pdf.ln(row_height)
        pdf.set_font('helvetica', '', 8)

    table_header()
    # Database returns newest first; taking the tail previously showed the oldest rows.
    for alert in alerts_data[:50]:
        if pdf.get_y() + row_height > pdf.h - pdf.b_margin:
            pdf.add_page()
            table_header()
        keys = ['timestamp', 'alert_type', 'source_ip', 'destination_ip', 'severity']
        for width, key in zip(widths, keys):
            text = _pdf_text(alert.get(key, ''))
            while text and pdf.get_string_width(text) > width - 3:
                text = text[:-1]
            pdf.cell(width, row_height, text, border=1)
        pdf.ln(row_height)
    pdf.output(str(output_path))
    return output_path
