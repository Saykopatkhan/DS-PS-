import os
from fpdf import FPDF
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('helvetica', 'B', 15)
        # Move to the right
        self.cell(80)
        # Title
        self.cell(30, 10, 'DS-IPS SOC Siber Olay Raporu', 0, 0, 'C')
        # Line break
        self.ln(20)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('helvetica', 'I', 8)
        # Page number
        self.cell(0, 10, f'Sayfa {self.page_no()}/{{nb}}', 0, 0, 'C')

def generate_pdf_report(alerts_data, output_path):
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('helvetica', '', 12)
    
    # Rapor Başlığı ve Tarih
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, f'Rapor Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
    pdf.ln(5)
    
    # Olay Özeti
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Olay Ozeti:', 0, 1)
    pdf.set_font('helvetica', '', 10)
    pdf.multi_cell(0, 8, f'Toplam kaydedilen siber olay (alarm) sayisi: {len(alerts_data)}.')
    pdf.ln(5)
    
    # Son 50 Alarmi Listele
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Tespit Edilen Son Saldirilar:', 0, 1)
    pdf.set_font('helvetica', '', 9)
    
    # Tablo Basliklari
    col_width = pdf.w / 5.5
    row_height = pdf.font_size * 2
    
    headers = ['Tarih', 'Tur', 'Kaynak', 'Hedef', 'Ciddiyet']
    for header in headers:
        pdf.cell(col_width, row_height, header, border=1, align='C')
    pdf.ln(row_height)
    
    for alert in alerts_data[-50:]:
        # Karakter hatalarini onlemek icin ingilizce karakterlere cast edelim
        # fpdf2 utf8 destekler ama helvetica icindeki karakterler sinirlidir.
        date_str = str(alert.get('timestamp', ''))[:19]
        a_type = str(alert.get('alert_type', ''))[:15].encode('ascii', 'ignore').decode('ascii')
        src = str(alert.get('source_ip', ''))[:15]
        dst = str(alert.get('destination_ip', ''))[:15]
        sev = str(alert.get('severity', ''))[:10]
        
        pdf.cell(col_width, row_height, date_str, border=1)
        pdf.cell(col_width, row_height, a_type, border=1)
        pdf.cell(col_width, row_height, src, border=1)
        pdf.cell(col_width, row_height, dst, border=1)
        pdf.cell(col_width, row_height, sev, border=1)
        pdf.ln(row_height)
        
    pdf.ln(10)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Onerilen Onlemler:', 0, 1)
    pdf.set_font('helvetica', '', 10)
    pdf.multi_cell(0, 8, '- Tespit edilen kritik IP adreslerinin Firewall / WAF uzerinde kalici olarak engellenmesi.\n- Sunucu uzerinde gereksiz portlarin kapatilmasi.\n- Uygulama guvenligi icin girdi dogrulama (Input Validation) politikalarinin siki tutulmasi.')
    
    pdf.output(output_path)
    return output_path
