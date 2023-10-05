from barcode import Code128
import barcode
from barcode.writer import ImageWriter
from barcode import generate

# Define the data for the Code 128 barcode
data = 'A0000F224250123'

# Create the Code 128 barcode with customized dimensions
code = barcode.get('code128', data, writer=ImageWriter())
code.writer.dpi = 300

code.save('2X7.png', options={'module_width': 0.2, 'module_height': 7, 'font_size': 5, 'text_distance': 2})
