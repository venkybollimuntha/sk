import barcode
from barcode import Code128
from barcode.writer import ImageWriter
import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
from PIL import Image

# Load your Excel file
excel_file = "venky-test.xlsx"
wb = openpyxl.load_workbook(excel_file)

# Select the desired sheet (e.g., "Sheet1")
sheet = wb["Sheet1"]

# Read data from the "memberID" column and store it in a list
member_ids = [cell.value for cell in sheet["A"][1:]]  # Assuming member IDs are in column A, starting from the second row

# Create a new column "barcode" in the Excel sheet
sheet.insert_cols(2)  # Insert a new column at index 2
c = 0
# Generate and insert barcodes into the "barcode" column
for row_idx, member_id in enumerate(member_ids, start=2):  # Start from row 2
    if c<=20:
        c+=1
        continue
    # Generate the barcode for the current member ID
    code = barcode.get('code128', member_id, writer=ImageWriter())
    # code.writer.dpi = 300
    code.save(f'barcode_{member_id}', options={'module_width': 0.2, 'module_height': 6, 'font_size': 5, 'text_distance': 2})
    # Save the barcode image to a temporary file
    barcode_image_path = f"barcode_{member_id}"
    print(barcode_image_path)

    # Insert the barcode image into the Excel sheet in the "barcode" column
    img = openpyxl.drawing.image.Image(barcode_image_path)
    sheet.add_image(img, f"B{row_idx}")  # Insert the image into column B
    c+=1
    
# Save the modified Excel sheet
output_excel_file = "venky-test.xlsx"
wb.save(output_excel_file)

# Close the Excel workbook
wb.close()

print(f"Barcodes generated and inserted into {output_excel_file}")
