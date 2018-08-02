from PIL import Image
import pytesseract

image = Image.open('d:\\code.jpg')      # 打开要识别的图片
code = pytesseract.image_to_string(image)       #识别验证码

f = open('d:\\result.txt','w')      # 将结果写入result.txt
f.write(code)
f.close()

print(code)
