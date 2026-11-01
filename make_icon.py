"""PCMonitor.exe 아이콘 생성 (모니터 화면 + 심박 그래프)."""
import sys
from PIL import Image, ImageDraw

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([16, 28, 240, 188], radius=22, fill=(31, 41, 61, 255))          # 화면 테두리
d.rounded_rectangle([30, 42, 226, 174], radius=12, fill=(20, 110, 222, 255))        # 화면
d.rectangle([110, 188, 146, 214], fill=(31, 41, 61, 255))                          # 받침 목
d.rounded_rectangle([70, 210, 186, 230], radius=8, fill=(31, 41, 61, 255))          # 받침
pts = [(42, 112), (86, 112), (104, 76), (124, 150), (144, 92), (158, 112), (214, 112)]
d.line(pts, fill=(255, 255, 255, 255), width=12, joint="curve")
img.save(sys.argv[1] if len(sys.argv) > 1 else "pcmon.ico",
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
