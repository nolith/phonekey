// Command genicons renders web/icon-*.png, matching web/icon.svg.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	for _, size := range []int{192, 512} {
		if err := write(fmt.Sprintf("web/icon-%d.png", size), size); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// inside reports whether point (x, y) in 512-unit space is covered.
func inside(x, y float64) (bg, fg bool) {
	// Rounded square, radius 112. iOS masks icons itself, so fill fully.
	bg = true
	// Ring: center (200,256), radius 88, stroke 44.
	d := math.Hypot(x-200, y-256)
	if math.Abs(d-88) <= 22 {
		return bg, true
	}
	seg := func(x1, y1, x2, y2 float64) bool {
		// Round-capped segment of width 44.
		dx, dy := x2-x1, y2-y1
		t := math.Max(0, math.Min(1, ((x-x1)*dx+(y-y1)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(x-(x1+t*dx), y-(y1+t*dy)) <= 22
	}
	return bg, seg(288, 256, 438, 256) || seg(398, 256, 398, 318) || seg(342, 256, 342, 300)
}

func write(path string, size int) error {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	green := color.RGBA{0x19, 0x70, 0x5a, 0xff}
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var hits int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+.5)/ss) * 512 / float64(size)
					y := (float64(py) + (float64(sy)+.5)/ss) * 512 / float64(size)
					if _, fg := inside(x, y); fg {
						hits++
					}
				}
			}
			a := float64(hits) / ss / ss
			mix := func(c uint8) uint8 { return uint8(float64(c)*(1-a) + 255*a) }
			img.Set(px, py, color.RGBA{mix(green.R), mix(green.G), mix(green.B), 0xff})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}
