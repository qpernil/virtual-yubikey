#!/usr/bin/env ruby
# frozen_string_literal: true

# Convert the 240x240 BGRA bitmap produced by macOS `sips` into the two
# big-endian RGB565 frames consumed by the ST7789 display.  The active frame
# changes only the dark lowercase-y glyph and NFC arcs cut into the gold touch
# sensor.

unless ARGV.length == 5
  abort "usage: #{$PROGRAM_NAME} INPUT.bmp IDLE.rgb565 ACTIVE.rgb565 IDLE.ppm ACTIVE.ppm"
end

input_path, idle_path, active_path, idle_preview_path, active_preview_path = ARGV
bitmap = File.binread(input_path)
abort "input is not a BMP" unless bitmap.start_with?("BM")

pixel_offset = bitmap.byteslice(10, 4).unpack1("V")
width = bitmap.byteslice(18, 4).unpack1("l<")
height = bitmap.byteslice(22, 4).unpack1("l<")
bits_per_pixel = bitmap.byteslice(28, 2).unpack1("v")
compression = bitmap.byteslice(30, 4).unpack1("V")
abort "expected a top-down 240x240 BGRA bitmap" unless width == 240 && height == -240
abort "expected a 32-bit bitfields bitmap" unless bits_per_pixel == 32 && compression == 3

idle = String.new(capacity: width * -height * 2, encoding: Encoding::BINARY)
active = String.new(capacity: width * -height * 2, encoding: Encoding::BINARY)
idle_rgb = String.new(capacity: width * -height * 3, encoding: Encoding::BINARY)
active_rgb = String.new(capacity: width * -height * 3, encoding: Encoding::BINARY)
background_red = 27
background_green = 29
background_blue = 33

(-height).times do |y|
  width.times do |x|
    offset = pixel_offset + (y * width + x) * 4
    blue, green, red, alpha = bitmap.byteslice(offset, 4).bytes
    red = (red * alpha + background_red * (255 - alpha)) / 255
    green = (green * alpha + background_green * (255 - alpha)) / 255
    blue = (blue * alpha + background_blue * (255 - alpha)) / 255

    # At 240x240 the y and NFC arcs occupy this box.  Their olive pixels are
    # much darker than the surrounding gold, allowing the antialiased edges to
    # be selected without changing the sensor itself.
    cutout = x.between?(109, 131) && y.between?(84, 121) && red < 190 && green < 180 && blue < 125

    # Darken only the gold face of the circular sensor.  The circle test and
    # gold threshold preserve its dark rim as well as every other gold detail
    # on the product image.
    sensor = (x - 120)**2 + (y - 105)**2 <= 23**2
    if sensor && red > 150 && green > 110 && blue < 160
      red = red * 3 / 4
      green = green * 3 / 4
      blue = blue * 3 / 4
    end

    idle_red, idle_green, idle_blue = cutout ? [0, 0, 0] : [red, green, blue]
    active_red, active_green, active_blue = cutout ? [24, 255, 72] : [red, green, blue]

    idle << [((idle_red >> 3) << 11) | ((idle_green >> 2) << 5) | (idle_blue >> 3)].pack("n")
    active << [((active_red >> 3) << 11) | ((active_green >> 2) << 5) | (active_blue >> 3)].pack("n")
    idle_rgb << idle_red.chr << idle_green.chr << idle_blue.chr
    active_rgb << active_red.chr << active_green.chr << active_blue.chr
  end
end

File.binwrite(idle_path, idle)
File.binwrite(active_path, active)
File.binwrite(idle_preview_path, "P6\n#{width} #{-height}\n255\n" + idle_rgb)
File.binwrite(active_preview_path, "P6\n#{width} #{-height}\n255\n" + active_rgb)
