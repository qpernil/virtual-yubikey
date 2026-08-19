#[cfg(target_os = "linux")]
mod linux {
    use embedded_graphics::{
        framebuffer::{buffer_size, Framebuffer},
        mono_font::{ascii::FONT_10X20, ascii::FONT_6X10, MonoTextStyle},
        pixelcolor::{
            raw::{BigEndian, RawU16},
            Rgb565, RgbColor,
        },
        prelude::*,
        primitives::{Circle, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle},
        text::{Alignment, Text},
    };
    use gpiocdev::{line::Value, Request};
    use spidev::{SpiModeFlags, Spidev, SpidevOptions};
    use std::{
        error::Error,
        io::Write,
        thread,
        time::{Duration, Instant},
    };

    const WIDTH: usize = 240;
    const HEIGHT: usize = 240;
    const SPI_SPEED_HZ: u32 = 62_500_000;
    const GPIO_DC: u32 = 25;
    const GPIO_RESET: u32 = 27;
    const GPIO_BACKLIGHT: u32 = 24;
    const SPI_CHUNK: usize = 4096;

    type DisplayBuffer = Framebuffer<
        Rgb565,
        RawU16,
        BigEndian,
        WIDTH,
        HEIGHT,
        { buffer_size::<Rgb565>(WIDTH, HEIGHT) },
    >;

    struct St7789 {
        spi: Spidev,
        gpio: Request,
    }

    impl St7789 {
        fn open(spi_path: &str, gpio_path: &str) -> Result<Self, Box<dyn Error>> {
            let mut spi = Spidev::open(spi_path)?;
            let options = SpidevOptions::new()
                .bits_per_word(8)
                .max_speed_hz(SPI_SPEED_HZ)
                .lsb_first(false)
                .mode(SpiModeFlags::SPI_MODE_0)
                .build();
            spi.configure(&options)?;

            let gpio = Request::builder()
                .on_chip(gpio_path)
                .with_consumer("virtual-yubikey-display-demo")
                .with_lines(&[GPIO_DC, GPIO_RESET, GPIO_BACKLIGHT])
                .as_output(Value::Inactive)
                .request()?;

            let mut display = Self { spi, gpio };
            display.reset()?;
            display.initialize()?;
            Ok(display)
        }

        fn reset(&self) -> Result<(), Box<dyn Error>> {
            self.gpio.set_value(GPIO_BACKLIGHT, Value::Inactive)?;
            self.gpio.set_value(GPIO_RESET, Value::Active)?;
            thread::sleep(Duration::from_millis(100));
            self.gpio.set_value(GPIO_RESET, Value::Inactive)?;
            thread::sleep(Duration::from_millis(100));
            self.gpio.set_value(GPIO_RESET, Value::Active)?;
            thread::sleep(Duration::from_millis(100));
            Ok(())
        }

        fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
            const STEPS: &[(&[u8], u64)] = &[
                (&[0x11], 120),
                (&[0x36, 0x70], 0),
                (&[0x3a, 0x05], 0),
                (&[0xb2, 0x0c, 0x0c, 0x00, 0x33, 0x33], 0),
                (&[0xb7, 0x00], 0),
                (&[0xbb, 0x3f], 0),
                (&[0xc0, 0x2c], 0),
                (&[0xc2, 0x01], 0),
                (&[0xc3, 0x0d], 0),
                (&[0xc6, 0x0f], 0),
                (&[0xd0, 0xa7], 0),
                (&[0xd0, 0xa4, 0xa1], 0),
                (&[0xd6, 0xa1], 0),
                (
                    &[
                        0xe0, 0xf0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x27, 0x43, 0x3f, 0x33, 0x0e,
                        0x0e, 0x26, 0x2e,
                    ],
                    0,
                ),
                (
                    &[
                        0xe1, 0xf0, 0x07, 0x0d, 0x0d, 0x0b, 0x16, 0x26, 0x43, 0x3e, 0x3f, 0x19,
                        0x19, 0x31, 0x3a,
                    ],
                    0,
                ),
                (&[0x21], 0),
                (&[0x29], 20),
            ];

            for (bytes, delay_ms) in STEPS {
                self.command(bytes[0])?;
                if bytes.len() > 1 {
                    self.data(&bytes[1..])?;
                }
                if *delay_ms != 0 {
                    thread::sleep(Duration::from_millis(*delay_ms));
                }
            }
            Ok(())
        }

        fn command(&mut self, command: u8) -> Result<(), Box<dyn Error>> {
            self.gpio.set_value(GPIO_DC, Value::Inactive)?;
            self.spi.write_all(&[command])?;
            Ok(())
        }

        fn data(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
            self.gpio.set_value(GPIO_DC, Value::Active)?;
            for chunk in data.chunks(SPI_CHUNK) {
                self.spi.write_all(chunk)?;
            }
            Ok(())
        }

        fn set_full_window(&mut self) -> Result<(), Box<dyn Error>> {
            self.command(0x2a)?;
            self.data(&[0x00, 0x00, 0x00, 0xef])?;
            self.command(0x2b)?;
            self.data(&[0x00, 0x00, 0x00, 0xef])?;
            self.command(0x2c)
        }

        fn flush(&mut self, buffer: &DisplayBuffer) -> Result<(), Box<dyn Error>> {
            self.set_full_window()?;
            self.data(buffer.data())?;
            self.gpio.set_value(GPIO_BACKLIGHT, Value::Active)?;
            Ok(())
        }
    }

    fn draw_scene(buffer: &mut DisplayBuffer, frame: u32) {
        let background = Rgb565::new(0, 2, 5);
        buffer.clear(background).unwrap();

        Rectangle::new(Point::new(5, 5), Size::new(230, 230))
            .into_styled(
                PrimitiveStyleBuilder::new()
                    .stroke_color(Rgb565::CYAN)
                    .stroke_width(3)
                    .build(),
            )
            .draw(buffer)
            .unwrap();

        Text::with_alignment(
            "RUST UI",
            Point::new(120, 38),
            MonoTextStyle::new(&FONT_10X20, Rgb565::YELLOW),
            Alignment::Center,
        )
        .draw(buffer)
        .unwrap();

        Text::with_alignment(
            "embedded-graphics\non real ST7789",
            Point::new(120, 74),
            MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE),
            Alignment::Center,
        )
        .draw(buffer)
        .unwrap();

        let travel = 164;
        let phase = (frame % (travel * 2)) as i32;
        let ball_x = if phase <= travel as i32 {
            38 + phase
        } else {
            38 + travel as i32 * 2 - phase
        };
        Circle::new(Point::new(ball_x - 10, 116), 20)
            .into_styled(PrimitiveStyle::with_fill(Rgb565::MAGENTA))
            .draw(buffer)
            .unwrap();

        Rectangle::new(Point::new(25, 160), Size::new(190, 18))
            .into_styled(
                PrimitiveStyleBuilder::new()
                    .stroke_color(Rgb565::WHITE)
                    .stroke_width(2)
                    .build(),
            )
            .draw(buffer)
            .unwrap();
        let progress = 2 + ((frame % 120) * 186 / 119);
        Rectangle::new(Point::new(27, 162), Size::new(progress, 14))
            .into_styled(PrimitiveStyle::with_fill(Rgb565::GREEN))
            .draw(buffer)
            .unwrap();

        Text::with_alignment(
            "VIRTUAL TOKEN  READY",
            Point::new(120, 207),
            MonoTextStyle::new(&FONT_6X10, Rgb565::GREEN),
            Alignment::Center,
        )
        .draw(buffer)
        .unwrap();
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut arguments = std::env::args();
        let program = arguments.next().unwrap_or_else(|| "display-demo".into());
        let spi_path = arguments.next().unwrap_or_else(|| "/dev/spidev0.0".into());
        let gpio_path = arguments.next().unwrap_or_else(|| "/dev/gpiochip0".into());
        if arguments.next().is_some() {
            return Err(format!("usage: {program} [spidev [gpiochip]]").into());
        }

        let mut display = St7789::open(&spi_path, &gpio_path)?;
        let mut buffer = DisplayBuffer::new();
        let start = Instant::now();
        for frame in 0..240 {
            draw_scene(&mut buffer, frame);
            display.flush(&buffer)?;
        }
        let elapsed = start.elapsed();
        println!(
            "Rendered 240 embedded-graphics frames in {:.2}s ({:.1} frames/s)",
            elapsed.as_secs_f64(),
            240.0 / elapsed.as_secs_f64()
        );
        println!("Press Enter to release the display GPIOs.");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("st7789-embedded-graphics-demo: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("st7789-embedded-graphics-demo requires Linux SPI and GPIO devices");
    std::process::exit(1);
}
