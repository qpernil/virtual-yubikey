# YubiKey display frames

`yubikey-5-nfc-source.png` is Yubico's public front product image for the
YubiKey 5 NFC, downloaded from the product media CDN linked by
<https://www.yubico.com/product/yubikey-5-series/yubikey-5-nfc/> on 2026-08-23.
Yubico owns that image and the YubiKey marks; it is not covered by this
repository's MIT or Apache-2.0 code licenses. Use and redistribution must
follow Yubico's brand-asset terms.

The two 240x240 previews preserve the vertical product framing and composite
the transparent source over charcoal gray so the black silhouette remains
visible. Their matching `.rgb565` files are complete 115,200-byte, big-endian
RGB565 ST7789 frames:

- `yubikey-idle` uses black cut-outs on a deliberately darkened gold sensor;
- `yubikey-active` illuminates only the lowercase-y and NFC-arc cut-outs bright
  green while retaining the darker gold sensor.

The checked-in Ruby converter builds both native frames from the 240x240 BGRA
bitmap produced by `sips`. The worker includes the native frames directly, so
the deployed Pi does not decode or transform images at runtime.
