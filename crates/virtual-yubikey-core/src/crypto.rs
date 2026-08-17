use aes::{
    cipher::{consts::U16, Block, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
    Aes128, Aes192, Aes256,
};

pub(crate) const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

pub(crate) fn aes_ecb_block(key: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, ()> {
    if data.len() != AES_BLOCK_SIZE {
        return Err(());
    }

    fn apply<C>(key: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, ()>
    where
        C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
    {
        let cipher = C::new_from_slice(key).map_err(|_| ())?;
        let mut block = Block::<C>::default();
        block.copy_from_slice(data);
        match direction {
            Direction::Encrypt => cipher.encrypt_block(&mut block),
            Direction::Decrypt => cipher.decrypt_block(&mut block),
        }
        Ok(block.to_vec())
    }

    match key.len() {
        16 => apply::<Aes128>(key, data, direction),
        24 => apply::<Aes192>(key, data, direction),
        32 => apply::<Aes256>(key, data, direction),
        _ => Err(()),
    }
}

pub(crate) fn aes_cbc(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, ()> {
    if iv.len() != AES_BLOCK_SIZE || data.len() % AES_BLOCK_SIZE != 0 {
        return Err(());
    }

    fn apply<C>(key: &[u8], iv: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, ()>
    where
        C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
    {
        let cipher = C::new_from_slice(key).map_err(|_| ())?;
        let mut chaining = [0_u8; AES_BLOCK_SIZE];
        chaining.copy_from_slice(iv);
        let mut output = Vec::with_capacity(data.len());

        for input in data.chunks_exact(AES_BLOCK_SIZE) {
            let mut block = Block::<C>::default();
            block.copy_from_slice(input);
            match direction {
                Direction::Encrypt => {
                    for (byte, previous) in block.iter_mut().zip(chaining) {
                        *byte ^= previous;
                    }
                    cipher.encrypt_block(&mut block);
                    chaining.copy_from_slice(&block);
                }
                Direction::Decrypt => {
                    let mut ciphertext = [0_u8; AES_BLOCK_SIZE];
                    ciphertext.copy_from_slice(&block);
                    cipher.decrypt_block(&mut block);
                    for (byte, previous) in block.iter_mut().zip(chaining) {
                        *byte ^= previous;
                    }
                    chaining = ciphertext;
                }
            }
            output.extend_from_slice(&block);
        }
        Ok(output)
    }

    match key.len() {
        16 => apply::<Aes128>(key, iv, data, direction),
        24 => apply::<Aes192>(key, iv, data, direction),
        32 => apply::<Aes256>(key, iv, data, direction),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_192_ecb_matches_the_nist_example() {
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let ciphertext = [
            0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f,
            0xa5, 0xcc,
        ];
        assert_eq!(
            aes_ecb_block(&key, &plaintext, Direction::Encrypt).unwrap(),
            ciphertext
        );
        assert_eq!(
            aes_ecb_block(&key, &ciphertext, Direction::Decrypt).unwrap(),
            plaintext
        );
    }
}
