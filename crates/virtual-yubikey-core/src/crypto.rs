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

pub(crate) fn aes_cbc(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, ()> {
    if iv.len() != AES_BLOCK_SIZE || !data.len().is_multiple_of(AES_BLOCK_SIZE) {
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
