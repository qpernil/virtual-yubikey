use software_key_core::software_symmetric::{
    decrypt_aes_block, decrypt_aes_cbc, encrypt_aes_block, encrypt_aes_cbc,
};

pub(crate) use software_key_core::software_symmetric::AES_BLOCK_SIZE;

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

pub(crate) fn aes_ecb_block(key: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, ()> {
    let block: &[u8; AES_BLOCK_SIZE] = data.try_into().map_err(|_| ())?;
    match direction {
        Direction::Encrypt => encrypt_aes_block(key, block),
        Direction::Decrypt => decrypt_aes_block(key, block),
    }
    .map(|block| block.to_vec())
    .map_err(|_| ())
}

pub(crate) fn aes_cbc(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, ()> {
    match direction {
        Direction::Encrypt => encrypt_aes_cbc(key, iv, data),
        Direction::Decrypt => decrypt_aes_cbc(key, iv, data),
    }
    .map_err(|_| ())
}
