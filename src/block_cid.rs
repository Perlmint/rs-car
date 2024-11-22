use blake2b_simd::Params;
#[cfg(feature = "async")]
use futures::{AsyncRead, AsyncReadExt};
use libipld::{cid, multihash::MultihashGeneric};
use sha2::{Digest, Sha256};

#[cfg(feature = "async")]
use crate::varint::read_varint_u64_async;
use crate::{
    error::{CarDecodeError, HashCode},
    Cid,
};
#[cfg(feature = "sync")]
use crate::{sync_util::CursorExt, varint::read_varint_u64_sync};

const CODE_IDENTITY: u64 = 0x00;
const CODE_SHA2_256: u64 = 0x12;
const CODE_BLAKE2B_256: u64 = 0xb220;
const DIGEST_SIZE: usize = 64;
const CID_V0_MH_SIZE: usize = 32;

#[cfg(feature = "async")]
pub(crate) async fn read_block_cid_async<R: AsyncRead + Unpin>(
    src: &mut R,
) -> Result<(Cid, usize), CarDecodeError> {
    let (version, version_len) = read_varint_u64_async(src)
        .await?
        .ok_or(cid::Error::InvalidCidVersion)?;
    let (codec, codec_len) = read_varint_u64_async(src)
        .await?
        .ok_or(cid::Error::InvalidCidV0Codec)?;

    // A CIDv0 is indicated by a first byte of 0x12 followed by 0x20 which specifies a 32-byte (0x20) length SHA2-256 (0x12) digest.
    if [version, codec] == [CODE_SHA2_256, 0x20] {
        let mut digest = [0u8; CID_V0_MH_SIZE];
        src.read_exact(&mut digest).await?;
        let mh = MultihashGeneric::wrap(version, &digest).expect("Digest is always 32 bytes.");
        return Ok((Cid::new_v0(mh)?, version_len + codec_len + CID_V0_MH_SIZE));
    }

    // CIDv1 components:
    // 1. Version as an unsigned varint (should be 1)
    // 2. Codec as an unsigned varint (valid according to the multicodec table)
    // 3. The raw bytes of a multihash
    let version = cid::Version::try_from(version).unwrap();
    match version {
        cid::Version::V0 => Err(cid::Error::InvalidExplicitCidV0)?,
        cid::Version::V1 => {
            let (mh, mh_len) = read_multihash_async(src).await?;
            Ok((
                Cid::new(version, codec, mh)?,
                version_len + codec_len + mh_len,
            ))
        }
    }
}

#[cfg(feature = "sync")]
pub(crate) fn read_block_cid_sync<'a>(
    src: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(Cid, usize), CarDecodeError> {
    let (version, version_len) = read_varint_u64_sync(src)?.ok_or(cid::Error::InvalidCidVersion)?;
    let (codec, codec_len) = read_varint_u64_sync(src)?.ok_or(cid::Error::InvalidCidV0Codec)?;

    // A CIDv0 is indicated by a first byte of 0x12 followed by 0x20 which specifies a 32-byte (0x20) length SHA2-256 (0x12) digest.
    if [version, codec] == [CODE_SHA2_256, 0x20] {
        let digest = src.get_slice(CID_V0_MH_SIZE)?;
        let mh = MultihashGeneric::wrap(version, &digest).expect("Digest is always 32 bytes.");
        return Ok((Cid::new_v0(mh)?, version_len + codec_len + CID_V0_MH_SIZE));
    }

    // CIDv1 components:
    // 1. Version as an unsigned varint (should be 1)
    // 2. Codec as an unsigned varint (valid according to the multicodec table)
    // 3. The raw bytes of a multihash
    let version = cid::Version::try_from(version).unwrap();
    match version {
        cid::Version::V0 => Err(cid::Error::InvalidExplicitCidV0)?,
        cid::Version::V1 => {
            let (mh, mh_len) = read_multihash_sync(src)?;
            Ok((
                Cid::new(version, codec, mh)?,
                version_len + codec_len + mh_len,
            ))
        }
    }
}

#[cfg(feature = "async")]
async fn read_multihash_async<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(MultihashGeneric<DIGEST_SIZE>, usize), CarDecodeError> {
    let (code, code_len) =
        read_varint_u64_async(r)
            .await?
            .ok_or(CarDecodeError::InvalidMultihash(
                "invalid code varint".to_string(),
            ))?;
    let (size, size_len) =
        read_varint_u64_async(r)
            .await?
            .ok_or(CarDecodeError::InvalidMultihash(
                "invalid size varint".to_string(),
            ))?;

    if size > u8::MAX as u64 {
        panic!("digest size {} > max {}", size, DIGEST_SIZE)
    }

    let mut digest = [0; DIGEST_SIZE];
    r.read_exact(&mut digest[..size as usize]).await?;

    // TODO: Sad, copies the digest (again)..
    // Multihash does not expose a way to construct Self without some decoding or copying
    // unwrap: multihash must be valid since it's constructed manually
    let mh = MultihashGeneric::wrap(code, &digest[..size as usize]).unwrap();

    Ok((mh, code_len + size_len + size as usize))
}

#[cfg(feature = "sync")]
fn read_multihash_sync<'a>(
    r: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(MultihashGeneric<DIGEST_SIZE>, usize), CarDecodeError> {
    let (code, code_len) = read_varint_u64_sync(r)?.ok_or(CarDecodeError::InvalidMultihash(
        "invalid code varint".to_string(),
    ))?;
    let (size, size_len) = read_varint_u64_sync(r)?.ok_or(CarDecodeError::InvalidMultihash(
        "invalid size varint".to_string(),
    ))?;

    if size > u8::MAX as u64 {
        panic!("digest size {} > max {}", size, DIGEST_SIZE)
    }

    let digest = r.get_slice(size as _)?;

    // TODO: Sad, copies the digest (again)..
    // Multihash does not expose a way to construct Self without some decoding or copying
    // unwrap: multihash must be valid since it's constructed manually
    let mh = MultihashGeneric::wrap(code, &digest).unwrap();

    Ok((mh, code_len + size_len + size as usize))
}

pub(crate) fn assert_block_cid(cid: &Cid, block: &[u8]) -> Result<(), CarDecodeError> {
    let (hash_fn_name, block_digest) = match cid.hash().code() {
        // TODO: Remove need to copy on .to_vec()
        CODE_IDENTITY => ("identity", block.to_vec()),
        CODE_SHA2_256 => ("sha2-256", hash_sha2_256(block).to_vec()),
        CODE_BLAKE2B_256 => ("blake2b-256", hash_blake2b_256(block).to_vec()),
        code => {
            return Err(CarDecodeError::UnsupportedHashCode((
                HashCode::Code(code),
                *cid,
            )));
        }
    };

    let cid_digest = cid.hash().digest();

    fn to_hex_lower(s: impl AsRef<[u8]>) -> String {
        s.as_ref()
            .iter()
            .map(|i| format!("{i:02x}"))
            .collect::<Vec<_>>()
            .as_slice()
            .join("")
    }

    if cid_digest != block_digest {
        return Err(CarDecodeError::BlockDigestMismatch(format!(
            "{} digest mismatch cid {:?} cid digest {} block digest {}",
            hash_fn_name,
            cid,
            to_hex_lower(cid_digest),
            to_hex_lower(block_digest),
        )));
    }

    Ok(())
}

fn hash_sha2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_blake2b_256(data: &[u8]) -> [u8; 32] {
    Params::new()
        .hash_length(32)
        .to_state()
        .update(data)
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use std::io;

    use futures::executor;
    use libipld::cid::{
        multihash::{Multihash, MultihashGeneric},
        Cid,
    };

    use super::assert_block_cid;
    #[cfg(feature = "async")]
    use super::{read_block_cid_async, read_multihash_async};
    #[cfg(feature = "sync")]
    use super::{read_block_cid_sync, read_multihash_sync};
    use crate::{block_cid::CODE_SHA2_256, error::CarDecodeError};

    const CID_V0_STR: &str = "QmUU2HcUBVSXkfWPUc3WUSeCMrWWeEJTuAgR9uyWBhh9Nf";
    const CID_V0_HEX: &str = "12205b0995ced69229d26009c53c185a62ea805a339383521edbed1028c496615448";
    const CID_DIGEST: &str = "5b0995ced69229d26009c53c185a62ea805a339383521edbed1028c496615448";

    const CID_V1_STR: &str = "bafyreihyrpefhacm6kkp4ql6j6udakdit7g3dmkzfriqfykhjw6cad5lrm";
    const CID_V1_HEX: &str =
        "01711220f88bc853804cf294fe417e4fa83028689fcdb1b1592c5102e1474dbc200fab8b";

    // Cursor = easy way to get AsyncRead from an AsRef<[u8]>
    #[cfg(feature = "async")]
    fn from_hex_async(input: &str) -> futures::io::Cursor<Vec<u8>> {
        futures::io::Cursor::new(hex::decode(input).unwrap())
    }

    #[test]
    #[cfg(feature = "async")]
    fn read_block_cid_from_v0_async() {
        let cid_expected = Cid::try_from(CID_V0_STR).unwrap();

        let mut input_stream = from_hex_async(CID_V0_HEX);
        let (cid, cid_len) = executor::block_on(read_block_cid_async(&mut input_stream)).unwrap();

        assert_eq!(cid, cid_expected);
        assert_eq!(cid_len, cid_expected.to_bytes().len());
    }

    #[test]
    #[cfg(feature = "sync")]
    fn read_block_cid_from_v0_sync() {
        let cid_expected = Cid::try_from(CID_V0_STR).unwrap();

        let data = hex::decode(CID_V0_HEX).unwrap();
        let mut input_stream = std::io::Cursor::new(data.as_slice());
        let (cid, cid_len) = read_block_cid_sync(&mut input_stream).unwrap();

        assert_eq!(cid, cid_expected);
        assert_eq!(cid_len, cid_expected.to_bytes().len());
    }

    #[test]
    #[cfg(feature = "async")]
    fn read_multihash_from_v0_async() {
        let digest = hex::decode(CID_DIGEST).unwrap();
        let mh_expected = MultihashGeneric::<64>::wrap(CODE_SHA2_256, &digest).unwrap();

        let mut input_stream = from_hex_async(CID_V0_HEX);
        let (mh, mh_len) = executor::block_on(read_multihash_async(&mut input_stream)).unwrap();

        assert_eq!(mh, mh_expected);
        assert_eq!(mh_len, mh_expected.to_bytes().len());

        // Sanity check, same result as sync version. Sync API can dynamically shrink size to 32 bytes
        let mh_sync = Multihash::read(&mut mh_expected.to_bytes().as_slice()).unwrap();
        assert_eq!(mh_sync, mh_expected);
    }

    #[test]
    #[cfg(feature = "sync")]
    fn read_multihash_from_v0_sync() {
        let digest = hex::decode(CID_DIGEST).unwrap();
        let mh_expected = MultihashGeneric::<64>::wrap(CODE_SHA2_256, &digest).unwrap();

        let data = hex::decode(CID_V0_HEX).unwrap();
        let mut input_stream = std::io::Cursor::new(data.as_slice());
        let (mh, mh_len) = read_multihash_sync(&mut input_stream).unwrap();

        assert_eq!(mh, mh_expected);
        assert_eq!(mh_len, mh_expected.to_bytes().len());

        // Sanity check, same result as sync version. Sync API can dynamically shrink size to 32 bytes
        let mh_sync = Multihash::read(&mut mh_expected.to_bytes().as_slice()).unwrap();
        assert_eq!(mh_sync, mh_expected);
    }

    #[test]
    #[cfg(feature = "async")]
    fn read_block_cid_from_v1_async() {
        let cid_expected = Cid::try_from(CID_V1_STR).unwrap();

        let mut input_stream = from_hex_async(CID_V1_HEX);
        let (cid, cid_len) = executor::block_on(read_block_cid_async(&mut input_stream)).unwrap();

        // Double check multihash before full CID
        assert_eq!(cid.hash(), cid_expected.hash());

        assert_eq!(cid, cid_expected);
        assert_eq!(cid_len, cid_expected.to_bytes().len());
    }

    #[test]
    #[cfg(feature = "sync")]
    fn read_block_cid_from_v1_sync() {
        let cid_expected = Cid::try_from(CID_V1_STR).unwrap();

        let data = hex::decode(CID_V1_HEX).unwrap();
        let mut input_stream = std::io::Cursor::new(data.as_slice());
        let (cid, cid_len) = read_block_cid_sync(&mut input_stream).unwrap();

        // Double check multihash before full CID
        assert_eq!(cid.hash(), cid_expected.hash());

        assert_eq!(cid, cid_expected);
        assert_eq!(cid_len, cid_expected.to_bytes().len());
    }

    #[test]
    #[cfg(feature = "async")]
    fn read_multihash_error_varint_unexpected_eof_async() {
        let mut input_stream = from_hex_async("ffff");

        match executor::block_on(read_multihash_async(&mut input_stream)) {
            Err(CarDecodeError::IoError(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof)
            }
            x => panic!("other result {:?}", x),
        }
    }

    #[test]
    #[cfg(feature = "sync")]
    fn read_multihash_error_varint_unexpected_eof_sync() {
        let data = hex::decode("ffff").unwrap();
        let mut input_stream = std::io::Cursor::new(data.as_slice());

        match read_multihash_sync(&mut input_stream) {
            Err(CarDecodeError::IoError(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof)
            }
            x => panic!("other result {:?}", x),
        }
    }

    #[test]
    fn assert_block_cid_v0_helloworld() {
        // simple dag-pb of string "helloworld"
        let cid = Cid::try_from("QmUU2HcUBVSXkfWPUc3WUSeCMrWWeEJTuAgR9uyWBhh9Nf").unwrap();
        let block = hex::decode("0a110802120b68656c6c6f776f726c640a180b").unwrap();
        assert_block_cid(&cid, &block).unwrap();
    }
}
