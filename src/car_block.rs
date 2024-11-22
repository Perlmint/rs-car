use std::io;

#[cfg(feature = "async")]
use crate::{block_cid::read_block_cid_async, varint::read_varint_u64_async};
#[cfg(feature = "sync")]
use crate::{block_cid::read_block_cid_sync, varint::read_varint_u64_sync};
#[cfg(feature = "async")]
use futures::{AsyncRead, AsyncReadExt};

use crate::{error::CarDecodeError, Cid};

/// Arbitrary high value to prevent big allocations
const MAX_BLOCK_LEN: u64 = 1073741824;

/// # Returns
///
/// (cid, block buffer, total block byte length including varint)
#[cfg(feature = "async")]
pub(crate) async fn decode_block_async<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(&mut R, Cid, Vec<u8>, usize), CarDecodeError> {
    let (len, cid, varint_len, cid_len) = decode_block_header_async(r).await?;

    // len from header = block_len - varint_len
    let block_len = len - cid_len;

    let mut block_buf = vec![0u8; block_len];
    r.read_exact(&mut block_buf).await?;

    Ok((r, cid, block_buf, len + varint_len))
}

/// # Returns
///
/// (cid, block buffer, total block byte length including varint)
#[cfg(feature = "sync")]
pub(crate) fn decode_block_sync<'a>(
    r: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(Cid, &'a [u8], usize), CarDecodeError> {
    use crate::sync_util::CursorExt;
    let (len, cid, varint_len, cid_len) = decode_block_header_sync(r)?;

    // len from header = block_len - varint_len
    let block_len = len - cid_len;

    let block_buf = r.get_slice(block_len)?;

    Ok((cid, block_buf, len + varint_len))
}

#[cfg(feature = "async")]
async fn decode_block_header_async<R: AsyncRead + Unpin>(
    src: &mut R,
) -> Result<(usize, Cid, usize, usize), CarDecodeError> {
    let (len, varint_len) = match read_varint_u64_async(src).await {
        Ok(Some(len)) => len,
        Ok(None) => {
            return Err(CarDecodeError::InvalidBlockHeader(
                "invalid block header varint".to_string(),
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(CarDecodeError::BlockStartEOF)
        }
        Err(err) => Err(err)?,
    };

    if len == 0 {
        return Err(CarDecodeError::InvalidBlockHeader(
            "zero length".to_string(),
        ));
    }

    if len > MAX_BLOCK_LEN {
        return Err(CarDecodeError::InvalidBlockHeader(format!(
            "block len too big {}",
            len
        )));
    }

    let (cid, cid_len) = read_block_cid_async(src).await?;

    Ok((len as usize, cid, varint_len, cid_len))
}

#[cfg(feature = "sync")]
fn decode_block_header_sync<'a>(
    src: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(usize, Cid, usize, usize), CarDecodeError> {
    let (len, varint_len) = match read_varint_u64_sync(src) {
        Ok(Some(len)) => len,
        Ok(None) => {
            return Err(CarDecodeError::InvalidBlockHeader(
                "invalid block header varint".to_string(),
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(CarDecodeError::BlockStartEOF)
        }
        Err(err) => Err(err)?,
    };

    if len == 0 {
        return Err(CarDecodeError::InvalidBlockHeader(
            "zero length".to_string(),
        ));
    }

    if len > MAX_BLOCK_LEN {
        return Err(CarDecodeError::InvalidBlockHeader(format!(
            "block len too big {}",
            len
        )));
    }

    let (cid, cid_len) = read_block_cid_sync(src)?;

    Ok((len as usize, cid, varint_len, cid_len))
}
