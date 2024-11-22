#[cfg(feature = "async")]
use crate::varint::read_varint_u64_async;
use crate::{
    carv1_header::{decode_carv1_header, CarV1Header},
    carv2_header::{decode_carv2_header, CarV2Header, CARV2_HEADER_SIZE, CARV2_PRAGMA_SIZE},
    error::CarDecodeError,
    Cid,
};
#[cfg(feature = "sync")]
use crate::{sync_util::CursorExt, varint::read_varint_u64_sync};
#[cfg(feature = "async")]
use futures::{AsyncRead, AsyncReadExt};

/// Arbitrary high value to prevent big allocations
const MAX_HEADER_LEN: u64 = 1048576;
/// Arbitrary high value to prevent big allocations
const MAX_PADDING_LEN: usize = 1073741824;

#[derive(Debug, PartialEq)]
pub(crate) enum StreamEnd {
    AfterNBytes(usize),
    OnBlockEOF,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CarVersion {
    V1 = 1,
    V2 = 2,
}

#[derive(Debug)]
pub struct CarHeader {
    pub version: CarVersion,
    pub roots: Vec<Cid>,
    pub characteristics_v2: Option<u128>,
    pub(crate) eof_stream: StreamEnd,
}

impl CarHeader {}

#[cfg(feature = "async")]
pub(crate) async fn read_car_header_async<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<CarHeader, CarDecodeError> {
    let (header, _) = read_carv1_header_async(r).await?;

    match header.version {
        1 => Ok(CarHeader {
            version: CarVersion::V1,
            roots: header.roots.ok_or(CarDecodeError::InvalidCarV1Header(
                "v1 header has not roots".to_owned(),
            ))?,
            characteristics_v2: None,
            eof_stream: StreamEnd::OnBlockEOF,
        }),
        2 => {
            let (header_v2, (header_v1, header_v1_len)) = read_carv2_header_async(r).await?;
            let blocks_len = header_v2.data_size as usize - header_v1_len;
            Ok(CarHeader {
                version: CarVersion::V2,
                roots: header_v1.roots.ok_or(CarDecodeError::InvalidCarV1Header(
                    "v1 header has not roots".to_owned(),
                ))?,
                characteristics_v2: Some(header_v2.characteristics),
                eof_stream: StreamEnd::AfterNBytes(blocks_len),
            })
        }
        _ => Err(CarDecodeError::UnsupportedCarVersion {
            version: header.version,
        }),
    }
}

#[cfg(feature = "async")]
pub(crate) fn read_car_header_sync<'a>(
    r: &mut std::io::Cursor<&'a [u8]>,
) -> Result<CarHeader, CarDecodeError> {
    let (header, _) = read_carv1_header_sync(r)?;

    match header.version {
        1 => Ok(CarHeader {
            version: CarVersion::V1,
            roots: header.roots.ok_or(CarDecodeError::InvalidCarV1Header(
                "v1 header has not roots".to_owned(),
            ))?,
            characteristics_v2: None,
            eof_stream: StreamEnd::OnBlockEOF,
        }),
        2 => {
            let (header_v2, (header_v1, header_v1_len)) = read_carv2_header_sync(r)?;
            let blocks_len = header_v2.data_size as usize - header_v1_len;
            Ok(CarHeader {
                version: CarVersion::V2,
                roots: header_v1.roots.ok_or(CarDecodeError::InvalidCarV1Header(
                    "v1 header has not roots".to_owned(),
                ))?,
                characteristics_v2: Some(header_v2.characteristics),
                eof_stream: StreamEnd::AfterNBytes(blocks_len),
            })
        }
        _ => Err(CarDecodeError::UnsupportedCarVersion {
            version: header.version,
        }),
    }
}

/// # Returns
///
/// (header, total header byte length including varint)
#[cfg(feature = "async")]
async fn read_carv1_header_async<R: AsyncRead + Unpin>(
    src: &mut R,
) -> Result<(CarV1Header, usize), CarDecodeError> {
    // Decode header varint
    let (header_len, varint_len) =
        read_varint_u64_async(src)
            .await?
            .ok_or(CarDecodeError::InvalidCarV1Header(
                "invalid header varint".to_string(),
            ))?;

    if header_len > MAX_HEADER_LEN {
        return Err(CarDecodeError::InvalidCarV1Header(format!(
            "header len too big {}",
            header_len
        )));
    }

    let mut header_buf = vec![0u8; header_len as usize];
    src.read_exact(&mut header_buf).await?;

    let header = decode_carv1_header(&header_buf)?;

    Ok((header, header_len as usize + varint_len))
}

#[cfg(feature = "sync")]
fn read_carv1_header_sync<'a>(
    src: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(CarV1Header, usize), CarDecodeError> {
    // Decode header varint
    let (header_len, varint_len) = read_varint_u64_sync(src)?.ok_or(
        CarDecodeError::InvalidCarV1Header("invalid header varint".to_string()),
    )?;

    if header_len > MAX_HEADER_LEN {
        return Err(CarDecodeError::InvalidCarV1Header(format!(
            "header len too big {}",
            header_len
        )));
    }

    let header_buf = src.get_slice(header_len as usize)?;

    let header = decode_carv1_header(&header_buf)?;

    Ok((header, header_len as usize + varint_len))
}

#[cfg(feature = "async")]
async fn read_carv2_header_async<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(CarV2Header, (CarV1Header, usize)), CarDecodeError> {
    let mut header_buf = [0u8; CARV2_HEADER_SIZE];
    r.read_exact(&mut header_buf).await?;

    let header_v2 = decode_carv2_header(&header_buf)?;

    // Read padding, and throw away
    let padding_len = header_v2.data_offset as usize - CARV2_PRAGMA_SIZE - CARV2_HEADER_SIZE;
    if padding_len > 0 {
        if padding_len > MAX_PADDING_LEN {
            return Err(CarDecodeError::InvalidCarV1Header(format!(
                "padding len too big {}",
                padding_len
            )));
        }
        let mut padding_buf = vec![0u8; padding_len];
        r.read_exact(&mut padding_buf).await?;
    }

    // Read inner CARv1 header
    let header_v1 = read_carv1_header_async(r).await?;

    Ok((header_v2, header_v1))
}

#[cfg(feature = "sync")]
fn read_carv2_header_sync<'a>(
    r: &mut std::io::Cursor<&'a [u8]>,
) -> Result<(CarV2Header, (CarV1Header, usize)), CarDecodeError> {
    use std::io::{Seek, SeekFrom};
    let header_buf = r.get_array::<CARV2_HEADER_SIZE>()?;

    let header_v2 = decode_carv2_header(&header_buf)?;

    // Read padding, and throw away
    let padding_len = header_v2.data_offset as usize - CARV2_PRAGMA_SIZE - CARV2_HEADER_SIZE;
    if padding_len > 0 {
        if padding_len > MAX_PADDING_LEN {
            return Err(CarDecodeError::InvalidCarV1Header(format!(
                "padding len too big {}",
                padding_len
            )));
        }
        r.seek(SeekFrom::Current(padding_len as _))?;
    }

    // Read inner CARv1 header
    let header_v1 = read_carv1_header_sync(r)?;

    Ok((header_v2, header_v1))
}

#[cfg(test)]
mod tests {
    use futures::executor;

    use super::*;
    use crate::{
        carv1_header::CarV1Header,
        carv2_header::{CARV2_PRAGMA, CARV2_PRAGMA_SIZE},
    };

    #[test]
    #[cfg(feature = "async")]
    fn read_carv1_header_v2_pragma_async() {
        executor::block_on(async {
            assert_eq!(
                read_carv1_header_async(&mut futures::io::Cursor::new(&CARV2_PRAGMA))
                    .await
                    .unwrap(),
                (
                    CarV1Header {
                        version: 2,
                        roots: None
                    },
                    CARV2_PRAGMA_SIZE
                )
            )
        })
    }

    #[test]
    #[cfg(feature = "sync")]
    fn read_carv1_header_v2_pragma_sync() {
        assert_eq!(
            read_carv1_header_sync(&mut std::io::Cursor::new(CARV2_PRAGMA.as_slice())).unwrap(),
            (
                CarV1Header {
                    version: 2,
                    roots: None
                },
                CARV2_PRAGMA_SIZE
            )
        )
    }
}
