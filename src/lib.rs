use asynchronous_codec::Framed;
use std::io::{BufRead, BufReader, Read};
use unsigned_varint;

pub mod async_fn;
mod carv1_header;
mod carv2_header;
mod cid;
mod codec;
mod error;
mod varint;

/// CARv1 consists of:
/// - TODO
///
/// ```nn
/// [-------header---------][---------------data---------------]
/// [varint][DAG-CBOR block][varint|CID|block][varint|CID|block]
/// ```
///
/// ## Header
/// First
pub fn read_carv1<R: Read>(buf_reader: BufReader<R>) {}

/// CARv2 consists of:
/// - 11-byte pragma
/// - 40-byte header with characteristics and locations
/// - CARv1 data payload, including header, roots and sequence of CID:Bytes pairs
/// - Optional index for fast lookup
///
/// ```nn
/// [pragma][v2 header][opt padding][CARv1][opt padding][opt index]
/// ```
///

#[cfg(test)]
mod tests {
    use asynchronous_codec::FramedRead;

    use crate::async_fn::decode_car;
    use crate::codec::CARv1Codec;

    use super::*;
    use futures::{Stream, StreamExt};
    use std::fs;
    use std::io::prelude::*;
    use std::io::BufReader;

    #[tokio::test]
    async fn open_car_v1_framed() {
        let car_filepath = "./testdata/helloworld.car";
        let mut file = async_std::fs::File::open(car_filepath).await.unwrap();
        let mut file_framed = FramedRead::new(file, CARv1Codec::new());

        // Trigger reading all stream
        loop {
            match file_framed.next().await {
                Some(value) => {
                    // Process the value here
                    println!("read stream value: {:?}", value.unwrap());
                }
                None => {
                    // End of stream
                    break;
                }
            }
        }
    }

    #[tokio::test]
    async fn decode_carv1_helloworld() {
        let car_filepath = "./testdata/helloworld.car";
        let mut file = async_std::fs::File::open(car_filepath).await.unwrap();
        decode_car(&mut file).await.unwrap();
    }

    #[tokio::test]
    async fn decode_carv1_carv1_basic() {
        let car_filepath = "./testdata/carv1-basic.car";
        let mut file = async_std::fs::File::open(car_filepath).await.unwrap();
        decode_car(&mut file).await.unwrap();
    }

    #[tokio::test]
    async fn decode_carv1_carv2_basic() {
        // 0aa16776657273696f6e02  - v2 pragma
        // 00000000000000000000000000000000  - v2 header characteristics
        // 3300000000000000  - v2 header data_offset
        // c001000000000000  - v2 header data_size
        // f301000000000000  - v2 header index_offset
        // 38a265726f6f747381
        // d82a5823001220fb16f5083412ef1371d031ed4aa239903d84efdadf1ba3
        // cd678e6475b1a232f86776657273696f6e01511220fb16f5083412ef1371
        // d031ed4aa239903d84efdadf1ba3cd678e6475b1a232f8122d0a221220d9
        // c0d5376d26f1931f7ad52d7acc00fc1090d2edb0808bf61eeb0a152826f6
        // 261204f09f8da418a40185011220d9c0d5376d26f1931f7ad52d7acc00fc
        // 1090d2edb0808bf61eeb0a152826f62612310a221220d745b7757f5b4593
        // eeab7820306c7bc64eb496a7410a0d07df7a34ffec4b97f1120962617272
        // 656c657965183a122e0a2401551220a2e1c40da1ae335d4dffe729eb4d5c
        // a23b74b9e51fc535f4a804a261080c294d1204f09f90a11807581220d745
        // b7757f5b4593eeab7820306c7bc64eb496a7410a0d07df7a34ffec4b97f1
        // 12340a2401551220b474a99a2705e23cf905a484ec6d14ef58b56bbe62e9
        // 292783466ec363b5072d120a666973686d6f6e67657218042801551220b4
        // 74a99a2705e23cf905a484ec6d14ef58b56bbe62e9292783466ec363b507
        // 2d666973682b01551220a2e1c40da1ae335d4dffe729eb4d5ca23b74b9e5
        // 1fc535f4a804a261080c294d6c6f62737465720100000028000000c80000
        // 0000000000a2e1c40da1ae335d4dffe729eb4d5ca23b74b9e51fc535f4a8
        // 04a261080c294d9401000000000000b474a99a2705e23cf905a484ec6d14
        // ef58b56bbe62e9292783466ec363b5072d6b01000000000000d745b7757f
        // 5b4593eeab7820306c7bc64eb496a7410a0d07df7a34ffec4b97f1120100
        // 0000000000d9c0d5376d26f1931f7ad52d7acc00fc1090d2edb0808bf61e
        // eb0a152826f6268b00000000000000fb16f5083412ef1371d031ed4aa239
        // 903d84efdadf1ba3cd678e6475b1a232f83900000000000000
        let car_filepath = "./testdata/carv2-basic.car";
        let mut file = async_std::fs::File::open(car_filepath).await.unwrap();
        decode_car(&mut file).await.unwrap();
    }
}
