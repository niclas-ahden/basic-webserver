//! Hosted pseudorandom seed effects backed by the OS entropy source.

use core::mem::ManuallyDrop;

use crate::abi::{
    io_err_from_io, roc_host, RandomSeedU32Result, RandomSeedU32ResultPayload,
    RandomSeedU32ResultTag, RandomSeedU64Result, RandomSeedU64ResultPayload,
    RandomSeedU64ResultTag,
};

fn entropy_error(error: getrandom::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[no_mangle]
pub extern "C" fn hosted_random_seed_u32() -> RandomSeedU32Result {
    let roc_host = roc_host();
    let mut bytes = [0u8; 4];
    match getrandom::getrandom(&mut bytes) {
        Ok(()) => RandomSeedU32Result {
            payload: RandomSeedU32ResultPayload {
                ok: ManuallyDrop::new(u32::from_ne_bytes(bytes)),
            },
            tag: RandomSeedU32ResultTag::Ok,
        },
        Err(error) => RandomSeedU32Result {
            payload: RandomSeedU32ResultPayload {
                err: ManuallyDrop::new(io_err_from_io(&entropy_error(error), roc_host)),
            },
            tag: RandomSeedU32ResultTag::Err,
        },
    }
}

#[no_mangle]
pub extern "C" fn hosted_random_seed_u64() -> RandomSeedU64Result {
    let roc_host = roc_host();
    let mut bytes = [0u8; 8];
    match getrandom::getrandom(&mut bytes) {
        Ok(()) => RandomSeedU64Result {
            payload: RandomSeedU64ResultPayload {
                ok: ManuallyDrop::new(u64::from_ne_bytes(bytes)),
            },
            tag: RandomSeedU64ResultTag::Ok,
        },
        Err(error) => RandomSeedU64Result {
            payload: RandomSeedU64ResultPayload {
                err: ManuallyDrop::new(io_err_from_io(&entropy_error(error), roc_host)),
            },
            tag: RandomSeedU64ResultTag::Err,
        },
    }
}
