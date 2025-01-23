// Copyright 2015-2025 Brian Smith.
// Portions Copyright (c) 2014, 2015, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![cfg(all(target_arch = "arm", target_endian = "little"))]

use super::{Key, Tag, TAG_LEN};
use crate::{c, cpu::arm::Neon};
use core::{mem::MaybeUninit, num::NonZeroUsize};

// XXX/TODO(MSRV): change to `pub(super)`.
pub(in super::super) struct State {
    state: poly1305_state_st,
    neon: Neon,
}

// TODO: Is 16 enough?
#[repr(C, align(16))]
struct poly1305_state_st {
    r: fe1305x2,
    h: fe1305x2,
    c: fe1305x2,
    precomp: [fe1305x2; 2],

    // Not used in C or Rust; assume the assembly code writes to it before it
    // reads from it.
    data: MaybeUninit<[u8; 128]>,

    buf: [u8; 32],
    buf_used: c::size_t,
    key: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C, align(16))] // align(16) is for ZERO in particular.
struct fe1305x2 {
    v: [u32; 12], // for alignment; only using 10
}

impl fe1305x2 {
    const ZERO: Self = Self { v: [0u32; 12] };
}

impl State {
    pub(super) fn new_context(
        Key {
            key_and_nonce: ref key,
        }: Key,
        neon: Neon,
    ) -> super::Context {
        prefixed_extern! {
            fn openssl_poly1305_neon2_addmulmod(r: *mut fe1305x2, x: &fe1305x2,
                y: &fe1305x2, c: &fe1305x2);
        }
        #[inline(always)]
        fn load32(key: &[u8; 32], i: usize) -> u32 {
            let bytes = key[i..][..4].try_into().unwrap();
            u32::from_le_bytes(bytes)
        }
        let rv_01 = 0x3ffffff & load32(key, 0);
        let rv_23 = 0x3ffff03 & (load32(key, 3) >> 2);
        let rv_45 = 0x3ffc0ff & (load32(key, 6) >> 4);
        let rv_67 = 0x3f03fff & (load32(key, 9) >> 6);
        let rv_89 = 0x00fffff & (load32(key, 12) >> 8);
        let key = (key[16..]).try_into().unwrap();
        // TODO: Avoid zeroing `precomp` before initializing it.
        let mut r = Self {
            state: poly1305_state_st {
                r: fe1305x2 {
                    v: [
                        rv_01, rv_01, rv_23, rv_23, rv_45, rv_45, rv_67, rv_67, rv_89, rv_89, 0, 0,
                    ],
                },
                h: fe1305x2::ZERO,
                c: fe1305x2::ZERO,
                precomp: [fe1305x2::ZERO; 2],
                data: MaybeUninit::uninit(),
                buf: [0u8; 32],
                buf_used: 0,
                key,
            },
            neon,
        };

        // r^2
        {
            let precomp0 = &mut r.state.precomp[0];
            let r = &r.state.r;
            unsafe { openssl_poly1305_neon2_addmulmod(precomp0, r, r, &fe1305x2::ZERO) };
        }
        // r^4
        {
            let [ref precomp0, ref mut precomp1] = &mut r.state.precomp;
            unsafe {
                openssl_poly1305_neon2_addmulmod(precomp1, precomp0, precomp0, &fe1305x2::ZERO)
            };
        }
        super::Context::ArmNeon(r)
    }

    pub(super) fn update_internal(&mut self, input: &[u8]) {
        prefixed_extern! {
            fn CRYPTO_poly1305_update_neon(
                st: &mut poly1305_state_st,
                input: *const u8,
                in_len: c::NonZero_size_t);
        }
        if let Some(len) = NonZeroUsize::new(input.len()) {
            let _: Neon = self.neon;
            let input = input.as_ptr();
            unsafe { CRYPTO_poly1305_update_neon(&mut self.state, input, len) }
        }
    }

    pub(super) fn finish(mut self) -> Tag {
        prefixed_extern! {
            fn CRYPTO_poly1305_finish_neon(st: &mut poly1305_state_st, mac: &mut [u8; TAG_LEN]);
        }
        let mut tag = Tag([0u8; TAG_LEN]);
        unsafe { CRYPTO_poly1305_finish_neon(&mut self.state, &mut tag.0) }
        tag
    }
}
