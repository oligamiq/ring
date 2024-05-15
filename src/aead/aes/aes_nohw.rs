// Copyright (c) 2019, Google Inc.
// Portions Copyright 2024 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{KeyBytes, AES_KEY};

pub(super) fn set_encrypt_key(key: &mut AES_KEY, bytes: KeyBytes) {
    prefixed_extern! {
        fn aes_nohw_setup_key_128(key: *mut AES_KEY, input: &[u8; 128 / 8]);
        fn aes_nohw_setup_key_256(key: *mut AES_KEY, input: &[u8; 256 / 8]);
    }
    match bytes {
        KeyBytes::AES_128(bytes) => unsafe { aes_nohw_setup_key_128(key, bytes) },
        KeyBytes::AES_256(bytes) => unsafe { aes_nohw_setup_key_256(key, bytes) },
    }
}
