// Copyright 2025 Brian Smith.
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

pub(crate) use crate::error::LenMismatchError;

pub(crate) trait AliasingSlices2<T> {
    fn with_ra_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T) -> R,
    ) -> Result<R, LenMismatchError>;
}

impl<T> AliasingSlices2<T> for &mut [T] {
    fn with_ra_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let r = self;
        if r.len() != expected_len {
            return Err(LenMismatchError::new(r.len()));
        }
        Ok(f(r.as_mut_ptr(), r.as_ptr()))
    }
}

impl<T> AliasingSlices2<T> for (&mut [T], &[T]) {
    fn with_ra_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let (r, a) = self;
        if r.len() != expected_len {
            return Err(LenMismatchError::new(r.len()));
        }
        if a.len() != expected_len {
            return Err(LenMismatchError::new(a.len()));
        }
        Ok(f(r.as_mut_ptr(), a.as_ptr()))
    }
}

pub(crate) trait AliasingSlices3<T> {
    fn with_rab_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError>;
}

// TODO:
// impl<A, T> AliasingSlices3<T> for A where Self: AliasingSlices2<T> {
//     fn with_rab_pointers<R>(
//         self,
//         expected_len: usize,
//         f: impl FnOnce(*mut T, *const T, *const T) -> R,
//     ) -> Result<R, LenMismatchError> {
//         <Self as AliasingSlices2<T>>::with_ra_pointers(expected_len, |r, a| f(r, r, a))
//     }
// }

impl<T> AliasingSlices3<T> for &mut [T] {
    fn with_rab_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        <Self as AliasingSlices2<T>>::with_ra_pointers(self, expected_len, |r, a| f(r, r, a))
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl<T> AliasingSlices3<T> for (&mut [T], &[T], &[T]) {
    fn with_rab_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let (r, a, b) = self;
        ((r, a), b).with_rab_pointers(expected_len, f)
    }
}

impl<RA, T> AliasingSlices3<T> for (RA, &[T])
where
    RA: AliasingSlices2<T>,
{
    fn with_rab_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let (ra, b) = self;
        if b.len() != expected_len {
            return Err(LenMismatchError::new(b.len()));
        }
        ra.with_ra_pointers(expected_len, |r, a| f(r, a, b.as_ptr()))
    }
}
