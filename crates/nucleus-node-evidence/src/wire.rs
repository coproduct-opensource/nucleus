//! A bounds-checked cursor over the two byte orders this crate reads.
//!
//! TPM 2.0 structures (`TPMS_ATTEST`, `TPMT_SIGNATURE`, `TPMT_PUBLIC`) are
//! big-endian; the TCG PC Client event log and the Linux IMA log are
//! little-endian. Every read is checked: a short buffer is an error, never a
//! zero, so a truncated structure cannot parse as a smaller valid one.

use crate::Malformed;

/// A read cursor. `what` names the structure for error messages.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn short(&self, need: usize) -> Malformed {
        Malformed::Truncated {
            structure: self.what,
            offset: self.pos,
            needed: need,
        }
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.short(n))?;
        let out = self.buf.get(self.pos..end).ok_or_else(|| self.short(n))?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn be_u16(&mut self) -> Result<u16, Malformed> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn be_u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn be_u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn le_u16(&mut self) -> Result<u16, Malformed> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn le_u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn le_u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A TPM `TPM2B_*`: a big-endian `u16` size, then that many bytes.
    pub(crate) fn tpm2b(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.be_u16()?;
        self.bytes(usize::from(n))
    }

    /// A little-endian `u32` length, then that many bytes (event logs).
    pub(crate) fn le_sized(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.le_u32()?;
        let n = usize::try_from(n).map_err(|_| self.short(usize::MAX))?;
        self.bytes(n)
    }

    /// Refuse trailing bytes: a structure that parsed with bytes left over
    /// is not the structure it claimed to be.
    pub(crate) fn finish(self) -> Result<(), Malformed> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Malformed::TrailingBytes {
                structure: self.what,
                count: self.remaining(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reads_are_errors_not_zeros() {
        let mut r = Reader::new(&[0x01], "t");
        assert!(r.be_u16().is_err());
        let mut r = Reader::new(&[0x00, 0x05, 1, 2], "t");
        assert!(
            r.tpm2b().is_err(),
            "a TPM2B longer than the buffer is truncated"
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut r = Reader::new(&[0, 1, 2], "t");
        r.be_u16().unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn byte_orders() {
        let mut r = Reader::new(&[0x12, 0x34, 0x12, 0x34], "t");
        assert_eq!(r.be_u16().unwrap(), 0x1234);
        assert_eq!(r.le_u16().unwrap(), 0x3412);
    }
}
