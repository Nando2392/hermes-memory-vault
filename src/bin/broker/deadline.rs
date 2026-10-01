use std::io::{self, Read, Write};
use std::time::{Duration, Instant};
pub trait TimedIo: Read + Write {
    fn timeout(&self, remaining: Duration) -> io::Result<()>;
}
pub struct Deadline<T> {
    pub inner: T,
    pub end: Instant,
}
impl<T: TimedIo> Deadline<T> {
    fn remaining(&self) -> io::Result<()> {
        let remaining = self
            .end
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline"))?;
        self.inner.timeout(remaining)
    }
}
impl<T: TimedIo> Read for Deadline<T> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.remaining()?;
        self.inner.read(b)
    }
}
impl<T: TimedIo> Write for Deadline<T> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.remaining()?;
        self.inner.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.inner.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Never;
    impl Read for Never {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read after absolute deadline")
        }
    }
    impl Write for Never {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("write after absolute deadline")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl TimedIo for Never {
        fn timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn expired_absolute_deadline_prevents_read_and_write() {
        let mut io = Deadline {
            inner: Never,
            end: Instant::now(),
        };
        assert_eq!(
            io.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(io.write(&[0]).unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
