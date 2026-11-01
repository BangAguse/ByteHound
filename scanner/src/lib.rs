use aho_corasick::{AhoCorasick, MatchKind};
use memmap2::MmapOptions;
use std::ffi::CStr;
use std::fs::File;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::OnceLock;

const SIGNATURES: &[(&str, &[u8])] = &[
    ("EICAR test marker", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
    ("PowerShell encoded-command indicator", b"powershell -enc"),
    ("shell download-and-execute indicator", b"curl | sh"),
    ("PHP dynamic-evaluation indicator", b"base64_decode("),
    ("JavaScript dynamic-evaluation indicator", b"eval("),
    ("script permission-change indicator", b"chmod +x"),
    ("Windows script-host indicator", b"CreateObject(\"WScript.Shell\")"),
    ("suspicious process-launch indicator", b"Process.Start("),
];

#[repr(C)]
pub struct BhResult {
    pub status: u32,
    pub size: u64,
    pub entropy: f64,
    pub matches: u64,
    pub signature: [u8; 128],
}

fn automaton() -> &'static AhoCorasick {
    static AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();
    AUTOMATON.get_or_init(|| {
        let patterns: Vec<&[u8]> = SIGNATURES.iter().map(|(_, pattern)| *pattern).collect();
        AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(patterns)
            .expect("static ByteHound signatures must form a valid automaton")
    })
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0u64; 256];
    for &byte in bytes {
        frequencies[byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    frequencies
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn set_signature(destination: &mut [u8; 128], label: &str) {
    let bytes = label.as_bytes();
    let count = bytes.len().min(destination.len() - 1);
    destination[..count].copy_from_slice(&bytes[..count]);
}

fn scan(path: &Path, result: &mut BhResult) -> Result<(), u32> {
    let file = File::open(path).map_err(|_| 2u32)?;
    let metadata = file.metadata().map_err(|_| 2u32)?;
    if !metadata.is_file() {
        return Err(1u32);
    }
    result.size = metadata.len();
    if metadata.len() == 0 {
        return Ok(());
    }
    // The map is read-only. Files should not be modified or truncated during a scan.
    let mapped = unsafe { MmapOptions::new().map(&file) }.map_err(|_| 2u32)?;
    result.entropy = entropy(&mapped);
    for found in automaton().find_overlapping_iter(&mapped) {
        result.matches += 1;
        if result.signature[0] == 0 {
            if let Some((label, _)) = SIGNATURES.get(found.pattern().as_usize()) {
                set_signature(&mut result.signature, label);
            }
        }
    }
    Ok(())
}

/// Scan a regular file using a read-only memory map and bundled byte signatures.
///
/// Status codes: 0 success, 1 invalid/non-regular file, 2 I/O or mmap error,
/// 3 invalid path or an internal panic.
#[no_mangle]
pub unsafe extern "C" fn bytehound_scan(path: *const c_char, result: *mut BhResult) -> i32 {
    if path.is_null() || result.is_null() {
        return 3;
    }
    let output = &mut *result;
    *output = BhResult {
        status: 0,
        size: 0,
        entropy: 0.0,
        matches: 0,
        signature: [0; 128],
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let path = CStr::from_ptr(path).to_str().map_err(|_| 3u32)?;
        scan(Path::new(path), output)
    }));
    match outcome {
        Ok(Ok(())) => 0,
        Ok(Err(code)) => {
            output.status = code;
            code as i32
        }
        Err(_) => {
            output.status = 3;
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{entropy, SIGNATURES};

    #[test]
    fn entropy_is_zero_for_empty_and_uniform_data() {
        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(&[42; 256]), 0.0);
    }

    #[test]
    fn entropy_of_all_byte_values_is_eight_bits() {
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        assert!((entropy(&bytes) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn bundled_signatures_are_nonempty_and_unique() {
        for (index, (label, pattern)) in SIGNATURES.iter().enumerate() {
            assert!(!label.is_empty());
            assert!(!pattern.is_empty());
            assert!(!SIGNATURES[..index].iter().any(|(_, previous)| previous == pattern));
        }
    }
}
