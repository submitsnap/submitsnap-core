//! Identifying a file from its leading bytes.
//!
//! This is defence in depth, not proof. Its job is to stop the cheap attack where somebody
//! declares `image/png` and sends something else, on the assumption that the declared type is
//! what gets trusted and later served back. A signature can be forged by anyone who bothers, so
//! the download path also refuses to render anything inline and sends `nosniff` — see the
//! submission download handler.

/// Formats with a signature at the start of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    Png,
    Jpeg,
    Gif,
    Webp,
    Pdf,
    Zip,
    Gzip,
    /// Nothing matched, which is the honest answer for a format that has no signature — CSV and
    /// plain text are the usual ones — and for a file too short to compare against one.
    Unknown,
}

/// Reads the signature from the start of a file.
///
/// Callers should supply at least [`SUGGESTED_HEAD_BYTES`] bytes; a shorter slice can only ever
/// produce a confident answer for the shorter signatures.
pub fn sniff(head: &[u8]) -> Sniffed {
    if head.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Sniffed::Png;
    }
    if head.starts_with(&[0xff, 0xd8, 0xff]) {
        return Sniffed::Jpeg;
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Sniffed::Gif;
    }
    // RIFF container; the form is named four bytes later.
    if head.len() >= 12 && head.starts_with(b"RIFF") && &head[8..12] == b"WEBP" {
        return Sniffed::Webp;
    }
    if head.starts_with(b"%PDF-") {
        return Sniffed::Pdf;
    }
    // Also the signature of every OOXML document, because those are zipped.
    if head.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        return Sniffed::Zip;
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Sniffed::Gzip;
    }

    Sniffed::Unknown
}

/// How much of an upload to look at before deciding. Comfortably longer than the longest
/// signature above, which is what makes an [`Sniffed::Unknown`] answer meaningful.
pub const SUGGESTED_HEAD_BYTES: usize = 16;

impl Sniffed {
    /// The media type this signature implies, when it implies exactly one.
    pub fn content_type(self) -> Option<&'static str> {
        match self {
            Self::Png => Some("image/png"),
            Self::Jpeg => Some("image/jpeg"),
            Self::Gif => Some("image/gif"),
            Self::Webp => Some("image/webp"),
            Self::Pdf => Some("application/pdf"),
            Self::Gzip => Some("application/gzip"),
            // A zip is a container that many media types are built on, so it implies nothing on
            // its own.
            Self::Zip | Self::Unknown => None,
        }
    }

    /// Whether a declared media type is consistent with what the bytes actually look like.
    ///
    /// Permissive exactly where a container legitimately carries other media types: a `.docx` is
    /// a zip, so a zip signature must not contradict an OOXML declaration.
    pub fn is_consistent_with(self, declared: &str) -> bool {
        let declared = declared
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        match self {
            Self::Unknown => true,
            Self::Png => declared == "image/png",
            Self::Jpeg => declared == "image/jpeg",
            Self::Gif => declared == "image/gif",
            Self::Webp => declared == "image/webp",
            Self::Pdf => declared == "application/pdf",
            Self::Gzip => matches!(declared.as_str(), "application/gzip" | "application/x-gzip"),
            Self::Zip => {
                declared == "application/zip"
                    || declared.starts_with("application/vnd.openxmlformats-officedocument.")
                    || declared.starts_with("application/vnd.oasis.opendocument.")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_recognised() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n....."), Sniffed::Png);
        assert_eq!(sniff(b"\xff\xd8\xff\xe0"), Sniffed::Jpeg);
        assert_eq!(sniff(b"GIF89a...."), Sniffed::Gif);
        assert_eq!(sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Sniffed::Webp);
        assert_eq!(sniff(b"%PDF-1.7"), Sniffed::Pdf);
        assert_eq!(sniff(b"PK\x03\x04...."), Sniffed::Zip);
        assert_eq!(sniff(b"\x1f\x8b\x08"), Sniffed::Gzip);
        assert_eq!(sniff(b"name,email\n"), Sniffed::Unknown);
        assert_eq!(sniff(b""), Sniffed::Unknown);
    }

    #[test]
    fn a_short_read_is_not_mistaken_for_a_different_format() {
        // Two bytes of a PNG must not read as something else; it is simply inconclusive.
        assert_eq!(sniff(b"\x89P"), Sniffed::Unknown);
    }

    #[test]
    fn a_declared_type_must_agree_with_the_bytes() {
        assert!(Sniffed::Png.is_consistent_with("image/png"));
        assert!(Sniffed::Png.is_consistent_with("image/png; charset=binary"));
        assert!(!Sniffed::Png.is_consistent_with("application/pdf"));
        assert!(!Sniffed::Png.is_consistent_with("text/html"));

        // A container holds many media types, so it constrains far less.
        assert!(Sniffed::Zip.is_consistent_with("application/zip"));
        assert!(Sniffed::Zip.is_consistent_with(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ));
        assert!(!Sniffed::Zip.is_consistent_with("image/png"));

        // Nothing was recognised, so nothing can be contradicted.
        assert!(Sniffed::Unknown.is_consistent_with("text/csv"));
    }
}
