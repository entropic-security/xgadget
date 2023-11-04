use thiserror;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Library errors
pub enum Error {
    /// Unsupported architecture
    #[error("unsupported architecture")]
    UnsupportedArch,
    /// Unsupported file format
    #[error("unsupported file format")]
    UnsupportedFileFormat,
    /// Failed to determine filename
    #[error("failed to determine filename")]
    NoFileName,
    /// No binaries to search
    #[error("No binaries to search")]
    NoBinaries,
    /// Failed to read binary file
    #[error("failed to read binary file")]
    FileReadError(#[from] std::io::Error),
}
