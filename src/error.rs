use thiserror;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unsupported architecture")]
    UnsupportedArch,
    #[error("unsupported file format")]
    UnsupportedFileFormat,
    #[error("failed to determine filename")]
    NoFileName,
    #[error("No binaries to search")]
    NoBinaries,
    #[error("failed to read binary file")]
    FileReadError(#[from] std::io::Error),
    // TODO: remove this
    #[error("should be removed")]
    TemporaryError,
}
