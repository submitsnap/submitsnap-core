//! File storage, and the deliberate possibility of having none.
//!
//! Storage is optional: a deployment that never sets `S3_BUCKET` keeps every other feature, and
//! the only consequence is that a form containing a file field cannot be published. That is why
//! this is an enum with a `Disabled` arm rather than an `Option` checked ad hoc at each call
//! site — every caller has to state what it does without storage, and the compiler insists.
//!
//! Uploads are streamed through this service rather than handed to the browser as presigned URLs.
//! The trade is bandwidth for enforcement: a presigned PUT never shows us the bytes, so
//! `max_bytes` and the accepted content types would only ever validate what the client *claimed*.
//! Here the real size is counted and the real bytes are inspected, and the bucket itself can stay
//! entirely private with no CORS configuration.

use anyhow::Context;
use bytes::Bytes;
use futures_util::{StreamExt, stream::BoxStream};
use object_store::{
    ObjectStore, ObjectStoreExt, WriteMultipart, aws::AmazonS3Builder, path::Path as ObjectPath,
};
use secrecy::ExposeSecret;

use crate::shared::config::AppConfig;

/// How much is buffered before a part is handed to the bucket.
///
/// Fixed rather than "whatever the client sent", because Cloudflare R2 requires every part except
/// the last to be exactly the same size.
const PART_SIZE: usize = 5 * 1024 * 1024;

/// How many parts may be in flight for one upload. This is what bounds the memory a single upload
/// can occupy, and therefore what stops a large file from becoming a memory attack.
const MAX_PARTS_IN_FLIGHT: usize = 4;

/// Recorded when a client sends no usable `Content-Type`.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Handle for an object being written, discarded, or read.
#[derive(Debug)]
pub enum FileStorage {
    Disabled,
    S3(Box<S3Storage>),
}

#[derive(Debug)]
pub struct S3Storage {
    store: Box<dyn ObjectStore>,
    bucket: String,
    endpoint: Option<String>,
}

/// An object being read back, with the size the caller needs for `Content-Length`.
pub struct StoredObject {
    pub stream: BoxStream<'static, Result<Bytes, StorageError>>,
    pub size: u64,
}

/// A write in progress. Bytes are handed over as they arrive, so the file never has to fit in
/// memory — which is the whole reason this is a streaming writer rather than a `put` of a buffer.
pub struct UploadWriter {
    multipart: WriteMultipart,
    written: u64,
    limit: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("file storage is not configured")]
    NotConfigured,
    #[error("the file exceeds the {limit} byte limit")]
    TooLarge { limit: u64 },
    #[error("the stored file was not found")]
    NotFound,
    #[error("storage error")]
    Internal(#[from] anyhow::Error),
}

impl FileStorage {
    pub fn from_config(config: &AppConfig) -> anyhow::Result<Self> {
        let Some(bucket) = non_empty(config.s3_bucket.as_deref()) else {
            return Ok(Self::Disabled);
        };

        let endpoint = non_empty(config.s3_endpoint.as_deref());
        // Plain http is what a local MinIO uses, so it is honoured when the endpoint asks for it
        // — and reported at startup, because in production it would put both the credentials and
        // the files on the wire in the clear.
        let allow_http = endpoint.is_some_and(|endpoint| endpoint.starts_with("http://"));

        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(config.s3_region.trim())
            .with_allow_http(allow_http)
            .with_virtual_hosted_style_request(!config.s3_force_path_style);

        if let Some(endpoint) = endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        if let Some(key_id) = non_empty(config.s3_access_key_id.as_deref()) {
            builder = builder.with_access_key_id(key_id);
        }
        if let Some(secret) = &config.s3_secret_access_key {
            builder = builder.with_secret_access_key(secret.expose_secret());
        }

        let store = builder.build().context("the S3 settings are not usable")?;

        Ok(Self::S3(Box::new(S3Storage {
            store: Box::new(store),
            bucket: bucket.to_owned(),
            endpoint: endpoint.map(str::to_owned),
        })))
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::S3(_))
    }

    /// A description for the startup banner. Never includes a credential.
    pub fn describe(&self) -> String {
        match self {
            Self::Disabled => "disabled (file fields cannot be published)".to_owned(),
            Self::S3(storage) => match &storage.endpoint {
                Some(endpoint) => format!("s3://{} via {endpoint}", storage.bucket),
                None => format!("s3://{}", storage.bucket),
            },
        }
    }

    /// Whether files and credentials travel unencrypted to the bucket.
    pub fn uses_plaintext(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::S3(storage) => storage
                .endpoint
                .as_deref()
                .is_some_and(|endpoint| endpoint.starts_with("http://")),
        }
    }

    /// Starts a streamed write, refusing to accept more than `limit` bytes.
    pub async fn begin_upload(&self, key: &str, limit: u64) -> Result<UploadWriter, StorageError> {
        let Self::S3(s3) = self else {
            return Err(StorageError::NotConfigured);
        };

        let path = ObjectPath::parse(key).map_err(|error| {
            StorageError::Internal(anyhow::anyhow!("unusable object key {key:?}: {error}"))
        })?;

        let upload = s3
            .store
            .put_multipart(&path)
            .await
            .map_err(map_object_error)?;

        Ok(UploadWriter {
            multipart: WriteMultipart::new_with_chunk_size(upload, PART_SIZE),
            written: 0,
            limit,
        })
    }

    /// Opens a streamed read.
    pub async fn open(&self, key: &str) -> Result<StoredObject, StorageError> {
        let Self::S3(s3) = self else {
            return Err(StorageError::NotConfigured);
        };

        let path = ObjectPath::parse(key)
            .map_err(|error| StorageError::Internal(anyhow::anyhow!("unusable key: {error}")))?;
        let result = s3.store.get(&path).await.map_err(map_object_error)?;
        let size = result.meta.size;

        Ok(StoredObject {
            stream: result
                .into_stream()
                .map(|chunk| chunk.map_err(map_object_error))
                .boxed(),
            size,
        })
    }

    /// Removes an object. A missing object is not an error: both the reaper and the delete paths
    /// must be safe to run twice.
    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let Self::S3(s3) = self else {
            return Err(StorageError::NotConfigured);
        };

        let path = ObjectPath::parse(key)
            .map_err(|error| StorageError::Internal(anyhow::anyhow!("unusable key: {error}")))?;

        match s3.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(map_object_error(error)),
        }
    }
}

impl UploadWriter {
    /// Accepts the next chunk, or refuses once the running total has passed the limit.
    ///
    /// The limit is enforced by counting what actually arrives, not by trusting a declared size,
    /// which is the whole reason uploads come through this service.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), StorageError> {
        let total = self.written + chunk.len() as u64;
        if total > self.limit {
            return Err(StorageError::TooLarge { limit: self.limit });
        }

        // Backpressure: without this a fast client would keep buffering parts in memory while the
        // bucket lagged behind.
        self.multipart
            .wait_for_capacity(MAX_PARTS_IN_FLIGHT)
            .await
            .map_err(map_object_error)?;
        self.multipart.write(chunk);
        self.written = total;

        Ok(())
    }

    /// Completes the write and reports how many bytes were stored.
    pub async fn finish(self) -> Result<u64, StorageError> {
        self.multipart.finish().await.map_err(map_object_error)?;
        Ok(self.written)
    }

    /// How many bytes have been accepted so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Throws away a partial upload. Called whenever a request fails after bytes have been sent,
    /// so a rejected file leaves nothing behind in the bucket.
    pub async fn abort(self) -> Result<(), StorageError> {
        self.multipart.abort().await.map_err(map_object_error)
    }
}

fn map_object_error(error: object_store::Error) -> StorageError {
    match error {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Internal(other.into()),
    }
}

/// A blank value is how a `.env` file says "not set", so blank is treated as absent everywhere.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}
