use deadpool_redis::{Config, Pool, Runtime};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

const EMAIL_QUEUE_SUFFIX: &str = "email-jobs";
const EMAIL_DEAD_LETTER_SUFFIX: &str = "email-dead-letter";

#[derive(Clone)]
pub struct EmailQueue {
    pool: Pool,
    keys: QueueKeys,
}

/// Where this deployment's queues live. Prefixed so two deployments, or a test and a
/// development instance, can share one Redis without taking each other's jobs.
#[derive(Debug, Clone)]
struct QueueKeys {
    jobs: String,
    dead_letter: String,
}

impl QueueKeys {
    fn new(prefix: &str) -> Self {
        let prefix = prefix.trim().trim_end_matches(':');
        Self {
            jobs: format!("{prefix}:{EMAIL_QUEUE_SUFFIX}"),
            dead_letter: format!("{prefix}:{EMAIL_DEAD_LETTER_SUFFIX}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailJob {
    pub to: String,
    pub subject: String,
    pub text_body: String,
}

impl EmailQueue {
    pub fn connect(redis_url: &str, key_prefix: &str) -> anyhow::Result<Self> {
        let config = Config::from_url(redis_url);
        let pool = config.create_pool(Some(Runtime::Tokio1))?;
        Ok(Self {
            pool,
            keys: QueueKeys::new(key_prefix),
        })
    }

    pub async fn enqueue(&self, job: &EmailJob) -> anyhow::Result<()> {
        let payload = serde_json::to_string(job)?;
        let mut connection = self.pool.get().await?;
        connection
            .rpush::<_, _, ()>(&self.keys.jobs, payload)
            .await?;
        Ok(())
    }

    pub async fn dequeue(&self) -> anyhow::Result<Option<EmailJob>> {
        let mut connection = self.pool.get().await?;
        let payload: Option<String> = connection.lpop(&self.keys.jobs, None).await?;
        payload
            .map(|item| serde_json::from_str(&item))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn dead_letter(&self, job: &EmailJob) -> anyhow::Result<()> {
        let payload = serde_json::to_string(job)?;
        let mut connection = self.pool.get().await?;
        connection
            .rpush::<_, _, ()>(&self.keys.dead_letter, payload)
            .await?;
        Ok(())
    }

    /// How many jobs are waiting. Used by tests and by an operator asking whether the worker is
    /// keeping up.
    pub async fn pending(&self) -> anyhow::Result<i64> {
        let mut connection = self.pool.get().await?;
        let length: i64 = connection.llen(&self.keys.jobs).await?;
        Ok(length)
    }

    /// Removes this deployment's keys. Only ever called by tests.
    pub async fn clear(&self) -> anyhow::Result<()> {
        let mut connection = self.pool.get().await?;
        redis::cmd("DEL")
            .arg(&self.keys.jobs)
            .arg(&self.keys.dead_letter)
            .query_async::<i64>(&mut connection)
            .await?;
        Ok(())
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut connection = self.pool.get().await?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await?;
        Ok(())
    }
}
