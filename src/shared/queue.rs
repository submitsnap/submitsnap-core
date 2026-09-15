use deadpool_redis::{Config, Pool, Runtime};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

const EMAIL_QUEUE_KEY: &str = "submitsnap:email-jobs";
const EMAIL_DEAD_LETTER_QUEUE_KEY: &str = "submitsnap:email-dead-letter";

#[derive(Clone)]
pub struct EmailQueue {
    pool: Pool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailJob {
    pub to: String,
    pub subject: String,
    pub text_body: String,
}

impl EmailQueue {
    pub fn connect(redis_url: &str) -> anyhow::Result<Self> {
        let config = Config::from_url(redis_url);
        let pool = config.create_pool(Some(Runtime::Tokio1))?;
        Ok(Self { pool })
    }

    pub async fn enqueue(&self, job: &EmailJob) -> anyhow::Result<()> {
        let payload = serde_json::to_string(job)?;
        let mut connection = self.pool.get().await?;
        connection
            .rpush::<_, _, ()>(EMAIL_QUEUE_KEY, payload)
            .await?;
        Ok(())
    }

    pub async fn dequeue(&self) -> anyhow::Result<Option<EmailJob>> {
        let mut connection = self.pool.get().await?;
        let payload: Option<String> = connection.lpop(EMAIL_QUEUE_KEY, None).await?;
        payload
            .map(|item| serde_json::from_str(&item))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn dead_letter(&self, job: &EmailJob) -> anyhow::Result<()> {
        let payload = serde_json::to_string(job)?;
        let mut connection = self.pool.get().await?;
        connection
            .rpush::<_, _, ()>(EMAIL_DEAD_LETTER_QUEUE_KEY, payload)
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
