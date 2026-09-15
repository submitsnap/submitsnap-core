use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn users_schema_is_available(pool: PgPool) {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
