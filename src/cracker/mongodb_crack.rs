//! MongoDB 爆破模块

use async_trait::async_trait;
use mongodb::{Client, options::ClientOptions};
use std::time::Duration;

use crate::cracker::base;
use crate::cracker::service::{CrackConfig, CrackResult, CrackService, Cracker};

/// MongoDB 爆破器
pub struct MongodbCracker;

impl MongodbCracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MongodbCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cracker for MongodbCracker {
    async fn crack(&self, config: &CrackConfig) -> CrackResult {
        let target = config.target.clone();
        let port = config.port;

        base::run_crack(config, CrackService::Mongodb, "MongoDB", move |_username, password, _, _, timeout| {
            let connection_string = format!(
                "mongodb://:{}@{}:{}/admin",
                password, target, port
            );

            // 使用 tokio runtime 执行异步连接
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return false,
            };

            rt.block_on(async {
                match tokio::time::timeout(timeout, async {
                    match ClientOptions::parse(&connection_string).await {
                        Ok(opts) => {
                            match Client::with_options(opts) {
                                Ok(_) => true,
                                Err(_) => false,
                            }
                        }
                        Err(_) => false,
                    }
                }).await
                {
                    Ok(success) => success,
                    Err(_) => false,
                }
            })
        }).await
    }

    async fn verify(&self, target: &str, port: u16, _username: Option<&str>, password: &str) -> bool {
        Self::try_connect_async(target, port, password, Duration::from_secs(5)).await
    }
}

impl MongodbCracker {
    async fn try_connect_async(target: &str, port: u16, password: &str, timeout: Duration) -> bool {
        let connection_string = format!(
            "mongodb://:{}@{}:{}/admin",
            password, target, port
        );

        match tokio::time::timeout(timeout, async {
            match ClientOptions::parse(&connection_string).await {
                Ok(opts) => {
                    match Client::with_options(opts) {
                        Ok(_) => true,
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        }).await
        {
            Ok(success) => success,
            Err(_) => false,
        }
    }
}
