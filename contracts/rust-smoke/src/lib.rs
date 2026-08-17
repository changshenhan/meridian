//! contract-smoke 共享件库：让 `main.rs`（S-11d 三场景）与 `bin/m1_demo.rs`（S-14 M1）
//! 复用同一套 anvil 部署 / sol! 绑定 / 信封构造，避免重复维护。

pub mod common;
