use tracing_subscriber;

pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
}
