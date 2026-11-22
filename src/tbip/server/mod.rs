mod accept;
mod dispatch;
mod stream;

pub async fn run() -> anyhow::Result<()> {
	accept::run().await
}
