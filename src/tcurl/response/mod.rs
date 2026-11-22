use crate::transport::response_header_end;
use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub async fn handle_response(
    response: &[u8],
    head: bool,
    output: &Option<PathBuf>,
    output_header: &Option<PathBuf>,
) -> Result<()> {
    let header_end = response_header_end(response)
        .ok_or_else(|| anyhow!("Server returned an incomplete response"))?;

    let header = &response[..header_end];
    let body = if head {
        &response[header_end..header_end]
    } else {
        &response[header_end..]
    };

    let header_text = String::from_utf8_lossy(header);

    for line in header_text.lines() {
        eprintln!("{line}");
    }

    if let Some(path) = output_header {
        tokio::fs::write(path, response)
            .await
            .with_context(|| format!("Cannot save complete response to {}", path.display()))?;
    }

    if let Some(path) = output {
        tokio::fs::write(path, body)
            .await
            .with_context(|| format!("Cannot save response body to {}", path.display()))?;
    } else {
        let mut stdout = tokio::io::stdout();
        stdout.write_all(body).await?;
        stdout.flush().await?;
    }

    Ok(())
}
