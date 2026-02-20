use vlt_sshd::core_syslog::VltLogger;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_ip =
        std::env::var("VLT_SYSLOG_SERVER").unwrap_or_else(|_| "192.168.1.40".to_string());
    println!("Testing Syslog sending to {} on UDP 514...", server_ip);

    let logger = VltLogger::new(&server_ip, "vlt-test-tool");

    // Send a few test messages
    logger.info("Syslog Integration Test: Phase 15 Verification (Info)").await;
    logger.error("Syslog Integration Test: Phase 15 Verification (Error)").await;
    logger.auth_info("Syslog Integration Test: Authentication Success Simulation").await;

    println!("Test messages sent. Please check the Syslog receiver output.");
    Ok(())
}
