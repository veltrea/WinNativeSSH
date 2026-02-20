pub const EVT_SERVICE_START: &str = "1000";
pub const EVT_SERVICE_STOP: &str = "1001";
pub const EVT_AUTH_SUCCESS: &str = "1100";
pub const EVT_AUTH_FAIL: &str = "1101";
pub const EVT_SESSION_START: &str = "1200";
pub const EVT_SESSION_END: &str = "1201";
pub const EVT_CHANNEL_OPEN: &str = "1300";
pub const EVT_CHANNEL_DENIED: &str = "1301";
pub const EVT_POLICY_CHANGED: &str = "1400";
pub const EVT_KEY_EVENT: &str = "1500";
pub const EVT_USER_STATE: &str = "1600";

pub fn is_warning(code: &str) -> bool {
    matches!(code, EVT_AUTH_FAIL | EVT_CHANNEL_DENIED)
}
