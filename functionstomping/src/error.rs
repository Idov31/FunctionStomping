use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("Usage: funquerade <pid>")]
    CliUsage,
    #[error("Invalid PID!")]
    InvalidPID,
    #[error("Cannot find module on the specified executable!")]
    InvalidModuleName,
    #[error("Cannot write more than 4096 bytes!")]
    ShellcodeTooBig
}