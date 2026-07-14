use super::{Args, LogTarget, ShutdownSignal};
use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::Mutex;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{service_dispatcher, Error as WindowsServiceError};
use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};

const SERVICE_NAME: &str = "meow";
const SERVICE_DISPLAY_NAME: &str = "meow-rs Proxy Service";
const SERVICE_DESCRIPTION: &str = "meow-rs rule-based proxy kernel";
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_DELETE_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

define_windows_service!(ffi_service_main, service_main);

pub(super) fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to connect meow to the Windows Service Control Manager")
}

pub(super) fn install(config_override: Option<&str>, args: &Args) -> Result<()> {
    let current_exe = std::env::current_exe()?;
    let executable_path = canonical_file(&current_exe, "meow executable")?;
    let requested_config = absolute_path(config_override.unwrap_or(&args.config))?;
    let config_path = canonical_file(&requested_config, "configuration file")?;
    let home_dir = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("configuration file has no parent directory")?
        .to_path_buf();
    let log_dir = service_log_dir()?;
    std::fs::create_dir_all(&log_dir).with_context(|| {
        format!(
            "failed to create Windows service log directory {}",
            log_dir.display()
        )
    })?;

    let service_info = build_service_info(&executable_path, &config_path, &home_dir);
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context(
        "failed to open the Windows Service Control Manager; run PowerShell as Administrator",
    )?;

    let service_access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP;

    let (service, updated) = match manager.open_service(SERVICE_NAME, service_access) {
        Ok(service) => {
            stop_and_wait(&service, SERVICE_STOP_TIMEOUT)
                .context("failed to stop the existing meow service before updating it")?;
            service
                .change_config(&service_info)
                .context("failed to update the existing meow service")?;
            (service, true)
        }
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
            let service = manager
                .create_service(&service_info, service_access)
                .context(
                    "failed to create the meow Windows service; run PowerShell as Administrator",
                )?;
            (service, false)
        }
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            anyhow::bail!(
                "the meow service is pending deletion; wait for it to disappear or restart Windows before installing again"
            )
        }
        Err(error) => {
            return Err(error).context(
                "failed to open the meow Windows service; run PowerShell as Administrator",
            )
        }
    };

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("failed to set the meow service description")?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            }]),
        })
        .context("failed to configure meow service recovery")?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .context("failed to enable meow service recovery for non-crash failures")?;

    service
        .start::<&OsStr>(&[])
        .context("failed to start the meow Windows service")?;
    wait_until_running(&service, SERVICE_START_TIMEOUT)?;

    println!(
        "meow service {} and started.",
        if updated { "updated" } else { "installed" }
    );
    println!();
    println!("  Config:  {}", config_path.display());
    println!("  Home:    {}", home_dir.display());
    println!("  Binary:  {}", executable_path.display());
    println!("  Logs:    {}", log_dir.display());
    println!();
    println!("PowerShell commands:");
    println!("  Get-Service {SERVICE_NAME}");
    println!("  Restart-Service {SERVICE_NAME}");
    println!("  Stop-Service {SERVICE_NAME}");

    Ok(())
}

pub(super) fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context(
            "failed to open the Windows Service Control Manager; run PowerShell as Administrator",
        )?;
    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service(SERVICE_NAME, service_access) {
        Ok(service) => service,
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
            println!("meow service is not installed.");
            return Ok(());
        }
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            println!("meow service is already pending deletion.");
            return Ok(());
        }
        Err(error) => {
            return Err(error).context(
                "failed to open the meow Windows service; run PowerShell as Administrator",
            )
        }
    };

    // Mark first so recovery actions cannot start another instance while the
    // current process is shutting down and open handles are being released.
    service
        .delete()
        .context("failed to mark the meow Windows service for deletion")?;
    if let Err(error) = stop_and_wait(&service, SERVICE_STOP_TIMEOUT) {
        eprintln!("warning: {error:#}");
    }
    drop(service);

    let deadline = Instant::now() + SERVICE_DELETE_TIMEOUT;
    while Instant::now() < deadline {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(error) if is_winapi_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
                println!("meow service uninstalled.");
                println!("Configuration and logs were preserved.");
                return Ok(());
            }
            Err(error) if is_winapi_error(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {}
            Err(error) => return Err(error).context("failed while waiting for service deletion"),
            Ok(service) => drop(service),
        }
        thread::sleep(POLL_INTERVAL);
    }

    println!(
        "meow service is marked for deletion and will be removed after all handles close or Windows restarts."
    );
    println!("Configuration and logs were preserved.");
    Ok(())
}

pub(super) fn status() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to open the Windows Service Control Manager")?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
            println!("meow service is not installed.");
            return Ok(());
        }
        Err(error) if is_winapi_error(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            println!("meow service is pending deletion.");
            return Ok(());
        }
        Err(error) => return Err(error).context("failed to open the meow Windows service"),
    };

    let service_status = service
        .query_status()
        .context("failed to query the meow Windows service status")?;
    print!("{}", format_service_status(&service_status));
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        // A service process has no visible console, but this still helps when
        // the internal entry point is invoked manually while debugging.
        eprintln!("meow Windows service failed: {error:#}");
    }
}

fn run_service() -> Result<()> {
    let mut args = Args::try_parse().context("failed to parse Windows service launch arguments")?;
    args.command = None;
    let log_dir = service_log_dir()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    struct ControlState {
        status_handle: Option<ServiceStatusHandle>,
        shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
        stopping: bool,
    }

    let control_state = Arc::new(Mutex::new(ControlState {
        status_handle: None,
        shutdown_tx: Some(shutdown_tx),
        stopping: false,
    }));
    let handler_state = Arc::clone(&control_state);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let mut state = handler_state.lock();
                state.stopping = true;
                if let Some(status_handle) = state.status_handle {
                    let _ = status_handle.set_service_status(stop_pending_status());
                }
                if let Some(sender) = state.shutdown_tx.take() {
                    let _ = sender.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("failed to register the meow service control handler")?;
    {
        let mut state = control_state.lock();
        state.status_handle = Some(status_handle);
        status_handle.set_service_status(if state.stopping {
            stop_pending_status()
        } else {
            running_status()
        })?;
    }

    let result = super::run_application(
        args,
        LogTarget::WindowsService(log_dir),
        ShutdownSignal::WindowsService(shutdown_rx),
    );
    if let Err(error) = &result {
        tracing::error!(error = %format_args!("{error:#}"), "Windows service stopped with an error");
    }

    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    let status_result = status_handle.set_service_status(stopped_status(exit_code));

    match result {
        Err(error) => Err(error),
        Ok(()) => status_result.context("failed to report the stopped service status"),
    }
}

fn absolute_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn canonical_file(path: &Path, description: &str) -> Result<PathBuf> {
    if !path.is_file() {
        anyhow::bail!("{description} not found: {}", path.display());
    }
    path.canonicalize()
        .with_context(|| format!("failed to resolve {description}: {}", path.display()))
}

fn program_data_dir() -> Result<PathBuf> {
    std::env::var_os("ProgramData")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("ProgramData environment variable is not set")
}

fn log_dir_from_program_data(program_data: &Path) -> PathBuf {
    program_data.join("meow").join("logs")
}

fn service_log_dir() -> Result<PathBuf> {
    Ok(log_dir_from_program_data(&program_data_dir()?))
}

fn build_service_info(executable: &Path, config: &Path, home_dir: &Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments: vec![
            OsString::from("-f"),
            config.as_os_str().to_os_string(),
            OsString::from("-d"),
            home_dir.as_os_str().to_os_string(),
            OsString::from("run-service"),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

fn wait_until_running(
    service: &windows_service::service::Service,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status()?;
        match status.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped => {
                anyhow::bail!(
                    "meow service stopped during startup with exit code {:?}; check the service log",
                    status.exit_code
                )
            }
            _ if Instant::now() >= deadline => {
                anyhow::bail!("timed out waiting for the meow service to start")
            }
            _ => thread::sleep(POLL_INTERVAL),
        }
    }
}

fn stop_and_wait(service: &windows_service::service::Service, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status()?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }

        if status.current_state != ServiceState::StopPending {
            match service.stop() {
                Ok(_) => {}
                Err(error) if is_winapi_error(&error, ERROR_SERVICE_NOT_ACTIVE) => return Ok(()),
                Err(error) if is_winapi_error(&error, ERROR_SERVICE_CANNOT_ACCEPT_CTRL) => {}
                Err(error) => return Err(error).context("failed to request service stop"),
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for the meow service to stop");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn is_winapi_error(error: &WindowsServiceError, code: u32) -> bool {
    matches!(
        error,
        WindowsServiceError::Winapi(error) if error.raw_os_error() == Some(code as i32)
    )
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 1,
        wait_hint: SERVICE_STOP_TIMEOUT,
        process_id: None,
    }
}

fn stopped_status(exit_code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

fn format_service_status(status: &ServiceStatus) -> String {
    let pid = status
        .process_id
        .map_or_else(|| "-".to_string(), |pid| pid.to_string());
    format!(
        "Service: {SERVICE_NAME}\nState: {:?}\nPID: {pid}\nExit code: {:?}\n",
        status.current_state, status.exit_code
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_info_preserves_unicode_paths_and_expected_launch_order() {
        let executable = Path::new(r"C:\Program Files\meow 猫\meow.exe");
        let config = Path::new(r"C:\Users\测试 User\配置 files\config.yaml");
        let home = config.parent().unwrap();
        let info = build_service_info(executable, config, home);

        assert_eq!(info.name, OsStr::new(SERVICE_NAME));
        assert_eq!(info.display_name, OsStr::new(SERVICE_DISPLAY_NAME));
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(info.executable_path, executable);
        assert_eq!(
            info.launch_arguments,
            vec![
                OsString::from("-f"),
                config.as_os_str().to_os_string(),
                OsString::from("-d"),
                home.as_os_str().to_os_string(),
                OsString::from("run-service"),
            ]
        );
        assert!(info.account_name.is_none());
        assert!(info.account_password.is_none());
    }

    #[test]
    fn service_log_directory_is_under_program_data() {
        let program_data = Path::new(r"D:\Shared Program Data");
        assert_eq!(
            log_dir_from_program_data(program_data),
            PathBuf::from(r"D:\Shared Program Data\meow\logs")
        );
    }

    #[test]
    fn status_output_contains_state_pid_and_exit_code() {
        let status = ServiceStatus {
            process_id: Some(4242),
            ..running_status()
        };
        let output = format_service_status(&status);
        assert!(output.contains("State: Running"));
        assert!(output.contains("PID: 4242"));
        assert!(output.contains("Exit code: Win32(0)"));
    }

    #[tokio::test]
    async fn windows_service_shutdown_signal_completes() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        sender.send(()).unwrap();
        ShutdownSignal::WindowsService(receiver)
            .wait()
            .await
            .unwrap();
    }
}
