use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn json_field(name: &str, value: Option<String>) -> String {
    match value {
        Some(v) => format!("\"{}\":\"{}\"", name, escape_json(&v)),
        None => format!("\"{}\":null", name),
    }
}

fn json_number_field(name: &str, value: Option<u64>) -> String {
    match value {
        Some(v) => format!("\"{}\":{}", name, v),
        None => format!("\"{}\":null", name),
    }
}

fn get_hostname() -> String {
    run_command("hostname", &[]).unwrap_or_else(|| "Unknown".to_string())
}

// -------------------------
// Windows collectors
// -------------------------

#[cfg(target_os = "windows")]
fn query_registry_value(path: &str, value_name: &str) -> Option<String> {
    let output = run_command("reg", &["query", path, "/v", value_name])?;

    for line in output.lines() {
        if line.contains(value_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 3 {
                return Some(parts[2..].join(" "));
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn query_registry_u64(path: &str, value_name: &str) -> Option<u64> {
    query_registry_value(path, value_name).and_then(|v| v.parse::<u64>().ok())
}

#[cfg(target_os = "windows")]
fn windows_product_from_build(build: u64) -> &'static str {
    if build >= 22000 {
        "Windows 11"
    } else if build >= 10240 {
        "Windows 10"
    } else {
        "Windows"
    }
}

#[cfg(target_os = "windows")]
fn get_file_version(path: &str) -> Option<String> {
    if !Path::new(path).exists() {
        return None;
    }

    let ps_script = format!(
        "(Get-Item '{}').VersionInfo.ProductVersion",
        path.replace('\'', "''")
    );

    run_command("powershell", &["-NoProfile", "-Command", &ps_script])
}

#[cfg(target_os = "windows")]
fn get_os_info() -> String {
    let nt_path = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    let raw_product_name = query_registry_value(nt_path, "ProductName")
        .unwrap_or_else(|| "Unknown".to_string());

    let display_version = query_registry_value(nt_path, "DisplayVersion")
        .or_else(|| query_registry_value(nt_path, "ReleaseId"))
        .unwrap_or_else(|| "Unknown".to_string());

    let current_build = query_registry_u64(nt_path, "CurrentBuildNumber")
        .or_else(|| query_registry_u64(nt_path, "CurrentBuild"));

    let ubr = query_registry_u64(nt_path, "UBR");

    let corrected_product_name = current_build
        .map(windows_product_from_build)
        .unwrap_or("Windows");

    let full_build = match (current_build, ubr) {
        (Some(build), Some(ubr)) => format!("{}.{}", build, ubr),
        (Some(build), None) => build.to_string(),
        (None, _) => "Unknown".to_string(),
    };

    format!(
        "{{\"platform\":\"windows\",\"product_name\":\"{}\",\"raw_product_name\":\"{}\",\"display_version\":\"{}\",\"build\":\"{}\",{},{}}}",
        escape_json(corrected_product_name),
        escape_json(&raw_product_name),
        escape_json(&display_version),
        escape_json(&full_build),
        json_number_field("build_number", current_build),
        json_number_field("ubr", ubr)
    )
}

#[cfg(target_os = "windows")]
fn get_browser_versions() -> String {
    let chrome = query_registry_value(r"HKCU\Software\Google\Chrome\BLBeacon", "version")
        .or_else(|| query_registry_value(r"HKLM\Software\Google\Chrome\BLBeacon", "version"))
        .or_else(|| get_file_version(r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
        .or_else(|| get_file_version(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"));

    let edge = query_registry_value(r"HKCU\Software\Microsoft\Edge\BLBeacon", "version")
        .or_else(|| query_registry_value(r"HKLM\Software\Microsoft\Edge\BLBeacon", "version"))
        .or_else(|| get_file_version(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"))
        .or_else(|| get_file_version(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"));

    let firefox = query_registry_value(r"HKLM\Software\Mozilla\Mozilla Firefox", "CurrentVersion")
        .or_else(|| get_file_version(r"C:\Program Files\Mozilla Firefox\firefox.exe"))
        .or_else(|| get_file_version(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"));

    let opera = get_file_version(r"C:\Program Files\Opera\launcher.exe")
        .or_else(|| get_file_version(r"C:\Program Files (x86)\Opera\launcher.exe"));

    format!(
        "{{{},{},{},{}}}",
        json_field("chrome", chrome),
        json_field("edge", edge),
        json_field("firefox", firefox),
        json_field("opera", opera)
    )
}

// -------------------------
// macOS collectors
// -------------------------

#[cfg(target_os = "macos")]
fn get_macos_app_plist_value(app_path: &str, key: &str) -> Option<String> {
    let plist_path = format!("{}/Contents/Info.plist", app_path);

    if !Path::new(&plist_path).exists() {
        return None;
    }

    run_command("defaults", &["read", &plist_path, key])
}

#[cfg(target_os = "macos")]
fn get_macos_app_version(app_path: &str) -> Option<String> {
    get_macos_app_plist_value(app_path, "CFBundleShortVersionString")
}

#[cfg(target_os = "macos")]
fn get_macos_app_full_version(app_path: &str) -> Option<String> {
    get_macos_app_plist_value(app_path, "CFBundleVersion")
        .or_else(|| get_macos_app_plist_value(app_path, "CFBundleShortVersionString"))
}

#[cfg(target_os = "macos")]
fn get_os_info() -> String {
    let product_name = run_command("sw_vers", &["-productName"])
        .unwrap_or_else(|| "Unknown".to_string());

    let product_version = run_command("sw_vers", &["-productVersion"])
        .unwrap_or_else(|| "Unknown".to_string());

    let build_version = run_command("sw_vers", &["-buildVersion"])
        .unwrap_or_else(|| "Unknown".to_string());

    let kernel = run_command("uname", &["-r"])
        .unwrap_or_else(|| "Unknown".to_string());

    format!(
        "{{\"platform\":\"macos\",\"product_name\":\"{}\",\"product_version\":\"{}\",\"build\":\"{}\",\"kernel\":\"{}\"}}",
        escape_json(&product_name),
        escape_json(&product_version),
        escape_json(&build_version),
        escape_json(&kernel)
    )
}

#[cfg(target_os = "macos")]
fn get_browser_versions() -> String {
    let chrome = get_macos_app_version("/Applications/Google Chrome.app");
    let edge = get_macos_app_version("/Applications/Microsoft Edge.app");
    let firefox = get_macos_app_version("/Applications/Firefox.app");
    let brave = get_macos_app_version("/Applications/Brave Browser.app");
    let safari = get_macos_app_version("/Applications/Safari.app");
    let opera = get_macos_app_full_version("/Applications/Opera.app");
    let opera_gx = get_macos_app_full_version("/Applications/Opera GX.app");

    format!(
        "{{{},{},{},{},{},{},{}}}",
        json_field("chrome", chrome),
        json_field("edge", edge),
        json_field("firefox", firefox),
        json_field("brave", brave),
        json_field("safari", safari),
        json_field("opera", opera),
        json_field("opera_gx", opera_gx)
    )
}

// -------------------------
// Linux collectors
// -------------------------

#[cfg(target_os = "linux")]
fn read_os_release_value(key: &str) -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{}=", key)) {
            return Some(rest.trim_matches('"').to_string());
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn command_exists(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {} >/dev/null 2>&1", program))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn get_binary_version(binary_names: &[&str]) -> Option<String> {
    for binary in binary_names {
        if command_exists(binary) {
            if let Some(version) = run_command(binary, &["--version"]) {
                return Some(version);
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn get_os_info() -> String {
    let pretty_name = read_os_release_value("PRETTY_NAME")
        .unwrap_or_else(|| "Unknown".to_string());

    let id = read_os_release_value("ID")
        .unwrap_or_else(|| "Unknown".to_string());

    let version_id = read_os_release_value("VERSION_ID")
        .unwrap_or_else(|| "Unknown".to_string());

    let version_codename = read_os_release_value("VERSION_CODENAME")
        .or_else(|| read_os_release_value("UBUNTU_CODENAME"));

    let id_like = read_os_release_value("ID_LIKE");

    let kernel = run_command("uname", &["-r"])
        .unwrap_or_else(|| "Unknown".to_string());

    format!(
        "{{\"platform\":\"linux\",\"pretty_name\":\"{}\",\"id\":\"{}\",\"id_like\":{},\"version_id\":\"{}\",\"version_codename\":{},\"kernel\":\"{}\"}}",
        escape_json(&pretty_name),
        escape_json(&id),
        match id_like {
            Some(v) => format!("\"{}\"", escape_json(&v)),
            None => "null".to_string(),
        },
        escape_json(&version_id),
        match version_codename {
            Some(v) => format!("\"{}\"", escape_json(&v)),
            None => "null".to_string(),
        },
        escape_json(&kernel)
    )
}

#[cfg(target_os = "linux")]
fn get_browser_versions() -> String {
    let chrome = get_binary_version(&[
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ]);

    let firefox = get_binary_version(&[
        "firefox",
        "firefox-esr",
    ]);

    let edge = get_binary_version(&[
        "microsoft-edge",
        "microsoft-edge-stable",
        "msedge",
    ]);

    let brave = get_binary_version(&[
        "brave-browser",
        "brave",
    ]);

    let opera = get_binary_version(&[
        "opera",
        "opera-stable",
    ]);

    format!(
        "{{{},{},{},{},{}}}",
        json_field("chrome_or_chromium", chrome),
        json_field("firefox", firefox),
        json_field("edge", edge),
        json_field("brave", brave),
        json_field("opera", opera)
    )
}

// -------------------------
// Unsupported fallback
// -------------------------

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn get_os_info() -> String {
    "{\"platform\":\"unsupported\"}".to_string()
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn get_browser_versions() -> String {
    "{}".to_string()
}

// -------------------------
// Basic network discovery
// -------------------------

fn get_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;

    // Does not actually send meaningful data. It asks the OS which local
    // address would be used to reach this destination.
    socket.connect("8.8.8.8:80").ok()?;

    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn tcp_probe(ip: Ipv4Addr, ports: &[u16], timeout_ms: u64) -> Vec<String> {
    let mut results = Vec::new();

    for port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);

        let status = match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
            Ok(_) => "open".to_string(),

            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => "closed".to_string(),
                io::ErrorKind::TimedOut => "timeout_or_filtered".to_string(),
                io::ErrorKind::HostUnreachable => "host_unreachable".to_string(),
                io::ErrorKind::NetworkUnreachable => "network_unreachable".to_string(),
                _ => format!("error:{}", escape_json(&e.to_string())),
            },
        };

        results.push(format!(
            "{{\"port\":{},\"status\":\"{}\"}}",
            port,
            status
        ));
    }

    results
}

fn scan_local_24() -> String {
    let local_ip = match get_local_ipv4() {
        Some(ip) => ip,
        None => {
            return "{\"error\":\"could_not_determine_local_ipv4\"}".to_string();
        }
    };

    let octets = local_ip.octets();

    let ports = vec![22, 53, 80, 443, 445, 3389];
    let timeout_ms = 250;

    let mut handles = Vec::new();

    for host in 1..=254u8 {
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], host);

        if ip == local_ip {
            continue;
        }

        let ports_clone = ports.clone();

        let handle = thread::spawn(move || {
            let open_ports = tcp_probe(ip, &ports_clone, timeout_ms);

            if open_ports.is_empty() {
                None
            } else {
                Some((ip, open_ports))
            }
        });

        handles.push(handle);
    }

    let mut hosts = Vec::new();

    for handle in handles {
        if let Ok(Some((ip, open_ports))) = handle.join() {
            let open_only: Vec<String> = open_ports
                .into_iter()
                .filter(|p| p.contains("\"status\":\"open\""))
                .collect();

            if open_only.is_empty() {
                continue;
            }

            let ports_json = open_only.join(",");

            hosts.push(format!(
                "{{\"ip\":\"{}\",\"open_ports\":[{}]}}",
                ip,
                ports_json
            ));
        }
    }

    format!(
        "{{\"method\":\"tcp_connect\",\"local_ip\":\"{}\",\"assumed_subnet\":\"{}.{}.{}.0/24\",\"tested_ports\":[22,53,80,443,445,3389],\"hosts\":[{}]}}",
        local_ip,
        octets[0],
        octets[1],
        octets[2],
        hosts.join(",")
    )
}

// -------------------------
// Main
// -------------------------

// -------------------------
// External version check
// -------------------------

fn fetch_url(url: &str) -> Option<String> {
    // Prefer curl because it is available by default on macOS and most Linux installs,
    // and is also present on many modern Windows systems.
    let curl_output = run_command("curl", &["-fsSL", url]);

    if let Some(output) = curl_output {
        return Some(output);
    }

    // Windows fallback if curl is unavailable or blocked.
    #[cfg(target_os = "windows")]
    {
        let ps_script = format!(
            "(Invoke-WebRequest -UseBasicParsing -Uri '{}').Content",
            url.replace('\'', "''")
        );

        return run_command("powershell", &["-NoProfile", "-Command", &ps_script]);
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn extract_json_string_value(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let key_pos = json.find(&needle)?;
    let after_key = &json[key_pos + needle.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if !after_colon.starts_with('"') {
        return None;
    }

    let value_start = 1;
    let value_end = after_colon[value_start..].find('"')? + value_start;
    Some(after_colon[value_start..value_end].to_string())
}

fn extract_first_dotted_version_after(text: &str, marker: &str) -> Option<String> {
    let marker_pos = text.find(marker)?;
    let after_marker = &text[marker_pos + marker.len()..];

    let mut started = false;
    let mut version = String::new();

    for ch in after_marker.chars() {
        if ch.is_ascii_digit() || (started && ch == '.') {
            started = true;
            version.push(ch);
        } else if started {
            break;
        }
    }

    if version.contains('.') {
        Some(version)
    } else {
        None
    }
}

fn extract_version_near_marker(text: &str, marker: &str, search_window: usize) -> Option<String> {
    let marker_pos = text.find(marker)?;
    let after_marker = &text[marker_pos + marker.len()..];
    let window_end = after_marker.len().min(search_window);
    let window = &after_marker[..window_end];

    let mut version = String::new();
    let mut started = false;

    for ch in window.chars() {
        if ch.is_ascii_digit() || (started && ch == '.') {
            started = true;
            version.push(ch);
        } else if started {
            break;
        }
    }

    if version.contains('.') {
        Some(version)
    } else {
        None
    }
}

fn fallback_latest_macos_same_major(installed: &str) -> Option<String> {
    // Fallback values from Apple's "Which versions of macOS are the latest?" support page.
    // Keep this as a fallback only; the live Apple page is still tried first.
    if installed.starts_with("26.") {
        return Some("26.4.1".to_string());
    }

    if installed.starts_with("15.") {
        return Some("15.7.5".to_string());
    }

    if installed.starts_with("14.") {
        return Some("14.8.5".to_string());
    }

    if installed.starts_with("13.") {
        return Some("13.7.8".to_string());
    }

    if installed.starts_with("12.") {
        return Some("12.7.6".to_string());
    }

    None
}

fn fallback_latest_windows_version(os_info: &str) -> Option<String> {
    let product_name = extract_json_string_value(os_info, "product_name")?;

    if product_name.contains("Windows 11") {
        return Some("25H2".to_string());
    }

    if product_name.contains("Windows 10") {
        return Some("22H2".to_string());
    }

    None
}

fn windows_os_source(os_info: &str) -> &'static str {
    let product_name = extract_json_string_value(os_info, "product_name").unwrap_or_default();

    if product_name.contains("Windows 11") {
        "Microsoft Windows 11 release information / latest GA feature version policy"
    } else if product_name.contains("Windows 10") {
        "Microsoft Windows 10 release information / final 22H2 feature version policy"
    } else {
        "backend_policy_required"
    }
}

fn linux_id_or_like_matches(os_info: &str, needle: &str) -> bool {
    let distro_id = extract_json_string_value(os_info, "id").unwrap_or_default();
    let id_like = extract_json_string_value(os_info, "id_like").unwrap_or_default();

    distro_id == needle || id_like.split_whitespace().any(|part| part == needle)
}

fn fallback_latest_linux_version(os_info: &str) -> Option<String> {
    let distro_id = extract_json_string_value(os_info, "id")?;
    let installed = extract_json_string_value(os_info, "version_id");

    if distro_id == "kali" {
        // Kali is rolling, but its installer/images still have quarterly release labels.
        return Some("2025.4".to_string());
    }

    if distro_id == "ubuntu" {
        // Current stable/LTS policy fallback. This should later be fed from distro metadata.
        return Some("26.04".to_string());
    }

    if distro_id == "debian" {
        // Current Debian stable point-release fallback.
        return Some("13.4".to_string());
    }

    if distro_id == "fedora" {
        // Fedora 44 is scheduled for release immediately after this project snapshot.
        // Until then Fedora 43 is the latest generally available stable release.
        return Some("43".to_string());
    }

    if distro_id == "linuxmint" {
        return Some("22.2".to_string());
    }

    if distro_id == "pop" || distro_id == "popos" {
        return Some("22.04".to_string());
    }

    if distro_id == "opensuse-leap" {
        return Some("15.6".to_string());
    }

    if distro_id == "arch"
        || distro_id == "manjaro"
        || distro_id == "opensuse-tumbleweed"
        || distro_id == "nixos"
        || distro_id == "void"
        || distro_id == "gentoo"
    {
        // Rolling or pseudo-rolling distros do not have a single useful latest OS version.
        // Treat the local release label as the comparison reference and rely on package-update checks later.
        return installed.filter(|v| v != "Unknown");
    }

    if linux_id_or_like_matches(os_info, "debian") {
        return Some("13.4".to_string());
    }

    if linux_id_or_like_matches(os_info, "ubuntu") {
        return Some("26.04".to_string());
    }

    if linux_id_or_like_matches(os_info, "fedora") {
        return Some("43".to_string());
    }

    // Last-resort cross-distro behaviour: do not return null if the distro gives us a version.
    // This avoids backend_policy_required for unknown Linux families, but the source label will be honest.
    installed.filter(|v| v != "Unknown")
}

fn linux_os_source(os_info: &str) -> &'static str {
    let distro_id = extract_json_string_value(os_info, "id").unwrap_or_default();

    if distro_id == "kali" {
        "Kali official release history / rolling release image label policy"
    } else if distro_id == "ubuntu" || linux_id_or_like_matches(os_info, "ubuntu") {
        "Ubuntu release cycle / latest stable-LTS fallback policy"
    } else if distro_id == "debian" || linux_id_or_like_matches(os_info, "debian") {
        "Debian stable release information / point-release fallback policy"
    } else if distro_id == "fedora" || linux_id_or_like_matches(os_info, "fedora") {
        "Fedora release schedule / latest stable fallback policy"
    } else if distro_id == "linuxmint" {
        "Linux Mint release information fallback policy"
    } else if distro_id == "pop" || distro_id == "popos" {
        "Pop!_OS release information fallback policy"
    } else if distro_id == "opensuse-leap" {
        "openSUSE Leap release information fallback policy"
    } else if distro_id == "arch"
        || distro_id == "manjaro"
        || distro_id == "opensuse-tumbleweed"
        || distro_id == "nixos"
        || distro_id == "void"
        || distro_id == "gentoo"
    {
        "Rolling Linux distribution / local version self-reference policy"
    } else {
        "Generic Linux /etc/os-release self-reference fallback policy"
    }
}


fn version_to_parts(version: &str) -> Vec<u64> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

fn compare_versions(installed: &str, latest: &str) -> &'static str {
    let installed_parts = version_to_parts(installed);
    let latest_parts = version_to_parts(latest);

    if installed_parts.is_empty() || latest_parts.is_empty() {
        return "unknown";
    }

    let max_len = installed_parts.len().max(latest_parts.len());

    for i in 0..max_len {
        let installed_part = *installed_parts.get(i).unwrap_or(&0);
        let latest_part = *latest_parts.get(i).unwrap_or(&0);

        if installed_part < latest_part {
            return "outdated";
        }

        if installed_part > latest_part {
            return "newer_than_reference";
        }
    }

    "current"
}

fn latest_chrome_version() -> Option<String> {
    #[cfg(target_os = "windows")]
    let platform = "win";

    #[cfg(target_os = "macos")]
    let platform = "mac";

    #[cfg(target_os = "linux")]
    let platform = "linux";

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let platform = "win";

    let url = format!(
        "https://versionhistory.googleapis.com/v1/chrome/platforms/{}/channels/stable/versions?pageSize=1",
        platform
    );

    let json = fetch_url(&url)?;
    extract_json_string_value(&json, "version")
}

fn latest_firefox_version() -> Option<String> {
    let json = fetch_url("https://product-details.mozilla.org/1.0/firefox_versions.json")?;
    extract_json_string_value(&json, "LATEST_FIREFOX_VERSION")
}

fn latest_edge_version() -> Option<String> {
    let json = fetch_url("https://edgeupdates.microsoft.com/api/products")?;

    #[cfg(target_os = "windows")]
    let platform_marker = "\"Platform\":\"Windows\"";

    #[cfg(target_os = "macos")]
    let platform_marker = "\"Platform\":\"MacOS\"";

    #[cfg(target_os = "linux")]
    let platform_marker = "\"Platform\":\"Linux\"";

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let platform_marker = "\"Platform\":\"Windows\"";

    let stable_pos = json.find("\"Product\":\"Stable\"")?;
    let stable_json = &json[stable_pos..];
    let platform_pos = stable_json.find(platform_marker)?;
    let platform_json = &stable_json[platform_pos..];

    extract_json_string_value(platform_json, "ProductVersion")
}

fn latest_opera_version() -> Option<String> {
    // Opera does not expose a Chrome-style public version-history JSON API.
    // This autoupdate verification endpoint is used by packaging/update tooling and returns current_version.
    let update_json = fetch_url("https://autoupdate.geo.opera.com/api/verify?product=Opera&version=0");

    if let Some(json) = update_json {
        if let Some(version) = extract_json_string_value(&json, "current_version") {
            return Some(version);
        }
    }

    // Fallback only: the blog is not ideal, but better than returning unknown when the update API is unavailable.
    let html = fetch_url("https://blogs.opera.com/desktop/")?;

    extract_first_dotted_version_after(&html, "version:")
        .or_else(|| extract_version_near_marker(&html, "Opera has just promoted version", 80))
        .or_else(|| extract_version_near_marker(&html, "Opera ", 80))
}

fn latest_safari_version() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let html = fetch_url("https://support.apple.com/en-us/126800")?;
        return extract_first_dotted_version_after(&html, "Safari ");
    }

    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

fn latest_os_version(os_info: &str) -> Option<String> {
    let platform = extract_json_string_value(os_info, "platform")?;

    if platform == "macos" {
        let installed = extract_json_string_value(os_info, "product_version")?;

        if let Some(html) = fetch_url("https://support.apple.com/en-us/109033") {
            if installed.starts_with("26.") {
                return extract_version_near_marker(&html, "macOS Tahoe", 160)
                    .or_else(|| fallback_latest_macos_same_major(&installed));
            }

            if installed.starts_with("15.") {
                return extract_version_near_marker(&html, "macOS Sequoia", 160)
                    .or_else(|| fallback_latest_macos_same_major(&installed));
            }

            if installed.starts_with("14.") {
                return extract_version_near_marker(&html, "macOS Sonoma", 160)
                    .or_else(|| fallback_latest_macos_same_major(&installed));
            }

            if installed.starts_with("13.") {
                return extract_version_near_marker(&html, "macOS Ventura", 160)
                    .or_else(|| fallback_latest_macos_same_major(&installed));
            }

            if installed.starts_with("12.") {
                return extract_version_near_marker(&html, "macOS Monterey", 160)
                    .or_else(|| fallback_latest_macos_same_major(&installed));
            }
        }

        return fallback_latest_macos_same_major(&installed);
    }

    if platform == "windows" {
        return fallback_latest_windows_version(os_info);
    }

    if platform == "linux" {
        return fallback_latest_linux_version(os_info);
    }

    None
}
fn latest_brave_version() -> Option<String> {
    // Brave's /latest GitHub pointer has historically not always been trustworthy for stable.
    // Use Brave's own versions dataset and extract the current public release version.
    let json = fetch_url("https://versions.brave.com/latest/release.version")?;
    let trimmed = json.trim().trim_start_matches('v');

    if trimmed.chars().next()?.is_ascii_digit() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn status_json(name: &str, installed: Option<String>, latest: Option<String>, source: &str) -> String {
    match (installed, latest) {
        (Some(installed_version), Some(latest_version)) => format!(
            "{{\"name\":\"{}\",\"installed\":\"{}\",\"latest\":\"{}\",\"status\":\"{}\",\"source\":\"{}\"}}",
            escape_json(name),
            escape_json(&installed_version),
            escape_json(&latest_version),
            compare_versions(&installed_version, &latest_version),
            escape_json(source)
        ),
        (Some(installed_version), None) => format!(
            "{{\"name\":\"{}\",\"installed\":\"{}\",\"latest\":null,\"status\":\"latest_unknown\",\"source\":\"{}\"}}",
            escape_json(name),
            escape_json(&installed_version),
            escape_json(source)
        ),
        (None, Some(latest_version)) => format!(
            "{{\"name\":\"{}\",\"installed\":null,\"latest\":\"{}\",\"status\":\"not_installed_or_not_detected\",\"source\":\"{}\"}}",
            escape_json(name),
            escape_json(&latest_version),
            escape_json(source)
        ),
        (None, None) => format!(
            "{{\"name\":\"{}\",\"installed\":null,\"latest\":null,\"status\":\"not_installed_or_not_detected\",\"source\":\"{}\"}}",
            escape_json(name),
            escape_json(source)
        ),
    }
}

fn get_version_status(os_info: &str, browsers: &str) -> String {
    let installed_chrome = extract_json_string_value(browsers, "chrome")
        .or_else(|| extract_json_string_value(browsers, "chrome_or_chromium"));
    let installed_edge = extract_json_string_value(browsers, "edge");
    let installed_firefox = extract_json_string_value(browsers, "firefox");
    let installed_brave = extract_json_string_value(browsers, "brave");
    let installed_safari = extract_json_string_value(browsers, "safari");
    let installed_opera = extract_json_string_value(browsers, "opera");

    let latest_brave = if installed_brave.is_some() {
        latest_brave_version()
    } else {
        None
    };

    let latest_opera = if installed_opera.is_some() {
        latest_opera_version()
    } else {
        None
    };

    let latest_safari = if installed_safari.is_some() {
        latest_safari_version()
    } else {
        None
    };

    let chrome_status = status_json(
        "chrome",
        installed_chrome,
        latest_chrome_version(),
        "Google Chrome Version History API"
    );

    let firefox_status = status_json(
        "firefox",
        installed_firefox,
        latest_firefox_version(),
        "Mozilla Product Details API"
    );

    let edge_status = status_json(
        "edge",
        installed_edge,
        latest_edge_version(),
        "Microsoft Edge Updates API"
    );

    let brave_status = status_json(
        "brave",
        installed_brave,
        latest_brave,
        "Brave versions dataset"
    );

    let opera_status = status_json(
        "opera",
        installed_opera,
        latest_opera,
        "Opera autoupdate verify API with blog fallback"
    );

    let safari_status = status_json(
        "safari",
        installed_safari,
        latest_safari,
        "Apple Safari security release page"
    );

    let installed_os_version = extract_json_string_value(os_info, "product_version")
        .or_else(|| extract_json_string_value(os_info, "display_version"))
        .or_else(|| extract_json_string_value(os_info, "version_id"));

    let platform = extract_json_string_value(os_info, "platform").unwrap_or_else(|| "unknown".to_string());
    let os_source = if platform == "macos" {
        "Apple latest macOS versions support page / same-major policy"
    } else if platform == "windows" {
        windows_os_source(os_info)
    } else if platform == "linux" {
        linux_os_source(os_info)
    } else {
        "backend_policy_required"
    };

    let os_status = status_json(
        "os",
        installed_os_version,
        latest_os_version(os_info),
        os_source
    );

    format!(
        "{{\"items\":[{},{},{},{},{},{},{}]}}",
        os_status,
        chrome_status,
        firefox_status,
        edge_status,
        brave_status,
        opera_status,
        safari_status
    )
}

fn get_summary(version_status: &str, network: &str) -> String {
    let outdated_count = version_status.matches("\"status\":\"outdated\"").count();
    let unknown_count = version_status.matches("\"status\":\"latest_unknown\"").count()
        + version_status.matches("\"status\":\"not_compared\"").count();
    let open_service_count = network.matches("\"status\":\"open\"").count();

    let overall = if outdated_count > 0 {
        "warnings"
    } else if unknown_count > 0 {
        "unknowns"
    } else {
        "healthy"
    };

    format!(
        "{{\"overall\":\"{}\",\"outdated_count\":{},\"unknown_count\":{},\"open_service_count\":{}}}",
        overall,
        outdated_count,
        unknown_count,
        open_service_count
    )
}

pub fn run() {
    let hostname = get_hostname();
    let os_info = get_os_info();
    let browsers = get_browser_versions();
    let network = scan_local_24();
    let version_status = get_version_status(&os_info, &browsers);
    let summary = get_summary(&version_status, &network);

    let json = format!(
        concat!(
        "{{",
        "\"hostname\":\"{}\",",
        "\"os\":{},",
        "\"browsers\":{},",
        "\"version_status\":{},",
        "\"network_discovery\":{},",
        "\"summary\":{}",
        "}}"
        ),
        escape_json(&hostname),
        os_info,
        browsers,
        version_status,
        network,
        summary
    );

    println!("{}", json);
}

fn main() {
    run();
}