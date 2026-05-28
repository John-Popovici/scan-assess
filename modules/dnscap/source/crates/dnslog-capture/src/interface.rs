use anyhow::{Context, Result};
use pcap::Device;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = Device::list().context("failed to list capture interfaces")?;
    Ok(devices
        .into_iter()
        .map(|device| InterfaceInfo {
            name: device.name,
            description: device.desc,
            addresses: device
                .addresses
                .into_iter()
                .map(|addr| addr.addr.to_string())
                .collect(),
        })
        .collect())
}

pub fn default_interface_name() -> Result<String> {
    let interfaces = list_interfaces()?;
    interfaces
        .iter()
        .find(|iface| {
            let name = iface.name.to_ascii_lowercase();
            !(name.contains("lo") || name.contains("loopback"))
        })
        .or_else(|| interfaces.first())
        .map(|iface| iface.name.clone())
        .context("no capture interfaces found")
}
