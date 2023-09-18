use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};

use pcap::Device;
use crate::error::NetUtilsError;


// ============ Utility ============ //
pub fn mac_to_string(mac_addr: &[u8; 6]) -> String {
    mac_addr
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

pub fn string_to_mac(string: &str) -> Result<[u8; 6], NetUtilsError> {
    let hx: Vec<u8> = string
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();

    if hx.len() != 6 {
        return Err(NetUtilsError::InvalidMacAddress("MAC address octet length is invalid.".to_string()));
    }

    let mut mac_addr = [0u8; 6];
    for (&x, p) in hx.iter().zip(mac_addr.iter_mut()) {
        *p = x;
    }
    Ok(mac_addr)
}

// ============ Information Gathering ============ //

/// Resolves and returns the first private IPv4 address associated with a given network `Device`.
pub fn resolve_private_ipv4(device: &Device) -> Result<Ipv4Addr, NetUtilsError> {
    device
        .addresses
        .iter()
        .find_map(|addr_info| match addr_info.addr {
            IpAddr::V4(ipv4) if ipv4.is_private() => Some(ipv4),
            _ => None,
        })
        .ok_or(NetUtilsError::IpAddressNotFound("No private IPv4 address found".to_string()))
}

/// Retrieves the MAC address of the given network interface and returns it as an array of 6 bytes.
pub fn get_interface_mac_addr(interface_name: &str) -> Result<[u8; 6], NetUtilsError> {
    let path = format!("/sys/class/net/{}/address", interface_name);
    let mut mac_addr_buf = String::new();

    // Open the file and read its contents into the buffer
    let mut f = File::open(&path)?;
    f.read_to_string(&mut mac_addr_buf)?;

    // Convert the MAC address from string to byte array
    let mac = string_to_mac(mac_addr_buf.trim())?;
    Ok(mac)
}


// ============ Manipulation/Action ============ //

/// Opens a pcap capture device
pub fn pcap_open(
    device: Device,
    pcap_filter: &str,
) -> Result<pcap::Capture<pcap::Active>, NetUtilsError> {
    let mut cap = device
        .open()
        .map_err(|e| NetUtilsError::PcapError(format!("Failed to open device: {}", e)))?;
        
    cap.filter(pcap_filter, true)
        .map_err(|e| NetUtilsError::PcapError(format!("Failed to apply filter: {}", e)))?;
        
    Ok(cap)
}

/// Modifies `/proc/sys/net/ipv4/ip_forward` to enable/disable ip forwarding
pub fn ip_forward(enable: bool) -> Result<(), NetUtilsError> {
    let ipv4_fw_path = "/proc/sys/net/ipv4/ip_forward";
    let ipv4_fw_value = match enable {
        true => "1\n",
        false => "0\n",
    };

    let result = OpenOptions::new()
        .write(true)
        .open(ipv4_fw_path)
        .map_err(|e| NetUtilsError::IoError(format!("Unable to open {}: {}", ipv4_fw_path, e)))
        .and_then(|mut f| {
            f.write_all(ipv4_fw_value.as_bytes())
                .map_err(|e| NetUtilsError::IoError(format!("Failed to write to {}: {}", ipv4_fw_path, e)))
        });

    result
}

