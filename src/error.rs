use std::io;
use std::fmt;
use std::net::AddrParseError;

// This allows for more structured error handling and easier matching
// against errors to perform specific actions based on error type

#[derive(Debug)]
pub enum CliError {
    InterfaceEmpty,
    DeviceListError(String),
    InterfaceNotFound(String),
    TargetIpEmpty,
    TargetIpInvalid(String),
    TargetIpNotPrivate,
    GatewayEmpty,
    GatewayInvalid(String),
    GatewayNotPrivate,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CliError::InterfaceEmpty => write!(f, "Interface name cannot be empty."),
            CliError::DeviceListError(e) => write!(f, "Unable to list devices: {}", e),
            CliError::InterfaceNotFound(intf) => write!(f, "Given interface \"{}\" not found.", intf),
            CliError::TargetIpEmpty => write!(f, "Target IP address cannot be empty."),
            CliError::TargetIpInvalid(e) => write!(f, "Target IP address is not valid: {}", e),
            CliError::TargetIpNotPrivate => write!(f, "Target IP address must be private."),
            CliError::GatewayEmpty => write!(f, "Gateway IP address cannot be empty."),
            CliError::GatewayInvalid(e) => write!(f, "Gateway IP address is not valid: {}", e),
            CliError::GatewayNotPrivate => write!(f, "Gateway IP address must be private."),
        }
    }
}

#[derive(Debug)]
pub enum NetUtilsError {
    IoError(String),
    IpAddressNotFound(String),
    InvalidMacAddress(String),
    PcapError(String),
    AddrParseError(String),
    CliError(CliError),
}

impl From<io::Error> for NetUtilsError {
    fn from(err: io::Error) -> Self {
        NetUtilsError::IoError(err.to_string())
    }
}

impl From<pcap::Error> for NetUtilsError {
    fn from(err: pcap::Error) -> Self {
        NetUtilsError::PcapError(err.to_string())
    }
}

impl From<AddrParseError> for NetUtilsError {
    fn from(err: AddrParseError) -> Self {
        NetUtilsError::AddrParseError(err.to_string())
    }
}

impl From<CliError> for NetUtilsError {
    fn from(err: CliError) -> Self {
        NetUtilsError::CliError(err)
    }
}

impl fmt::Display for NetUtilsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetUtilsError::IoError(e) => write!(f, "IO Error: {}", e),
            NetUtilsError::IpAddressNotFound(ip) => write!(f, "IP Address Not Found: {}", ip),
            NetUtilsError::InvalidMacAddress(mac) => write!(f, "Invalid MAC Address: {}", mac),
            NetUtilsError::PcapError(e) => write!(f, "PCAP Error: {}", e),
            NetUtilsError::AddrParseError(e) => write!(f, "Address Parse Error: {}", e),
            NetUtilsError::CliError(cli_err) => cli_err.fmt(f),  // Directly delegate to the inner error's Display implementation
        }
    }
}

