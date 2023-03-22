extern crate argparse;
extern crate nix;
extern crate pcap;

use std::net::{IpAddr, Ipv4Addr};
use std::process;

use argparse::{ArgumentParser, Print, Store, StoreFalse, StoreTrue};
use nix::sys::signal;
use nix::sys::signal::SigHandler;
use pcap::Device;

use crate::utils::{get_interface_mac_addr, ip_forward, mac_to_string};

mod arp;
mod utils;

macro_rules! abort {
    ($($arg:tt)*) => {{
        println!($($arg)*);
        process::exit(1);
    }};
}

/// Struct which holds all possible arguments
struct ArgOptions {
    interface: String,
    target_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    ip_forward: bool,
    log_traffic: bool,
}

fn main() {
    // Define SIGINT handler
    let sig_action = signal::SigAction::new(
        SigHandler::Handler(handle_sigint),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        signal::sigaction(signal::SIGINT, &sig_action).expect("Unable to register SIGINT handler");
    }

    let arg_options = parse_args();
    let all_devices = Device::list().expect("Unable to list devices");
    let device = match all_devices
        .into_iter()
        .filter(|d| d.name == arg_options.interface)
        .last()
    {
        Some(d) => d,
        None => {
            abort!("Given interface \"{}\" not found", arg_options.interface)
        }
    };

    // Resolve IP and MAC address
    let own_ip_addr = match resolve_own_ip_addr(&device) {
        Some(ip) => ip,
        None => {
            abort!("Unable to get address for interface")
        }
    };
    let own_mac_addr = get_interface_mac_addr(&arg_options.interface);
    println!("[*] Using device {} ...\n -> ip address: {}\n -> mac address: {}\n -> connection_status: {:?}",
             device.name,
             own_ip_addr,
             mac_to_string(&own_mac_addr),
             device.flags.connection_status,
    );

    // Enable kernel ip forwarding
    if arg_options.ip_forward {
        ip_forward(arg_options.ip_forward).expect("ip_forward failed!");
    }

    arp::arp_poisoning(
        device,
        own_mac_addr,
        own_ip_addr,
        arg_options.target_ip,
        arg_options.gateway_ip,
        arg_options.log_traffic,
    );
}

/// Resolves the ip addresses for the given device and returns the first one found
fn resolve_own_ip_addr(device: &Device) -> Option<Ipv4Addr> {
    device
        .addresses
        .iter()
        .filter_map(|i| match i.addr {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        })
        .last()
}

/// extern "C" sigint handler
extern "C" fn handle_sigint(_: i32) {
    match ip_forward(false) {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    }
    abort!("\nInterrupted!");
}

/// Parses args or panics if something is missing.
fn parse_args() -> ArgOptions {
    let mut options = ArgOptions {
        interface: String::from(""),
        target_ip: Ipv4Addr::new(0, 0, 0, 0),
        gateway_ip: Ipv4Addr::new(0, 0, 0, 0),
        ip_forward: true,
        log_traffic: false,
    };
    {
        // This block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Minimal ARP spoofing tool written in Rust.");
        ap.refer(&mut options.interface)
            .add_option(&["-i", "--interface"], Store, "interface name")
            .required();
        ap.refer(&mut options.target_ip)
            .add_option(&["--target"], Store, "target ipv4 address")
            .required();
        ap.refer(&mut options.gateway_ip)
            .add_option(&["--gateway"], Store, "gateway ipv4 address")
            .required();
        ap.refer(&mut options.log_traffic).add_option(
            &["--log-traffic"],
            StoreTrue,
            "logs all target traffic to `save.pcap`",
        );
        ap.refer(&mut options.ip_forward).add_option(
            &["-n", "--no-forward"],
            StoreFalse,
            "leave `/proc/sys/net/ipv4/ip_forward` untouched",
        );
        ap.add_option(
            &["-V", "--version"],
            Print(env!("CARGO_PKG_VERSION").to_string()),
            "show version",
        );
        ap.parse_args_or_exit();
    }
    for ip in [options.target_ip, options.gateway_ip] {
        if !ip.is_private() {
            abort!("{} is no private ip address", ip);
        }
    }
    options
}
