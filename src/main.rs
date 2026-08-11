use std::env;
use std::net::UdpSocket;
use std::process;

struct Header {
    packet_type: u8,  // 1 byte
    seq_num: u32,     // 4 bytes
    payload_len: u16, // 2 bytes
}

impl Header {
    fn pack(&self) -> [u8; 7] {
        let mut buffer = [0u8; 7];

        buffer[0] = self.packet_type;

        // packing the sequence number
        buffer[1] = (self.seq_num >> 24) as u8;
        buffer[2] = (self.seq_num >> 16) as u8;
        buffer[3] = (self.seq_num >> 8) as u8;
        buffer[4] = self.seq_num as u8;

        // payload length
        buffer[5] = (self.payload_len >> 8) as u8;
        buffer[6] = self.payload_len as u8;

        buffer
    }
    
    fn unpack(buffer: &[u8]) -> Self {
        let packet_type = buffer[0];
        let seq_num = ((buffer[1] as u32) << 24) | ((buffer[2] as u32) << 16) | ((buffer[3] as u32) << 8) | (buffer[4] as u32);

        let payload_len = ((buffer[5] as u16) << 8) | (buffer[6] as u16);

        Header {
            packet_type,
            seq_num,
            payload_len,
        }
    }
}



fn main() {
    let args: Vec<String> = env::args().collect();    

    if args.len()<2 {
        eprintln!("{} [recieve | send <ip:port>", args[0]);
        process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "recieve" => {
            println!("Starting in reciever mode");
            run_reciever();
        }
        "send" => {
            if args.len()!=3 {
                eprintln!("Usage for sending: {} send <ip:port>", args[0]);
                process::exit(1);
            }
            let target_ip = &args[2];
            println!("Starting in sending mode to {}", target_ip);
            run_sender(target_ip);
        }
        _ => {
            eprintln!("Unknown command. Use send or recieve");
            process::exit(1);
        }
    }
}


fn run_reciever() {
    let socket = UdpSocket::bind("0.0.0.0:8080").expect("Failed to bind");
    println!("Listning on port 8080");

    let mut buffer = [0; 1024];

    let (size, source) = socket.recv_from(&mut buffer).expect("failed to recieve");

    if size < 7 {
        eprintln!("Packet too small from {}", source);
        return;
    }

    let header = Header::unpack(&buffer[0..7]);

    println!("--- INCOMING PACKET METADATA ---");
    println!("Type: {}", header.packet_type);
    println!("Chunk Number: {}", header.seq_num);
    println!("Message Size: {}", header.payload_len);

    let payload_start = 7;
    let payload_end = 7 + header.payload_len as usize;

    if size < payload_end {
        eprintln!("Corrupted packet: expected {} bytes but got less", header.payload_len);
        return;

    }

    let payload_bytes = &buffer[payload_start..payload_end];
    let message = String::from_utf8_lossy(payload_bytes);
    println!("Message: {}",message);

}


fn run_sender(target: &str) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");

    print!("What's the message: ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let mut message = String::new();
    std::io::stdin().read_line(&mut message).expect("Failed to input the message");

    let message = message.trim_end();
    let payload = message.as_bytes();

    let header = Header {
        packet_type: 0,
        seq_num: 1,
        payload_len: payload.len() as u16,
    };

    let header_bytes = header.pack();

    let mut packet = Vec::new();
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(payload);
    socket.send_to(&packet, target).expect("Failed to send");
    println!("Sent packet with sequence number {}.", header.seq_num);
}
