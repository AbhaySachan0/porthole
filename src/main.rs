use std::env;
use std::net::UdpSocket;
use std::process;
use std::fs::File;
use std::io::{ Read, Write};
use std::time::Duration;

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

    let mut file = File::create("recieved_file.txt").expect("Failed to create file");

    let mut buffer = [0; 1500];

    let mut expected_seq_num = 1;

    loop {
        let (size, source) = socket.recv_from(&mut buffer).expect("failed to recieve");
        if size <7 {
            continue;
        }
        let header = Header::unpack(&buffer[0..7]);

        if header.packet_type == 0 {
            if header.seq_num == expected_seq_num {
                let payload_end = 7 + header.payload_len as usize;
                if size >= payload_end {
                    let payload_bytes = &buffer[7..payload_end];
                    file.write_all(payload_bytes).expect("Failed to write to file");
                    println!("Saved chunk {} ({} bytes", header.seq_num, header.payload_len);

                    expected_seq_num += 1;
                }

            }
            let ack_header = Header {
                packet_type:1,
                seq_num: header.seq_num,
                payload_len:0,
            };
            socket.send_to(&ack_header.pack(), source).expect("Failed to send ACK");
        } else if header.packet_type == 2 {
            println!("Recieved EOF packet. Transfer complete");
            let ack_header = Header {
                packet_type: 1,
                seq_num: header.seq_num,
                payload_len: 0,
            };
            socket.send_to(&ack_header.pack(), source).expect("Failed to send EOF ACK packet");
            break;
        } 
    }
}


fn run_sender(target: &str) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");


    socket.set_read_timeout(Some(Duration::from_millis(100))).expect("failed to set timeout");

    let mut file = File::open("test.txt").expect("Failed to open file..");
    let mut seq_num = 1;
    let mut chunk_buffer = [0u8; 1000];

    println!("Starting file transfer.....");

    loop {
        let bytes_read = file.read(&mut chunk_buffer).expect("Failed to read file");
        let is_eof = bytes_read==0;
        
        let packet_type = if is_eof {2} else {0};
    
        let header = Header {
            packet_type,
            seq_num,
            payload_len: bytes_read as u16,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&header.pack());
        packet.extend_from_slice(&chunk_buffer[..bytes_read]); // only the bytes we read

        // loop will keep sending this exact chunk until we get an ACk
        loop {
            socket.send_to(&packet, target).expect("Failed to send chunk..");
            let mut ack_buffer = [0; 7];  // ACK is 7-byte header
            match socket.recv_from(&mut ack_buffer) {
                Ok((size, _)) => {
                    if size >=7 {
                        let ack_header = Header::unpack(&ack_buffer[0..7]);

                        // if it is not ACK ( type 1) AND it matches current sequence number
                        if ack_header.packet_type == 1 && ack_header.seq_num==seq_num{
                            println!("-> ACK recieved from chunk {} ", seq_num);
                            break;
                            // break out the inner loop to read next chunk
                        }
                    }
                }
                Err(_) => {
                // executing if 100ms pass without ACk
                // loop restarts
                println!("Timeout! Resending chunk {}...", seq_num);
                }
            } 
        }


        if is_eof {
            println!("Transfer complete and acknowledged!");
            break;
        }
        seq_num +=1;
    }
}
