use std::env;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::timeout;



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



#[tokio::main]
async fn main() {

    let args: Vec<String> = env::args().collect();    

    if args.len()<2 {
        eprintln!("{} [recieve | send <ip:port>", args[0]);
        process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "recieve" => {
            println!("Starting in reciever mode");
            run_reciever().await;
        }
        "send" => {
            if args.len()!=3 {
                eprintln!("Usage for sending: {} send <ip:port>", args[0]);
                process::exit(1);
            }
            let target_ip = &args[2];
            println!("Starting in sending mode to {}", target_ip);
            run_sender(target_ip).await;
        }
        _ => {
            eprintln!("Unknown command. Use send or recieve");
            process::exit(1);
        }
    }
}


async fn run_reciever() {
    let socket = UdpSocket::bind("0.0.0.0:8080").await.expect("Failed to bind");
    println!("Listning on port 8080....");

    let file = File::create("recieved_file.txt").await.expect("Failed to create file");
    let mut writer = BufWriter::new(file);

    let mut buffer = [0; 2048];
    let mut expected_seq_num = 1;

    loop {
        let (size, source) = socket.recv_from(&mut buffer).await.expect("failed to recieve");
        if size <7 {
            continue;
        }
        let header = Header::unpack(&buffer[0..7]);

        if header.packet_type == 0 {
            if header.seq_num == expected_seq_num {
                let payload_end = 7 + header.payload_len as usize;
                if size >= payload_end {
                    let payload_bytes = &buffer[7..payload_end];
                    writer.write_all(payload_bytes).await.expect("Failed to write to file");

                    expected_seq_num += 1;
                }

            }
            let ack_header = Header {
                packet_type:1,
                seq_num: header.seq_num,
                payload_len:0,
            };
            socket.send_to(&ack_header.pack(), source).await.expect("Failed to send ACK");
        } else if header.packet_type == 2 {
            println!("Recieved EOF packet. Transfer complete");
            let ack_header = Header {
                packet_type: 1,
                seq_num: header.seq_num,
                payload_len: 0,
            };
            
            socket.send_to(&ack_header.pack(), source).await.expect("Failed to send EOF ACK packet");
            writer.flush().await.expect("Flush failed");
            break;
        } 
    }
}


async fn run_sender(target: &str) {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind"));
    let listener_socket = socket.clone();

    // channel to hold 100 ACKs in tube at once
    let (tx, mut rx) = mpsc::channel::<u32>(100);

    tokio::spawn(async move {

        let mut ack_buffer = [0u8; 7];
        loop {
            if let Ok((size, _)) = listener_socket.recv_from(&mut ack_buffer).await {
                if size >=7 {
                    let header = Header::unpack(&ack_buffer[0..7]);
                    if header.packet_type == 1 { // ACk
                        // push acknowledged sequence number into tube
                        let _ = tx.send(header.seq_num).await;
                    }
                }
            }
        }
    });

    let file = File::open("test.txt").await.expect("Failed to open file..");
    let mut reader = BufReader::new(file);

    let mut seq_num = 1;
    let mut last_acked = 0;
    let window_size = 50;

    let mut chunk_buffer = [0u8; 1400];

    println!("Starting file transfer.....");

    loop {

        //PIPELINE CHECK
        while seq_num - last_acked > window_size {
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(acked_num)) => {
                    if acked_num > last_acked { last_acked = acked_num; }
                }
                _ => {
                    // Timeout! window is clocked
                    println!("Network clogged! Waiting for ACKs...");
                }
            }
        }

        
        let bytes_read = reader.read(&mut chunk_buffer).await.expect("Failed to read file");
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

        
        socket.send_to(&packet, target).await.expect("Send failed..");

        if is_eof {
            println!("Transfer complete and acknowledged!");
            break;
        }
        seq_num +=1;

        while let Ok(acked_num) = rx.try_recv() {
            if acked_num > last_acked { last_acked = acked_num; }
        }
    }
}
