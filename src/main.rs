use std::env;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::timeout;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce
};

use spake2::{Spake2, Ed25519Group, Password, Identity};

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


// padding 40byte seqence number into 12-byte Nonce
fn seq_to_nonce(seq_num: u32) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[8] = (seq_num >> 24) as u8;
    nonce_bytes[9] = (seq_num >> 16) as u8;
    nonce_bytes[10] = (seq_num >> 8) as u8;
    nonce_bytes[11] = seq_num as u8;

    Nonce::from(nonce_bytes)
}

fn encrypt_chunk(seq_num: u32, plaintext: &[u8], secret_key: &[u8; 32]) -> Vec<u8> {
    let key = Key::from(*secret_key);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = seq_to_nonce(seq_num);
    cipher.encrypt(&nonce, plaintext).expect("Encryption Failed..")
}

fn decrypt_chunk(seq_num: u32, ciphertext: &[u8], secret_key: &[u8; 32]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from(*secret_key);
    
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = seq_to_nonce(seq_num);
    cipher.decrypt(&nonce, ciphertext)
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

    //HNADSHAKE START
    let pw = Password::new(b"super-secret-password");
    let id_a = Identity::new(b"sender");
    let id_b = Identity::new(b"receiver");

    let mut derived_key = [0u8; 32];
    let mut handshake_buffer = [0u8; 2048];

    println!("Waiting for Sender to initiate handshake...");
    
    let (msg_a, source) = loop {
        let (size, src) = socket.recv_from(&mut handshake_buffer).await.expect("Failed to receive");
        if size < 7 { continue; }
        let header = Header::unpack(&handshake_buffer[0..7]);
        if header.packet_type == 3 { 
            break (handshake_buffer[7..size].to_vec(), src);
        }
    };

    println!("Message A received. Generating Message B...");

    // 2. Call start_b with all THREE required arguments
    let (state, my_msg_b) = Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b);
    let final_key_vec = state.finish(&msg_a).expect("Handshake failed! Wrong password?");
    derived_key.copy_from_slice(&final_key_vec);
    
    // sending msg to Sender
    let header_b = Header { packet_type: 4, seq_num: 0, payload_len: my_msg_b.len() as u16};
    let mut packet_b = Vec::new();
    packet_b.extend_from_slice(&header_b.pack());
    packet_b.extend_from_slice(&my_msg_b);

    for _ in 0..5 {
        socket.send_to(&packet_b, source).await.expect("Failed to send message B");
    }
    println!("Handshake successfull! 32-byte key securely generated");
// ------------------
    // HANDSHAKE END
    //
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

        if header.packet_type == 0 { // DATA
            if header.seq_num == expected_seq_num {
                let payload_end = 7 + header.payload_len as usize;
                if size >= payload_end {
                    let encrypted_payload = &buffer[7..payload_end];

                    match decrypt_chunk(header.seq_num, encrypted_payload, &derived_key) {
                        Ok(decrypted_bytes) => {

                            writer.write_all(&decrypted_bytes).await.expect("Failed to write to file");
                            expected_seq_num += 1;
                        }
                        Err(_) => {
                            eprintln!("WARNING: chunk {} failed crytographic authentication! Droping packet..", header.seq_num);

                        }
                    }

                    
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

    // --- THE HANDSHAKE  ---
    let pw = Password::new(b"super-secret-password");
    let id_a = Identity::new(b"sender");
    let id_b = Identity::new(b"receiver");
    
    let mut derived_key = [0u8; 32];
    
    println!("Initiating SPAKE2 Handshake...");
    
    let (state, my_msg_a) = Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b);

    let header_a = Header { packet_type: 3, seq_num: 0, payload_len: my_msg_a.len() as u16 };

    let mut packet_a = Vec::new();
    packet_a.extend_from_slice(&header_a.pack());
    packet_a.extend_from_slice(&my_msg_a);

    let mut handshake_buffer = [0u8; 2048];
    
    // Loop until we get Message B
    loop {
        socket.send_to(&packet_a, target).await.expect("Failed to send Message A");
        
        match timeout(Duration::from_millis(500), socket.recv_from(&mut handshake_buffer)).await {
            Ok(Ok((size, _))) => {
                if size >= 7 {
                    let header = Header::unpack(&handshake_buffer[0..7]);
                    if header.packet_type == 4 { // Type 4 is Message B
                        let msg_b = &handshake_buffer[7..size];
                        let final_key_vec = state.finish(msg_b).expect("Handshake failed! Wrong password?");
                        derived_key.copy_from_slice(&final_key_vec);
                        println!("Handshake successful! 32-byte key securely generated.");
                        break;
                    }
                }
            }
            _ => { println!("Timeout waiting for Message B. Retrying..."); }
        }
    }
    // --- END HANDSHAKE ---

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

        let plaintext = &chunk_buffer[..bytes_read];
        let encrypted_payload = encrypt_chunk(seq_num, plaintext, &derived_key);

        
        let packet_type = if is_eof {2} else {0};
    
        let header = Header {
            packet_type,
            seq_num,
            payload_len: encrypted_payload.len() as u16,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&header.pack());
        packet.extend_from_slice(&encrypted_payload); // only the bytes we read

        
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
