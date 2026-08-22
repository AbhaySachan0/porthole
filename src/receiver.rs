use std::io::{self, Write};
use std::process;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::time::timeout;
use spake2::{Spake2, Ed25519Group, Password, Identity};

use crate::protocol::Header;
use crate::crypto::decrypt_chunk;

pub async fn run_receiver(save_path: &str) {
    let socket = UdpSocket::bind("0.0.0.0:8080").await.expect("Failed to bind");
    println!("Listning on port 8080....");

    //HNADSHAKE START
    let mut handshake_buffer = [0u8; 2048];

    println!("Waiting for sender to initiate handshake...");
    let (msg_a, source) = loop {
        let (size, src) = socket.recv_from(&mut handshake_buffer).await.expect("Failed to receive");
        if size < 7 { continue; }
        let header = Header::unpack(&handshake_buffer[0..7]);
        if header.packet_type == 3 { 
            break (handshake_buffer[7..size].to_vec(), src);
        }
    };
    println!("Sender connected..Waiting for authentication....");
    print!("Enter code: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("failed to read line");
    let code = input.trim();

    let pw = Password::new(code.as_bytes());
    let id_a = Identity::new(b"sender");
    let id_b = Identity::new(b"receiver");

    let mut derived_key = [0u8; 32];
    // let mut final_msg_b = Vec::new();
    // let mut attempts = 3;
    // let mut success = false;
    //
    let (state, my_msg_b) = Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b);
    let final_key_vec = state.finish(&msg_a).expect("Math error");
    derived_key.copy_from_slice(&final_key_vec);

    let header_b = Header { packet_type: 4, seq_num: 0, payload_len: my_msg_b.len() as u16};
    let mut packet_b = Vec::new();
    packet_b.extend_from_slice(&header_b.pack());
    packet_b.extend_from_slice(&my_msg_b);

    for _ in 0..5 { socket.send_to(&packet_b, source).await.unwrap(); }
    println!("Waiting for sender to confirm password");
    
    loop {
        match timeout(Duration::from_millis(500), socket.recv_from(&mut handshake_buffer)).await {
            Ok(Ok((size, _))) => {
                if size >= 7 {
                    let header = Header::unpack(&handshake_buffer[0..7]);
                    if header.packet_type == 5 {
                        let ciphertext = &handshake_buffer[7..size];
                        match decrypt_chunk(0, ciphertext, &derived_key) {
                            Ok(plaintext) if plaintext == b"AUTH" => {
                                // PASSWORDS MATCH! Send Type 6 (ACK)
                                let ack = Header { packet_type: 6, seq_num: 0, payload_len: 0 };
                                for _ in 0..5 { socket.send_to(&ack.pack(), source).await.unwrap(); }
                                println!("✅ Password is correct! Ready to receive data.");
                                break; // Exit handshake, start receiving file
                            }
                            _ => {
                                eprintln!("❌ Authentication failed: Incorrect password!");
                                process::exit(1);
                            }
                                
                        }
                    }
                }
            }
            _ => {
                let _ = socket.send_to(&packet_b, source).await;
            }
        }
    }

   
    let file = File::create(save_path).await.expect("Failed to create file");
    let mut writer = BufWriter::new(file);

    let mut buffer = [0; 2048];
    let mut expected_seq_num = 1;

    loop {
        let (size, source) = socket.recv_from(&mut buffer).await.expect("failed to receive");
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
                            let ack_header = Header {
                                packet_type: 1,
                                seq_num: header.seq_num,
                                payload_len: 0,
                            };
                            socket.send_to(&ack_header.pack(), source).await.expect("Failed to send ack...");
                        }
                        Err(_) => {
                            eprintln!("WARNING: chunk {} failed crytographic authentication! Droping packet..", header.seq_num);
                            process::exit(1);

                        }
                    }

                    
                }

            }
            else if header.seq_num < expected_seq_num {
                let ack_header = Header {
                    packet_type:1,
                    seq_num: header.seq_num,
                    payload_len:0,
            };
            socket.send_to(&ack_header.pack(), source).await.expect("Failed to send ACK");

            }
        } else if header.packet_type == 2 {
            println!("Received EOF packet. Transfer complete");
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

