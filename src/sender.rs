
use std::sync::Arc;
use std::time::Duration;
use std::process;
use std::path::Path;

use tokio::net::UdpSocket;
use tokio::fs::File;
use std::io::SeekFrom;
use tokio::io::{AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::timeout;
use spake2::{Spake2, Ed25519Group, Password, Identity};

use crate::protocol::Header;
use crate::crypto:: {generate_magic_code, encrypt_chunk};

use indicatif::{ProgressBar, ProgressStyle};


pub async fn run_sender(file_path: &str, target: &str) {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("Failed to bind"));
    let listener_socket = socket.clone();

    // --- THE HANDSHAKE  ---

    let code = generate_magic_code();
    println!("==========================================");
    println!("Share this code with the receiver: {}", code);
    println!("==========================================");
    println!("Waiting for receiver to connect...");

    let pw = Password::new(code.as_bytes());
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
                        let final_key_vec = state.finish(msg_b).expect("Math error");
                        derived_key.copy_from_slice(&final_key_vec);
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    println!("Verifying password with receiver...");

    let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();

    let mut auth_message = b"AUTH:".to_vec();
    auth_message.extend_from_slice(file_name.as_bytes());


    let auth_ciphertext = encrypt_chunk(0, &auth_message, &derived_key);
    let auth_header = Header { packet_type:5, seq_num: 0, payload_len: auth_ciphertext.len() as u16};
    let mut auth_packet = Vec::new();
    auth_packet.extend_from_slice(&auth_header.pack());
    auth_packet.extend_from_slice(&auth_ciphertext);

    let mut authenticated = false;

    for _ in 0..10 {
        socket.send_to(&auth_packet, target).await.expect("failed to send auth packet..");
        match timeout(Duration::from_millis(500), socket.recv_from(&mut handshake_buffer)).await {
            Ok(Ok((size, _))) => {
                if size >=7 && Header::unpack(&handshake_buffer[0..7]).packet_type == 6 {
                    authenticated = true;
                    break;
                }
            }
            _ => {}
        }
    }
     if !authenticated {
         eprintln!("Authentication failed..");
         process::exit(1);
     }
     println!("Password verified..");
          
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

    let file = File::open(file_path).await.expect("Failed to open file..");

    let file_size = file.metadata().await.expect("Failed to read metadata").len();

    let pb = ProgressBar::new(file_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-")
        );

    let mut reader = BufReader::with_capacity(1024*1024*8, file);

    let mut seq_num = 1;
    let mut last_acked = 0;
    let mut window_size = 100;
    const MIN_WINDOW: u32 = 10;
    const MAX_WINDOW: u32 = 5000;


    let mut dup_ack_count = 0;   // duplicate ACK counts
    let mut chunk_buffer = [0u8; 1400];

    println!("Starting file transfer.....");

    loop {

        //PIPELINE CHECK
        while seq_num - last_acked > window_size {
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(acked_num)) => {
                    if acked_num > last_acked { 
                        last_acked = acked_num; 
                        dup_ack_count = 0;

                        window_size = (window_size +1).min(MAX_WINDOW);
                    }
                }
                _ => {
                    window_size = (window_size/2).max(MIN_WINDOW);
                    seq_num = last_acked +1;
                    let rewind_offset = (last_acked as u64) * 1400;

                    reader.seek(SeekFrom::Start(rewind_offset)).await.expect("Failed to rewind file");
                    break;
                }
            }
        }

        
        let bytes_read = reader.read(&mut chunk_buffer).await.expect("Failed to read file");
        let is_eof = bytes_read==0;

        if bytes_read > 0 {
            pb.set_position(((seq_num-1) as u64) * 1400 + bytes_read as u64);
        }

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
            pb.finish_with_message(format!("Transfer complete ! Send {}", file_path));
            break;
        }
        seq_num +=1;

        while let Ok(acked_num) = rx.try_recv() {
            if acked_num > last_acked { 
                last_acked = acked_num; 
                dup_ack_count = 0;
            } else if acked_num ==  last_acked {
                dup_ack_count += 1;
                if dup_ack_count >= 3 {
                    seq_num = last_acked +1;
                    let rewind_offset = (last_acked as u64) * 1400;
                    reader.seek(SeekFrom::Start(rewind_offset)).await.expect("Failed to rewind file..");
                    dup_ack_count = 0;
                    break;
                }

            }
        }
    }
}
