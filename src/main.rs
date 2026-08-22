use std::env;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use std::io::{self, Write};

use clap::{Parser, Subcommand};

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

use rand::prelude::IndexedRandom;  // random words
use rand::RngExt;

struct Header {
    packet_type: u8,  // 1 byte
    seq_num: u32,     // 4 bytes
    payload_len: u16, // 2 bytes
}

#[derive(Parser)]
#[command(name = "Porthole")]
#[command(about = "A secure, fast P2P file transfer tool", long_about = None)]

struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Recieve {
        file: String,
    },
    Send {
        file:String,
        target: String,
    },

}


fn generate_magic_code() -> String {
    let adjectives = [
        "autumn", "hidden", "bitter", "misty", "silent", "empty", "dry", "dark",
        "summer", "icy", "delicate", "quiet", "white", "cool", "spring", "winter",
        "patient", "twilight", "dawn", "crimson", "wispy", "weathered", "blue",
    ];
    let nouns = [
        "waterfall", "river", "breeze", "moon", "rain", "wind", "sea", "morning",
        "snow", "lake", "sunset", "pine", "shadow", "leaf", "dawn", "glitter",
        "forest", "hill", "cloud", "meadow", "sun", "glade", "bird", "brook",
    ];

    let mut rng = rand::rng();
    let number = rng.random_range(1..100);
    let adj = adjectives.choose(&mut rng).unwrap();
    let noun = nouns.choose(&mut rng).unwrap();

    format!("{}-{}-{}", number, adj, noun)
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
     
    let cli = Cli::parse();

    match &cli.command {
        Commands::Recieve {file} => {
            println!("Starting porthole in Reciever mode...");
            run_reciever(&file).await;
        }
        Commands::Send { file, target } => {
            println!("Starting porthole in sender mode to {}...", target);
            run_sender(&file, &target).await;
        }
    }
}


async fn run_reciever(save_path: &str) {
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


async fn run_sender(file_path: &str, target: &str) {
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
    println!("Verifying password with reciever...");

    let auth_ciphertext = encrypt_chunk(0, b"AUTH", &derived_key);
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
