use std::env;
use std::net::UdpSocket;
use std::process;

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

    let message = String::from_utf8_lossy(&buffer[..size]);

    println!("Recieved '{}' from {}",message,source);
}


fn run_sender(target: &str) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");

    print!("What's the message: ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let mut message = String::new();
    std::io::stdin().read_line(&mut message).expect("Failed to input the message");

    let message = message.trim_end();
    socket.send_to(message.as_bytes(), target).expect("Failed to send");
    println!("message sent");
}
