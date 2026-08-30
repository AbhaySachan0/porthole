
use clap::{Parser, Subcommand};

mod protocol;
mod crypto;
mod sender;
mod receiver;

use crate::sender::run_sender;
use crate::receiver::run_receiver;

#[derive(Parser)]
#[command(name = "Porthole")]
#[command(about = "A secure, fast P2P file transfer tool", long_about = None)]

struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Receive {
       dir: String,
    },
    Send {
        file:String,
        target: String,
    },

}


#[tokio::main]
async fn main() {

    let cli = Cli::parse();

    match &cli.command {
        Commands::Receive {dir} => {
            println!("Starting porthole in Receiver mode...");
            run_receiver(dir).await;
        }
        Commands::Send { file, target } => {
            println!("Starting porthole in sender mode to {}...", target);
            run_sender(&file, &target).await;
        }
    }
}


