// Author: Victor Youdom Kemmoe

use openssl::ssl::{SslMethod, SslConnector, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;
use el_gam_ot1n::elgamal_ot::Receiver;

fn main() {
    
    let mut receiver:Receiver = Default::default();
    receiver.hide_choice(4,receiver.get_pubkey());
    let key = receiver.get_dec_key(receiver.get_pubkey());
    //println!("{}", hex::encode(&key[..]));

    //test enc, dec
    let key = hex::decode("4669591e056fa4361d5ee044e430f7c3").unwrap();
    let data = b"bonjour people comment vent aller messon sdflsdnglj sjsj";
    let ciphertext = receiver.ec_handler.enc_data(&key[..],data);
    println!("Cipher text returned {}",hex::encode(&ciphertext[..]));
    let message = receiver.ec_handler.dec_data(&key[..],&ciphertext[..]);
    println!("Message {}", String::from_utf8_lossy(&message));

    /*let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_ca_file("src/keyfile/certs.pem");
    let connector = connector.build();

    let stream = TcpStream::connect("127.0.0.1:9000").unwrap();
    let mut stream = connector.connect("127.0.0.1",stream).unwrap();*/

    //Recieiver handler for the OT protocol
    /*let mut receiver:Receiver = Default::default();
    let rec_pubkey = receiver.get_pubkey();
    let pubkey_bytes = receiver.pubkey_to_bytes(rec_pubkey);
    println!("pubkey length:{}, actual value: {}",pubkey_bytes.len(), hex::encode(&pubkey_bytes[..]));

    stream.write(&pubkey_bytes).unwrap();
    stream.flush().unwrap();
    println!("client sent its message");

    let mut server_pubkey = vec![];
    stream.read_to_end(&mut server_pubkey).unwrap();
    let server_pubkey = receiver.bytes_to_pubkey(&server_pubkey);
    let ec_ssk = receiver.ec_mul(&server_pubkey, receiver.get_privkey());
    let ec_ssk:Vec<u8> = receiver.pubkey_to_bytes(&ec_ssk);
    println!("ECDH: {}",hex::encode(&ec_ssk[..]));*/
   // stream.write_all(b"client").unwrap();

    println!("Client");
}
