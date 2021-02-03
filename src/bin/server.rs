// Author: Victor Youdom Kemmoe

use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
use std::thread;
use std::sync::Arc;
use std::net::{TcpStream, TcpListener};
use std::io::{Read, Write};
use el_gam_ot1n::elgamal_ot::Sender;

fn handle_client(mut stream: SslStream<TcpStream>, ot_sender:&mut Sender){
    /*println!("Passed in handling method");
    let eph_key_sender = ot_sender.get_eph_key();
    let eph_key_bytes:Vec<u8> = ot_sender.pubkey_to_bytes(eph_key_sender.public_key());
    let mut data = [0u8;33];
    let length = stream.read(&mut data).unwrap();
    println!("read successfully; size read:{}", length);
    println!("Key from receiver {}", hex::encode(&data[..]));

    stream.write(&eph_key_bytes).unwrap();

    let reciever_pubkey = ot_sender.bytes_to_pubkey(&data);
    let ec_ssk = ot_sender.ec_mul(&reciever_pubkey, &eph_key_sender.private_key());
    let ec_ssk:Vec<u8> = ot_sender.pubkey_to_bytes(&ec_ssk);
    println!("ECDH key: {}", hex::encode(&ec_ssk[..]));*/
}

fn main() {
    //instantiate OT sender in rust
    let mut ot_sender: Sender = Default::default();

    //remember: certificate should always be signed
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file("src/keyfile/key.pem", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_file("src/keyfile/certs.pem",SslFiletype::PEM).unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind("127.0.0.1:9000").unwrap();

    for stream in listener.incoming(){
        match stream{
            Ok(stream)=>{
                println!("a receiver is connected");
                let acceptor = acceptor.clone();
                //thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    handle_client(stream, &mut ot_sender);
                //});
            }
            Err(_e)=>{println!{"connection failed"}}
        }
    }


    println!("Server");
}
