// Author: Victor Youdom Kemmoe

use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
use std::thread;
use std::sync::Arc;
use std::net::{TcpStream, TcpListener};
use std::io::{Read, Write};
use el_gam_ot1n::elgamal_ot::Sender;
use openssl::pkey::Private;
use openssl::ec::EcKey;

fn gen_messages(n: u32)->Vec<Vec<u8>>{
    let mut messages:Vec<Vec<u8>> = Vec::with_capacity(3);
    for i in 1..(n+1){
        let m = "Message ".to_owned()+ &i.to_string();
        let m = m.as_bytes();
        messages.push(m.to_vec());
    }
    messages
}

fn handle_client(mut stream: SslStream<TcpStream>, ot_sender:&mut Sender){

    println!("Generate ephemeral key");
    let eph_key: EcKey<Private> = ot_sender.ec_handler.gen_key(); //generates sender eph key
    let eph_key_bytes = ot_sender.ec_handler.pubkey_to_bytes(eph_key.public_key()); // convert eph key to bytes
    let mut ephk_bytes_choices:Vec<u8> = eph_key_bytes.clone(); // initialize buffer to hold both eph key and choices

    let mut choices = vec![1u8,2,3];
    let messages = gen_messages(choices.len() as u32);

    ephk_bytes_choices.extend(& choices); // combine eph key and choice to send
    println!("Send ephemeral key to receiver");
    stream.write(&ephk_bytes_choices).unwrap(); // send ephemeral key to client

    let mut receiver_choice = [0u8;33]; // receiver hidden choice
    stream.read(&mut receiver_choice).unwrap();
    let receiver_choice = ot_sender.ec_handler.bytes_to_pubkey(&receiver_choice[..]);
    println!("Sender received Reciever choice");

    let ciphertexts = ot_sender.enc_items(&choices[..], &messages, &eph_key, &eph_key_bytes, &receiver_choice);
    let mut buffer:Vec<u8> = vec![];
    let crlf = b"0000"; // using carriage returns as a delimiter for cipher text

    for i in 0..ciphertexts.len(){
        buffer.extend(&ciphertexts[i]);
        if i<ciphertexts.len()-1{
            buffer.extend(crlf);
        }
    }
    println!("{}", hex::encode(&buffer));
    stream.write(&buffer).unwrap();

    /*let reciever_pubkey = ot_sender.bytes_to_pubkey(&data);
    let ec_ssk = ot_sender.ec_mul(&reciever_pubkey, &eph_key_sender.private_key());
    let ec_ssk:Vec<u8> = ot_sender.pubkey_to_bytes(&ec_ssk);
    println!("ECDH key: {}", hex::encode(&ec_ssk[..]));*/
}

fn main() {
    
    println!("Server");

    println!("Prepare OT Sender");
    let mut ot_sender: Sender = Default::default(); //instantiate OT sender in rust

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
}
