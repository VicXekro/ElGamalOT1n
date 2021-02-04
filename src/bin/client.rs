// Author: Victor Youdom Kemmoe

use openssl::ssl::{SslMethod, SslConnector, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;
use el_gam_ot1n::elgamal_ot::Receiver;
use el_gam_ot1n::elgamal_ot::data_handler;

// Given a buffer of raw bytes, divides them into ciphertexts. use b"0000" as dividers
fn get_ciphertexts(buffer:&[u8])->Vec<Vec<u8>>{
    let div = b"0"; 
    let mut ciphertexts:Vec<Vec<u8>> = Vec::new();
    let length = buffer.len();
    let mut i:usize = 0;
    let mut start:usize = 0;
    let mut end:usize = 0;
   
    while i+3<length{
        //println!("So far so good i:{}, length:{}", i, length);
        if buffer[i]==div[0] && buffer[i+1] == div[0] && buffer[i+2] == div[0] && buffer[i+3] == div[0]{
            //println!("found limit i:{}, length:{}", i, length);
            end = i;
            let mut ciphertext = vec![0u8; end-start];
            ciphertext.copy_from_slice(&buffer[start..end]);
            ciphertexts.push(ciphertext);
            start = i+4;
            i = start;
            continue;
        }
        i+=1;
    }

    //get the last cipher text without the padded zeros
    end = length-1; // first find where the padding start --> this will represent the end of last cipher
    while end>=0 {
        if buffer[end]!= 0 as u8{
            break;
        }
        end-=1;
    }
    end+=1; // add one since range is from [start, end)

    let mut ciphertext = vec![0u8; end-start];
    ciphertext.copy_from_slice(&buffer[start..end]);
    ciphertexts.push(ciphertext);

    for i in ciphertexts.iter(){
        println!("cipher: {}", hex::encode(&i));
    }

    ciphertexts
}

fn main() {
    println!("Client");

    println!("Prepare OT Receiver");
    let receiver:Receiver = Default::default();
    //receiver.hide_choice(4,receiver.get_pubkey());
    //let key = receiver.get_dec_key(receiver.get_pubkey());

    /*********************************
    *   PREPARING CONNECTION OVER TLS
    **********************************/
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_ca_file("src/keyfile/certs.pem");
    let connector = connector.build();

    let stream = TcpStream::connect("127.0.0.1:9000").unwrap();
    let mut stream = connector.connect("127.0.0.1",stream).unwrap();

    /*********************************
    *   OT PROTOCOL RECEIVER SIDE
    **********************************/
    let mut sender_ephk_choices = [0u8;40];

    stream.read(&mut sender_ephk_choices).unwrap();
    let sender_eph_key = receiver.ec_handler.bytes_to_pubkey(&sender_ephk_choices[..33]);
    println!("Received Sender Ephemeral Key");

    let choices = &sender_ephk_choices[33..];
    print!("Received Sender available indexes: ");
    for i in choices.iter(){
        print!("{}, ",i);
    }
    print!("\n");

    let receiver_choice = choices[2] as u32;
    let hidden_choice = receiver.hide_choice(receiver_choice, &sender_eph_key);
    let hidden_choice = receiver.ec_handler.pubkey_to_bytes(&hidden_choice);
    println!("Selected and hide index: {}", receiver_choice);
    stream.write(&hidden_choice).unwrap();
    println!("Sent choice to sender\n");

    let mut buffer = [0u8; 110]; // reading ciphertext sent by sender
    stream.read(&mut buffer).unwrap();
    println!("Message received from sender: {}\n", hex::encode(&buffer[..]));

    println!("Etracting cipher from messages received");
    let ciphertexts = get_ciphertexts(&buffer[..]);

    let messages = receiver.dec_items(&ciphertexts, &sender_eph_key);

    println!("\nReading Plain text message");
    for message in messages.iter(){
        println!("{}", String::from_utf8_lossy(message));
    }

    /*let rec_pubkey = receiver.get_pubkey();
    let pubkey_bytes = receiver.pubkey_to_bytes(rec_pubkey);
    println!("pubkey length:{}, actual value: {}",pubkey_bytes.len(), hex::encode(&pubkey_bytes[..]));

    stream.write(&pubkey_bytes).unwrap();
    stream.flush().unwrap();
    println!("client sent its message");

    
    let server_pubkey = receiver.bytes_to_pubkey(&server_pubkey);
    let ec_ssk = receiver.ec_mul(&server_pubkey, receiver.get_privkey());
    let ec_ssk:Vec<u8> = receiver.pubkey_to_bytes(&ec_ssk);
    println!("ECDH: {}",hex::encode(&ec_ssk[..]));
   // stream.write_all(b"client").unwrap();*/

   //test enc, dec
    /*let key = hex::decode("4669591e056fa4361d5ee044e430f7c3").unwrap();
    let data = b"bonjour people comment vent aller messon sdflsdnglj sjsj";
    let ciphertext = receiver.ec_handler.enc_data(&key[..],data);
    println!("Cipher text returned {}",hex::encode(&ciphertext[..]));
    data_handler::encode_data_64(&ciphertext[..]);
    let message = receiver.ec_handler.dec_data(&key[..],&ciphertext[..]);
    println!("Message {}", String::from_utf8_lossy(&message));*/
}
