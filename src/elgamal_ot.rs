// This file contains the different method necessary to perform a 1-n OT between a Sender and a Receiver
// Default Elliptic curve group to be used is SECP256K1
// Future work: improve code reusability

use openssl::ec::{EcPointRef,EcPoint,EcKey, EcKeyRef};
use openssl::pkey::Private;
use openssl::bn::{BigNumRef,BigNum};
use openssl::nid::Nid;
use openssl::hash::{Hasher, MessageDigest};

pub mod ec_handler;
use ec_handler::EcHandler;

pub struct Receiver{
    pub ec_handler: EcHandler, // module in charge of handling Elliptic Curve Operation
    key: EcKey<Private>, // public private key to be used for OT
}

pub struct Sender{
    pub ec_handler: EcHandler, // module in charge of handling Elliptic Curve Operation
    // The sender doesn't need a static ephemeral key since it will generates multiple one during protocol execution.
}


/****************************
 *  RECIEVER IMPLEMENTATION
 ****************************/
impl Receiver{
    // return reference to receiver public key
    pub fn get_pubkey(&self)-> &EcPointRef{
        let pubkey = self.key.public_key();
        pubkey
    }

    // return reference to receiver private key
    pub fn get_privkey(&self)-> &BigNumRef{
        let privkey = self.key.private_key();
        privkey
    }

    // represent setp 2 of the OT protocol from Dan Boneh Book.
    // using its public key g^a, and index i and the sender public key v, it computes 
    // u<- g^a.v^(-i). In an EC group, this is equivalent to U<- aG+(-i)V 
    // @param choice, the chosen index of the receiver. 
    // @param sender_pubkey, the public key sent by the sender
    pub fn hide_choice(&self, choice:u32, sender_pubkey:&EcPointRef)->EcPoint{
        let choice:BigNum = BigNum::from_u32(choice).unwrap();
        let mut v:EcPoint = self.ec_handler.ec_mul(&sender_pubkey, &choice);
        self.ec_handler.ec_invert(&mut v);// -(iV) = (-i)V
        let u:EcPoint = self.ec_handler.ec_add(self.get_pubkey(), &v);
        let temp:Vec<u8> = self.ec_handler.pubkey_to_bytes(&u); 
        u
    }

    // Compute the decryption key that will be used by the receiver to decipher message m_i
    // from all the message the sender sent. Only message m_i can be deciphered by this key
    // hence, complying with the basic definition of OT protocol
    // return Key <- H(v,w)
    pub fn get_dec_key(&self, sender_pubkey:&EcPointRef)->Vec<u8>{
        //compute w<- v^a 
        let w:EcPoint = self.ec_handler.ec_mul(&sender_pubkey, self.get_privkey());
        let w:Vec<u8> = self.ec_handler.pubkey_to_bytes(&w);

        let v:Vec<u8> = self.ec_handler.pubkey_to_bytes(&sender_pubkey);

        EcHandler::derive_key(&v,&w)
    }
}

// Default value for a receiver
impl Default for Receiver{
    fn default()->Receiver{
        let handler = EcHandler::new(Nid::SECP256K1);
        Receiver{
            key: handler.gen_key(),
            ec_handler: handler
        }
    }
}

/****************************
 *  SENDER IMPLEMENTATION
 ****************************/
impl Sender{
    //  given an item index and the keymaterial of the reciever (an elliptic curve point hidding its choice),
    //  return an encryption for that item
    //  @param item_index: the index of the item for which we want to generate the key
    //  @param sender_ephk: the sender ephemeral key
    //  @param receiver_km: hidden choice of receiver
    pub fn get_item_key(&self, item_index:u32, sender_ephk:&EcKeyRef<Private>, 
                        sender_ephk_bytes:&Vec<u8>,receiver_km:&EcPointRef)-> Vec<u8>{
        let item_index:BigNum = BigNum::from_u32(item_index).unwrap();
        let v_powerj:EcPoint = self.ec_handler.ec_mul(sender_ephk.public_key(), &item_index); //compute v^j
        let u_j:EcPoint = self.ec_handler.ec_add(&v_powerj, &receiver_km); //computer u.v^j
        let w_j:EcPoint = self.ec_handler.ec_mul(&u_j, sender_ephk.private_key()); // compute w_j <- (u.v^j)^b
        let w_j:Vec<u8> = self.ec_handler.pubkey_to_bytes(&w_j);
        EcHandler::derive_key(sender_ephk_bytes, &w_j)
    }



}

// Default instance of a sender
impl Default for Sender{
    fn default() ->Sender{
        Sender{
            ec_handler: EcHandler::new(Nid::SECP256K1),
        }
    }
}