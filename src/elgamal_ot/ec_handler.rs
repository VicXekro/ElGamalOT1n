//  This file contains all the different operations related to EC crypto for the OT protocol
//  Supplemented with methods to derive encryption keys, encrypt and decrypt binary data
use openssl::ec::*;
use openssl::pkey::Private;
use openssl::bn::*;
use openssl::nid::Nid;
use openssl::symm::*;
use openssl::rand::rand_bytes;

use hkdf::Hkdf;
use sha2::Sha256;


pub struct EcHandler{
    ecgroup: EcGroup, // Elliptic curve group to be used
    block_cipher: Cipher // block cipher that will be used for symmetric encryption, decryption (default is AES 128 CBC)
}

impl EcHandler{
    
    // convert app info into a vector of binary
    #[inline]
    pub fn APP_INFO()->Vec<u8>{
        let info = b"EC ELGAMAL 1-N OT";
        info.to_vec()
    }

    // get the salt (8 bytes) to be used for the application
    // it is randomly generated variable 
    #[inline]
    pub fn APP_SALT()->Vec<u8>{
        let salt = hex::decode("19b43144e977bd6823a40287d4406819").unwrap();
        salt
    }

    //take a curve name from Nid and initialize the group
    pub fn new(curve: Nid)->EcHandler{
        EcHandler{
            ecgroup:EcGroup::from_curve_name(curve).unwrap(),
            block_cipher: Cipher::aes_128_cbc()
        }
    }

    //convert a bytes represent of an EC pubkey to an actual EC pubkey
    pub fn bytes_to_pubkey(&self, buf:&[u8])->EcPoint{
        let mut ctx = BigNumContext::new().unwrap(); // temporary storage for BigNums on the secure Heap
        let pubkey = EcPoint::from_bytes(&self.ecgroup,buf,&mut ctx).unwrap();
        pubkey
    }

    //generate an new private/public key pair on the ec curve
    pub fn gen_key(&self)->EcKey<Private>{
        let key_pair = EcKey::<Private>::generate(&self.ecgroup).unwrap();
        key_pair
    }

    //Convert an Elliptic curve public key into bytes
    pub fn pubkey_to_bytes(&self, pubkey: &EcPointRef)->Vec<u8>{
        let mut ctx = BigNumContext::new().unwrap(); // temporary storage for BigNums on the secure Heap
        let key_bytes = pubkey.to_bytes(&self.ecgroup,PointConversionForm::COMPRESSED,&mut ctx).unwrap();
        key_bytes
    }

    // given reference to EC point Q and secret m, compute temp = m.Q and return temp
    pub fn ec_mul(&self, q:&EcPointRef, m:&BigNumRef)->EcPoint{
        let mut ctx = BigNumContext::new().unwrap(); // temporary storage for BigNums on the secure Heap
        let mut temp = EcPoint::new(&self.ecgroup).unwrap();
        temp.mul(&self.ecgroup, q, m, &mut ctx);
        temp
    }

    // given reference to EC points P and Q, compute P+Q
    pub fn ec_add(&self, p:&EcPointRef, q:&EcPointRef)->EcPoint{
        let mut ctx = BigNumContext::new().unwrap(); // temporary storage for BigNums on the secure Heap
        let mut temp = EcPoint::new(&self.ecgroup).unwrap();
        temp.add(&self.ecgroup,p,q,&mut ctx);
        temp
    }

    //  given a point P return -P
    pub fn ec_invert(&self, p:&mut EcPointRef){
        let mut ctx = BigNumContext::new().unwrap(); // temporary storage for BigNums on the secure Heap
        p.invert(&self.ecgroup,&ctx);
    }

    //  given the bytes representation of two elliptic curve points V and W, this function 
    //  returns Key <- HKDF(V||W) of 128-bits (16bytes)
    pub fn derive_key(v:&Vec<u8>, w:&Vec<u8>)->Vec<u8>{
        let mut ikm = v.clone();//initial key material (ikm) is the concatenation of v and w
        ikm.extend(w);
        let h = Hkdf::<Sha256>::new(Some(&EcHandler::APP_SALT()),&ikm);
        let mut okm = [0u8; 16];
        h.expand(&EcHandler::APP_INFO(), &mut okm).unwrap();
        okm.to_vec()
    }

    // This function encrypt binary data using an encryption key and return a ciphertext
    // It use AES 128 CBC as block cipher
    pub fn enc_data(&self, key:&[u8], data:&[u8])->Vec<u8>{
        let mut iv = [0u8;16]; // 16 bytes initialization vector
        rand_bytes(&mut iv).unwrap(); // fill IV with random bytes

        let cipher = encrypt(self.block_cipher, key, Some(&iv[..]),data).unwrap();
        let mut ciphertext = iv.to_vec();
        ciphertext.extend(cipher);
        ciphertext
    }

    // This function takes a ciphertext and an encryption key as inputs. It returns the corresponding plaintext
    // It use AES 128 CBC as block cipher
    pub fn dec_data(&self, key:&[u8], ciphertext:&[u8])->Vec<u8>{
        let iv = &ciphertext[0..16];//read first 16 bytes of ciphertext to get the IV
        let ciphertext = &ciphertext[16..];
        let data = decrypt(self.block_cipher, key, Some(&iv[..]), ciphertext).unwrap();
        data
    }
}

