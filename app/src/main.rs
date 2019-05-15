extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{fs::File, io::*, path::Path};

extern "C" {
    fn ecall_main(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

fn main() {
    let enclave = init_enclave(".", true, "../bin/enclave.signed.so");
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_main(enclave.geteid(), &mut retval) };
    assert_eq!(result, sgx_status_t::SGX_SUCCESS);
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
}

pub fn init_enclave<P: AsRef<Path>>(token_path: P, use_token: bool, enclave_location: P) -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;

    if use_token {
        match File::open(&token_path) {
            Err(_) => println!("[-] Open token file {} error! Will create one.", token_path.as_ref().display()),
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    }
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
    let enclave = SgxEnclave::create(enclave_location, debug, &mut launch_token, &mut launch_token_updated, &mut misc_attr).unwrap();

    if launch_token_updated != 0 {
        dbg!("Enclave created, Token: {:?}", &enclave);
        let mut f = File::create(&token_path).unwrap();
        f.write_all(&launch_token).unwrap();
    }
    enclave
}
