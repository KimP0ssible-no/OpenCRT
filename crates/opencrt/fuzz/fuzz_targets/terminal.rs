#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| opencrt::fuzz::terminal(data));
