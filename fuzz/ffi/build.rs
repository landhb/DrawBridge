use cc;

fn main() {

    println!("cargo:rerun-if-changed=../../src/parser.c");
    println!("cargo:rerun-if-changed=src/memory.c");
    
    cc::Build::new()
        .file("../../src/parser.c")
        .file("./src/memory.c")
        .include("../../include")
        .define("FUZZING", Some("1"))
        .define("GFP_KERNEL", Some("1"))
        .compile("parser");
}
