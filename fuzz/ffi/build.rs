use cc;

fn main() {

    println!("cargo:rerun-if-changed=../../kernel/parser.c");
    println!("cargo:rerun-if-changed=src/memory.c");
    
    cc::Build::new()
        .file("../../kernel/parser.c")
        .file("./src/memory.c")
        .define("FUZZING", Some("1"))
        .define("GFP_KERNEL", Some("1"))
        .compile("parser");
}
