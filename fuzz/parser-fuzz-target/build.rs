use cc;

fn main() {
    cc::Build::new()
        .file("../../../kernel/parser.c")
        .file("./src/memory.c")
        .define("FUZZING", Some("1"))
        .define("GFP_KERNEL", Some("1"))
        .compile("parser");
}