use clap::Parser;

#[derive(Parser)]
pub struct Args {
    pub pcap : String,

    #[arg(short = 'c', long,default_value_t = 10)]
    pub pcap_count : i32,

    #[arg(short = 'f' , long, default_value_t = String::from("json"))]
    pub output_format : String,

    #[arg(short, long, default_value_t = String::from("result"))]
    pub output_file : String,
}