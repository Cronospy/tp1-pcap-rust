use clap::Parser;
use tp1::args::Args;
use tp1::analysis::analyse;
use tp1::models::DroneDataList;

fn main() {
    let parse = Args::parse();

    let drone_data_list = analyse(parse.pcap,parse.pcap_count);
    drone_data_list.save_to_file(parse.output_format,parse.output_file)
}