fn main() {
    let mut my_pcap = pcap::Capture::from_file(r"pcap\Capture-dji.pcapng").unwrap();

    while let Ok(packet) = my_pcap.next_packet() {

        println!("Paquet reçu ! Taille : {} octets", packet.header.len);

        let data = packet.data;

        if data.len() > 10 {
            println!("Début des données : {:02x?}", &data[0..10]);
        }
    }
}
