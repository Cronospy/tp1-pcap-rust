fn main() {
    let mut my_pcap = pcap::Capture::from_file(r"pcap\Capture-dji.pcapng").unwrap();

    while let Ok(packet) = my_pcap.next_packet() {
        let data = packet.data;

        let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize; // On récupère la taille de radiotype avec les deux octet qui encode la longueur de la cette partie
        let fc = &data[radiotap_len..];
        let frame_control = fc[0];
        let frame_type    = (frame_control >> 2) & 0x03;   // bits 2-3
        let frame_subtype = (frame_control >> 4) & 0x0F;   // bits 4-7
        if frame_type != 0 || frame_subtype != 8 {
            continue;
        }

        let mac = &fc[16..radiotap_len + 22];
        print!("MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        let tlv_start = 24 + 12;
        let mut offset = tlv_start;
        while offset + 2 <= fc.len() {
            let tag_type   = data[offset];       // 1 octet : type du champ
            let tag_length = data[offset + 1] as usize; // 1 octet : longueur de la valeur

            // Sécurité : vérifie que la valeur ne dépasse pas la taille du paquet
            if offset + 2 + tag_length > data.len() { break; }

            let tag_value = &data[offset + 2..offset + 2 + tag_length];

            // Type 0x00 = SSID (nom du réseau Wi-Fi)
            // from_utf8_lossy convertit les octets en texte,
            // en remplaçant les caractères invalides par '?'
            if tag_type == 0x00 {
                let ssid = String::from_utf8_lossy(tag_value);
                println!("SSID: \"{}\"\n", ssid);
                break; // On a trouvé le SSID, inutile de continuer
            }
            // On avance au TLV suivant : 2 octets (type+longueur) + la valeur
            offset += 2 + tag_length;
        }
    }
}
