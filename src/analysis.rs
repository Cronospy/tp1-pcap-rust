use crate::constants::*;
use crate::models::{DroneData, DroneDataList};

pub fn analyse(_path_pcap:String, packet_count: i32) -> DroneDataList {
    let mut my_pcap = pcap::Capture::from_file(r"pcap/capture-23-05-08-ttgo.pcapng").unwrap();
    let mut drone_data_list = DroneDataList::new();

    let mut limited_print = packet_count;
    while let Ok(packet) = my_pcap.next_packet() && limited_print > 0  {
        // On récupère la data du packet
        let data = packet.data;

        // On retire la partie "En-tête Radiotap"
        let radiotap_offset = u16::from_le_bytes([data[2], data[3]]) as usize; // On récupère la taille de radiotype avec les deux octet qui encode la longueur de la cette partie
        let data = &data[radiotap_offset..];

        // On récupère les bytes de frame control pour obtenir le type et le sous type
        let frame_control = data[0];
        let frame_type    = (frame_control >> 2) & 0x03;   // masque pour avoir les bits 2-3
        let frame_subtype = (frame_control >> 4) & 0x0F;   // masque pour avoir les bits 4-7

        // On check que le type et le sous type sont ceux de beacon
        if frame_type != BEACON_TYPE|| frame_subtype != BEACON_SUBTYPE {
            continue; // On passe au packet d'après si c'est pas le bon type. continue to the next loop
        }

        // On retire 1 à limite de print
        limited_print -= 1;

        // On récupère l'addresse mac
        let mac = &data[MAC_OFFSET..MAC_OFFSET + MAC_ADRESSE_LEN];

        //début du parcours des TLV
        let tlv_start = BEACON_FRAME_OFFSET + FIXED_PARAMETER_OFFSET;
        let mut offset = tlv_start;

        // on enregistre toutes les tvl pour les traiter après
        let mut tvl_list = Vec::new();
        while offset + 2 <= data.len() {
            let tag_type   = data[offset];       // 1 octet : type du champ
            let tag_length = data[offset + 1] as usize; // 1 octet : longueur de la valeur
            let tag_value = &data[offset + 2..offset + 2 + tag_length];
            tvl_list.push((tag_type,tag_length,tag_value));
            // On avance au TLV suivant : 2 octets (type+longueur) + la valeur
            offset += 2 + tag_length;
        }

        let mut is_drone = false;
        let mut vendor_specific_tab : &[u8] = &[]; // On initialise une variable pour stocker la partie vendor specific du TLV
        let mut drone_data = DroneData::new();

        for (tag_type,_,value) in tvl_list {
            match tag_type {
                SSID_TAG => drone_data.ssid = String::from_utf8(value.to_vec()).unwrap(),
                VENDOR_SPECIFIC_TAG => {
                    is_drone = true;
                    // On retire les 4 premiers octets qui sont l'OUI (3 octets) et le type spécifique du fabricant
                    vendor_specific_tab = &value[4..];
                    drone_data.vendor_specific = format!("{:02x?}",&value[0..3]);
                },
                _ => (),
            }
        }

        // Si ce n'est pas un drone on passe au packet suivant
        if !is_drone {continue;}

        // On mets l'adresse mac
        drone_data.mac_address = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}"
                                        , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // On parcours les tvl de l'encapsulation specific vendor
        let mut offset = 0;
        let mut tvl_list = Vec::new();

        while offset + 2 < vendor_specific_tab.len() {
            let tag_type   = vendor_specific_tab[offset];       // 1 octet : type du champ
            let tag_length = vendor_specific_tab[offset + 1] as usize; // 1 octet : longueur de la valeur

            // Sécurité : on vérifie que la longueur du tag ne dépasse pas les limites du tableau
            if offset + 2 + tag_length > vendor_specific_tab.len() {
                //println!("Erreur : TLV dépasse les limites du tableau vendor specific !");
                break; // On sort de la boucle pour éviter un panic
            }

            let tag_value = &vendor_specific_tab[offset + 2..offset + 2 + tag_length];
            tvl_list.push((tag_type,tag_length,tag_value));

            // On avance au TLV suivant : 2 octets (type+longueur) + la valeur
            offset += 2 + tag_length;

            // On récupère les infos que l'on a besoin
            if tag_type == LONGITUDE_TAG {
                drone_data.longitude = i32::from_le_bytes(tag_value.try_into().unwrap());
            }
            if tag_type == LATITUDE_TAG {
                drone_data.latitude = i32::from_le_bytes(tag_value.try_into().unwrap());
            }
            if tag_type == ALTITUDE_TAG {
                drone_data.altitude = i16::from_le_bytes(tag_value.try_into().unwrap());
            }
        }

        drone_data_list.add(drone_data);

    };
    return drone_data_list;
}

pub fn rt_capture(interface: &str, filter: &Option<String>, packet_count:i32) {
    let mut cap = pcap::Capture::from_device(interface).unwrap().open().unwrap();

    //appliquer le filtre
    if let Some(f) = filter {
        cap.filter(f, true).unwrap();
    }

    let mut results = DroneDataList::new();
    let mut count = 0;

    while let Ok(packet) = cap.next_packet() {
        count += 1;
        if count >= packet_count {
            break;
        }
    }
}