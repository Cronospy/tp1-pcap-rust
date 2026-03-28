use std::fs::File;
use serde::{Deserialize, Serialize};
use csv;
#[derive(Serialize,Deserialize)]
pub struct DroneData {
    pub ssid : String,
    pub vendor_specific : String,
    pub mac_address : String,
    pub latitude : i32,
    pub longitude : i32,
    pub altitude : i16,
}

impl DroneData {
    pub fn new() -> DroneData {
        DroneData {
            ssid : String::from(""),
            vendor_specific : String::from(""),
            mac_address : String::from(""),
            latitude : 0,
            longitude : 0,
            altitude : 0,
        }
    }
}

#[derive(Serialize,Deserialize)]
pub struct DroneDataList {
    items : Vec<DroneData>,
}

impl DroneDataList {
    pub fn new() -> DroneDataList {
        DroneDataList {
            items : Vec::new()
        }
    }

    pub fn add(self: &mut DroneDataList, item: DroneData) {
        self.items.push(item);
    }

    pub fn save_to_file(self: &DroneDataList, format: String, filename: String) {
        //create file
        let file = File::create(format!(r"output\{}.{}", filename, format)).expect("Unable to create file");

        match format.as_str() {
            "json" => {
                // écrit tout le Vec en json formaté en 1 seule fois
                serde_json::to_writer_pretty(file,self).expect("Unable to write to json file");
            }
            "csv" => {
                // crée un Writer csv à partir du fichier
                let mut wtr = csv::Writer::from_writer(file);

                //écrit chaque paramètre ligne par ligne
                for dronedata in &self.items {
                    wtr.serialize(dronedata).expect("Unable to write to csv file");
                }
                // Vide le buffer et finalise le fichier
                wtr.flush().expect("Unable to write to csv file");
            }
            _ => {
                println!("Unknown format : {}", format);
            }
        }
    }

}