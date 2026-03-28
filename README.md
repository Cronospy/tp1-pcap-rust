# Network Analyzer

Programme Rust d'analyse de trames Wi-Fi pour détecter et extraire les informations des trames DroneID (identification et localisation de drones).

## Prérequis

- Rust / Cargo
- [Npcap](https://npcap.com) installé sur Windows
- [Npcap SDK](https://npcap.com/#download) extrait dans `C:\npcap-sdk`

## Installation
```bash
git clone https://github.com/ton-username/tp1.git
cd tp1
```

Place ton fichier `.pcapng` dans le dossier `pcap/` et crée le dossier `output/` :
```
tp1/
├── pcap/
│   └── capture-23-05-08-ttgo.pcapng
└── output/
```

## Utilisation
```bash
cargo run <fichier_pcap> [OPTIONS]
```

### Exemples

Analyse basique (sortie JSON par défaut) :
```bash
cargo run "pcap/capture-23-05-08-ttgo.pcapng"
```

Choisir le format de sortie :
```bash
cargo run "pcap/capture-23-05-08-ttgo.pcapng" -f json
cargo run "pcap/capture-23-05-08-ttgo.pcapng" -f csv
```

Choisir le nom du fichier de sortie :
```bash
cargo run "pcap/capture-23-05-08-ttgo.pcapng" -o mon_fichier
```

Limiter le nombre de paquets analysés :
```bash
cargo run "pcap/capture-23-05-08-ttgo.pcapng" -c 20
```

Tout combiner :
```bash
cargo run "pcap/capture-23-05-08-ttgo.pcapng" -c 50 -f csv -o resultats
```

## Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-c, --pcap-count` | Nombre de paquets à analyser | 10 |
| `-f, --output-format` | Format de sortie (`json` ou `csv`) | json |
| `-o, --output-file` | Nom du fichier de sortie (sans extension) | result |

## Résultats

Les fichiers sont générés automatiquement dans le dossier `output/` avec l'extension correspondant au format choisi :
```
output/result.json    ← généré avec -f json
output/result.csv     ← généré avec -f csv
```

## Structure du projet
```
tp1/
├── src/
│   ├── main.rs         — point d'entrée
│   ├── lib.rs          — déclaration des modules
│   ├── analysis.rs     — parsing des trames PCAP
│   ├── models.rs       — structures DroneData et DroneDataList
│   ├── args.rs         — arguments de ligne de commande (clap)
│   └── constants.rs    — constantes 802.11 et DroneID
├── pcap/               — fichiers de capture
├── output/             — fichiers de résultats générés
└── Cargo.toml
```