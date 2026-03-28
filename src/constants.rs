pub const BEACON_TYPE : u8 = 0;
pub const BEACON_SUBTYPE : u8 = 8;

pub const MAC_OFFSET : usize = 16;
pub const MAC_ADRESSE_LEN : usize = 6;
pub const BEACON_FRAME_OFFSET : usize = 24;
pub const FIXED_PARAMETER_OFFSET : usize = 12;

pub const SSID_TAG : u8 = 0x00;
pub const VENDOR_SPECIFIC_TAG : u8 = 0xdd;
pub const LATITUDE_TAG : u8 = 0x04;
pub const LONGITUDE_TAG : u8 = 0x05;
pub const ALTITUDE_TAG : u8 = 0x06;