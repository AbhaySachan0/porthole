
pub struct Header {
    pub packet_type: u8,  // 1 byte
    pub seq_num: u32,     // 4 bytes
    pub payload_len: u16, // 2 bytes
}

impl Header {
    pub fn pack(&self) -> [u8; 7] {
        let mut buffer = [0u8; 7];

        buffer[0] = self.packet_type;

        // packing the sequence number
        buffer[1] = (self.seq_num >> 24) as u8;
        buffer[2] = (self.seq_num >> 16) as u8;
        buffer[3] = (self.seq_num >> 8) as u8;
        buffer[4] = self.seq_num as u8;

        // payload length
        buffer[5] = (self.payload_len >> 8) as u8;
        buffer[6] = self.payload_len as u8;

        buffer
    }
    
    pub fn unpack(buffer: &[u8]) -> Self {
        let packet_type = buffer[0];
        let seq_num = ((buffer[1] as u32) << 24) | ((buffer[2] as u32) << 16) | ((buffer[3] as u32) << 8) | (buffer[4] as u32);

        let payload_len = ((buffer[5] as u16) << 8) | (buffer[6] as u16);

        Header {
            packet_type,
            seq_num,
            payload_len,
        }
    }
}
