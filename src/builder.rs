use std::collections::HashMap;

use byteorder::{ByteOrder, BigEndian, WriteBytesExt};

use {Opcode, ResponseCode, Header, QueryType, QueryClass, Type, Class};

/// Allows to build a DNS packet
///
/// Both query and answer packets may be built with this interface, although,
/// much of functionality is not implemented yet.
#[derive(Debug)]
pub struct Builder {
    buf: Vec<u8>,
    labels: HashMap<String, u16>,
}

pub const OFFSET_FLAG : u16 = 0b1100_0000_0000_0000;

impl Builder {
    /// Creates a new query
    ///
    /// Initially all sections are empty. You're expected to fill
    /// the questions section with `add_question`
    pub fn new_query(id: u16, recursion: bool) -> Builder {
        let mut buf = Vec::with_capacity(512);
        let head = Header {
            id: id,
            query: true,
            opcode: Opcode::StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: recursion,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        buf.extend([0u8; 12].iter());
        head.write(&mut buf[..12]);
        Builder { buf: buf, labels: HashMap::new() }
    }


    /// Creates a new response
    /// 
    /// Similar to `new_query`, all sections are empty. You
    /// will need to add all your questions first, then add
    /// your answers.
    pub fn new_response(id: u16, rc: ResponseCode, tc: bool, 
        rd: bool, ra:bool, ad: bool, cd: bool) -> Builder {
        let mut buf = Vec::with_capacity(512);
        let head = Header {
            id: id,
            query: false,
            opcode: Opcode::StandardQuery,
            authoritative: true,
            truncated: tc,
            recursion_desired: rd,
            recursion_available: ra,
            authenticated_data: ad,
            checking_disabled: cd,
            response_code: rc,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        buf.extend([0u8; 12].iter());
        head.write(&mut buf[..12]);
        Builder { buf: buf, labels: HashMap::new() }
    }
    /// Adds a question to the packet
    ///
    /// # Panics
    ///
    /// * Answers, nameservers or additional section has already been written
    /// * There are already 65535 questions in the buffer.
    /// * When name is invalid
    pub fn add_question(&mut self, qname: &str, prefer_unicast: bool,
        qtype: QueryType, qclass: QueryClass)
        -> &mut Builder
    {
        if &self.buf[6..12] != b"\x00\x00\x00\x00\x00\x00" {
            panic!("Too late to add a question");
        }
        self.write_name(qname);
        self.buf.write_u16::<BigEndian>(qtype as u16).unwrap();
        let prefer_unicast: u16 = if prefer_unicast { 0x8000 } else { 0x0000 };
        self.buf.write_u16::<BigEndian>(qclass as u16 | prefer_unicast).unwrap();
        let oldq = BigEndian::read_u16(&self.buf[4..6]);
        if oldq == 65535 {
            panic!("Too many questions");
        }
        BigEndian::write_u16(&mut self.buf[4..6], oldq+1);
        self
    }


    /// Adds an answer to the packet
    ///
    /// NOTE: You need to add all you questions first before adding answers.
    /// # Panics
    /// 
    /// * There are too many answers in the buffer.
    /// * When name is invalid
    // TODO(david-cao): untested, only works for type A
    pub fn add_answer(&mut self, aname: &str, atype: Type,
        aclass: Class, ttl: u32, data: Vec<u8>) -> &mut Builder
    {
        self.write_name(aname);
        self.buf.write_u16::<BigEndian>(atype as u16).unwrap();
        self.buf.write_u16::<BigEndian>(aclass as u16).unwrap();
        self.buf.write_u32::<BigEndian>(ttl).unwrap();
        let ln = data.len() as u16;
        self.buf.write_u16::<BigEndian>(ln).unwrap();
        self.buf.extend(data);
        // self.buf.write_u32::<BigEndian>(data).unwrap();
        let olda = BigEndian::read_u16(&self.buf[6..8]);
        if olda == 65535 {
            panic!("Too many answers");
        }
        BigEndian::write_u16(&mut self.buf[6..8], olda+1);
        self
    }


    fn write_name(&mut self, name: &str) {
        if self.labels.contains_key(name) {
            // write offset to buffer
            let offset = self.labels.get(name).unwrap();
            let pointer : u16 = offset | OFFSET_FLAG;
            self.buf.write_u16::<BigEndian>(pointer).unwrap();
        } else {
            let offset = self.buf.len() as u16;
            self.labels.insert(name.to_owned(), offset);
            for part in name.split('.') {
                assert!(part.len() < 63);
                let ln = part.len() as u8;
                self.buf.push(ln);
                self.buf.extend(part.as_bytes());
            }
            self.buf.push(0);
        }
    }

    /// Returns the final packet
    ///
    /// When packet is not truncated method returns `Ok(packet)`. If
    /// packet is truncated the method returns `Err(packet)`. In both
    /// cases the packet is fully valid.
    ///
    /// In the server implementation you may use
    /// `x.build().unwrap_or_else(|x| x)`.
    ///
    /// In the client implementation it's probably unwise to send truncated
    /// packet, as it doesn't make sense. Even panicking may be more
    /// appropriate.
    // TODO(tailhook) does the truncation make sense for TCP, and how
    // to treat it for EDNS0?
    pub fn build(mut self) -> Result<Vec<u8>,Vec<u8>> {
        // TODO(tailhook) optimize labels
        if self.buf.len() > 512 {
            Header::set_truncated(&mut self.buf[..12]);
            Err(self.buf)
        } else {
            Ok(self.buf)
        }
    }
}

#[cfg(test)]
mod test {
    use QueryType as QT;
    use QueryClass as QC;
    use Type as T;
    use Class as C;
    use byteorder::{ByteOrder, BigEndian, WriteBytesExt};

    use {Opcode, ResponseCode, Header, QueryType, QueryClass, Type, Class};
    use std::net::Ipv4Addr;
    use super::Builder;

    #[test]
    fn build_query() {
        let mut bld = Builder::new_query(1573, true);
        bld.add_question("example.com", false, QT::A, QC::IN);
        let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_unicast_query() {
        let mut bld = Builder::new_query(1573, true);
        bld.add_question("example.com", true, QT::A, QC::IN);
        let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x80\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_srv_query() {
        let mut bld = Builder::new_query(23513, true);
        bld.add_question("_xmpp-server._tcp.gmail.com", false, QT::SRV, QC::IN);
        let result = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_response() {
        let ip = Ipv4Addr::new(158, 130, 68, 91);
        let ipnum = ip.octets().to_vec();
        let mut bld = Builder::new_response(23513, ResponseCode::NoError, false, true, true);
        bld.add_question("seas.upenn.edu", QT::A, QC::IN);
        bld.add_answer("seas.upenn.edu", T::A, C::IN, 7130, ipnum);
        let result = bld.build().unwrap();
        println!("{:?}", result);
    }
}
