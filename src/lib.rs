use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
};

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_snmp::{v2, v2c};

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq)]
pub enum SnmpError {
    SendError,
    ReceiveError,
    ParseError,
}

type SnmpResult<T> = Result<T, SnmpError>;

const BUFFER_SIZE: usize = 4096;

pub struct SyncSession {
    community: OctetString,
    socket: UdpSocket,
    version: Integer,
}

impl SyncSession {
    pub fn new<A>(version: u8, dest_addr: A, community: &[u8], timeout: u64) -> io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let socket = match dest_addr.to_socket_addrs()?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
            Some(SocketAddr::V6(_)) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?,
            None => panic!("empty list of socket addrs"),
        };

        socket.set_read_timeout(Some(Duration::from_millis(timeout)))?;
        socket.connect(dest_addr)?;

        Ok(SyncSession {
            community: community.to_vec().into(),
            socket,
            version: version.into(),
        })
    }

    fn send_and_recv(socket: &UdpSocket, send: Vec<u8>) -> SnmpResult<Vec<u8>> {
        let mut recv: Box<[u8; BUFFER_SIZE]> = Box::new([0; BUFFER_SIZE]);

        for _ in 0..2 {
            if let Ok(_) = socket.send(&send) {
                match socket.recv(recv.as_mut_slice()) {
                    Ok(_) => return Ok(recv.to_vec()),
                    Err(_) => continue,
                }
            } else {
                return Err(SnmpError::SendError);
            }
        }

        Err(SnmpError::ReceiveError)
    }

    fn parse_oid(value: &String) -> ObjectIdentifier {
        let oid: Cow<'static, [u32]> = value
            .split('.')
            .filter_map(|part| part.parse::<u32>().ok())
            .collect();

        ObjectIdentifier::new_unchecked(oid)
    }

    fn parse_response(message: v2c::Message<v2::Pdus>) -> SnmpResult<v2::VarBindList> {
        if let v2::Pdus::Response(response) = message.data {
            println!(
                "Error: status: {}, index: {}",
                response.0.error_status, response.0.error_index
            );

            Ok(response.0.variable_bindings)
        } else {
            Err(SnmpError::ParseError)
        }
    }

    fn parse_value(var: v2::VarBindValue) -> String {
        match var {
            v2::VarBindValue::Value(value) => match value {
                v2::ObjectSyntax::Simple(simple) => match simple {
                    rasn_smi::v2::SimpleSyntax::Integer(int) => int.to_string(),
                    rasn_smi::v2::SimpleSyntax::String(str) => {
                        String::from_utf8(str.to_vec()).unwrap()
                    }
                    rasn_smi::v2::SimpleSyntax::ObjectId(oid) => oid
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("."),
                },
                v2::ObjectSyntax::ApplicationWide(wide) => match wide {
                    rasn_smi::v2::ApplicationSyntax::Address(ip) => {
                        ip.0.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                    }
                    rasn_smi::v2::ApplicationSyntax::Counter(counter) => counter.0.to_string(),
                    rasn_smi::v2::ApplicationSyntax::Ticks(tick) => tick.0.to_string(),
                    rasn_smi::v2::ApplicationSyntax::BigCounter(counter) => counter.0.to_string(),
                    rasn_smi::v2::ApplicationSyntax::Unsigned(gauge) => gauge.0.to_string(),
                    rasn_smi::v2::ApplicationSyntax::Arbitrary(opaque) => {
                        println!("{:?}", opaque);
                        "".to_string()
                    }
                },
            },
            _ => "".to_string(),
        }
    }

    pub fn get(&self, oid: &String) {
        let message = v2c::Message {
            version: self.version.clone(),
            community: self.community.clone(),
            data: v2::GetRequest(v2::Pdu {
                request_id: 1,
                error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                error_index: 0,
                variable_bindings: vec![v2::VarBind {
                    name: Self::parse_oid(oid),
                    value: v2::VarBindValue::Unspecified,
                }],
            }),
        };

        let message = rasn::ber::encode(&message).unwrap();
        let message = Self::send_and_recv(&self.socket, message).unwrap();
        let message: v2c::Message<v2::Response>= rasn::ber::decode(&message).unwrap();

        // let vars = Self::parse_response(message).unwrap();
        for var in message.data.0.variable_bindings {
            println!("{} = {:#?}", var.name, var.value);
        }
    }

    pub fn getnext(&self, oid: &String) -> SnmpResult<v2::VarBindList> {
        let message = v2c::Message {
            version: v2c::Message::<v2::GetNextRequest>::VERSION.into(),
            community: self.community.clone(),
            data: v2::GetNextRequest(v2::Pdu {
                request_id: 1,
                error_status: v2::Pdu::ERROR_STATUS_NO_ERROR,
                error_index: 0,
                variable_bindings: vec![v2::VarBind {
                    name: Self::parse_oid(oid),
                    value: v2::VarBindValue::Unspecified,
                }],
            }),
        };

        let message = rasn::ber::encode(&message).unwrap();
        let message = Self::send_and_recv(&self.socket, message).unwrap();
        let message = rasn::ber::decode(&message).unwrap();

        Self::parse_response(message)
    }

    pub fn getbulk(&self, oid: &String, non_repeaters: u32, max_repetitions: u32) {
        let message = v2c::Message {
            version: self.version.clone(),
            community: self.community.clone(),
            data: v2::GetBulkRequest(v2::BulkPdu {
                request_id: 1,
                non_repeaters,
                max_repetitions,
                variable_bindings: vec![v2::VarBind {
                    name: Self::parse_oid(oid),
                    value: v2::VarBindValue::Unspecified,
                }],
            }),
        };

        let message = rasn::ber::encode(&message).unwrap();
        let message = Self::send_and_recv(&self.socket, message).unwrap();
        let message = rasn::ber::decode(&message).unwrap();

        let vars = Self::parse_response(message).unwrap();
        for var in vars {
            println!("{} = {}", var.name, Self::parse_value(var.value));
        }
    }

    pub fn walk(&self, oid: &String) -> SnmpResult<BTreeMap<Vec<u32>, v2::VarBindValue>> {
        let start = Self::parse_oid(oid);

        let mut current = oid.clone();
        let mut result = BTreeMap::new();

        loop {
            match self.getnext(&current) {
                Ok(vars) => {
                    let var = vars[0].clone();

                    if var.name.starts_with(&start) {
                        let (_, right) = var.name.split_at(start.len());

                        result.insert(right.to_vec(), var.value);

                        current = var.name.to_string();
                    } else {
                        return Ok(result);
                    };
                }
                Err(_) => {}
            }
        }
    }
}
