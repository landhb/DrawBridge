use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;

/// Packet wrapper to pass to TransportSender
/// This allows us to return both MutableTcpPacket
/// and MutableUdpPacket from the builders
pub enum PktWrapper<'a> {
    Tcp(MutableTcpPacket<'a>),
    Udp(MutableUdpPacket<'a>),
}

/// tx.send_to's first argument must implement
/// the pnet::packet::Packet Trait
impl pnet::packet::Packet for PktWrapper<'_> {
    fn packet(&self) -> &[u8] {
        match self {
            PktWrapper::Tcp(pkt) => pkt.packet(),
            PktWrapper::Udp(pkt) => pkt.packet(),
        }
    }
    fn payload(&self) -> &[u8] {
        match self {
            PktWrapper::Tcp(pkt) => pkt.payload(),
            PktWrapper::Udp(pkt) => pkt.payload(),
        }
    }
}

mod tcp;
pub use tcp::TcpBuilder;

mod udp;
pub use udp::UdpBuilder;
