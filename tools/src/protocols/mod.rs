use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;

/// Packet wrapper to pass to TransportSender
/// This allows us to return both MutableTcpPacket
/// and MutableUdpPacket from the builders
pub enum PktWrapper<'a> {
    Tcp(MutableTcpPacket<'a>),
    Udp(MutableUdpPacket<'a>),
}

mod tcp;
pub use tcp::TcpBuilder;

mod udp;
pub use udp::UdpBuilder;
