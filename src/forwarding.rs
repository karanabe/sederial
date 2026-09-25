//! Coordinates client validation, route selection and upstream exchange.
//!
//! Both client transports use this path. Socket framing belongs to `server`
//! and `transport`; this module returns a complete DNS message or a decision
//! to discard the input without replying.
use crate::{
    dns::{Header, MessageType, Packet, QueryDecision, ResponseCode},
    logging,
    routing::RoutingTable,
    transport::{Deadline, Transport},
    upstream::{ForwardError, Forwarder},
};
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};

/// Each worker owns its exchange state and shares immutable routing policy.
pub(crate) struct RequestHandler {
    routing: Arc<RoutingTable>,
    forwarder: Forwarder,
    stop: Arc<AtomicBool>,
}

impl RequestHandler {
    /// Creates worker-local exchange state while sharing routing and cancellation.
    ///
    /// # Errors
    /// Returns an I/O error if the OS entropy source cannot be opened.
    pub(crate) fn new(routing: Arc<RoutingTable>, stop: Arc<AtomicBool>) -> io::Result<Self> {
        Ok(Self {
            routing,
            forwarder: Forwarder::new()?,
            stop,
        })
    }

    /// Releases an expired upstream connection when the owning worker polls.
    pub(crate) fn expire_idle(&mut self) {
        self.forwarder.expire_idle();
    }

    /// Produces a client reply, including DNS errors for rejected queries.
    ///
    /// Returns `None` for an unreadable header or an unsolicited response.
    /// Successful upstream replies regain the client's ID; oversized UDP replies
    /// become complete minimal TC replies. Upstream failures become SERVFAIL.
    pub(crate) fn respond(
        &mut self,
        wire: &[u8],
        transport: Transport,
        deadline: Deadline,
    ) -> Option<Vec<u8>> {
        // Expired queued jobs and cancellation are silent, with no parsing or I/O.
        deadline.remaining(&self.stop).ok()?;
        let header = match Header::parse(wire) {
            Ok(header) => header,
            Err(error) => {
                logging::warn(format_args!("malformed client packet: {error}"));
                return None;
            }
        };
        // Never respond to responses, avoiding reflection loops.
        if header.message_type() != MessageType::Query {
            return None;
        }
        let packet = match Packet::parse_for_reply(wire) {
            Ok(packet) => packet,
            Err(failure) => {
                logging::warn(format_args!("malformed client packet: {}", failure.error));
                return failure.format_reply();
            }
        };
        let query = match packet.validate_query() {
            QueryDecision::Forward(query) => query,
            QueryDecision::Reject(code) => {
                let reply = packet.local_error_reply(code);
                if reply.is_none() {
                    logging::warn(format_args!(
                        "local error suppressed: no validated response cookie"
                    ));
                }
                return reply;
            }
            QueryDecision::Ignore => return None,
        };
        let selection = self.routing.select(query.name());
        let upstreams = selection.upstreams();
        let response = match self
            .forwarder
            .forward(&query, upstreams, transport, &self.stop, deadline)
        {
            Ok(response) => response,
            Err(ForwardError::Cancelled) => return None,
            Err(error) => {
                deadline.remaining(&self.stop).ok()?;
                logging::warn(format_args!("forwarding failed: {error}"));
                let reply = query.error_reply(ResponseCode::ServerFailure);
                if reply.is_none() {
                    logging::warn(format_args!(
                        "local error suppressed: no validated response cookie"
                    ));
                }
                return reply;
            }
        };
        deadline.remaining(&self.stop).ok()?;
        if matches!(transport, Transport::Udp) && response.wire().len() > query.udp_limit() {
            Some(query.truncated_reply(&response))
        } else {
            Some(response.with_id(query.id()))
        }
    }
}
