use super::{TIMER_T1, TIMER_T2, TransactionState};
use crate::types::message::{Request, Response};
use tokio::sync::mpsc;

pub struct ClientInviteTransaction {
    pub state: TransactionState,
    pub request: Request,
    response_tx: mpsc::Sender<Response>,
    retransmit_tx: Option<mpsc::Sender<Request>>,
}

pub enum ClientInviteEvent {
    Response(Response),
    TimerAFired,
    TimerBFired,
    TransportError,
}

impl ClientInviteTransaction {
    pub fn new(request: Request, response_tx: mpsc::Sender<Response>) -> Self {
        Self {
            state: TransactionState::Calling,
            request,
            response_tx,
            retransmit_tx: None,
        }
    }

    pub fn with_retransmit_channel(
        request: Request,
        response_tx: mpsc::Sender<Response>,
        retransmit_tx: mpsc::Sender<Request>,
    ) -> Self {
        Self {
            state: TransactionState::Calling,
            request,
            response_tx,
            retransmit_tx: Some(retransmit_tx),
        }
    }

    pub async fn handle_event(&mut self, event: ClientInviteEvent) {
        match (&self.state, event) {
            (TransactionState::Calling, ClientInviteEvent::TimerAFired) => {
                self.retransmit_invite().await;
            }
            (TransactionState::Calling, ClientInviteEvent::Response(resp)) => {
                self.on_response_in_calling(resp).await;
            }
            (TransactionState::Proceeding, ClientInviteEvent::Response(resp)) => {
                self.on_response_in_proceeding(resp).await;
            }
            (TransactionState::Calling, ClientInviteEvent::TimerBFired) => {
                tracing::warn!("INVITE client transaction Timer B expired");
                self.state = TransactionState::Terminated;
            }
            (TransactionState::Calling, ClientInviteEvent::TransportError) => {
                self.state = TransactionState::Terminated;
            }
            _ => {}
        }
    }

    async fn retransmit_invite(&self) {
        if let Some(tx) = &self.retransmit_tx {
            let _ = tx.send(self.request.clone()).await;
        }
    }

    async fn on_response_in_calling(&mut self, resp: Response) {
        match resp.status.class() {
            1 => {
                self.state = TransactionState::Proceeding;
                let _ = self.response_tx.send(resp).await;
            }
            2 => {
                self.state = TransactionState::Terminated;
                let _ = self.response_tx.send(resp).await;
            }
            3..=6 => {
                self.state = TransactionState::Completed;
                let _ = self.response_tx.send(resp).await;
            }
            _ => {}
        }
    }

    async fn on_response_in_proceeding(&mut self, resp: Response) {
        match resp.status.class() {
            1 => {
                let _ = self.response_tx.send(resp).await;
            }
            2 => {
                self.state = TransactionState::Terminated;
                let _ = self.response_tx.send(resp).await;
            }
            3..=6 => {
                self.state = TransactionState::Completed;
                let _ = self.response_tx.send(resp).await;
            }
            _ => {}
        }
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
    }

    /// Spawns the RFC 3261 §17.1.1.2 Timer A retransmit loop.
    ///
    /// Fires `TimerAFired` on `event_tx` at T1, 2×T1, 4×T1, … (capped at T2).
    /// The task exits when `event_tx` is closed (i.e., the transaction is gone).
    /// Callers are responsible for aborting the returned handle when a response
    /// arrives (transaction leaves the Calling state).
    pub fn spawn_timer_a(event_tx: mpsc::Sender<ClientInviteEvent>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut delay = TIMER_T1;
            loop {
                tokio::time::sleep(delay).await;
                if event_tx.send(ClientInviteEvent::TimerAFired).await.is_err() {
                    return;
                }
                delay = (delay * 2).min(TIMER_T2);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::header::{CSeq, Header, RportParam, Transport, Via};
    use crate::types::message::SipVersion;
    use crate::types::method::Method;
    use crate::types::status::StatusCode;

    fn invite_request() -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_owned(),
            version: SipVersion::V2_0,
            headers: vec![
                Header::Via(Via {
                    transport: Transport::Udp,
                    host: "client.example.com".to_owned(),
                    port: Some(5060),
                    branch: "z9hG4bK-client".to_owned(),
                    received: None,
                    rport: RportParam::Absent,
                    params: vec![],
                }),
                Header::CSeq(CSeq {
                    seq: 1,
                    method: Method::Invite,
                }),
            ],
            body: vec![],
        }
    }

    fn response(status: StatusCode) -> Response {
        Response {
            version: SipVersion::V2_0,
            status,
            reason: status.reason_phrase().to_owned(),
            headers: vec![],
            body: vec![],
        }
    }

    #[tokio::test]
    async fn timer_a_retransmits_invite_while_calling() {
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (retransmit_tx, mut retransmit_rx) = mpsc::channel(1);
        let mut transaction = ClientInviteTransaction::with_retransmit_channel(
            invite_request(),
            response_tx,
            retransmit_tx,
        );

        transaction
            .handle_event(ClientInviteEvent::TimerAFired)
            .await;

        let retransmit = retransmit_rx.recv().await.expect("retransmitted request");
        assert_eq!(retransmit.method, Method::Invite);
        assert_eq!(transaction.state, TransactionState::Calling);
    }

    #[tokio::test]
    async fn spawn_timer_a_stops_when_channel_is_dropped() {
        let (event_tx, event_rx) = mpsc::channel(1);
        let handle = ClientInviteTransaction::spawn_timer_a(event_tx);
        drop(event_rx);
        // After the channel receiver is dropped the task should exit cleanly.
        let res = tokio::time::timeout(super::TIMER_T1 * 3, handle).await;
        assert!(res.is_ok(), "task timed out");
    }

    #[tokio::test]
    async fn timer_a_does_not_retransmit_after_provisional_response() {
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (retransmit_tx, mut retransmit_rx) = mpsc::channel(1);
        let mut transaction = ClientInviteTransaction::with_retransmit_channel(
            invite_request(),
            response_tx,
            retransmit_tx,
        );
        transaction
            .handle_event(ClientInviteEvent::Response(response(StatusCode::TRYING)))
            .await;

        transaction
            .handle_event(ClientInviteEvent::TimerAFired)
            .await;

        assert!(retransmit_rx.try_recv().is_err());
        assert_eq!(transaction.state, TransactionState::Proceeding);
    }
}
