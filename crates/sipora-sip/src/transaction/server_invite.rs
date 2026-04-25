use super::TransactionState;
use crate::types::message::{Request, Response};
use tokio::sync::mpsc;

pub struct ServerInviteTransaction {
    pub state: TransactionState,
    pub request: Request,
    last_response: Option<Response>,
    response_tx: mpsc::Sender<Response>,
}

pub enum ServerInviteEvent {
    Request(Request),
    SendResponse(Response),
    TimerHFired,
    TimerIFired,
    TimerLFired,
    TransportError,
}

impl ServerInviteTransaction {
    pub fn new(request: Request, response_tx: mpsc::Sender<Response>) -> Self {
        Self {
            state: TransactionState::Proceeding,
            request,
            last_response: None,
            response_tx,
        }
    }

    pub async fn handle_event(&mut self, event: ServerInviteEvent) {
        match (&self.state, event) {
            (TransactionState::Proceeding, ServerInviteEvent::SendResponse(resp)) => {
                self.on_send_response_proceeding(resp).await;
            }
            (TransactionState::Proceeding, ServerInviteEvent::Request(_)) => {
                self.retransmit_last_response().await;
            }
            (TransactionState::Completed, ServerInviteEvent::Request(_)) => {
                self.retransmit_last_response().await;
            }
            (TransactionState::Accepted, ServerInviteEvent::Request(_)) => {}
            (TransactionState::Accepted, ServerInviteEvent::SendResponse(resp)) => {
                let _ = self.response_tx.send(resp).await;
            }
            (TransactionState::Completed, ServerInviteEvent::TimerHFired) => {
                self.state = TransactionState::Terminated;
            }
            (TransactionState::Confirmed, ServerInviteEvent::TimerIFired) => {
                self.state = TransactionState::Terminated;
            }
            (TransactionState::Accepted, ServerInviteEvent::TimerLFired) => {
                self.state = TransactionState::Terminated;
            }
            _ => {}
        }
    }

    async fn on_send_response_proceeding(&mut self, resp: Response) {
        let class = resp.status.class();
        self.last_response = Some(resp.clone());
        let _ = self.response_tx.send(resp).await;
        if class == 2 {
            self.state = TransactionState::Accepted;
        } else if (3..=6).contains(&class) {
            self.state = TransactionState::Completed;
        }
    }

    async fn retransmit_last_response(&self) {
        if let Some(resp) = &self.last_response {
            let _ = self.response_tx.send(resp.clone()).await;
        }
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
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
                    branch: "z9hG4bK-invite".to_owned(),
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
    async fn two_xx_response_moves_to_accepted() {
        let (tx, _rx) = mpsc::channel(1);
        let mut transaction = ServerInviteTransaction::new(invite_request(), tx);

        transaction
            .handle_event(ServerInviteEvent::SendResponse(response(StatusCode::OK)))
            .await;

        assert_eq!(transaction.state, TransactionState::Accepted);
    }

    #[tokio::test]
    async fn timer_l_terminates_accepted_transaction() {
        let (tx, _rx) = mpsc::channel(1);
        let mut transaction = ServerInviteTransaction::new(invite_request(), tx);
        transaction.state = TransactionState::Accepted;

        transaction
            .handle_event(ServerInviteEvent::TimerLFired)
            .await;

        assert_eq!(transaction.state, TransactionState::Terminated);
    }

    #[tokio::test]
    async fn accepted_retransmitted_invite_is_absorbed() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut transaction = ServerInviteTransaction::new(invite_request(), tx);
        transaction
            .handle_event(ServerInviteEvent::SendResponse(response(StatusCode::OK)))
            .await;
        rx.recv().await.expect("initial response sent");

        transaction
            .handle_event(ServerInviteEvent::Request(invite_request()))
            .await;

        assert!(rx.try_recv().is_err());
        assert_eq!(transaction.state, TransactionState::Accepted);
    }
}
