use super::TransactionState;
use crate::types::message::{Request, Response};
use tokio::sync::mpsc;

pub struct ClientInviteTransaction {
    pub state: TransactionState,
    pub request: Request,
    response_tx: mpsc::Sender<Response>,
}

pub enum ClientInviteEvent {
    Response(Response),
    TimerBFired,
    TransportError,
}

impl ClientInviteTransaction {
    pub fn new(request: Request, response_tx: mpsc::Sender<Response>) -> Self {
        Self {
            state: TransactionState::Calling,
            request,
            response_tx,
        }
    }

    pub async fn handle_event(&mut self, event: ClientInviteEvent) {
        match (&self.state, event) {
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
}
