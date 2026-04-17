use super::TransactionState;
use crate::types::message::{Request, Response};
use tokio::sync::mpsc;

pub struct ClientNonInviteTransaction {
    pub state: TransactionState,
    pub request: Request,
    response_tx: mpsc::Sender<Response>,
}

pub enum ClientNonInviteEvent {
    Response(Response),
    TimerFFired,
    TimerKFired,
    TransportError,
}

impl ClientNonInviteTransaction {
    pub fn new(request: Request, response_tx: mpsc::Sender<Response>) -> Self {
        Self {
            state: TransactionState::Trying,
            request,
            response_tx,
        }
    }

    pub async fn handle_event(&mut self, event: ClientNonInviteEvent) {
        match (&self.state, event) {
            (TransactionState::Trying, ClientNonInviteEvent::Response(resp)) => {
                if resp.status.class() == 1 {
                    self.state = TransactionState::Proceeding;
                } else {
                    self.state = TransactionState::Completed;
                }
                let _ = self.response_tx.send(resp).await;
            }
            (TransactionState::Proceeding, ClientNonInviteEvent::Response(resp)) => {
                if resp.status.class() >= 2 {
                    self.state = TransactionState::Completed;
                }
                let _ = self.response_tx.send(resp).await;
            }
            (
                TransactionState::Trying | TransactionState::Proceeding,
                ClientNonInviteEvent::TimerFFired,
            ) => {
                self.state = TransactionState::Terminated;
            }
            (TransactionState::Completed, ClientNonInviteEvent::TimerKFired) => {
                self.state = TransactionState::Terminated;
            }
            _ => {}
        }
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
    }
}
