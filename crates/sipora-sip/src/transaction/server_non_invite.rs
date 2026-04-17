use super::TransactionState;
use crate::types::message::{Request, Response};
use tokio::sync::mpsc;

pub struct ServerNonInviteTransaction {
    pub state: TransactionState,
    pub request: Request,
    last_response: Option<Response>,
    response_tx: mpsc::Sender<Response>,
}

pub enum ServerNonInviteEvent {
    Request(Request),
    SendResponse(Response),
    TimerJFired,
    TransportError,
}

impl ServerNonInviteTransaction {
    pub fn new(request: Request, response_tx: mpsc::Sender<Response>) -> Self {
        Self {
            state: TransactionState::Trying,
            request,
            last_response: None,
            response_tx,
        }
    }

    pub async fn handle_event(&mut self, event: ServerNonInviteEvent) {
        match (&self.state, event) {
            (TransactionState::Trying, ServerNonInviteEvent::SendResponse(resp)) => {
                self.on_send_response(resp, true).await;
            }
            (TransactionState::Proceeding, ServerNonInviteEvent::SendResponse(resp)) => {
                self.on_send_response(resp, false).await;
            }
            (
                TransactionState::Trying | TransactionState::Proceeding,
                ServerNonInviteEvent::Request(_),
            ) => {
                self.retransmit_last_response().await;
            }
            (TransactionState::Completed, ServerNonInviteEvent::Request(_)) => {
                self.retransmit_last_response().await;
            }
            (TransactionState::Completed, ServerNonInviteEvent::TimerJFired) => {
                self.state = TransactionState::Terminated;
            }
            _ => {}
        }
    }

    async fn on_send_response(&mut self, resp: Response, from_trying: bool) {
        let class = resp.status.class();
        self.last_response = Some(resp.clone());
        let _ = self.response_tx.send(resp).await;
        if from_trying && class == 1 {
            self.state = TransactionState::Proceeding;
        } else if class >= 2 {
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
