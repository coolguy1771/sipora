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
            (TransactionState::Completed, ServerInviteEvent::TimerHFired) => {
                self.state = TransactionState::Terminated;
            }
            (TransactionState::Confirmed, ServerInviteEvent::TimerIFired) => {
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
            self.state = TransactionState::Terminated;
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
