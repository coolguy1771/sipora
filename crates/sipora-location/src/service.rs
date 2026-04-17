use crate::ContactBinding;
use sipora_core::redis_keys;

pub struct LocationService {
    max_contacts_per_aor: usize,
    publish_events: bool,
}

impl LocationService {
    pub fn new(max_contacts_per_aor: usize, publish_events: bool) -> Self {
        Self {
            max_contacts_per_aor,
            publish_events,
        }
    }

    pub fn aor_key(&self, domain: &str, username: &str) -> String {
        redis_keys::location_key(domain, username)
    }

    pub fn change_channel(domain: &str, username: &str) -> String {
        format!("location:changed:{domain}:{username}")
    }

    pub fn max_contacts(&self) -> usize {
        self.max_contacts_per_aor
    }

    pub fn should_publish(&self) -> bool {
        self.publish_events
    }

    /// Score = q_value, member = contact_uri
    pub fn parse_binding(member: &str, score: f64) -> ContactBinding {
        ContactBinding {
            uri: member.to_owned(),
            q_value: score as f32,
            expires: 0,
        }
    }

    pub fn sort_by_q(contacts: &mut [ContactBinding]) {
        contacts.sort_by(|a, b| {
            b.q_value
                .partial_cmp(&a.q_value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}
