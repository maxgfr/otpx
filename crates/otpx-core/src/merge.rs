//! Conflict-free merge of two copies of a vault.
//!
//! Each entry carries the stamp of its last change; deletions leave a tombstone. The newer
//! stamp wins entry by entry, so two devices that edited different accounts both keep their
//! changes, and the result is the same whichever side merges (commutative, associative and
//! idempotent). An HOTP counter never goes back: the higher one is kept, so a code already
//! used is not shown again.

use std::collections::BTreeMap;

#[cfg(test)]
use crate::model::Kind;
use crate::model::{Entry, Identity, Tombstone, VaultData};

/// Tombstones older than this are dropped (180 days, in ms).
pub const TOMBSTONE_TTL_MS: u64 = 180 * 24 * 3600 * 1000;

/// Merges `a` and `b`. `now_ms` only decides which old tombstones are dropped.
pub fn merge(a: &VaultData, b: &VaultData, now_ms: u64) -> VaultData {
    let mut entries: BTreeMap<&str, Entry> = BTreeMap::new();
    for e in a.entries.iter().chain(&b.entries) {
        match entries.get_mut(e.id.as_str()) {
            None => {
                entries.insert(&e.id, e.clone());
            }
            Some(cur) => {
                let counter = cur.counter.max(e.counter);
                if e.updated > cur.updated || (e.updated == cur.updated && is_greater(e, cur)) {
                    *cur = e.clone();
                }
                // Kept for every kind so the result does not depend on the merge order.
                cur.counter = counter;
            }
        }
    }
    let mut tombs: BTreeMap<&str, Tombstone> = BTreeMap::new();
    for t in a.tombstones.iter().chain(&b.tombstones) {
        match tombs.get_mut(t.id.as_str()) {
            Some(cur) => {
                let counter = cur.counter.max(t.counter);
                if t.deleted > cur.deleted {
                    *cur = t.clone();
                }
                cur.counter = counter;
            }
            None => {
                tombs.insert(&t.id, t.clone());
            }
        }
    }
    // A deletion wins over every change it saw; an edit made after it brings the entry back.
    // Either way the HOTP counter moves to the survivor.
    for t in tombs.values_mut() {
        if let Some(e) = entries.get_mut(t.id.as_str()) {
            if e.updated <= t.deleted {
                t.counter = t.counter.max(e.counter);
                entries.remove(t.id.as_str());
            } else {
                e.counter = e.counter.max(t.counter);
            }
        }
    }
    let tombstones = tombs
        .into_values()
        .filter(|t| !entries.contains_key(t.id.as_str()))
        .filter(|t| t.deleted.t.saturating_add(TOMBSTONE_TTL_MS) >= now_ms)
        .collect();
    let mut identities: Vec<Identity> = Vec::new();
    for i in a.identities.iter().chain(&b.identities) {
        if !identities.iter().any(|x| x.public == i.public) {
            identities.push(i.clone());
        }
    }
    identities.sort_by(|x, y| (x.created, &x.public).cmp(&(y.created, &y.public)));
    let settings = if b.settings.updated > a.settings.updated {
        b.settings.clone()
    } else {
        a.settings.clone()
    };
    let mut entries: Vec<Entry> = entries.into_values().collect();
    entries.sort_by(|x, y| (x.created, &x.id).cmp(&(y.created, &y.id)));
    VaultData {
        entries,
        tombstones,
        identities,
        settings,
    }
}

/// Total order on entries with the same stamp (only reachable from hand-made data). The
/// counter is left out: it is merged on its own.
fn is_greater(a: &Entry, b: &Entry) -> bool {
    let key = |e: &Entry| {
        let mut e = e.clone();
        e.counter = 0;
        serde_json::to_string(&e).unwrap_or_default()
    };
    key(a) > key(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Stamp;
    use proptest::prelude::*;

    fn st(t: u64, d: &str) -> Stamp {
        Stamp {
            t,
            c: 0,
            d: d.into(),
        }
    }

    fn entry(id: &str, t: u64, d: &str, note: &str) -> Entry {
        let mut e = Entry::new("I", "a", vec![1, 2, 3]);
        e.id = id.into();
        e.updated = st(t, d);
        e.note = note.into();
        e
    }

    #[test]
    fn concurrent_edits_of_different_entries_both_survive() {
        let base = VaultData {
            entries: vec![entry("1", 1, "x", ""), entry("2", 1, "x", "")],
            ..Default::default()
        };
        let mut a = base.clone();
        a.entries[0].note = "from a".into();
        a.entries[0].updated = st(5, "a");
        let mut b = base.clone();
        b.entries[1].note = "from b".into();
        b.entries[1].updated = st(6, "b");
        let m = merge(&a, &b, 10);
        assert_eq!(m.entries[0].note, "from a");
        assert_eq!(m.entries[1].note, "from b");
    }

    #[test]
    fn deletion_and_resurrection() {
        let a = VaultData {
            entries: vec![entry("1", 1, "x", "")],
            ..Default::default()
        };
        let b = VaultData {
            tombstones: vec![Tombstone {
                id: "1".into(),
                deleted: st(2, "b"),
                counter: 0,
            }],
            ..Default::default()
        };
        assert!(merge(&a, &b, 3).entries.is_empty());
        let edited_later = VaultData {
            entries: vec![entry("1", 3, "a", "kept")],
            ..Default::default()
        };
        let m = merge(&edited_later, &b, 4);
        assert_eq!(m.entries.len(), 1);
        assert!(m.tombstones.is_empty());
    }

    #[test]
    fn hotp_counter_never_goes_back() {
        let mut a = entry("1", 1, "a", "");
        a.kind = Kind::Hotp;
        a.counter = 9;
        let mut b = a.clone();
        b.counter = 3;
        b.updated = st(5, "b");
        b.note = "renamed".into();
        let m = merge(
            &VaultData {
                entries: vec![a],
                ..Default::default()
            },
            &VaultData {
                entries: vec![b],
                ..Default::default()
            },
            6,
        );
        assert_eq!(
            (m.entries[0].counter, m.entries[0].note.as_str()),
            (9, "renamed")
        );
    }

    #[test]
    fn old_tombstones_expire() {
        let a = VaultData {
            tombstones: vec![Tombstone {
                id: "1".into(),
                deleted: st(1, "b"),
                counter: 0,
            }],
            ..Default::default()
        };
        assert_eq!(merge(&a, &a, 2).tombstones.len(), 1);
        assert!(merge(&a, &a, TOMBSTONE_TTL_MS + 2).tombstones.is_empty());
    }

    fn arb_data() -> impl Strategy<Value = VaultData> {
        let ent = (
            0u8..6,
            0u64..8,
            prop::sample::select(vec!["a", "b", "c"]),
            0u64..4,
            any::<bool>(),
        )
            .prop_map(|(id, t, d, counter, hotp)| {
                let mut e = entry(&id.to_string(), t, d, &format!("{id}{t}{d}"));
                if hotp {
                    e.kind = Kind::Hotp;
                }
                e.counter = counter;
                e
            });
        let tomb = (
            0u8..6,
            0u64..8,
            prop::sample::select(vec!["a", "b"]),
            0u64..4,
        )
            .prop_map(|(id, t, d, counter)| Tombstone {
                id: id.to_string(),
                deleted: st(t, d),
                counter,
            });
        (
            prop::collection::vec(ent, 0..6),
            prop::collection::vec(tomb, 0..3),
        )
            .prop_map(|(es, ts)| {
                // One copy holds each id at most once.
                let mut seen = std::collections::BTreeSet::new();
                let entries = es
                    .into_iter()
                    .filter(|e| seen.insert(e.id.clone()))
                    .collect();
                let mut seen_t = std::collections::BTreeSet::new();
                let tombstones = ts
                    .into_iter()
                    .filter(|t| seen_t.insert(t.id.clone()))
                    .collect();
                VaultData {
                    entries,
                    tombstones,
                    ..Default::default()
                }
            })
    }

    proptest! {
        #[test]
        fn merge_is_commutative(a in arb_data(), b in arb_data()) {
            prop_assert_eq!(merge(&a, &b, 100), merge(&b, &a, 100));
        }

        #[test]
        fn merge_is_associative(a in arb_data(), b in arb_data(), c in arb_data()) {
            prop_assert_eq!(
                merge(&merge(&a, &b, 100), &c, 100),
                merge(&a, &merge(&b, &c, 100), 100)
            );
        }

        #[test]
        fn merge_is_idempotent(a in arb_data(), b in arb_data()) {
            let m = merge(&a, &b, 100);
            prop_assert_eq!(merge(&m, &m, 100), m.clone());
            prop_assert_eq!(merge(&m, &a, 100), m);
        }
    }
}
